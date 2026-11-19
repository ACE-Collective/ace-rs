//! A collector's submissions (PLAN.md 6.1): what `ace collect <name>` (`ace_app::collector`) writes.
//!
//! A collector acts as the component `collector:<name>`, which holds the class `collector`'s grant,
//! `alert:create` (migration 0074, `Component::class`). [`Service::submit_collected`] makes its root
//! as `Service::submit` does, and records the item's key in `collection.submitted_keys` in the same
//! transaction, so a key is held exactly when its root exists. A key a live row holds is a
//! duplicate: nothing is written, and the earlier root is returned. That is ace3's
//! `DuplicateSubmissionFilter` over its `persistence` table, with one difference: ace3 marks the key in
//! one statement and stages the submission after it, so a crash between the two loses the item, and
//! a failure after the mark leaves it marked; here neither can happen.
//!
//! The key is claimed first, by an insert that does nothing on a live row, so two replicas of one
//! collector given the same item at once make one root: the second's insert waits for the first's
//! transaction and then finds its row.
//!
//! Growth: one row per submitted key, removed once it expires (`key_lifetime_seconds`, 4 hours by
//! default, ace3's), by each submission of its collector.

use ace_core::bucket::Bucket;
use ace_core::submit::{Origin, Submission, SubmittedFile};
use chrono::TimeDelta;
use uuid::Uuid;

use crate::gate::Audited;
use crate::permission::ALERT_CREATE;
use crate::{Actor, Service, ServiceError};

/// How long a key holds unless the collector's section says otherwise: ace3's
/// `persistence_unmodified_expiration_seconds`, the time after which ace3 forgets a key it never
/// updates.
pub const DEFAULT_KEY_LIFETIME: TimeDelta = TimeDelta::hours(4);

/// What a collected item made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Collected {
    /// A new root, with the tasks it queued.
    Submitted(ace_core::submit::Submitted),
    /// Its key made this root less than its lifetime ago, so nothing was written.
    Duplicate { root: Uuid },
}

impl Service {
    /// Creates a collected item's root, as `submit` does, unless its `key` already made one for
    /// `collector` within `key_lifetime`: the key is recorded with the root in one transaction. It
    /// needs `alert:create`. An item with no key is always submitted, as ace3's. A submission that
    /// can't be taken is `ServiceError::InvalidRequest` and writes nothing, its key included.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_collected(
        &self,
        actor: &Actor,
        bucket: &Bucket,
        collector: &str,
        key: Option<&str>,
        key_lifetime: TimeDelta,
        submission: &Submission,
        origin: &Origin,
        files: &[SubmittedFile],
    ) -> Result<Collected, ServiceError> {
        self.gate
            .write(actor, "submit_collected", &ALERT_CREATE, &|tx| {
                Box::pin(async move {
                    sqlx::query!(
                        "DELETE FROM collection.submitted_keys
                         WHERE collector = $1 AND expires_at <= now()",
                        collector,
                    )
                    .execute(tx.conn())
                    .await?;
                    if let Some(key) = key {
                        let claimed = sqlx::query_scalar!(
                            r#"INSERT INTO collection.submitted_keys
                                   (collector, hash, created_at, expires_at)
                               VALUES ($1, sha256(convert_to($2, 'UTF8')), now(), now() + make_interval(secs => $3))
                               ON CONFLICT (collector, hash) DO NOTHING
                               RETURNING 1 AS "claimed!""#,
                            collector,
                            key,
                            key_lifetime.as_seconds_f64(),
                        )
                        .fetch_optional(tx.conn())
                        .await?;
                        if claimed.is_none() {
                            let root = sqlx::query_scalar!(
                                r#"SELECT root AS "root!" FROM collection.submitted_keys
                                   WHERE collector = $1 AND hash = sha256(convert_to($2, 'UTF8'))"#,
                                collector,
                                key,
                            )
                            .fetch_one(tx.conn())
                            .await?;
                            return Ok(Audited::unchanged(Collected::Duplicate { root }));
                        }
                    }
                    let (submitted, change) = crate::submit::submit_in(
                        tx, self, bucket, actor, submission, origin, files,
                    )
                    .await?;
                    if let Some(key) = key {
                        sqlx::query!(
                            "UPDATE collection.submitted_keys SET root = $3
                             WHERE collector = $1 AND hash = sha256(convert_to($2, 'UTF8'))",
                            collector,
                            key,
                            submitted.uuid,
                        )
                        .execute(tx.conn())
                        .await?;
                    }
                    Ok(Audited::changed(Collected::Submitted(submitted), change))
                })
            })
            .await
    }
}
