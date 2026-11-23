//! What a detection export reads and writes (PLAN.md decision 58, `ace_app::export`): the live detections,
//! and its own record of what it last published, ace3's `saq/observables/export/state.py`.
//!
//! An export acts as the component `export:<name>`, which holds what the class `export` is granted,
//! `detection:read` and `export:record` (migration 0086). `active_detections` needs the first; the record's
//! read, claim and write need the second, and an export's component reaches only its own record: a
//! component `export:a` naming `b` is refused as a missing permission is.
//!
//! The record is one row of `export.targets`: the fingerprint of the last list a publish took in full, the
//! export's own JSON document (at most `MAX_EXPORT_STATE_BYTES`), and a lease. A pass claims the row, which takes
//! the lease when no live one holds it, publishes outside any transaction, and writes the row back, which
//! lets the lease go: so two replicas of one export never publish at once, and a process that died lets go
//! when its lease ends. No audit row: the record is the export's own bookkeeping, as a scheduled run's row
//! is, and ace3 keeps it in a file on the node.

use chrono::{DateTime, Utc};
use serde_json::Value;

use ace_core::rulesets::Detection;

use crate::permission::{DETECTION_READ, EXPORT_RECORD};
use crate::{Actor, Service, ServiceError};

/// The largest record an export keeps, as JSON: the table's own bound.
pub const MAX_EXPORT_STATE_BYTES: usize = 1 << 20;

/// An export's record (`export.targets`).
#[derive(Debug, Clone, PartialEq)]
pub struct ExportRecord {
    /// The fingerprint of the last list a publish took in full; None until one has.
    pub fingerprint: Option<String>,
    /// The export's own document, `{}` until it writes one.
    pub state: Value,
    /// When a publish last took a list in full.
    pub published_at: Option<DateTime<Utc>>,
    /// Who holds the pass, and until when.
    pub lease: Option<(String, DateTime<Utc>)>,
    pub updated_at: DateTime<Utc>,
}

/// What a pass writes back.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportOutcome<'a> {
    /// The fingerprint to keep: the new list's after a publish that took it in full, the one claimed
    /// otherwise.
    pub fingerprint: Option<&'a str>,
    pub state: &'a Value,
    /// True after a publish that took the list in full, which sets `published_at`.
    pub published: bool,
}

impl Service {
    /// The live detections with a value to export, in id order (`ace_core::rulesets::active_detections`):
    /// what a detection export selects from. Needs `detection:read`.
    pub async fn active_detections(&self, actor: &Actor) -> Result<Vec<Detection>, ServiceError> {
        self.gate
            .read(actor, "active_detections", &DETECTION_READ, &|tx| {
                Box::pin(async move { Ok(ace_core::rulesets::active_detections(tx.conn()).await?) })
            })
            .await
    }

    /// The export `name`'s record, if it has one. Needs `export:record`, and an export may read only its
    /// own.
    pub async fn export_record(
        &self,
        actor: &Actor,
        name: &str,
    ) -> Result<Option<ExportRecord>, ServiceError> {
        self.require_record(actor, "export_record", name).await?;
        let row = sqlx::query!(
            "SELECT fingerprint, state, published_at, lease_owner, lease_expires_at, updated_at
             FROM export.targets WHERE name = $1",
            name,
        )
        .fetch_optional(self.gate.db().pool())
        .await
        .map_err(ace_core::DbError::from)?;
        Ok(row.map(|row| ExportRecord {
            fingerprint: row.fingerprint,
            state: row.state,
            published_at: row.published_at,
            lease: row.lease_owner.zip(row.lease_expires_at),
            updated_at: row.updated_at,
        }))
    }

    /// Takes the export `name`'s pass for `owner` for `lease`, making its record if it has none, and
    /// returns the record; None when a live lease of another owner's holds it. Needs `export:record`.
    pub async fn claim_export(
        &self,
        actor: &Actor,
        name: &str,
        owner: &str,
        lease: std::time::Duration,
    ) -> Result<Option<ExportRecord>, ServiceError> {
        self.require_record(actor, "claim_export", name).await?;
        let pool = self.gate.db().pool();
        sqlx::query!(
            "INSERT INTO export.targets (name) VALUES ($1) ON CONFLICT (name) DO NOTHING",
            name,
        )
        .execute(pool)
        .await
        .map_err(|e| invalid_name(e, name))?;
        let row = sqlx::query!(
            "UPDATE export.targets
             SET lease_owner = $2, lease_expires_at = now() + make_interval(secs => $3),
                 updated_at = now()
             WHERE name = $1 AND (lease_owner IS NULL OR lease_owner = $2 OR lease_expires_at <= now())
             RETURNING fingerprint, state, published_at, lease_owner, lease_expires_at, updated_at",
            name,
            owner,
            lease.as_secs_f64(),
        )
        .fetch_optional(pool)
        .await
        .map_err(ace_core::DbError::from)?;
        Ok(row.map(|row| ExportRecord {
            fingerprint: row.fingerprint,
            state: row.state,
            published_at: row.published_at,
            lease: row.lease_owner.zip(row.lease_expires_at),
            updated_at: row.updated_at,
        }))
    }

    /// Writes back the pass `owner` claimed of the export `name` and lets its lease go. False when the
    /// lease isn't `owner`'s any more, such as after it ran out and another process took it: nothing is
    /// written then. A state that isn't a JSON object, or is over `MAX_EXPORT_STATE_BYTES`, is refused. Needs
    /// `export:record`.
    pub async fn record_export(
        &self,
        actor: &Actor,
        name: &str,
        owner: &str,
        outcome: &ExportOutcome<'_>,
    ) -> Result<bool, ServiceError> {
        self.require_record(actor, "record_export", name).await?;
        if !outcome.state.is_object() {
            return Err(ServiceError::InvalidRequest(format!(
                "the export {name}'s state must be a JSON object"
            )));
        }
        let size = serde_json::to_string(outcome.state)?.len();
        if size > MAX_EXPORT_STATE_BYTES {
            return Err(ServiceError::InvalidRequest(format!(
                "the export {name}'s state is {size} bytes, more than {MAX_EXPORT_STATE_BYTES}"
            )));
        }
        let written = sqlx::query!(
            "UPDATE export.targets
             SET fingerprint = $3, state = $4,
                 published_at = CASE WHEN $5 THEN now() ELSE published_at END,
                 lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
             WHERE name = $1 AND lease_owner = $2",
            name,
            owner,
            outcome.fingerprint,
            outcome.state,
            outcome.published,
        )
        .execute(self.gate.db().pool())
        .await
        .map_err(ace_core::DbError::from)?
        .rows_affected()
            > 0;
        Ok(written)
    }

    /// Refuses an actor without `export:record`, and an export's component naming another export's record.
    async fn require_record(
        &self,
        actor: &Actor,
        action: &'static str,
        name: &str,
    ) -> Result<(), ServiceError> {
        let own = match actor {
            Actor::Internal { id } if id.class() == Some("export") => {
                id.as_str() == format!("export:{name}")
            }
            _ => true,
        };
        if own && self.gate.allowed(actor, &EXPORT_RECORD).await? {
            return Ok(());
        }
        tracing::warn!(%actor, permission = %EXPORT_RECORD, action, export = name, "permission denied");
        Err(ServiceError::PermissionDenied {
            actor: actor.to_string(),
            permission: EXPORT_RECORD.clone(),
        })
    }
}

/// A name the table's check refuses is the caller's mistake; anything else is the database's.
fn invalid_name(error: sqlx::Error, name: &str) -> ServiceError {
    match &error {
        sqlx::Error::Database(db) if db.is_check_violation() => {
            ServiceError::InvalidRequest(format!("{name:?} can't name an export"))
        }
        _ => ace_core::DbError::from(error).into(),
    }
}
