//! The deletion of roots that never became alerts (PLAN.md decision 56), ace3's `cleanup` of an
//! analysis mode (`saq/engine/analysis_orchestrator.py`'s `_handle_cleanup`, at `85c8e9e5`).
//!
//! ace3 deletes a root's storage directory at the end of the pass that finds no outstanding work, when
//! the root's mode has `cleanup: true` and the root is still in it: a root that became an alert moved to
//! `correlation`, which keeps its roots. So a YARA-mode scan, a collector's email or a submitted file that
//! raised no detection leaves nothing behind. Here the same roots are deleted by `ace serve`'s scheduled
//! task `root_cleanup`, out of the transaction that ends a pass and out of the root's row lock, in
//! batches, and only after a grace (an hour by default), so a person or a test reading a root soon after
//! it ended still finds it.
//!
//! A root is deleted when all of these hold:
//! - it never became an alert (`alerted_at` is null), and its mode is one that cleans up
//!   (`crate::modes::Modes::cleans_up`), ace3's `cleanup` flags with the overlay's over them;
//! - it is finished: its last pass ended (`completed_pass = pass`), no hooks run is due, no task of it is
//!   queued, delayed or running (which covers a task a path hold keeps waiting, still `queued`), and no
//!   remediation or file collection it waits on is unfinished;
//! - its last pass ended more than the grace ago, or, with no pass, it was made more than the grace ago.
//!
//! Deleting a root deletes its tree, tasks and the rest with it (each table's `ON DELETE CASCADE`) and
//! releases its holds on the bucket's objects (`Hold::root`) in the same transaction, so each object
//! lives for its pool's grace from then and the bucket's GC frees it after, unless something else holds
//! it, such as another root, a QA match or the email archive. Rows that name a root without a foreign key
//! stay, each kept by its own retention: an archived email (`email_archive.archive`), a QA match
//! (`yara_qa`) and a collector's key (`collection.submitted_keys`, which says its root may have gone).
//!
//! **Races.** The batch takes each root's row with `FOR UPDATE SKIP LOCKED` and checks the conditions
//! again on the row it locked, so a root whose pass is ending, or that a write is starting a pass on
//! (`crate::queue::begin_pass` updates the row), is skipped and looked at again on the next run. A
//! write that comes after the delete finds no root and fails, as on a root that was never there.

use std::time::Duration;

use uuid::Uuid;

use crate::bucket::{self, BucketError};
use crate::db::{Db, Tx};

/// How long a finished root waits before it's deleted, when the overlay doesn't say.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(3600);
/// Roots deleted in one transaction.
pub const BATCH: i64 = 100;
/// The most batches one run deletes, so a run's work is bounded: 5,000 roots.
pub const MAX_BATCHES: u32 = 50;
/// The pause between two batches.
pub const BATCH_PAUSE: Duration = Duration::from_millis(200);

/// What one batch deleted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Deleted {
    pub roots: Vec<Uuid>,
    /// The holds the roots had on the bucket's objects, released.
    pub holds: u64,
}

/// Deletes at most `limit` roots of the modes in `modes` that are finished, never became alerts and
/// ended more than `grace` ago, oldest first, and releases their holds in each of `pools`, in one
/// transaction of its own.
pub async fn delete_batch(
    db: &Db,
    modes: &[String],
    grace: Duration,
    limit: i64,
    pools: &[String],
) -> Result<Deleted, BucketError> {
    if modes.is_empty() || limit <= 0 {
        return Ok(Deleted::default());
    }
    let mut tx = db.begin().await?;
    let deleted = delete_in(&mut tx, modes, grace, limit, pools).await?;
    tx.commit().await?;
    Ok(deleted)
}

async fn delete_in(
    tx: &mut Tx<'_>,
    modes: &[String],
    grace: Duration,
    limit: i64,
    pools: &[String],
) -> Result<Deleted, BucketError> {
    let roots = sqlx::query_scalar!(
        r#"WITH finished AS (
               SELECT r.id FROM analysis.roots r
               LEFT JOIN queue.root_completions c ON c.root_id = r.id AND c.pass = r.completed_pass
               WHERE r.alerted_at IS NULL
                 AND r.analysis_mode = ANY($1)
                 AND r.completed_pass = r.pass
                 AND NOT r.hooks_due
                 AND COALESCE(c.completed_at, r.created_at) < now() - make_interval(secs => $2)
                 AND NOT EXISTS (
                     SELECT 1 FROM queue.tasks t
                     WHERE t.root_id = r.id AND t.state IN ('queued', 'delayed', 'running'))
                 AND NOT EXISTS (
                     SELECT 1 FROM queue.action_roots ar
                     JOIN queue.actions a ON a.id = ar.action_id
                     WHERE ar.root_id = r.id AND a.status <> 'COMPLETED')
               ORDER BY r.created_at, r.id
               LIMIT $3
               FOR UPDATE OF r SKIP LOCKED)
           DELETE FROM analysis.roots WHERE id IN (SELECT id FROM finished)
           RETURNING id"#,
        modes,
        grace.as_secs_f64(),
        limit,
    )
    .fetch_all(tx.conn())
    .await?;
    let mut holds = 0;
    if !roots.is_empty() {
        let holders: Vec<String> = roots.iter().map(Uuid::to_string).collect();
        for pool in pools {
            holds += bucket::release_holders_in(tx, pool, bucket::ROOT_HOLD, &holders).await?;
        }
    }
    Ok(Deleted { roots, holds })
}
