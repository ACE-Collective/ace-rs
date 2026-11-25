//! Scans (PLAN.md 7.7), as the queue holds them in `queue.scans`: a module's task asks for one of its
//! scanner images to run on its file or URL, and waits for it as a delayed task.
//!
//! ace3's phishkit and js-deobfuscator modules send a Celery task through RabbitMQ to a manager
//! container, which runs `docker run` of a scanner image per file through the host's Docker socket,
//! and wait on Redis for the manager's answer: js-deobfuscator's for up to a minute in the analysis
//! worker, phishkit's by delaying the analysis and polling every 3 seconds. Here a module ends its run
//! with a delay that carries a `ScanRequest` (`ace_sdk::scanners`); the transaction that delays the
//! task queues the scan (`delay_for_scan`), with each input the module wrote put in the bucket and
//! held by the root. A scanner pool claims it through the lease API (`ScanWorker::claim`), renews its
//! lease while the container runs, which also tells it whether the root was cancelled, and ends it
//! once, with the output archive it uploaded (`ScanWorker::end`). The end wakes the task, which runs
//! again on its own pool and reads the scan with its lease (`latest_for_task`). Nothing here, and
//! nothing in the scanner pool, reads what the scanner wrote: the archive is bytes until the module's
//! contained run opens it.
//!
//! A scan runs at most once. A lost lease ends it abandoned (`reap_scans`), as does a queued scan no
//! pool took within its timeout and `QUEUED_GRACE`, and either wakes the task, whose module decides
//! what that means. Cancelling a root cancels its queued scans and asks its running ones to stop
//! (`cancel_for_root`), and a task that ends while its scan still runs asks it to stop too
//! (`cancel_for_task`).

use std::time::Duration;

use ace_results::Sha256;
use ace_sdk::scanners::{QUEUED_GRACE, ScanInput, ScanRequest, ScanState};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{Db, DbError, Isolation, Tx};
use crate::queue::{QueueError, TaskId};

/// The most an error on a scan's row holds.
const MAX_ERROR_CHARS: usize = 2000;

/// A scan's state, as the queue holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "queue.scan_state", rename_all = "snake_case")]
pub enum ScanRowState {
    Queued,
    Running,
    Completed,
    TimedOut,
    Cancelled,
    Failed,
    Abandoned,
}

impl ScanRowState {
    /// The state as a module's next run sees it.
    pub fn for_module(self) -> ScanState {
        match self {
            ScanRowState::Queued | ScanRowState::Running => ScanState::Pending,
            ScanRowState::Completed => ScanState::Completed,
            ScanRowState::TimedOut => ScanState::TimedOut,
            ScanRowState::Cancelled => ScanState::Cancelled,
            ScanRowState::Failed => ScanState::Failed,
            ScanRowState::Abandoned => ScanState::Abandoned,
        }
    }
}

/// Queues `request` for `task`, which the caller's transaction is delaying. Each input must already
/// be in the bucket's `alert_files` pool, held by the root. Its pools wake at the commit.
pub async fn queue(
    tx: &mut Tx<'_>,
    task: TaskId,
    root: Uuid,
    request: &ScanRequest,
) -> Result<i64, DbError> {
    let inputs = serde_json::to_value(&request.inputs)
        .map_err(|e| DbError::Decode(format!("a scan's inputs: {e}")))?;
    Ok(sqlx::query_scalar!(
        "INSERT INTO queue.scans (task_id, root_id, scanner, args, inputs, timeout_seconds, proxy)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id",
        task as TaskId,
        root,
        request.scanner,
        &request.args,
        inputs,
        i32::try_from(request.timeout_seconds).unwrap_or(i32::MAX),
        request.proxy,
    )
    .fetch_one(tx.conn())
    .await?)
}

/// A task's latest scan, as its lease carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskScan {
    pub id: i64,
    pub scanner: String,
    pub state: ScanRowState,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub output: Option<(Sha256, u64)>,
    /// The proxy it went through, without credentials.
    pub proxied: Option<String>,
}

/// The task's latest scan, if its module ever asked for one.
pub async fn latest_for_task(db: &Db, task: TaskId) -> Result<Option<TaskScan>, DbError> {
    let row = sqlx::query!(
        r#"SELECT id, scanner, state AS "state: ScanRowState", exit_code, error, output_sha256,
                  output_size, proxied
           FROM queue.scans WHERE task_id = $1 ORDER BY id DESC LIMIT 1"#,
        task as TaskId,
    )
    .fetch_optional(db.pool())
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let output = match (row.output_sha256, row.output_size) {
        (Some(sha256), Some(size)) => Some((
            sha256
                .parse::<Sha256>()
                .map_err(|e| DbError::Decode(format!("scan {}: {e}", row.id)))?,
            u64::try_from(size).unwrap_or_default(),
        )),
        _ => None,
    };
    Ok(Some(TaskScan {
        id: row.id,
        scanner: row.scanner,
        state: row.state,
        exit_code: row.exit_code,
        error: row.error,
        output,
        proxied: row.proxied,
    }))
}

/// Runs the task again now, if it is still waiting as a delayed task: its scan has ended.
async fn wake_task(tx: &mut Tx<'_>, task: i64) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE queue.tasks SET run_after = now(), updated_at = now()
         WHERE id = $1 AND state = 'delayed' AND run_after > now()",
        task,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Cancels a cancelled root's scans: a queued one ends cancelled, and a running one's pool learns at
/// its next renewal and kills it. Their tasks are cancelled already, so nothing is woken.
pub async fn cancel_for_root(tx: &mut Tx<'_>, root: Uuid) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE queue.scans
         SET state = 'cancelled', cancel_requested = true, finished_at = now(),
             error = 'its root was cancelled before a pool took it'
         WHERE root_id = $1 AND state = 'queued'",
        root,
    )
    .execute(tx.conn())
    .await?;
    sqlx::query!(
        "UPDATE queue.scans SET cancel_requested = true
         WHERE root_id = $1 AND state = 'running' AND NOT cancel_requested",
        root,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Stops the scans of a task that ended without waiting for them, as when its delay ran out first:
/// nothing would read what they bring back.
pub async fn cancel_for_task(db: &Db, task: TaskId) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE queue.scans
         SET state = 'cancelled', cancel_requested = true, finished_at = now(),
             error = 'its task ended before a pool took it'
         WHERE task_id = $1 AND state = 'queued'",
        task as TaskId,
    )
    .execute(db.pool())
    .await?;
    sqlx::query!(
        "UPDATE queue.scans SET cancel_requested = true
         WHERE task_id = $1 AND state = 'running' AND NOT cancel_requested",
        task as TaskId,
    )
    .execute(db.pool())
    .await?;
    Ok(())
}

/// A scan a scanner pool has claimed.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimedScan {
    pub id: i64,
    pub task: TaskId,
    pub root: Uuid,
    pub scanner: String,
    pub args: Vec<String>,
    pub inputs: Vec<ScanInput>,
    pub timeout_seconds: u32,
    pub deadline_at: DateTime<Utc>,
    /// From the claim's moment to the deadline, by the database's clock.
    pub deadline_in: Duration,
    /// Go through the pool's proxy, when it has one.
    pub proxy: bool,
}

/// How a pool ended a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndedScan<'a> {
    pub state: ScanRowState,
    pub exit_code: Option<i32>,
    pub error: Option<&'a str>,
    pub output: Option<(Sha256, u64)>,
    /// The id of the image its container ran (`ScanEnd::image_id`).
    pub image_id: Option<&'a str>,
    /// The proxy it went through, without credentials (`ScanEnd::proxied`).
    pub proxied: Option<&'a str>,
}

/// One scanner pool process's identity on the scans' queue.
#[derive(Debug, Clone)]
pub struct ScanWorker {
    db: Db,
    name: String,
    lease: Duration,
}

impl ScanWorker {
    pub fn new(db: Db, name: impl Into<String>, lease: Duration) -> Self {
        ScanWorker {
            db,
            name: name.into(),
            lease,
        }
    }

    pub fn lease(&self) -> Duration {
        self.lease
    }

    /// Claims the oldest queued scan of `scanners`, starting its clock: its deadline is now plus its
    /// timeout.
    pub async fn claim(&self, scanners: &[String]) -> Result<Option<ClaimedScan>, QueueError> {
        let row = sqlx::query!(
            r#"UPDATE queue.scans s
               SET state = 'running', lease_owner = $1,
                   lease_expires_at = now() + make_interval(secs => $2),
                   started_at = now(), deadline_at = now() + make_interval(secs => s.timeout_seconds)
               WHERE s.id = (SELECT id FROM queue.scans WHERE state = 'queued' AND scanner = ANY($3)
                             ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
               RETURNING s.id, s.task_id AS "task_id: TaskId", s.root_id, s.scanner, s.args, s.inputs,
                         s.timeout_seconds, s.deadline_at AS "deadline_at!", s.proxy,
                         extract(epoch FROM s.deadline_at - now())::float8 AS "deadline_in!""#,
            self.name,
            self.lease.as_secs_f64(),
            scanners,
        )
        .fetch_optional(self.db.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let inputs: Vec<ScanInput> = serde_json::from_value(row.inputs)
            .map_err(|e| DbError::Decode(format!("scan {}'s inputs: {e}", row.id)))?;
        Ok(Some(ClaimedScan {
            id: row.id,
            task: row.task_id,
            root: row.root_id,
            scanner: row.scanner,
            args: row.args,
            inputs,
            timeout_seconds: u32::try_from(row.timeout_seconds).unwrap_or_default(),
            deadline_at: row.deadline_at,
            deadline_in: Duration::try_from_secs_f64(row.deadline_in).unwrap_or_default(),
            proxy: row.proxy,
        }))
    }

    /// The task and root of a scan the worker holds, or None.
    pub async fn owned(&self, id: i64) -> Result<Option<(TaskId, Uuid)>, QueueError> {
        let row = sqlx::query!(
            r#"SELECT task_id AS "task_id: TaskId", root_id FROM queue.scans
               WHERE id = $1 AND lease_owner = $2 AND state = 'running'"#,
            id,
            self.name,
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|row| (row.task_id, row.root_id)))
    }

    /// Renews the lease on a scan the worker holds. True when its root was cancelled.
    pub async fn renew(&self, id: i64) -> Result<bool, QueueError> {
        sqlx::query_scalar!(
            "UPDATE queue.scans SET lease_expires_at = now() + make_interval(secs => $3)
             WHERE id = $1 AND lease_owner = $2 AND state = 'running'
             RETURNING cancel_requested",
            id,
            self.name,
            self.lease.as_secs_f64(),
        )
        .fetch_optional(self.db.pool())
        .await?
        .ok_or(QueueError::LeaseLost(TaskId(id)))
    }

    /// Ends a scan the worker holds and wakes its task, inside `tx`, which also puts its output in the
    /// bucket.
    pub async fn end_in(
        &self,
        tx: &mut Tx<'_>,
        id: i64,
        ended: &EndedScan<'_>,
    ) -> Result<(), QueueError> {
        let error = ended.error.map(bounded_error);
        let (sha256, size) = match ended.output {
            Some((sha256, size)) => (
                Some(sha256.to_hex()),
                Some(i64::try_from(size).unwrap_or(i64::MAX)),
            ),
            None => (None, None),
        };
        let task = sqlx::query_scalar!(
            "UPDATE queue.scans
             SET state = $3::queue.scan_state, exit_code = $4,
                 error = CASE $3::queue.scan_state
                     WHEN 'timed_out'::queue.scan_state THEN
                         coalesce($5, format('stopped at its deadline, %s seconds after it started',
                                             timeout_seconds))
                     WHEN 'cancelled'::queue.scan_state THEN coalesce($5, 'cancelled while it ran')
                     ELSE $5 END,
                 output_sha256 = $6, output_size = $7, image_id = $8, proxied = $9,
                 finished_at = now(),
                 lease_owner = NULL, lease_expires_at = NULL
             WHERE id = $1 AND lease_owner = $2 AND state = 'running'
             RETURNING task_id",
            id,
            self.name,
            ended.state as ScanRowState,
            ended.exit_code,
            error.as_deref(),
            sha256,
            size,
            ended.image_id,
            ended
                .proxied
                .map(|p| p.chars().take(512).collect::<String>()),
        )
        .fetch_optional(tx.conn())
        .await?
        .ok_or(QueueError::LeaseLost(TaskId(id)))?;
        wake_task(tx, task).await?;
        Ok(())
    }

    /// `end_in` in a transaction of its own, for an end with no output.
    pub async fn end(&self, id: i64, ended: &EndedScan<'_>) -> Result<(), QueueError> {
        self.db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move { self.end_in(tx, id, ended).await })
            })
            .await
    }
}

/// The id of the image each scanner of `scanners` ran for the task's latest scan of it that got as
/// far as a container, by `scanner:<name>`, as the analysis cache keys a scanning module's result
/// (`ace_sdk::cache::Cache::scanners`). A scanner with no such scan isn't there.
pub async fn image_ids(
    tx: &mut Tx<'_>,
    task: TaskId,
    scanners: &[&str],
) -> Result<std::collections::BTreeMap<String, String>, DbError> {
    let scanners: Vec<String> = scanners.iter().map(|s| (*s).to_owned()).collect();
    let rows = sqlx::query!(
        r#"SELECT DISTINCT ON (scanner) scanner, image_id AS "image_id!"
           FROM queue.scans
           WHERE task_id = $1 AND scanner = ANY($2) AND image_id IS NOT NULL
           ORDER BY scanner, id DESC"#,
        task as TaskId,
        &scanners,
    )
    .fetch_all(tx.conn())
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| (format!("scanner:{}", row.scanner), row.image_id))
        .collect())
}

/// `error` with NUL as U+FFFD, cut to `MAX_ERROR_CHARS`.
fn bounded_error(error: &str) -> String {
    error
        .replace('\0', "\u{fffd}")
        .chars()
        .take(MAX_ERROR_CHARS)
        .collect()
}

/// What the reaper ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReapedScans {
    /// Running scans whose pool stopped renewing their lease.
    pub unreported: u64,
    /// Queued scans no pool took within their timeout and `QUEUED_GRACE`.
    pub untaken: u64,
}

/// Ends as abandoned what nothing will finish, and wakes each one's task: a running scan whose lease
/// expired, and a queued one no pool took in time. Neither runs again. The pool that held a running
/// one removes its container when it starts again, or at its next sweep if it never does
/// (`ace_pool::scanners`).
pub async fn reap_scans(db: &Db) -> Result<ReapedScans, DbError> {
    let grace = QUEUED_GRACE.as_secs_f64();
    let (unreported, untaken) = db
        .transaction(Isolation::ReadCommitted, |tx| {
            Box::pin(async move {
                let unreported = sqlx::query_scalar!(
                    "UPDATE queue.scans
                     SET state = 'abandoned', finished_at = now(), lease_owner = NULL,
                         lease_expires_at = NULL,
                         error = 'its pool stopped reporting on it before it ended'
                     WHERE state = 'running' AND lease_expires_at < now()
                     RETURNING task_id",
                )
                .fetch_all(tx.conn())
                .await?;
                let untaken = sqlx::query_scalar!(
                    "UPDATE queue.scans
                     SET state = 'abandoned', finished_at = now(),
                         error = 'no scanner pool took it in time'
                     WHERE state = 'queued'
                       AND created_at + make_interval(secs => timeout_seconds::float8 + $1) < now()
                     RETURNING task_id",
                    grace,
                )
                .fetch_all(tx.conn())
                .await?;
                for task in unreported.iter().chain(&untaken) {
                    wake_task(tx, *task).await?;
                }
                Ok::<_, DbError>((unreported.len() as u64, untaken.len() as u64))
            })
        })
        .await?;
    if unreported + untaken > 0 {
        tracing::warn!(
            unreported,
            untaken,
            "ended scans nothing will finish as abandoned"
        );
    }
    Ok(ReapedScans {
        unreported,
        untaken,
    })
}

/// A scan's row, for tests and for the GUI's task details.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanRow {
    pub id: i64,
    pub task: TaskId,
    pub scanner: String,
    pub state: ScanRowState,
    pub cancel_requested: bool,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    pub inputs: Value,
}

/// Every scan of a root, oldest first.
pub async fn for_root(db: &Db, root: Uuid) -> Result<Vec<ScanRow>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT id, task_id AS "task_id: TaskId", scanner, state AS "state: ScanRowState",
                  cancel_requested, exit_code, error, inputs
           FROM queue.scans WHERE root_id = $1 ORDER BY id"#,
        root,
    )
    .fetch_all(db.pool())
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| ScanRow {
            id: row.id,
            task: row.task_id,
            scanner: row.scanner,
            state: row.state,
            cancel_requested: row.cancel_requested,
            exit_code: row.exit_code,
            error: row.error,
            inputs: row.inputs,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_module_sees_a_queued_or_running_scan_as_pending() {
        assert_eq!(ScanRowState::Queued.for_module(), ScanState::Pending);
        assert_eq!(ScanRowState::Running.for_module(), ScanState::Pending);
        assert_eq!(ScanRowState::TimedOut.for_module(), ScanState::TimedOut);
        assert_eq!(bounded_error("a\0b"), "a\u{fffd}b");
        assert_eq!(bounded_error(&"x".repeat(5000)).len(), MAX_ERROR_CHARS);
    }
}
