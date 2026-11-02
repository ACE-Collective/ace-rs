//! The task queue: every module run is a task, (root, observable, module), in `queue.tasks`.
//!
//! A worker claims the oldest claimable task of the modules it hosts with `FOR UPDATE SKIP
//! LOCKED`, so workers never wait on each other's claims and no task is claimed twice. A
//! claim takes a lease: the worker is the task's owner until the lease expires. Every later
//! change a worker makes to the task checks that it still owns it, so a worker whose lease ran
//! out can't overwrite what the task's next owner does.
//!
//! A worker with nothing to claim waits on `LISTEN ace4_tasks` (`Wakeups`), which a trigger
//! notifies whenever a task becomes claimable, with a bounded wait as the fallback in case a
//! notification is lost.
//!
//! A worker renews its lease while the task runs (`Worker::keep_lease`). If the worker dies,
//! the renewals stop, and once the lease expires the reaper (`reap_expired_leases`) queues the
//! task again, or fails it when it has used its attempts.

use std::time::Duration;

use ace_results::ObservableKind;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::{Db, DbError, Tx};
use crate::tree::ObservableId;

/// A task's row id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, sqlx::Type)]
#[sqlx(transparent)]
pub struct TaskId(pub i64);

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task {}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "queue.task_state", rename_all = "snake_case")]
pub enum TaskState {
    Queued,
    Delayed,
    Running,
    Done,
    Failed,
    Cancelled,
}

impl TaskState {
    /// Queued, delayed and running tasks still have work to do.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            TaskState::Queued | TaskState::Delayed | TaskState::Running
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    /// The worker no longer owns the task: its lease expired and the reaper took it back, or
    /// the task was cancelled.
    #[error("{0} is no longer leased to this worker")]
    LeaseLost(TaskId),
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<sqlx::Error> for QueueError {
    fn from(error: sqlx::Error) -> Self {
        QueueError::Db(DbError::Sqlx(error))
    }
}

/// How many times a task may be claimed without finishing before it fails.
pub const DEFAULT_MAX_ATTEMPTS: i32 = 3;

/// Queues a task unless the root already has one for this observable and module. Returns its
/// id when it was queued. A file's sha256 is recorded as the task's input.
pub async fn enqueue(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    module: &str,
) -> Result<Option<TaskId>, QueueError> {
    let id = sqlx::query_scalar!(
        r#"INSERT INTO queue.tasks (root_id, observable_id, module, max_attempts, input_hashes)
           SELECT o.root_id, o.id, $3, $4,
                  CASE WHEN o.type = 'file' THEN ARRAY[o.value] ELSE '{}' END
           FROM analysis.observables o WHERE o.root_id = $1 AND o.id = $2
           ON CONFLICT (root_id, observable_id, module) DO NOTHING
           RETURNING id AS "id: TaskId""#,
        root,
        observable as ObservableId,
        module,
        DEFAULT_MAX_ATTEMPTS,
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(id)
}

/// The observable a claimed task analyzes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskObservable {
    pub id: ObservableId,
    pub kind: ObservableKind,
    pub value: String,
    pub time: Option<DateTime<Utc>>,
    pub directives: Vec<String>,
}

/// A task a worker holds the lease on.
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub id: TaskId,
    pub root: Uuid,
    pub observable: TaskObservable,
    pub module: String,
    /// This claim included.
    pub attempts: i32,
    pub input_hashes: Vec<String>,
    pub lease_expires_at: DateTime<Utc>,
}

/// One process's identity on the queue, the modules it runs, and how long its leases last.
#[derive(Debug, Clone)]
pub struct Worker {
    db: Db,
    name: String,
    modules: Vec<String>,
    lease: Duration,
}

impl Worker {
    /// A worker named `name`, which should be unique among workers, such as
    /// `<host>/<pid>/<n>`, running `modules`.
    pub fn new(db: Db, name: impl Into<String>, modules: Vec<String>, lease: Duration) -> Self {
        Worker {
            db,
            name: name.into(),
            modules,
            lease,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn lease(&self) -> Duration {
        self.lease
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Claims the oldest claimable task of the worker's modules, if there is one, and takes
    /// its lease.
    pub async fn claim(&self) -> Result<Option<Task>, QueueError> {
        let mut tx = self.db.begin().await?;
        let row = sqlx::query!(
            r#"UPDATE queue.tasks t
               SET state = 'running', lease_owner = $1,
                   lease_expires_at = now() + make_interval(secs => $2),
                   attempts = t.attempts + 1, updated_at = now()
               FROM analysis.observables o
               WHERE t.id = (
                       SELECT id FROM queue.tasks
                       WHERE state IN ('queued', 'delayed') AND run_after <= now()
                         AND module = ANY($3)
                       ORDER BY run_after, id
                       FOR UPDATE SKIP LOCKED
                       LIMIT 1)
                 AND o.id = t.observable_id
               RETURNING t.id AS "id: TaskId", t.root_id, t.module, t.attempts, t.input_hashes,
                         t.lease_expires_at AS "lease_expires_at!",
                         o.id AS "observable_id: ObservableId", o.type AS kind, o.value,
                         o.time, o.directives"#,
            self.name,
            self.lease.as_secs_f64(),
            &self.modules,
        )
        .fetch_optional(tx.conn())
        .await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let kind = row
            .kind
            .parse()
            .map_err(|e| DbError::Decode(format!("{}: {e}", row.id)))?;
        Ok(Some(Task {
            id: row.id,
            root: row.root_id,
            observable: TaskObservable {
                id: row.observable_id,
                kind,
                value: row.value,
                time: row.time,
                directives: row.directives,
            },
            module: row.module,
            attempts: row.attempts,
            input_hashes: row.input_hashes,
            lease_expires_at: row.lease_expires_at,
        }))
    }

    /// Claims the next task, waiting for a wakeup while there is none. Each wait lasts at most
    /// `fallback`, after which the worker tries to claim anyway.
    pub async fn next_task(
        &self,
        wakeups: &mut Wakeups,
        fallback: Duration,
    ) -> Result<(Task, WakeCount), QueueError> {
        let mut count = WakeCount::default();
        loop {
            if let Some(task) = self.claim().await? {
                return Ok((task, count));
            }
            match wakeups.wait(&self.modules, fallback).await? {
                Wake::Notified => count.notified += 1,
                Wake::TimedOut => count.timed_out += 1,
            }
        }
    }

    /// Extends the lease on a task the worker owns to a full lease from now, and returns when
    /// it now expires.
    pub async fn renew(&self, task: TaskId) -> Result<DateTime<Utc>, QueueError> {
        let mut tx = self.db.begin().await?;
        let expires = sqlx::query_scalar!(
            r#"UPDATE queue.tasks SET lease_expires_at = now() + make_interval(secs => $3)
               WHERE id = $1 AND lease_owner = $2 AND state = 'running'
               RETURNING lease_expires_at AS "lease_expires_at!""#,
            task as TaskId,
            self.name,
            self.lease.as_secs_f64(),
        )
        .fetch_optional(tx.conn())
        .await?;
        tx.commit().await?;
        expires.ok_or(QueueError::LeaseLost(task))
    }

    /// Renews the lease every third of its length until the keeper is dropped. The keeper's
    /// token fires when the worker loses the task, so the module can stop.
    pub fn keep_lease(&self, task: TaskId) -> LeaseKeeper {
        let token = CancellationToken::new();
        let worker = self.clone();
        let fired = token.clone();
        let handle = tokio::spawn(async move {
            let every = worker.lease / 3;
            loop {
                tokio::time::sleep(every).await;
                match worker.renew(task).await {
                    Ok(_) => {}
                    Err(QueueError::LeaseLost(_)) => {
                        tracing::warn!(%task, worker = %worker.name, "lost the lease");
                        fired.cancel();
                        return;
                    }
                    // the next renewal may get through before the lease runs out
                    Err(e) => tracing::warn!(%task, worker = %worker.name, "renewal failed: {e}"),
                }
            }
        });
        LeaseKeeper { handle, token }
    }

    /// Ends a task the worker owns: it ran to the end.
    pub async fn complete(&self, task: TaskId) -> Result<(), QueueError> {
        self.finish(task, TaskState::Done, None).await
    }

    /// Ends a task the worker owns: the module failed. A failed task isn't claimed again.
    pub async fn fail(&self, task: TaskId, error: &str) -> Result<(), QueueError> {
        self.finish(task, TaskState::Failed, Some(error)).await
    }

    async fn finish(
        &self,
        task: TaskId,
        state: TaskState,
        error: Option<&str>,
    ) -> Result<(), QueueError> {
        let mut tx = self.db.begin().await?;
        let finished = sqlx::query!(
            "UPDATE queue.tasks
             SET state = $3, error = $4, lease_owner = NULL, lease_expires_at = NULL,
                 updated_at = now()
             WHERE id = $1 AND lease_owner = $2 AND state = 'running'",
            task as TaskId,
            self.name,
            state as TaskState,
            error,
        )
        .execute(tx.conn())
        .await?
        .rows_affected();
        if finished == 0 {
            return Err(QueueError::LeaseLost(task));
        }
        tx.commit().await?;
        Ok(())
    }
}

/// The channel the queue's trigger notifies when a task becomes claimable. The payload is the
/// task's module.
pub const TASKS_CHANNEL: &str = "ace4_tasks";

/// Why a wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// A task of one of the worker's modules became claimable, or the listener reconnected
    /// and may have missed one.
    Notified,
    /// The fallback timeout passed.
    TimedOut,
}

/// How a `next_task` call's waits ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WakeCount {
    pub notified: u32,
    pub timed_out: u32,
}

/// A worker's subscription to the queue's notifications, on a connection of its own.
pub struct Wakeups {
    listener: PgListener,
}

impl Wakeups {
    pub async fn listen(db: &Db) -> Result<Wakeups, QueueError> {
        let mut listener = PgListener::connect_with(db.pool()).await?;
        listener.listen(TASKS_CHANNEL).await?;
        Ok(Wakeups { listener })
    }

    /// Waits for a notification about one of `modules`, or until `timeout` passes.
    /// Notifications about other modules are skipped.
    pub async fn wait(
        &mut self,
        modules: &[String],
        timeout: Duration,
    ) -> Result<Wake, QueueError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, self.listener.try_recv()).await {
                Err(_) => return Ok(Wake::TimedOut),
                // the connection dropped and reconnects; anything sent meanwhile is lost
                Ok(Ok(None)) => return Ok(Wake::Notified),
                Ok(Ok(Some(notification))) => {
                    if modules.iter().any(|m| m == notification.payload()) {
                        return Ok(Wake::Notified);
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
            }
        }
    }
}

impl std::fmt::Debug for Wakeups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wakeups").finish_non_exhaustive()
    }
}

/// Renews a task's lease in the background while it runs. Dropping it stops the renewals.
#[derive(Debug)]
pub struct LeaseKeeper {
    handle: JoinHandle<()>,
    token: CancellationToken,
}

impl LeaseKeeper {
    /// Fires when the worker loses the task. Hand it to the module's task context.
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }
}

impl Drop for LeaseKeeper {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// What a reaper pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reaped {
    /// Tasks queued again for another attempt.
    pub requeued: Vec<TaskId>,
    /// Tasks whose lease expired on their last attempt.
    pub failed: Vec<TaskId>,
}

/// Takes back every running task whose lease has expired: it is queued again, or fails if it
/// has used its attempts.
pub async fn reap_expired_leases(db: &Db) -> Result<Reaped, QueueError> {
    let mut tx = db.begin().await?;
    let rows = sqlx::query!(
        r#"UPDATE queue.tasks SET
               state = CASE WHEN attempts >= max_attempts THEN 'failed'::queue.task_state
                            ELSE 'queued'::queue.task_state END,
               error = CASE WHEN attempts >= max_attempts
                            THEN format('the lease expired on all %s attempts; the last owner was %s',
                                        attempts, lease_owner)
                            ELSE error END,
               lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
           WHERE state = 'running' AND lease_expires_at < now()
           RETURNING id AS "id: TaskId", state AS "state: TaskState""#,
    )
    .fetch_all(tx.conn())
    .await?;
    tx.commit().await?;
    let mut reaped = Reaped::default();
    for row in rows {
        if row.state == TaskState::Failed {
            reaped.failed.push(row.id);
        } else {
            reaped.requeued.push(row.id);
        }
    }
    if !reaped.requeued.is_empty() || !reaped.failed.is_empty() {
        tracing::info!(
            requeued = reaped.requeued.len(),
            failed = reaped.failed.len(),
            "took back tasks whose lease expired"
        );
    }
    Ok(reaped)
}

/// Runs `reap_expired_leases` every `interval` until `stop` fires.
pub async fn run_reaper(db: Db, interval: Duration, stop: CancellationToken) {
    loop {
        if let Err(e) = reap_expired_leases(&db).await {
            tracing::error!("the reaper failed: {e}");
        }
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(interval) => {}
        }
    }
}

/// A task's state, for tests and tools.
pub async fn state(db: &Db, task: TaskId) -> Result<Option<TaskState>, QueueError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT state AS "state: TaskState" FROM queue.tasks WHERE id = $1"#,
        task as TaskId,
    )
    .fetch_optional(db.pool())
    .await?)
}
