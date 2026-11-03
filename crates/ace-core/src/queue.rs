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
//! A module can ask to run again later (`Worker::delay`). The task goes back to the queue as
//! `delayed` with `run_after` in the future and can't be claimed before then. Nothing notifies
//! when that time comes, so a waiting worker also wakes when the next of its delayed tasks is
//! due.
//!
//! A root is complete when it has no queued, delayed or running tasks. Queueing work on an
//! idle root starts an analysis pass, and the transaction that ends its last task records the
//! pass's one completion (`check_completion`), which `Completions` waits for. Every change
//! that queues or ends tasks locks the root's row first, so two that race on one root take
//! turns and the second sees what the first did: a pass can't end twice, or not at all.
//!
//! Cancelling a root (`cancel_root`) cancels its queued and delayed tasks and asks its running
//! ones to stop. A worker learns of it from a notification (`CancelWatch`) at once, or from
//! its next lease renewal, and either way the task's cancellation token fires.
//!
//! A worker renews its lease while the task runs (`Worker::keep_lease`). If the worker dies,
//! the renewals stop, and once the lease expires the reaper (`reap_expired_leases`) queues the
//! task again, or fails it when it has used its attempts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ace_results::ObservableKind;
use ace_sdk::DelayedRun;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::db::{Db, DbError, Isolation, Retryable, Tx};
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
    /// The task's root was cancelled while it ran, so it won't run again.
    #[error("{0} was cancelled")]
    Cancelled(TaskId),
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<sqlx::Error> for QueueError {
    fn from(error: sqlx::Error) -> Self {
        QueueError::Db(DbError::Sqlx(error))
    }
}

impl Retryable for QueueError {
    fn is_retryable(&self) -> bool {
        matches!(self, QueueError::Db(e) if e.is_retryable())
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
    if id.is_some() {
        begin_pass(tx, root).await?;
    }
    Ok(id)
}

/// Locks the root's row until the transaction ends. Every change that queues or ends tasks
/// takes this lock first, so completion is decided by one transaction at a time.
pub async fn lock_root(tx: &mut Tx<'_>, root: Uuid) -> Result<(), QueueError> {
    sqlx::query!(
        "SELECT id FROM analysis.roots WHERE id = $1 FOR UPDATE",
        root
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(())
}

/// Starts a new analysis pass if the root's last one completed, as when tasks are queued on an
/// idle root. Locks the root.
pub async fn begin_pass(tx: &mut Tx<'_>, root: Uuid) -> Result<(), QueueError> {
    sqlx::query!(
        "UPDATE analysis.roots
         SET pass = CASE WHEN completed_pass = pass THEN pass + 1 ELSE pass END
         WHERE id = $1",
        root,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Ends the root's current pass if it has no queued, delayed or running tasks left, and returns
/// the pass. Call it last in a transaction that ended tasks, with the root locked.
pub async fn check_completion(tx: &mut Tx<'_>, root: Uuid) -> Result<Option<i32>, QueueError> {
    let active = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM queue.tasks
                          WHERE root_id = $1 AND state IN ('queued', 'delayed', 'running'))
           AS "active!""#,
        root,
    )
    .fetch_one(tx.conn())
    .await?;
    if active {
        return Ok(None);
    }
    let pass = sqlx::query_scalar!(
        "UPDATE analysis.roots SET completed_pass = pass
         WHERE id = $1 AND completed_pass < pass
         RETURNING pass",
        root,
    )
    .fetch_optional(tx.conn())
    .await?;
    if let Some(pass) = pass {
        sqlx::query!(
            "INSERT INTO queue.root_completions (root_id, pass) VALUES ($1, $2)",
            root,
            pass,
        )
        .execute(tx.conn())
        .await?;
        tracing::info!(%root, pass, "the root's analysis pass completed");
    }
    Ok(pass)
}

/// Queues a cancelled task again from the start, as when a root's mode changes and the module
/// is eligible in the new one. Returns false when the task isn't cancelled.
pub async fn requeue_cancelled(tx: &mut Tx<'_>, task: TaskId) -> Result<bool, QueueError> {
    let requeued = sqlx::query!(
        "UPDATE queue.tasks
         SET state = 'queued', run_after = now(), attempts = 0, error = NULL,
             delay_state = NULL, first_delayed_at = NULL, delays = 0, cancel_requested = false,
             updated_at = now()
         WHERE id = $1 AND state = 'cancelled'",
        task as TaskId,
    )
    .execute(tx.conn())
    .await?
    .rows_affected();
    if requeued > 0 {
        let root = sqlx::query_scalar!(
            "SELECT root_id FROM queue.tasks WHERE id = $1",
            task as TaskId
        )
        .fetch_one(tx.conn())
        .await?;
        begin_pass(tx, root).await?;
    }
    Ok(requeued > 0)
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
    /// Set when the module asked for a delay on an earlier run.
    pub delayed: Option<DelayedRun>,
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
        let row = self
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    Ok::<_, QueueError>(
                        sqlx::query!(
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
                         t.delay_state, t.first_delayed_at, t.delays,
                         o.id AS "observable_id: ObservableId", o.type AS kind, o.value,
                         o.time, o.directives"#,
                            self.name,
                            self.lease.as_secs_f64(),
                            &self.modules,
                        )
                        .fetch_optional(tx.conn())
                        .await?,
                    )
                })
            })
            .await?;
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
            delayed: row.first_delayed_at.map(|first_delayed_at| DelayedRun {
                state: row.delay_state.unwrap_or_default(),
                first_delayed_at,
                delays: u32::try_from(row.delays).unwrap_or_default(),
            }),
        }))
    }

    /// The modules the worker runs.
    pub fn modules(&self) -> &[String] {
        &self.modules
    }

    /// A task the worker owns, as it was claimed, or None when the worker doesn't own it.
    pub async fn owned(&self, task: TaskId) -> Result<Option<Task>, QueueError> {
        let row = sqlx::query!(
            r#"SELECT t.id AS "id: TaskId", t.root_id, t.module, t.attempts, t.input_hashes,
                      t.lease_expires_at AS "lease_expires_at!",
                      t.delay_state, t.first_delayed_at, t.delays,
                      o.id AS "observable_id: ObservableId", o.type AS kind, o.value,
                      o.time, o.directives
               FROM queue.tasks t JOIN analysis.observables o ON o.id = t.observable_id
               WHERE t.id = $1 AND t.lease_owner = $2 AND t.state = 'running'"#,
            task as TaskId,
            self.name,
        )
        .fetch_optional(self.db.pool())
        .await?;
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
            delayed: row.first_delayed_at.map(|first_delayed_at| DelayedRun {
                state: row.delay_state.unwrap_or_default(),
                first_delayed_at,
                delays: u32::try_from(row.delays).unwrap_or_default(),
            }),
        }))
    }

    /// When the next queued or delayed task of the worker's modules may be claimed.
    pub async fn next_due(&self) -> Result<Option<DateTime<Utc>>, QueueError> {
        Ok(sqlx::query_scalar!(
            "SELECT min(run_after) FROM queue.tasks
             WHERE state IN ('queued', 'delayed') AND module = ANY($1)",
            &self.modules,
        )
        .fetch_one(self.db.pool())
        .await?)
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
            // a delayed task comes due without a notification, so wait no longer than that;
            // a due task another worker is claiming gets a short wait, not a busy loop
            let until_due = self.next_due().await?.map(|due| {
                (due - Utc::now())
                    .to_std()
                    .unwrap_or_default()
                    .max(MIN_WAIT)
            });
            let (wait, due) = match until_due {
                Some(until_due) if until_due < fallback => (until_due, true),
                _ => (fallback, false),
            };
            match wakeups.wait(&self.modules, wait).await? {
                Wake::Notified => count.notified += 1,
                Wake::TimedOut if due => count.due += 1,
                Wake::TimedOut => count.timed_out += 1,
            }
        }
    }

    /// Sends a task the worker owns back to the queue until `after` from now, keeping `state`
    /// for the module's next run, as ace3's `delay_analysis`. A delay isn't a failed attempt,
    /// so the attempt count starts again.
    pub async fn delay(
        &self,
        task: TaskId,
        after: Duration,
        state: &serde_json::Value,
    ) -> Result<DateTime<Utc>, QueueError> {
        let run_after = self
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    let root = self.lock_task_root(tx, task).await?;
                    let row = sqlx::query!(
                        r#"UPDATE queue.tasks
               SET state = CASE WHEN cancel_requested THEN 'cancelled'::queue.task_state
                                ELSE 'delayed'::queue.task_state END,
                   run_after = now() + make_interval(secs => $3),
                   delay_state = $4, first_delayed_at = COALESCE(first_delayed_at, now()),
                   delays = delays + 1, attempts = 0, lease_owner = NULL,
                   lease_expires_at = NULL, updated_at = now()
               WHERE id = $1 AND lease_owner = $2 AND state = 'running'
               RETURNING run_after, state AS "state: TaskState""#,
                        task as TaskId,
                        self.name,
                        after.as_secs_f64(),
                        state,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or(QueueError::LeaseLost(task))?;
                    // a task whose root was cancelled while it ran ends here instead
                    if row.state == TaskState::Cancelled {
                        check_completion(tx, root).await?;
                        return Ok(None);
                    }
                    Ok::<_, QueueError>(Some(row.run_after))
                })
            })
            .await?;
        run_after.ok_or(QueueError::Cancelled(task))
    }

    /// The task's root, locked until the transaction ends.
    async fn lock_task_root(&self, tx: &mut Tx<'_>, task: TaskId) -> Result<Uuid, QueueError> {
        let root = sqlx::query_scalar!(
            "SELECT root_id FROM queue.tasks WHERE id = $1",
            task as TaskId
        )
        .fetch_optional(tx.conn())
        .await?
        .ok_or(QueueError::LeaseLost(task))?;
        lock_root(tx, root).await?;
        Ok(root)
    }

    /// Extends the lease on a task the worker owns to a full lease from now. The answer also
    /// says whether the task's root was cancelled meanwhile.
    pub async fn renew(&self, task: TaskId) -> Result<Lease, QueueError> {
        let row = self
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    Ok::<_, QueueError>(sqlx::query!(
            r#"UPDATE queue.tasks SET lease_expires_at = now() + make_interval(secs => $3)
               WHERE id = $1 AND lease_owner = $2 AND state = 'running'
               RETURNING lease_expires_at AS "expires_at!", cancel_requested"#,
            task as TaskId,
            self.name,
            self.lease.as_secs_f64(),
        )
        .fetch_optional(tx.conn())
        .await?)
                })
            })
            .await?;
        let row = row.ok_or(QueueError::LeaseLost(task))?;
        Ok(Lease {
            expires_at: row.expires_at,
            cancel_requested: row.cancel_requested,
        })
    }

    /// Renews the lease every third of its length until the keeper is dropped. The keeper's
    /// token fires when the worker loses the task or a renewal finds it cancelled, so the
    /// module can stop.
    pub fn keep_lease(&self, task: TaskId) -> LeaseKeeper {
        let token = CancellationToken::new();
        let worker = self.clone();
        let fired = token.clone();
        let handle = tokio::spawn(async move {
            let every = worker.lease / 3;
            loop {
                tokio::time::sleep(every).await;
                match worker.renew(task).await {
                    Ok(lease) if lease.cancel_requested => {
                        tracing::info!(%task, worker = %worker.name, "the task was cancelled");
                        fired.cancel();
                    }
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

    /// Ends a task the worker owns: the module stopped because the task was cancelled.
    pub async fn cancelled(&self, task: TaskId) -> Result<(), QueueError> {
        self.finish(task, TaskState::Cancelled, None).await
    }

    async fn finish(
        &self,
        task: TaskId,
        state: TaskState,
        error: Option<&str>,
    ) -> Result<(), QueueError> {
        self.db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    let root = self.finish_in(tx, task, state, error).await?;
                    check_completion(tx, root).await?;
                    Ok::<_, QueueError>(())
                })
            })
            .await
    }

    /// Ends a task the worker owns inside a transaction that also writes what the task found,
    /// and returns its root, which stays locked. The caller checks the root's completion last.
    pub async fn finish_in(
        &self,
        tx: &mut Tx<'_>,
        task: TaskId,
        state: TaskState,
        error: Option<&str>,
    ) -> Result<Uuid, QueueError> {
        let root = self.lock_task_root(tx, task).await?;
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
        Ok(root)
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
    /// Waits that ended when a delayed task came due.
    pub due: u32,
    /// Waits that ended at the fallback.
    pub timed_out: u32,
}

/// The shortest wait for a task that is due, so a worker that keeps losing the race for it
/// doesn't spin.
const MIN_WAIT: Duration = Duration::from_millis(20);

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

/// A renewed lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub expires_at: DateTime<Utc>,
    /// The task's root was cancelled: the module should stop.
    pub cancel_requested: bool,
}

/// What cancelling a root did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CancelledRoot {
    /// Queued and delayed tasks, now cancelled.
    pub cancelled: Vec<TaskId>,
    /// Running tasks asked to stop.
    pub signalled: Vec<TaskId>,
}

/// Cancels a root's analysis: its queued and delayed tasks are cancelled, and its running ones
/// are asked to stop through their cancellation tokens. Results that still land afterwards are
/// stored but queue nothing more, until a mode change restarts analysis. With no task left
/// running, this ends the root's pass.
pub async fn cancel_root(tx: &mut Tx<'_>, root: Uuid) -> Result<CancelledRoot, QueueError> {
    lock_root(tx, root).await?;
    sqlx::query!(
        "UPDATE analysis.roots SET cancelled_at = now() WHERE id = $1",
        root
    )
    .execute(tx.conn())
    .await?;
    let cancelled = sqlx::query_scalar!(
        r#"UPDATE queue.tasks SET state = 'cancelled', updated_at = now()
           WHERE root_id = $1 AND state IN ('queued', 'delayed')
           RETURNING id AS "id: TaskId""#,
        root,
    )
    .fetch_all(tx.conn())
    .await?;
    let signalled = sqlx::query_scalar!(
        r#"UPDATE queue.tasks SET cancel_requested = true, updated_at = now()
           WHERE root_id = $1 AND state = 'running' AND NOT cancel_requested
           RETURNING id AS "id: TaskId""#,
        root,
    )
    .fetch_all(tx.conn())
    .await?;
    check_completion(tx, root).await?;
    tracing::info!(
        %root,
        cancelled = cancelled.len(),
        signalled = signalled.len(),
        "cancelled the root's analysis"
    );
    Ok(CancelledRoot {
        cancelled,
        signalled,
    })
}

/// The channel a task's cancellation notifies, with the task's id as the payload.
pub const CANCEL_CHANNEL: &str = "ace4_cancel";

/// One listener per process that fires the cancellation token of each task the process runs
/// when its root is cancelled, without waiting for the next lease renewal.
pub struct CancelWatch {
    tokens: Arc<Mutex<HashMap<TaskId, CancellationToken>>>,
    handle: JoinHandle<()>,
}

impl CancelWatch {
    pub async fn start(db: &Db) -> Result<CancelWatch, QueueError> {
        let mut listener = PgListener::connect_with(db.pool()).await?;
        listener.listen(CANCEL_CHANNEL).await?;
        let tokens: Arc<Mutex<HashMap<TaskId, CancellationToken>>> = Arc::default();
        let watched = tokens.clone();
        let handle = tokio::spawn(async move {
            loop {
                match listener.recv().await {
                    Ok(notification) => {
                        let Ok(id) = notification.payload().parse::<i64>() else {
                            continue;
                        };
                        let token = watched
                            .lock()
                            .ok()
                            .and_then(|tokens| tokens.get(&TaskId(id)).cloned());
                        if let Some(token) = token {
                            tracing::info!(task = id, "the task was cancelled");
                            token.cancel();
                        }
                    }
                    // the renewals still deliver a cancel meanwhile
                    Err(e) => {
                        tracing::warn!("the cancel listener failed: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        Ok(CancelWatch { tokens, handle })
    }

    /// Fires `token` when `task` is cancelled, until the guard is dropped.
    pub fn watch(&self, task: TaskId, token: &CancellationToken) -> CancelGuard {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.insert(task, token.clone());
        }
        CancelGuard {
            tokens: self.tokens.clone(),
            task,
        }
    }
}

impl Drop for CancelWatch {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl std::fmt::Debug for CancelWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelWatch").finish_non_exhaustive()
    }
}

/// Stops watching a task when dropped.
#[derive(Debug)]
pub struct CancelGuard {
    tokens: Arc<Mutex<HashMap<TaskId, CancellationToken>>>,
    task: TaskId,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Ok(mut tokens) = self.tokens.lock() {
            tokens.remove(&self.task);
        }
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
    /// Tasks whose root was cancelled while they ran.
    pub cancelled: Vec<TaskId>,
}

/// Takes back every running task whose lease has expired: it is queued again, or fails if it
/// has used its attempts. One transaction per root, which locks the root first like every
/// other change that can end its tasks.
pub async fn reap_expired_leases(db: &Db) -> Result<Reaped, QueueError> {
    let roots = sqlx::query_scalar!(
        "SELECT DISTINCT root_id FROM queue.tasks
         WHERE state = 'running' AND lease_expires_at < now()
         ORDER BY root_id",
    )
    .fetch_all(db.pool())
    .await?;
    let mut reaped = Reaped::default();
    for root in roots {
        let rows = db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
        lock_root(tx, root).await?;
        let rows = sqlx::query!(
            r#"UPDATE queue.tasks SET
                   state = CASE WHEN cancel_requested THEN 'cancelled'::queue.task_state
                                WHEN attempts >= max_attempts THEN 'failed'::queue.task_state
                                ELSE 'queued'::queue.task_state END,
                   error = CASE WHEN NOT cancel_requested AND attempts >= max_attempts
                                THEN format('the lease expired on all %s attempts; the last owner was %s',
                                            attempts, lease_owner)
                                ELSE error END,
                   lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
               WHERE root_id = $1 AND state = 'running' AND lease_expires_at < now()
               RETURNING id AS "id: TaskId", state AS "state: TaskState""#,
            root,
        )
        .fetch_all(tx.conn())
        .await?;
        check_completion(tx, root).await?;
        Ok::<_, QueueError>(rows)
                })
            })
            .await?;
        for row in rows {
            match row.state {
                TaskState::Failed => reaped.failed.push(row.id),
                TaskState::Cancelled => reaped.cancelled.push(row.id),
                _ => reaped.requeued.push(row.id),
            }
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

/// The channel a root's completion notifies, with `<root>/<pass>` as the payload.
pub const COMPLETIONS_CHANNEL: &str = "ace4_root_complete";

/// One analysis pass's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub root: Uuid,
    pub pass: i32,
}

/// A subscription to roots' completions, on a connection of its own, for whatever acts once a
/// root's analysis is done, such as alert routing.
pub struct Completions {
    listener: PgListener,
}

impl Completions {
    pub async fn listen(db: &Db) -> Result<Completions, QueueError> {
        let mut listener = PgListener::connect_with(db.pool()).await?;
        listener.listen(COMPLETIONS_CHANNEL).await?;
        Ok(Completions { listener })
    }

    /// The next completion, or None if none comes within `timeout`. A notification lost while
    /// the listener reconnected is in `queue.root_completions` all the same.
    pub async fn next(&mut self, timeout: Duration) -> Result<Option<Completion>, QueueError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, self.listener.try_recv()).await {
                Err(_) => return Ok(None),
                Ok(Ok(None)) => continue,
                Ok(Ok(Some(notification))) => {
                    let parsed = notification.payload().split_once('/').and_then(|(r, p)| {
                        Some(Completion {
                            root: r.parse().ok()?,
                            pass: p.parse().ok()?,
                        })
                    });
                    match parsed {
                        Some(completion) => return Ok(Some(completion)),
                        None => tracing::warn!(
                            payload = notification.payload(),
                            "an unreadable completion notification"
                        ),
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
            }
        }
    }
}

impl std::fmt::Debug for Completions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Completions").finish_non_exhaustive()
    }
}

/// The root's completed passes, oldest first.
pub async fn completions(db: &Db, root: Uuid) -> Result<Vec<Completion>, QueueError> {
    Ok(sqlx::query_scalar!(
        "SELECT pass FROM queue.root_completions WHERE root_id = $1 ORDER BY pass",
        root,
    )
    .fetch_all(db.pool())
    .await?
    .into_iter()
    .map(|pass| Completion { root, pass })
    .collect())
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

/// Any task, as it was last claimed, whoever holds it, as for a replay. A task nobody holds has
/// the time it was read as its lease's expiry.
pub async fn find(db: &Db, task: TaskId) -> Result<Option<Task>, QueueError> {
    let row = sqlx::query!(
        r#"SELECT t.id AS "id: TaskId", t.root_id, t.module, t.attempts, t.input_hashes,
                  COALESCE(t.lease_expires_at, now()) AS "lease_expires_at!",
                  t.delay_state, t.first_delayed_at, t.delays,
                  o.id AS "observable_id: ObservableId", o.type AS kind, o.value,
                  o.time, o.directives
           FROM queue.tasks t JOIN analysis.observables o ON o.id = t.observable_id
           WHERE t.id = $1"#,
        task as TaskId,
    )
    .fetch_optional(db.pool())
    .await?;
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
        delayed: row.first_delayed_at.map(|first_delayed_at| DelayedRun {
            state: row.delay_state.unwrap_or_default(),
            first_delayed_at,
            delays: u32::try_from(row.delays).unwrap_or_default(),
        }),
    }))
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
