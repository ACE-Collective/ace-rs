//! The task queue: every module run is a task, (root, observable, module), in `queue.tasks`.
//!
//! A worker claims the oldest claimable tasks of the modules it hosts with `FOR UPDATE SKIP
//! LOCKED`, one or as many as it can start now (`Worker::claim_up_to`), so workers never wait on
//! each other's claims and no task is claimed twice. A claim takes a lease on each task: the
//! worker is the task's owner until the lease expires. Every later
//! change a worker makes to the task checks that it still owns it, so a worker whose lease ran
//! out can't overwrite what the task's next owner does. The claim records when it took the lease
//! (`claimed_at`), and the statement that ends the task or delays it adds that run, from the claim
//! to its own transaction's start, to the task's run time in the root's pass (`run_seconds`, `runs`,
//! `run_pass`), with what its pool said the run cost (`analyze_seconds`, `cpu_seconds`,
//! `Worker::with_cost`), which the pass's metrics events read (`crate::metrics`).
//!
//! A worker with nothing to claim waits on `LISTEN ace_rs_tasks` (`Wakeups`), which a trigger
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
//! pass's one completion (`check_completion`), which `Completions` waits for, and, for an alert, that its
//! routing is due (`queue.routing_due`, PLAN.md 7.13's `ace_service::routing`). The same transaction
//! reads the pass's metrics event, which is logged once it has committed (`crate::metrics`). Every change
//! that queues or ends tasks locks the root's row first, so two that race on one root take
//! turns and the second sees what the first did: a pass can't end twice, or not at all.
//! When the core's hooks are due (`crate::hooks`), the transaction that ends the last task queues
//! the hooks task instead, and the pass ends after it.
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
use ace_sdk::wire::RunCost;
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

/// How many times a task may be claimed without finishing, or end with its peer unavailable
/// (`Worker::retry_later`), before it fails.
pub const DEFAULT_MAX_ATTEMPTS: i32 = 3;

/// How long a task whose peer was unavailable waits before its next attempt (`Worker::retry_later`),
/// doubled for each attempt it has had.
pub const RETRY_AFTER_UNAVAILABLE: Duration = Duration::from_secs(30);
/// The longest such a wait gets.
pub const RETRY_AFTER_UNAVAILABLE_MAX: Duration = Duration::from_secs(600);

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
    lock_root_in_pass(tx, root).await?;
    Ok(())
}

/// `lock_root`, which also returns the root's current pass, or None when there's no such root. One
/// statement, `lock_root`'s, which a task's end and its delay read the pass from to record its run
/// (`Worker::finish_in`).
async fn lock_root_in_pass(tx: &mut Tx<'_>, root: Uuid) -> Result<Option<i32>, QueueError> {
    Ok(sqlx::query_scalar!(
        "SELECT pass FROM analysis.roots WHERE id = $1 FOR UPDATE",
        root
    )
    .fetch_optional(tx.conn())
    .await?)
}

/// Starts a new analysis pass if the root's last one completed, as when tasks are queued on an
/// idle root. Locks the root.
pub async fn begin_pass(tx: &mut Tx<'_>, root: Uuid) -> Result<(), QueueError> {
    Ok(start_pass(tx, root).await?)
}

/// `begin_pass`'s statement. A pass that begins records when (`pass_started_at`), which its end's
/// metrics event measures from (`crate::metrics`).
async fn start_pass(tx: &mut Tx<'_>, root: Uuid) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE analysis.roots
         SET pass = CASE WHEN completed_pass = pass THEN pass + 1 ELSE pass END,
             pass_started_at = CASE WHEN completed_pass = pass THEN now() ELSE pass_started_at END
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
        wake_held_back(tx, root).await?;
        return Ok(None);
    }
    // the hooks run before the pass ends, once nothing else is left (`crate::hooks`)
    let hooks = sqlx::query!(
        r#"SELECT hooks_due AND cancelled_at IS NULL AS "due!",
                  CASE WHEN cancelled_at IS NULL THEN svs_gate_extra_seconds END AS svs_gate
           FROM analysis.roots WHERE id = $1"#,
        root,
    )
    .fetch_optional(tx.conn())
    .await?;
    let (mut due, svs_gate) = hooks.map_or((false, None), |row| (row.due, row.svs_gate));
    if !due && let Some(extra) = svs_gate {
        // only SVS's hook is due: its task is queued while its gate is open, read under the lock that
        // orders this pass's end against a registration (`crate::svs::attribution`'s *The gate*)
        due = crate::svs::attribution::gate_open(
            tx.conn(),
            chrono::Utc::now(),
            chrono::TimeDelta::seconds(extra),
        )
        .await
        .map_err(QueueError::from)?;
        if !due {
            tracing::debug!(%root, "svs's gate is closed: no hooks task for this pass");
        }
    }
    // a hooks task that failed doesn't run again; the pass ends without it
    if due && queue_hooks(tx, root).await?.is_some() {
        return Ok(None);
    }
    if due || svs_gate.is_some() {
        sqlx::query!(
            "UPDATE analysis.roots SET hooks_due = false, svs_gate_extra_seconds = NULL WHERE id = $1",
            root
        )
        .execute(tx.conn())
        .await?;
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
        let completed_at = sqlx::query_scalar!(
            "INSERT INTO queue.root_completions (root_id, pass) VALUES ($1, $2)
             RETURNING completed_at",
            root,
            pass,
        )
        .fetch_one(tx.conn())
        .await?;
        tracing::info!(%root, pass, "the root's analysis pass completed");
        // the pass's metrics event, ace3's per-root one, emitted once this has committed
        crate::metrics::record(tx, root, pass, completed_at).await?;
        // an alert's routing runs on its completion (PLAN.md 7.13, `ace_service::routing`)
        sqlx::query!(
            "INSERT INTO queue.routing_due (root_id, pass)
             SELECT id, $2 FROM analysis.roots WHERE id = $1 AND alerted_at IS NOT NULL",
            root,
            pass,
        )
        .execute(tx.conn())
        .await?;
        // an alert's text is indexed for search on its completion (PLAN.md 7.11, `ace_search`)
        index_again(tx.conn(), &[root]).await?;
    }
    Ok(pass)
}

/// Asks for the search index's documents of those of `roots` that are alerts to be made again (PLAN.md
/// 7.11, `ace_search`): when an alert's analysis pass completes, and when its comments change. A new
/// request, or the one waiting made new, so an indexing under way doesn't count for this change.
pub async fn index_again(conn: &mut sqlx::PgConnection, roots: &[Uuid]) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO search.due (root_id)
         SELECT id FROM analysis.roots WHERE id = ANY ($1) AND alerted_at IS NOT NULL
         ORDER BY id
         ON CONFLICT (root_id) DO UPDATE
             SET due_at = now(), version = search.due.version + 1, attempts = 0,
                 claimed_until = NULL, failed_at = NULL, error = NULL",
        roots,
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Makes the root's tasks that wait for every other module due now, once nothing is left but tasks
/// the core holds back, and returns how many. They are the tasks of modules that run last
/// (`Module::RUNS_LAST`), which the lease holds back for 32 s (`HeldBackWait::next`,
/// `Worker::hold`), so this is what makes them run once the root goes quiet. Every end runs it
/// (`check_completion`), and so does every hold: the others' last end may come while the task is
/// still leased and unmarked, or every other module may have finished when one is held back for a
/// task below it, and no end may follow to say so.
///
/// It changes only when such a task next asks. Whether it runs is still decided where it's leased,
/// by `tree::held_back`, so one woken too early is held back again, and one this misses, as when a
/// pool dies holding the last other task, comes back when its wait ends. A task that waits for one
/// below it (`tree::HeldBack::ByLastBelow`) keeps its wait, which starts low.
///
/// What isn't marked counts as another module's task here: a task of a module that runs last that
/// hasn't asked yet, or that its own module delayed. That only puts this off until that task ends
/// or is held back in its turn. Call it with the root locked.
async fn wake_held_back(tx: &mut Tx<'_>, root: Uuid) -> Result<u64, QueueError> {
    Ok(sqlx::query!(
        "UPDATE queue.tasks SET run_after = now()
         WHERE root_id = $1 AND state = 'delayed' AND run_after > now()
           AND held_back_by = $2
           AND NOT EXISTS (
               SELECT 1 FROM queue.tasks other
               WHERE other.root_id = $1 AND other.state IN ('queued', 'delayed', 'running')
                 AND other.held_back_by IS NULL)",
        root,
        crate::tree::HeldBack::ByOthers.as_str(),
    )
    .execute(tx.conn())
    .await?
    .rows_affected())
}

/// Queues the root's hooks task (`crate::hooks`), on its first observable: a new one, or the one that
/// ran before, again. Returns None when there's nothing to queue it on, or it failed before.
async fn queue_hooks(tx: &mut Tx<'_>, root: Uuid) -> Result<Option<TaskId>, QueueError> {
    let id = sqlx::query_scalar!(
        r#"INSERT INTO queue.tasks AS t (root_id, observable_id, module, max_attempts)
           SELECT $1, min(o.id), $2, $3 FROM analysis.observables o
           WHERE o.root_id = $1 HAVING min(o.id) IS NOT NULL
           ON CONFLICT (root_id, observable_id, module) DO UPDATE
               SET state = 'queued', run_after = now(), attempts = 0, error = NULL,
                   lease_owner = NULL, lease_expires_at = NULL, delay_state = NULL,
                   first_delayed_at = NULL, delays = 0, held_back_by = NULL,
                   held_back_step = NULL, cancel_requested = false,
                   updated_at = now()
               WHERE t.state IN ('done', 'cancelled')
           RETURNING id AS "id: TaskId""#,
        root,
        crate::hooks::HOOKS_MODULE,
        DEFAULT_MAX_ATTEMPTS,
    )
    .fetch_optional(tx.conn())
    .await?;
    if id.is_some() {
        begin_pass(tx, root).await?;
    }
    Ok(id)
}

/// Marks a task that just ended done as incomplete (PLAN.md decision 34): it runs again once its
/// observable has changed since its claim, or on the root's next pass.
pub async fn mark_incomplete(tx: &mut Tx<'_>, task: TaskId) -> Result<(), DbError> {
    sqlx::query!(
        "UPDATE queue.tasks SET incomplete = true WHERE id = $1 AND state = 'done'",
        task as TaskId,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Queues again a task that ended incomplete, as ace3's engine runs a module again on an analysis
/// that isn't completed. True when it was queued.
pub async fn requeue_incomplete(tx: &mut Tx<'_>, task: TaskId) -> Result<bool, QueueError> {
    let root = sqlx::query_scalar!(
        "UPDATE queue.tasks
         SET state = 'queued', run_after = now(), attempts = 0, error = NULL, delay_state = NULL,
             first_delayed_at = NULL, delays = 0, held_back_by = NULL, held_back_step = NULL,
             cancel_requested = false, updated_at = now()
         WHERE id = $1 AND state = 'done' AND incomplete
         RETURNING root_id",
        task as TaskId,
    )
    .fetch_optional(tx.conn())
    .await?;
    if let Some(root) = root {
        begin_pass(tx, root).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Queues again the tasks of `modules` on the observable that ended with no result, as ace3's
/// `reset_analysis` clears a module's "no analysis" mark so it runs again.
pub async fn requeue_without_result(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    modules: &[String],
) -> Result<Vec<TaskId>, DbError> {
    let ids = sqlx::query_scalar!(
        r#"UPDATE queue.tasks t
           SET state = 'queued', run_after = now(), attempts = 0, error = NULL,
               delay_state = NULL, first_delayed_at = NULL, delays = 0, held_back_by = NULL,
               held_back_step = NULL, cancel_requested = false, updated_at = now()
           WHERE t.root_id = $1 AND t.observable_id = $2 AND t.module = ANY($3)
             AND t.state = 'done'
             AND NOT EXISTS (SELECT 1 FROM analysis.results r
                             WHERE r.root_id = t.root_id AND r.observable_id = t.observable_id
                               AND r.module = t.module)
           RETURNING id AS "id: TaskId""#,
        root,
        observable as ObservableId,
        modules,
    )
    .fetch_all(tx.conn())
    .await?;
    if !ids.is_empty() {
        start_pass(tx, root).await?;
    }
    Ok(ids)
}

/// Queues a cancelled task again from the start, as when a root's mode changes and the module
/// is eligible in the new one. Returns false when the task isn't cancelled.
pub async fn requeue_cancelled(tx: &mut Tx<'_>, task: TaskId) -> Result<bool, QueueError> {
    let requeued = sqlx::query!(
        "UPDATE queue.tasks
         SET state = 'queued', run_after = now(), attempts = 0, error = NULL,
             delay_state = NULL, first_delayed_at = NULL, delays = 0, held_back_by = NULL,
             held_back_step = NULL, cancel_requested = false, updated_at = now()
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

/// Queues a task that ended again, done or failed, as a new pass of its root does in ace3 for a
/// module whose work isn't a result: its attempts start over. False when it hadn't ended.
pub async fn requeue_ended(tx: &mut Tx<'_>, task: TaskId) -> Result<bool, QueueError> {
    let requeued = sqlx::query!(
        "UPDATE queue.tasks
         SET state = 'queued', run_after = now(), attempts = 0, error = NULL,
             delay_state = NULL, first_delayed_at = NULL, delays = 0, held_back_by = NULL,
             held_back_step = NULL, cancel_requested = false, updated_at = now()
         WHERE id = $1 AND state IN ('done', 'failed')",
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
    /// Set when the core held it back last, as a task that runs last (`Worker::hold`), and its module
    /// hasn't delayed it since.
    pub held_back: Option<HeldBackWait>,
}

/// The core's wait for a task that runs last: what holds it back, and how many times in a row that
/// has, which its next wait doubles with (`Api::leased`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldBackWait {
    pub by: crate::tree::HeldBack,
    pub step: u32,
}

/// The longest the core holds back a task that runs last before it asks again.
const HELD_BACK_MAX: Duration = Duration::from_secs(32);

/// How long a task that runs last and waits for one below it first waits, doubling up to
/// `HELD_BACK_MAX` while that holds it back. Nothing wakes it, so this is how soon it asks again,
/// and it starts low: what's below is usually done in a moment.
const LAST_BELOW_DELAY: Duration = Duration::from_millis(250);

impl HeldBackWait {
    /// The wait for a task that `by` holds back, after the one it was held back with last, and how
    /// long it is. One that waits for the others waits `HELD_BACK_MAX` at once: their last end wakes
    /// it (`wake_held_back`), so asking sooner only asks what the wake answers, and the wait is the
    /// fallback for a wake that's missed, as when a pool dies holding the last other task.
    pub fn next(
        before: Option<HeldBackWait>,
        by: crate::tree::HeldBack,
    ) -> (HeldBackWait, Duration) {
        let step = match before {
            Some(before) if before.by == by => before.step.saturating_add(1),
            _ => 0,
        };
        let after = match by {
            crate::tree::HeldBack::ByOthers => HELD_BACK_MAX,
            crate::tree::HeldBack::ByLastBelow => LAST_BELOW_DELAY
                .saturating_mul(2u32.saturating_pow(step.min(7)))
                .min(HELD_BACK_MAX),
        };
        (HeldBackWait { by, step }, after)
    }

    /// The wait a task's row records, if any. A mark this build doesn't know reads as none, so the
    /// next wait starts low.
    fn of_row(by: Option<String>, step: Option<i32>) -> Option<HeldBackWait> {
        Some(HeldBackWait {
            by: crate::tree::HeldBack::parse(&by?)?,
            step: u32::try_from(step.unwrap_or_default()).unwrap_or_default(),
        })
    }
}

/// The future `TaskEnded`'s methods return.
pub type EndedFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), QueueError>> + Send + 'a>>;

/// What follows some tasks' ends, in the transaction that ends them, before the root's completion
/// is checked. The orchestrator is the one implementation.
pub trait TaskEnded: Send + Sync {
    /// A file's type step, its first task, ended (PLAN.md decision 25): no other task on the file
    /// is queued until it has ended, however it ended, so whatever ends it (a result, a failure, a
    /// lease that ran out on its last attempt) calls this (`Orchestrator::type_step_ended`).
    fn type_step<'a>(
        &'a self,
        tx: &'a mut Tx<'_>,
        root: Uuid,
        observable: ObservableId,
    ) -> EndedFuture<'a>;

    /// A task of `module` on `observable` ended with no result: skipped, failed or cancelled, by its
    /// worker or when its lease ran out. A module held to an automation limit then has a place for
    /// work the limit held back (`Orchestrator::limit_freed`, `crate::limits`), and a module that
    /// depends on it may run on the observable (`Orchestrator::dependency_ended`). A task whose
    /// result lands doesn't call this: its result takes the place, and its landing runs
    /// eligibility.
    fn without_result<'a>(
        &'a self,
        tx: &'a mut Tx<'_>,
        root: Uuid,
        observable: ObservableId,
        module: &'a str,
    ) -> EndedFuture<'a>;
}

/// The module name of a file's type step, `file_type`.
pub const TYPE_STEP: &str = "file_type";

/// One process's identity on the queue, the modules it runs, and how long its leases last.
#[derive(Clone)]
pub struct Worker {
    db: Db,
    name: String,
    modules: Vec<String>,
    lease: Duration,
    /// What follows a task's end (`TaskEnded`); None for a worker whose ends need nothing, such
    /// as a test's.
    ended: Option<std::sync::Arc<dyn TaskEnded>>,
    /// What the run that this worker ends next cost in its pool, which its end adds to the task's
    /// (`with_cost`). Unknown for a worker the core runs itself.
    cost: RunCost,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker")
            .field("name", &self.name)
            .field("modules", &self.modules)
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
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
            ended: None,
            cost: RunCost::default(),
        }
    }

    /// This worker, calling `ended` as its tasks end (`TaskEnded`).
    pub fn with_ended(mut self, ended: std::sync::Arc<dyn TaskEnded>) -> Self {
        self.ended = Some(ended);
        self
    }

    /// This worker, adding `cost` to the run of each task it ends or delays (PLAN.md 3.6,
    /// `crate::metrics`): what a pool said the run cost, for the worker the lease API makes for that
    /// task's end.
    pub fn with_cost(mut self, cost: RunCost) -> Self {
        self.cost = cost;
        self
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
        Ok(self.claim_up_to(1).await?.pop())
    }

    /// Claims the oldest claimable tasks of the worker's modules, `most` of them at most, and
    /// takes the lease of each: what that many calls of `claim` would take, in the same order, in
    /// one statement. The tasks come back oldest first. A worker asks for as many as it can start
    /// now, so none of them waits in a worker that is busy while another could run it.
    pub async fn claim_up_to(&self, most: usize) -> Result<Vec<Task>, QueueError> {
        let most = i64::try_from(most.clamp(1, 1 << 20)).unwrap_or(1);
        // The tasks to claim are chosen and locked in CTEs, which Postgres runs once: as a
        // subquery of the UPDATE's WHERE it could run again for a row and lock more than `most`.
        //
        // `oldest` reads each module's oldest due tasks from its own range of `tasks_claimable`,
        // which is in `(module, run_after, id)` order, and stops after `most` of them, so the
        // claim reads at most that many a module and sorts only those. It used to read and
        // sort every due task of the pool's modules, 4,000 at the median under load, to take five
        // (`docs/measurements/lease.md`). A pool with nothing due reads an empty range a module,
        // whatever other pools have due, which an index in the claim's own order doesn't give: a
        // plan over it reads every other pool's due tasks to find none.
        //
        // `first` locks the oldest `most` of the oldest twice `most`, skipping what another claim
        // holds, as the claim always did; the rest are spares for a claim that races another. The
        // oldest `most` of the pool are among them, since no module has more than `most` of those.
        // Only when every one of them was locked, by claims of other workers of the same modules,
        // does `rest` read all the pool's due tasks to find unlocked ones, as the claim used to
        // each time: its conditions on `first` and `oldest` don't depend on the row, so Postgres
        // tests them once and otherwise reads nothing there.
        let mut rows = self
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    Ok::<_, QueueError>(
                        sqlx::query!(
                            r#"WITH oldest AS MATERIALIZED (
                   SELECT c.id FROM (SELECT DISTINCT unnest($3::text[]) AS module) m
                   CROSS JOIN LATERAL (
                       SELECT id, run_after FROM queue.tasks
                       WHERE module = m.module AND state IN ('queued', 'delayed')
                         AND run_after <= now()
                       ORDER BY run_after, id
                       LIMIT $4) c
                   ORDER BY c.run_after, c.id
                   LIMIT 2 * $4::int8),
               first AS MATERIALIZED (
                   SELECT t.id FROM queue.tasks t JOIN oldest ON oldest.id = t.id
                   WHERE t.state IN ('queued', 'delayed') AND t.run_after <= now()
                   ORDER BY t.run_after, t.id
                   FOR UPDATE OF t SKIP LOCKED
                   LIMIT $4),
               rest AS MATERIALIZED (
                   SELECT id FROM queue.tasks
                   WHERE state IN ('queued', 'delayed') AND run_after <= now()
                     AND module = ANY($3)
                     AND NOT EXISTS (SELECT FROM first) AND EXISTS (SELECT FROM oldest)
                   ORDER BY run_after, id
                   FOR UPDATE SKIP LOCKED
                   LIMIT $4),
               due AS (SELECT id FROM first UNION ALL SELECT id FROM rest)
               UPDATE queue.tasks t
               SET state = 'running', lease_owner = $1,
                   lease_expires_at = now() + make_interval(secs => $2),
                   attempts = t.attempts + 1, claimed_at = now(), updated_at = now(),
                   seen_changes = o.changes
               FROM due, analysis.observables o
               WHERE t.id = due.id AND o.id = t.observable_id
               RETURNING t.id AS "id: TaskId", t.root_id, t.module, t.attempts, t.input_hashes,
                         t.lease_expires_at AS "lease_expires_at!", t.run_after,
                         t.delay_state, t.first_delayed_at, t.delays, t.held_back_by,
                         t.held_back_step, o.id AS "observable_id: ObservableId", o.type AS kind, o.value,
                         o.time, o.directives"#,
                            self.name,
                            self.lease.as_secs_f64(),
                            &self.modules,
                            most,
                        )
                        .fetch_all(tx.conn())
                        .await?,
                    )
                })
            })
            .await?;
        // an UPDATE returns its rows in no order of its own
        rows.sort_by_key(|row| (row.run_after, row.id));
        rows.into_iter()
            .map(|row| {
                let kind = row
                    .kind
                    .parse()
                    .map_err(|e| DbError::Decode(format!("{}: {e}", row.id)))?;
                Ok(Task {
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
                    held_back: HeldBackWait::of_row(row.held_back_by, row.held_back_step),
                })
            })
            .collect()
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
                      t.delay_state, t.first_delayed_at, t.delays, t.held_back_by,
                      t.held_back_step, o.id AS "observable_id: ObservableId", o.type AS kind, o.value,
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
            held_back: HeldBackWait::of_row(row.held_back_by, row.held_back_step),
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

    /// Sends a task the worker owns back to the queue until `after` from now, before its module
    /// has seen it: the core holds it, as it holds a file's first task until its path is settled
    /// (`tree::choose_analysis_file`) and a task that runs last until the rest of its root is done
    /// (`held_back`, which `wake_held_back` finds it by, and runs for here). Unlike a module's `delay`, the module never
    /// learns of it: its delay state, count and first delay stay as they were, no run is counted
    /// (`crate::metrics`), and the claim isn't an attempt.
    pub async fn hold(
        &self,
        task: TaskId,
        after: Duration,
        held_back: Option<HeldBackWait>,
    ) -> Result<(), QueueError> {
        let (by, step) = held_back.map_or((None, None), |wait| {
            (
                Some(wait.by.as_str()),
                Some(i32::try_from(wait.step).unwrap_or(i32::MAX)),
            )
        });
        self.db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    let root = self.lock_task_root(tx, task).await?;
                    let state = sqlx::query_scalar!(
                        r#"UPDATE queue.tasks
               SET state = CASE WHEN cancel_requested THEN 'cancelled'::queue.task_state
                                ELSE 'delayed'::queue.task_state END,
                   run_after = now() + make_interval(secs => $3),
                   attempts = GREATEST(attempts - 1, 0), lease_owner = NULL,
                   lease_expires_at = NULL, held_back_by = $4, held_back_step = $5,
                   updated_at = now()
               WHERE id = $1 AND lease_owner = $2 AND state = 'running'
               RETURNING state AS "state: TaskState""#,
                        task as TaskId,
                        self.name,
                        after.as_secs_f64(),
                        by,
                        step,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or(QueueError::LeaseLost(task))?;
                    if state == TaskState::Cancelled {
                        check_completion(tx, root).await?;
                    } else if held_back.is_some() {
                        wake_held_back(tx, root).await?;
                    }
                    Ok::<_, QueueError>(())
                })
            })
            .await
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
                Box::pin(async move { self.delay_in(tx, task, after, state).await })
            })
            .await?;
        run_after
            .map(|(run_after, _)| run_after)
            .ok_or(QueueError::Cancelled(task))
    }

    /// `delay` inside the caller's transaction, which also queues what the task waits for, such as
    /// its scan (PLAN.md 7.7). The task's root stays locked. None when the root was cancelled while
    /// the task ran, so the task ended cancelled instead; otherwise when it runs again, and its root.
    pub async fn delay_in(
        &self,
        tx: &mut Tx<'_>,
        task: TaskId,
        after: Duration,
        state: &serde_json::Value,
    ) -> Result<Option<(DateTime<Utc>, Uuid)>, QueueError> {
        let (root, pass) = self.lock_task_root_in_pass(tx, task).await?;
        // the run ends here, as at a task's end (`finish_in`). A module that delays itself isn't held
        // back by the core any more, so its next hold's wait starts low, and until then it counts as
        // another module's task for the wake (`wake_held_back`).
        let row = sqlx::query!(
            r#"UPDATE queue.tasks
               SET state = CASE WHEN cancel_requested THEN 'cancelled'::queue.task_state
                                ELSE 'delayed'::queue.task_state END,
                   run_after = now() + make_interval(secs => $3),
                   delay_state = $4, first_delayed_at = COALESCE(first_delayed_at, now()),
                   delays = delays + 1, attempts = 0, lease_owner = NULL,
                   lease_expires_at = NULL, held_back_by = NULL, held_back_step = NULL,
                   updated_at = now(),
                   run_seconds = CASE WHEN run_pass = $5 THEN run_seconds ELSE 0 END
                       + GREATEST(COALESCE(EXTRACT(EPOCH FROM now() - claimed_at)::float8, 0), 0),
                   runs = CASE WHEN run_pass = $5 THEN runs ELSE 0 END + 1,
                   analyze_seconds = queue.add_known(
                       CASE WHEN run_pass = $5 THEN analyze_seconds END, $6),
                   cpu_seconds = queue.add_known(CASE WHEN run_pass = $5 THEN cpu_seconds END, $7),
                   run_pass = $5
               WHERE id = $1 AND lease_owner = $2 AND state = 'running'
               RETURNING run_after, state AS "state: TaskState""#,
            task as TaskId,
            self.name,
            after.as_secs_f64(),
            state,
            pass,
            self.cost.analyze_seconds,
            self.cost.cpu_seconds,
        )
        .fetch_optional(tx.conn())
        .await?
        .ok_or(QueueError::LeaseLost(task))?;
        // a task whose root was cancelled while it ran ends here instead
        if row.state == TaskState::Cancelled {
            check_completion(tx, root).await?;
            return Ok(None);
        }
        Ok(Some((row.run_after, root)))
    }

    /// The task's root, locked until the transaction ends.
    async fn lock_task_root(&self, tx: &mut Tx<'_>, task: TaskId) -> Result<Uuid, QueueError> {
        Ok(self.lock_task_root_in_pass(tx, task).await?.0)
    }

    /// `lock_task_root`, with the root's current pass, which a run that ends now ends in.
    async fn lock_task_root_in_pass(
        &self,
        tx: &mut Tx<'_>,
        task: TaskId,
    ) -> Result<(Uuid, Option<i32>), QueueError> {
        let root = sqlx::query_scalar!(
            "SELECT root_id FROM queue.tasks WHERE id = $1",
            task as TaskId
        )
        .fetch_optional(tx.conn())
        .await?
        .ok_or(QueueError::LeaseLost(task))?;
        let pass = lock_root_in_pass(tx, root).await?;
        Ok((root, pass))
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

    /// Gives a task the worker owns back to the queue, as at shutdown: queued again at once,
    /// with this attempt not counted. A task cancelled meanwhile ends cancelled instead.
    pub async fn release(&self, task: TaskId) -> Result<(), QueueError> {
        self.db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    let root = self.lock_task_root(tx, task).await?;
                    let released = sqlx::query!(
                        r#"UPDATE queue.tasks
                           SET state = CASE WHEN cancel_requested THEN 'cancelled'::queue.task_state
                                            ELSE 'queued'::queue.task_state END,
                               attempts = GREATEST(attempts - 1, 0), lease_owner = NULL,
                               lease_expires_at = NULL, updated_at = now()
                           WHERE id = $1 AND lease_owner = $2 AND state = 'running'"#,
                        task as TaskId,
                        self.name,
                    )
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if released == 0 {
                        return Err(QueueError::LeaseLost(task));
                    }
                    check_completion(tx, root).await?;
                    Ok(())
                })
            })
            .await
    }

    /// Ends a task the worker owns: it ran to the end.
    pub async fn complete(&self, task: TaskId) -> Result<(), QueueError> {
        self.finish(task, TaskState::Done, None).await
    }

    /// Ends a task the worker owns: the module failed. A failed task isn't claimed again.
    pub async fn fail(&self, task: TaskId, error: &str) -> Result<(), QueueError> {
        self.finish(task, TaskState::Failed, Some(error)).await
    }

    /// Ends a task the worker owns whose module's peer was unavailable (`ModuleError::Unavailable`):
    /// while it has attempts left (`max_attempts`), it goes back to the queue after
    /// `RETRY_AFTER_UNAVAILABLE`, doubled for each attempt it has had, at most
    /// `RETRY_AFTER_UNAVAILABLE_MAX`, with `error` as its last; on its last attempt it fails, as
    /// `fail` does. A delayed task keeps its delay's state, so its next run takes up the same step.
    /// Returns when it runs again, or None when it failed.
    pub async fn retry_later(
        &self,
        task: TaskId,
        error: &str,
    ) -> Result<Option<DateTime<Utc>>, QueueError> {
        let requeued = self
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    let (root, pass) = self.lock_task_root_in_pass(tx, task).await?;
                    // the run ends here, as at a task's end (`finish_in`)
                    let row = sqlx::query!(
                        r#"UPDATE queue.tasks
                               SET state = CASE WHEN cancel_requested
                                                THEN 'cancelled'::queue.task_state
                                                ELSE 'queued'::queue.task_state END,
                                   run_after = now() + make_interval(secs => LEAST(
                                       $4 * power(2, GREATEST(attempts - 1, 0)), $5)),
                                   error = $3, lease_owner = NULL, lease_expires_at = NULL,
                                   updated_at = now(),
                                   run_seconds = CASE WHEN run_pass = $6 THEN run_seconds ELSE 0 END
                                       + GREATEST(COALESCE(
                                           EXTRACT(EPOCH FROM now() - claimed_at)::float8, 0), 0),
                                   runs = CASE WHEN run_pass = $6 THEN runs ELSE 0 END + 1,
                                   analyze_seconds = queue.add_known(
                                       CASE WHEN run_pass = $6 THEN analyze_seconds END, $7),
                                   cpu_seconds = queue.add_known(
                                       CASE WHEN run_pass = $6 THEN cpu_seconds END, $8),
                                   run_pass = $6
                               WHERE id = $1 AND lease_owner = $2 AND state = 'running'
                                 AND attempts < max_attempts
                               RETURNING run_after, state AS "state: TaskState", module, attempts"#,
                        task as TaskId,
                        self.name,
                        error,
                        RETRY_AFTER_UNAVAILABLE.as_secs_f64(),
                        RETRY_AFTER_UNAVAILABLE_MAX.as_secs_f64(),
                        pass,
                        self.cost.analyze_seconds,
                        self.cost.cpu_seconds,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    // a task whose root was cancelled while it ran ends cancelled, as a delay's does
                    if row
                        .as_ref()
                        .is_some_and(|r| r.state == TaskState::Cancelled)
                    {
                        check_completion(tx, root).await?;
                    }
                    Ok::<_, QueueError>(row)
                })
            })
            .await?;
        match requeued {
            Some(row) if row.state == TaskState::Queued => {
                tracing::info!(
                    task = task.0,
                    module = %row.module,
                    attempt = row.attempts,
                    run_after = %row.run_after,
                    "a task whose peer was unavailable goes back to the queue: {error}"
                );
                Ok(Some(row.run_after))
            }
            Some(_) => Ok(None),
            // its last attempt, or a lease it lost, which `fail` reports
            None => {
                self.fail(task, error).await?;
                Ok(None)
            }
        }
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
                    // a task ended here leaves no result: a skip, a failure or a cancellation
                    self.ended_without_result(tx, root, task).await?;
                    check_completion(tx, root).await?;
                    Ok::<_, QueueError>(())
                })
            })
            .await
    }

    /// What follows the end of `task`, which ended in this transaction with no result
    /// (`TaskEnded::without_result`). Whatever ends a task with no result in a transaction of its
    /// own calls this after `finish_in`.
    pub async fn ended_without_result(
        &self,
        tx: &mut Tx<'_>,
        root: Uuid,
        task: TaskId,
    ) -> Result<(), QueueError> {
        let Some(ended) = &self.ended else {
            return Ok(());
        };
        let row = sqlx::query!(
            r#"SELECT module, observable_id AS "observable_id: ObservableId"
               FROM queue.tasks WHERE id = $1"#,
            task as TaskId
        )
        .fetch_one(tx.conn())
        .await?;
        ended
            .without_result(tx, root, row.observable_id, &row.module)
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
        let (root, pass) = self.lock_task_root_in_pass(tx, task).await?;
        // the run that ends here is added to the task's runs in this pass (`crate::metrics`): from
        // its claim to now(), this transaction's start, by the database's clock at both ends
        let finished = sqlx::query!(
            "UPDATE queue.tasks
             SET state = $3, error = $4, lease_owner = NULL, lease_expires_at = NULL,
                 updated_at = now(), incomplete = false,
                 run_seconds = CASE WHEN run_pass = $5 THEN run_seconds ELSE 0 END
                     + GREATEST(COALESCE(EXTRACT(EPOCH FROM now() - claimed_at)::float8, 0), 0),
                 runs = CASE WHEN run_pass = $5 THEN runs ELSE 0 END + 1,
                 analyze_seconds = queue.add_known(
                     CASE WHEN run_pass = $5 THEN analyze_seconds END, $6),
                 cpu_seconds = queue.add_known(CASE WHEN run_pass = $5 THEN cpu_seconds END, $7),
                 run_pass = $5
             WHERE id = $1 AND lease_owner = $2 AND state = 'running'
             RETURNING module, declined, observable_id",
            task as TaskId,
            self.name,
            state as TaskState,
            error,
            pass,
            self.cost.analyze_seconds,
            self.cost.cpu_seconds,
        )
        .fetch_optional(tx.conn())
        .await?;
        let Some(finished) = finished else {
            return Err(QueueError::LeaseLost(task));
        };
        // the audit of the modules' declarations: a task one declined that fails (`crate::takes`)
        if state == TaskState::Failed
            && let Some(declined) = &finished.declined
        {
            crate::takes::report_lost(task, &finished.module, declined, "failed");
        }
        // a type step that ended lets the file's other tasks be queued, done or failed alike
        if finished.module == TYPE_STEP
            && matches!(state, TaskState::Done | TaskState::Failed)
            && let Some(ended) = &self.ended
        {
            ended
                .type_step(tx, root, ObservableId(finished.observable_id))
                .await?;
        }
        Ok(root)
    }
}

/// The channel the queue's trigger notifies when a task becomes claimable. The payload is the
/// task's module.
pub const TASKS_CHANNEL: &str = "ace_rs_tasks";

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
    // the scans its tasks wait for (PLAN.md 7.7): a scanner pool kills a running one's container
    crate::scans::cancel_for_root(tx, root).await?;
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
pub const CANCEL_CHANNEL: &str = "ace_rs_cancel";

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
///
/// A file's type step that fails this way ends as any other end of it does (`TaskEnded`),
/// in the same transaction.
pub async fn reap_expired_leases(
    db: &Db,
    ended: Option<&dyn TaskEnded>,
) -> Result<Reaped, QueueError> {
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
               RETURNING id AS "id: TaskId", state AS "state: TaskState", module,
                         observable_id AS "observable_id: ObservableId""#,
            root,
        )
        .fetch_all(tx.conn())
        .await?;
        if let Some(ended) = ended {
            for row in &rows {
                if row.module == TYPE_STEP && row.state == TaskState::Failed {
                    ended.type_step(tx, root, row.observable_id).await?;
                }
                // a task that failed or was cancelled here left no result
                if matches!(row.state, TaskState::Failed | TaskState::Cancelled) {
                    ended
                        .without_result(tx, root, row.observable_id, &row.module)
                        .await?;
                }
            }
        }
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
pub const COMPLETIONS_CHANNEL: &str = "ace_rs_root_complete";

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

/// Whether the root is idle: its last pass completed, or nothing ever ran on it. A root with
/// work queued or a pass still open isn't.
pub async fn root_is_idle(db: &Db, root: Uuid) -> Result<bool, QueueError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT completed_pass = pass AS "idle!" FROM analysis.roots WHERE id = $1"#,
        root,
    )
    .fetch_optional(db.pool())
    .await?
    .unwrap_or(false))
}

/// A task of a root that ended in failure, with the observable it ran on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedTask {
    pub module: String,
    pub observable: String,
    pub error: String,
}

/// The tasks of the root that failed, or were cancelled, so whatever reads its tree can say why a
/// result is missing.
pub async fn failed_tasks(db: &Db, root: Uuid) -> Result<Vec<FailedTask>, QueueError> {
    Ok(sqlx::query!(
        r#"SELECT t.module, o.type || ':' || o.value AS "observable!",
                  t.state::text AS "state!", coalesce(t.error, '') AS "error!"
           FROM queue.tasks t JOIN analysis.observables o ON o.id = t.observable_id
           WHERE t.root_id = $1 AND t.state IN ('failed', 'cancelled')
           ORDER BY t.module, 2"#,
        root,
    )
    .fetch_all(db.pool())
    .await?
    .into_iter()
    .map(|row| FailedTask {
        module: row.module,
        observable: row.observable,
        error: format!("{}: {}", row.state, row.error),
    })
    .collect())
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

/// Runs `reap_expired_leases`, `commands::reap_commands` and `scans::reap_scans` every `interval` until `stop` fires.
pub async fn run_reaper(
    db: Db,
    interval: Duration,
    stop: CancellationToken,
    ended: Option<std::sync::Arc<dyn TaskEnded>>,
) {
    loop {
        if let Err(e) = reap_expired_leases(&db, ended.as_deref()).await {
            tracing::error!("the reaper failed: {e}");
        }
        // GUI commands (PLAN.md 5.12) never run twice, so their lost leases end them
        if let Err(e) = crate::commands::reap_commands(&db).await {
            tracing::error!("the reaper failed on commands: {e}");
        }
        // nor do scans (PLAN.md 7.7), whose tasks are woken to decide
        if let Err(e) = crate::scans::reap_scans(&db).await {
            tracing::error!("the reaper failed on scans: {e}");
        }
        // an action whose pool went away is tried again (PLAN.md 7.9)
        if let Err(e) = crate::actions::reap_actions(&db).await {
            tracing::error!("the reaper failed on actions: {e}");
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
                  t.delay_state, t.first_delayed_at, t.delays, t.held_back_by,
                  t.held_back_step, o.id AS "observable_id: ObservableId", o.type AS kind, o.value,
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
        held_back: HeldBackWait::of_row(row.held_back_by, row.held_back_step),
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
