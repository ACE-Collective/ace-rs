//! The task queue: every module run is a task, (root, observable, module), in `queue.tasks`.
//!
//! A worker claims the oldest claimable task of the modules it hosts with `FOR UPDATE SKIP
//! LOCKED`, so workers never wait on each other's claims and no task is claimed twice. A
//! claim takes a lease: the worker is the task's owner until the lease expires. Every later
//! change a worker makes to the task checks that it still owns it, so a worker whose lease ran
//! out can't overwrite what the task's next owner does.

use std::time::Duration;

use ace_results::ObservableKind;
use chrono::{DateTime, Utc};
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

/// A task's state, for tests and tools.
pub async fn state(db: &Db, task: TaskId) -> Result<Option<TaskState>, QueueError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT state AS "state: TaskState" FROM queue.tasks WHERE id = $1"#,
        task as TaskId,
    )
    .fetch_optional(db.pool())
    .await?)
}
