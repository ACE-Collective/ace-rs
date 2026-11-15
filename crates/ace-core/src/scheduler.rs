//! The scheduler's tables (PLAN.md 6.7): when each task is next due, which run holds it, and how
//! every run went. `ace_app`'s scheduler decides what the tasks are and runs them; this module is
//! how replicas of `ace serve` agree on who runs what.
//!
//! A task's row is claimed with `FOR UPDATE SKIP LOCKED`, and only when it's due and no run holds
//! its lease. The claim moves `due_at` to the schedule's next time after the database's now, takes
//! the lease for the run's timeout and a margin, and inserts the run's row, in one transaction. So
//! two replicas never start the same due time, a run never starts while another holds the task, as
//! ace3's yacron jobs have `concurrencyPolicy: Forbid`, and when the stack was down over several due
//! times the task runs once for all of them. A run whose node died keeps the lease until it ends,
//! and the next claim after that marks the run `abandoned`.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::db::{Db, DbError};

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Succeeded,
    Failed,
    /// It ran past its timeout and was stopped.
    TimedOut,
    /// Its process was shutting down and stopped it.
    Stopped,
    /// Its lease ended before it did: the process running it went away.
    Abandoned,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Succeeded => "succeeded",
            Outcome::Failed => "failed",
            Outcome::TimedOut => "timed_out",
            Outcome::Stopped => "stopped",
            Outcome::Abandoned => "abandoned",
        }
    }
}

/// A claimed run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub run: i64,
    /// The due time it was claimed for, which may be long past.
    pub scheduled_for: DateTime<Utc>,
    /// When the task is due again.
    pub next_due: DateTime<Utc>,
}

/// A run's row.
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub id: i64,
    pub task: String,
    pub scheduled_for: DateTime<Utc>,
    pub node: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub outcome: Option<String>,
    pub error: Option<String>,
    pub summary: Option<Value>,
}

/// How long a task's runs are kept.
pub const RUN_RETENTION_DAYS: i32 = 90;

/// The schedule's next time after a moment, or None when it has none.
pub type Next<'a> = &'a (dyn Fn(DateTime<Utc>) -> Option<DateTime<Utc>> + Sync);

/// Makes the task's row, due at the schedule's next time, or works its due time out again when the
/// row was made with another schedule. A row with the same schedule keeps its due time, so a
/// restart doesn't move it.
pub async fn ensure(db: &Db, task: &str, schedule: &str, next: Next<'_>) -> Result<(), DbError> {
    let now = db_now(db).await?;
    let due = next(now).ok_or_else(|| no_next(task, schedule))?;
    sqlx::query!(
        "INSERT INTO scheduler.tasks AS t (name, schedule, due_at) VALUES ($1, $2, $3)
         ON CONFLICT (name) DO UPDATE SET schedule = EXCLUDED.schedule, due_at = EXCLUDED.due_at,
             updated_at = now()
         WHERE t.schedule <> EXCLUDED.schedule",
        task,
        schedule,
        due,
    )
    .execute(db.pool())
    .await?;
    Ok(())
}

/// Claims the task's due run for `node`, holding the task for `lease`, or None when it isn't due,
/// another run holds it, or another replica is claiming it now.
pub async fn claim(
    db: &Db,
    task: &str,
    node: &str,
    lease: Duration,
    next: Next<'_>,
) -> Result<Option<Claimed>, DbError> {
    let mut tx = db.begin().await?;
    let Some(row) = sqlx::query!(
        r#"SELECT due_at, schedule, run_id, now() AS "now!" FROM scheduler.tasks
           WHERE name = $1 AND due_at <= now() AND (lease_until IS NULL OR lease_until < now())
           FOR UPDATE SKIP LOCKED"#,
        task,
    )
    .fetch_optional(tx.conn())
    .await?
    else {
        return Ok(None);
    };
    if let Some(stale) = row.run_id {
        sqlx::query!(
            "UPDATE scheduler.runs SET ended_at = now(), outcome = 'abandoned',
                 error = 'its lease ended before the run did: the process running it went away'
             WHERE id = $1 AND ended_at IS NULL",
            stale,
        )
        .execute(tx.conn())
        .await?;
    }
    let next_due = next(row.now).ok_or_else(|| no_next(task, &row.schedule))?;
    let run = sqlx::query_scalar!(
        "INSERT INTO scheduler.runs (task, scheduled_for, node) VALUES ($1, $2, $3) RETURNING id",
        task,
        row.due_at,
        node,
    )
    .fetch_one(tx.conn())
    .await?;
    sqlx::query!(
        "UPDATE scheduler.tasks SET due_at = $2, run_id = $3,
             lease_until = now() + make_interval(secs => $4), updated_at = now()
         WHERE name = $1",
        task,
        next_due,
        run,
        lease.as_secs_f64(),
    )
    .execute(tx.conn())
    .await?;
    sqlx::query!(
        "DELETE FROM scheduler.runs
         WHERE task = $1 AND started_at < now() - make_interval(days => $2)",
        task,
        RUN_RETENTION_DAYS,
    )
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(Some(Claimed {
        run,
        scheduled_for: row.due_at,
        next_due,
    }))
}

/// Records how a run ended and lets the task go. False when the run had already been marked
/// abandoned, because it outlived its lease.
pub async fn finish(
    db: &Db,
    task: &str,
    run: i64,
    outcome: Outcome,
    error: Option<&str>,
    summary: Option<&Value>,
) -> Result<bool, DbError> {
    let mut tx = db.begin().await?;
    let ended = sqlx::query!(
        "UPDATE scheduler.runs SET ended_at = now(), outcome = $2, error = $3, summary = $4
         WHERE id = $1 AND ended_at IS NULL",
        run,
        outcome.as_str(),
        error,
        summary,
    )
    .execute(tx.conn())
    .await?
    .rows_affected()
        > 0;
    sqlx::query!(
        "UPDATE scheduler.tasks SET run_id = NULL, lease_until = NULL, updated_at = now()
         WHERE name = $1 AND run_id = $2",
        task,
        run,
    )
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(ended)
}

/// The task's runs, newest first, at most `limit`.
pub async fn runs(db: &Db, task: &str, limit: i64) -> Result<Vec<Run>, DbError> {
    Ok(sqlx::query_as!(
        Run,
        "SELECT id, task, scheduled_for, node, started_at, ended_at, outcome, error, summary
         FROM scheduler.runs WHERE task = $1 ORDER BY id DESC LIMIT $2",
        task,
        limit,
    )
    .fetch_all(db.pool())
    .await?)
}

/// The most runs one read of the table returns.
pub const MAX_RUNS_READ: i64 = 500;

/// Runs of every task, or of one, newest first, at most `limit` (and `MAX_RUNS_READ`): what the
/// administration area's monitoring page lists (PLAN.md 7.12).
pub async fn recent_runs<'c>(
    executor: impl sqlx::PgExecutor<'c>,
    task: Option<&str>,
    limit: i64,
) -> Result<Vec<Run>, DbError> {
    Ok(sqlx::query_as!(
        Run,
        "SELECT id, task, scheduled_for, node, started_at, ended_at, outcome, error, summary
         FROM scheduler.runs WHERE $1::text IS NULL OR task = $1 ORDER BY id DESC LIMIT $2",
        task,
        limit.clamp(1, MAX_RUNS_READ),
    )
    .fetch_all(executor)
    .await?)
}

/// When the task is next due, if it has a row.
pub async fn due_at(db: &Db, task: &str) -> Result<Option<DateTime<Utc>>, DbError> {
    Ok(
        sqlx::query_scalar!("SELECT due_at FROM scheduler.tasks WHERE name = $1", task)
            .fetch_optional(db.pool())
            .await?,
    )
}

async fn db_now(db: &Db) -> Result<DateTime<Utc>, DbError> {
    Ok(sqlx::query_scalar!(r#"SELECT now() AS "now!""#)
        .fetch_one(db.pool())
        .await?)
}

fn no_next(task: &str, schedule: &str) -> DbError {
    DbError::Decode(format!(
        "task {task}'s schedule {schedule:?} has no time after now"
    ))
}
