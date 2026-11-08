//! Commands an analyst starts from the GUI (PLAN.md 5.12, ace3's `docs/GUI_CLI.md`), as the queue holds
//! them in `queue.commands`.
//!
//! ace3 runs such a command as a child of the API worker that took the request, so what contains it is
//! that worker and the session it made (#973). Here a command is leased like a task: the service queues
//! it (`enqueue`, in its audited transaction), a pool that runs commands claims it through the lease API
//! (`CommandWorker::claim`), and that pool's supervisor runs it in a contained process and kills it at its
//! deadline, which the claim fixes as the claim's time plus the command's timeout. Nothing about the
//! session that started it, or the API that took the request, is part of that: the row says when it must
//! end, and the supervisor holds the process to it.
//!
//! The pool reports the output so far every couple of seconds (`CommandWorker::report`), which also renews
//! its lease and tells it whether someone cancelled the command, and ends it once (`CommandWorker::end`).
//! A command runs at most once. Unlike a task, a lost lease never queues it again: the reaper
//! (`reap_commands`) ends a running command whose lease expired as abandoned, and a queued one no pool
//! took within its timeout too. Its process is still bounded then, by its supervisor's deadline and the
//! process's own alarm (`ace_pool::commands`).
//!
//! What a command wrote is text from a process, so it's data: NUL, which Postgres text can't hold, becomes
//! U+FFFD, and the core keeps at most `MAX_OUTPUT_BYTES` of it whatever a pool sends.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{Db, DbError, Tx};
use crate::queue::{QueueError, TaskId};

/// The most output a command keeps, as ace3's `MAX_OUTPUT_BYTES`. The rest is read and dropped.
pub const MAX_OUTPUT_BYTES: usize = 1 << 20;
/// The longest a command may run, as ace3's: a run longer than this belongs in a service.
pub const MAX_TIMEOUT_SECONDS: u32 = 3600;
/// The most an error on a command's row holds.
const MAX_ERROR_CHARS: usize = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, serde::Serialize)]
#[sqlx(type_name = "queue.command_state", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CommandState {
    Queued,
    Running,
    Completed,
    TimedOut,
    Cancelled,
    Failed,
    Abandoned,
}

impl CommandState {
    pub fn as_str(self) -> &'static str {
        match self {
            CommandState::Queued => "queued",
            CommandState::Running => "running",
            CommandState::Completed => "completed",
            CommandState::TimedOut => "timed_out",
            CommandState::Cancelled => "cancelled",
            CommandState::Failed => "failed",
            CommandState::Abandoned => "abandoned",
        }
    }

    /// Queued and running commands haven't ended.
    pub fn is_active(self) -> bool {
        matches!(self, CommandState::Queued | CommandState::Running)
    }
}

impl std::fmt::Display for CommandState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A command the service queues.
#[derive(Debug, Clone)]
pub struct NewCommand<'a> {
    /// The words after `ace`.
    pub argv: &'a [String],
    /// The words quoted again, for the pages.
    pub command: &'a str,
    pub timeout_seconds: u32,
    /// The actor, as the service records it.
    pub started_by: &'a Value,
    /// The person it runs for, when the actor is a user or a key with an owner.
    pub user_id: Option<Uuid>,
    pub username: &'a str,
}

/// Queues a command in the caller's transaction and returns its id. Its pools wake at the commit.
pub async fn enqueue(tx: &mut Tx<'_>, command: &NewCommand<'_>) -> Result<i64, DbError> {
    Ok(sqlx::query_scalar!(
        "INSERT INTO queue.commands (argv, command, timeout_seconds, started_by, user_id, username)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id",
        command.argv,
        command.command,
        i32::try_from(command.timeout_seconds).unwrap_or(i32::MAX),
        command.started_by,
        command.user_id,
        command.username,
    )
    .fetch_one(tx.conn())
    .await?)
}

/// What a cancel did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cancel {
    /// It was queued, so it ended cancelled at once and never ran.
    Ended,
    /// It runs: its pool learns at its next report and kills it.
    Requested,
    /// It runs, and was asked to stop already.
    AlreadyRequested,
    /// It had ended, in this state, so nothing changed.
    Over(CommandState),
    NotFound,
}

/// Cancels a command in the caller's transaction, recording who asked.
pub async fn cancel(tx: &mut Tx<'_>, id: i64, by: &Value) -> Result<Cancel, DbError> {
    let row = sqlx::query!(
        r#"SELECT state AS "state: CommandState", cancel_requested FROM queue.commands
           WHERE id = $1 FOR UPDATE"#,
        id,
    )
    .fetch_optional(tx.conn())
    .await?;
    let Some(row) = row else {
        return Ok(Cancel::NotFound);
    };
    match row.state {
        CommandState::Queued => {
            sqlx::query!(
                "UPDATE queue.commands
                 SET state = 'cancelled', cancel_requested = true, cancelled_by = $2,
                     error = 'cancelled before a pool took it', finished_at = now()
                 WHERE id = $1",
                id,
                by,
            )
            .execute(tx.conn())
            .await?;
            Ok(Cancel::Ended)
        }
        CommandState::Running if row.cancel_requested => Ok(Cancel::AlreadyRequested),
        CommandState::Running => {
            sqlx::query!(
                "UPDATE queue.commands SET cancel_requested = true, cancelled_by = $2 WHERE id = $1",
                id,
                by,
            )
            .execute(tx.conn())
            .await?;
            Ok(Cancel::Requested)
        }
        state => Ok(Cancel::Over(state)),
    }
}

/// A command a pool has claimed.
#[derive(Debug, Clone, PartialEq)]
pub struct ClaimedCommand {
    pub id: i64,
    pub argv: Vec<String>,
    pub timeout_seconds: u32,
    pub deadline_at: DateTime<Utc>,
    /// From the claim's moment to the deadline, by the database's clock.
    pub deadline_in: Duration,
}

/// One pool process's identity on the commands' queue.
#[derive(Debug, Clone)]
pub struct CommandWorker {
    db: Db,
    name: String,
    lease: Duration,
}

impl CommandWorker {
    pub fn new(db: Db, name: impl Into<String>, lease: Duration) -> Self {
        CommandWorker {
            db,
            name: name.into(),
            lease,
        }
    }

    pub fn lease(&self) -> Duration {
        self.lease
    }

    /// Claims the oldest queued command, starting its clock: its deadline is now plus its timeout.
    pub async fn claim(&self) -> Result<Option<ClaimedCommand>, QueueError> {
        let row = sqlx::query!(
            r#"UPDATE queue.commands c
               SET state = 'running', lease_owner = $1,
                   lease_expires_at = now() + make_interval(secs => $2),
                   started_at = now(), deadline_at = now() + make_interval(secs => c.timeout_seconds)
               WHERE c.id = (SELECT id FROM queue.commands WHERE state = 'queued'
                             ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1)
               RETURNING c.id, c.argv, c.timeout_seconds, c.deadline_at AS "deadline_at!",
                         extract(epoch FROM c.deadline_at - now())::float8 AS "deadline_in!""#,
            self.name,
            self.lease.as_secs_f64(),
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|row| ClaimedCommand {
            id: row.id,
            argv: row.argv,
            timeout_seconds: u32::try_from(row.timeout_seconds).unwrap_or_default(),
            deadline_at: row.deadline_at,
            deadline_in: Duration::try_from_secs_f64(row.deadline_in).unwrap_or_default(),
        }))
    }

    /// Stores what a command the worker holds has written so far and renews its lease. True when
    /// someone asked it to stop.
    pub async fn report(&self, id: i64, output: &str, truncated: bool) -> Result<bool, QueueError> {
        let (output, truncated) = bounded(output, truncated);
        let cancel = sqlx::query_scalar!(
            "UPDATE queue.commands
             SET output = $3, output_truncated = $4,
                 lease_expires_at = now() + make_interval(secs => $5)
             WHERE id = $1 AND lease_owner = $2 AND state = 'running'
             RETURNING cancel_requested",
            id,
            self.name,
            output.as_ref(),
            truncated,
            self.lease.as_secs_f64(),
        )
        .fetch_optional(self.db.pool())
        .await?;
        cancel.ok_or(QueueError::LeaseLost(TaskId(id)))
    }

    /// Ends a command the worker holds, with all it wrote. A timed-out or cancelled command's row says so
    /// in its error, with the deadline it was held to.
    pub async fn end(
        &self,
        id: i64,
        state: CommandState,
        exit_code: Option<i32>,
        error: Option<&str>,
        output: &str,
        truncated: bool,
    ) -> Result<(), QueueError> {
        let (output, truncated) = bounded(output, truncated);
        let error = error.map(|e| {
            e.replace('\0', "\u{fffd}")
                .chars()
                .take(MAX_ERROR_CHARS)
                .collect::<String>()
        });
        let ended = sqlx::query!(
            "UPDATE queue.commands
             SET state = $3::queue.command_state, exit_code = $4,
                 error = CASE $3::queue.command_state
                     WHEN 'timed_out'::queue.command_state THEN
                         format('killed at its deadline, %s seconds after it started', timeout_seconds)
                     WHEN 'cancelled'::queue.command_state THEN coalesce($5, 'cancelled while it ran')
                     ELSE $5 END,
                 output = $6, output_truncated = $7, finished_at = now(),
                 lease_owner = NULL, lease_expires_at = NULL
             WHERE id = $1 AND lease_owner = $2 AND state = 'running'",
            id,
            self.name,
            state as CommandState,
            exit_code,
            error.as_deref(),
            output.as_ref(),
            truncated,
        )
        .execute(self.db.pool())
        .await?
        .rows_affected();
        if ended == 0 {
            return Err(QueueError::LeaseLost(TaskId(id)));
        }
        Ok(())
    }
}

/// `output` with NUL as U+FFFD and at most `MAX_OUTPUT_BYTES`, cut at a character's boundary.
fn bounded(output: &str, truncated: bool) -> (std::borrow::Cow<'_, str>, bool) {
    let mut output = if output.contains('\0') {
        std::borrow::Cow::Owned(output.replace('\0', "\u{fffd}"))
    } else {
        std::borrow::Cow::Borrowed(output)
    };
    if output.len() <= MAX_OUTPUT_BYTES {
        return (output, truncated);
    }
    let mut end = MAX_OUTPUT_BYTES;
    while !output.is_char_boundary(end) {
        end -= 1;
    }
    output.to_mut().truncate(end);
    (output, true)
}

/// What the reaper ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReapedCommands {
    /// Running commands whose pool stopped renewing their lease.
    pub unreported: u64,
    /// Queued commands no pool took within their timeout.
    pub untaken: u64,
}

/// Ends as abandoned what nothing will finish: a running command whose lease expired, and a queued one
/// that waited longer than its timeout. Neither runs again.
pub async fn reap_commands(db: &Db) -> Result<ReapedCommands, DbError> {
    let unreported = sqlx::query!(
        "UPDATE queue.commands
         SET state = 'abandoned', finished_at = now(), lease_owner = NULL, lease_expires_at = NULL,
             error = 'its pool stopped reporting on it before it ended'
         WHERE state = 'running' AND lease_expires_at < now()",
    )
    .execute(db.pool())
    .await?
    .rows_affected();
    let untaken = sqlx::query!(
        "UPDATE queue.commands
         SET state = 'abandoned', finished_at = now(),
             error = 'no pool took it within its timeout'
         WHERE state = 'queued' AND created_at + make_interval(secs => timeout_seconds) < now()",
    )
    .execute(db.pool())
    .await?
    .rows_affected();
    if unreported + untaken > 0 {
        tracing::warn!(
            unreported,
            untaken,
            "ended commands nothing will finish as abandoned"
        );
    }
    Ok(ReapedCommands {
        unreported,
        untaken,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_bounded_at_a_character_and_loses_its_nul() {
        let (output, truncated) = bounded("a\0b", false);
        assert_eq!((output.as_ref(), truncated), ("a\u{fffd}b", false));
        let long = format!("{}é", "x".repeat(MAX_OUTPUT_BYTES - 1));
        let (output, truncated) = bounded(&long, false);
        assert!(truncated);
        assert_eq!(output.len(), MAX_OUTPUT_BYTES - 1);
    }
}
