//! Commands an analyst runs from the GUI (PLAN.md 5.12), ace3's `cli` router and its CLI page
//! (`ace3/docs/GUI_CLI.md`), over the core's `queue.commands` (`ace_core::commands`).
//!
//! ace3 runs `ace <command>` as a child of the API worker that took the request, on each node asked, so a
//! command is contained only by that worker's session, and only on the path where the API stops it
//! (#973). Here starting one queues it, in the audited write's transaction, and a parser pool's supervisor
//! leases it and runs it in a contained process until its deadline (`ace_pool::commands`). The session
//! and the API play no part in that: a command ends at its deadline however its session ends, and an
//! API restart only delays its row.
//!
//! What's checked here, as ace3's `parse_command`: the line splits as a shell would (`shlex`), a leading
//! `ace` is dropped, and it can't start with an option but `-h`, `--help`, `-V` or `--version`, which are
//! the only global options `ace` has. ace-rs's commands take no secret on their command line, so there is no
//! list of secret options to refuse; the line is stored as typed, as in ace3. The command runs as the
//! pool's task user, with no paths, no ports and no credentials, so what it can do is what `ace`'s own
//! parser does in that process (`ace_app`'s `cli::run_contained` says which commands run).
//!
//! `cli:execute`, ace3's name, starts a command, cancels one, and reads every run and its output, as in
//! ace3: the starter reads their own under the permission they started it with. Starting and cancelling
//! are audited writes. A command runs for a person: a user, or a key's owner. A key with no owner and a
//! component are refused, as ace3 refuses a config key, since the row names who ran it.
//!
//! The output is what a process wrote, so it's data: the core turns NUL into U+FFFD and keeps at most
//! 1 MiB, and an adapter escapes it.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use ace_core::commands::{self as queue, Cancel, MAX_TIMEOUT_SECONDS, NewCommand};
use ace_core::db::Tx;

pub use ace_core::commands::CommandState;

use crate::alerts::RecordedActor;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::CLI_EXECUTE;
use crate::{Actor, Service, ServiceError, UserId};

/// How long a command may run when its starter doesn't say, as ace3's default.
pub const DEFAULT_COMMAND_TIMEOUT_SECONDS: u32 = 300;
/// The longest a command may be given, as ace3's.
pub const MAX_COMMAND_TIMEOUT_SECONDS: u32 = MAX_TIMEOUT_SECONDS;
/// The longest command line, as ace3's.
pub const MAX_COMMAND_CHARS: usize = 8192;
/// The most words a command line may split into.
pub const MAX_COMMAND_WORDS: usize = 256;
/// The most runs one page lists, as ace3's.
pub const MAX_COMMANDS_PAGE: u32 = 200;
const DEFAULT_COMMANDS_PAGE: u32 = 50;

/// The options `ace` takes before a command.
const LEADING_OPTIONS: &[&str] = &["-h", "--help", "-V", "--version"];

/// The words after `ace` of a command line typed into the GUI, as ace3's `parse_command`.
pub fn parse_command(line: &str) -> Result<Vec<String>, ServiceError> {
    let invalid = |why: String| Err(ServiceError::InvalidRequest(why));
    if line.chars().count() > MAX_COMMAND_CHARS {
        return invalid(format!(
            "a command line is at most {MAX_COMMAND_CHARS} characters"
        ));
    }
    if line.chars().any(|c| c.is_control() && c != '\t') {
        return invalid("a command line has no control characters".to_owned());
    }
    let Some(mut words) = shlex::split(line) else {
        return invalid("the command line doesn't split: is a quote left open?".to_owned());
    };
    if words.first().is_some_and(|word| word == "ace") {
        words.remove(0);
    }
    let Some(first) = words.first() else {
        return invalid("enter a command, such as --help".to_owned());
    };
    if first.starts_with('-') && !LEADING_OPTIONS.contains(&first.as_str()) {
        return invalid(format!(
            "{first} isn't an option here: start with the command's name, or --help"
        ));
    }
    if words.len() > MAX_COMMAND_WORDS {
        return invalid(format!("a command is at most {MAX_COMMAND_WORDS} words"));
    }
    Ok(words)
}

/// One run of a command, without its output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRun {
    pub id: i64,
    /// The words after `ace`, quoted again.
    pub command: String,
    pub state: CommandState,
    /// Who it runs for, None once that user is deleted.
    pub user: Option<UserId>,
    pub username: String,
    /// The actor that started it.
    pub started_by: RecordedActor,
    pub timeout_seconds: u32,
    pub exit_code: Option<i32>,
    /// Why it didn't complete, as its pool or the core wrote it. It may quote what the command wrote.
    pub error: Option<String>,
    /// Someone asked it to stop.
    pub cancel_requested: bool,
    pub cancelled_by: Option<RecordedActor>,
    pub created_at: DateTime<Utc>,
    /// When a pool took it, and when that pool kills it.
    pub started_at: Option<DateTime<Utc>>,
    pub deadline_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// One run with what it wrote so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandDetail {
    pub run: CommandRun,
    /// What it wrote to stdout and stderr, interleaved, as text: show it as text.
    pub output: String,
    /// More was written than the 1 MiB kept.
    pub output_truncated: bool,
}

/// Runs newest first, and the cursor for the next page, None on the last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPage {
    pub commands: Vec<CommandRun>,
    pub next: Option<i64>,
}

/// A start's audit row.
#[derive(Serialize)]
struct Started<'a> {
    command: &'a str,
    timeout_seconds: u32,
    username: &'a str,
}

impl Recorded for Started<'_> {}

/// A command's state before and after a cancel.
#[derive(Serialize)]
struct Status {
    state: CommandState,
    cancel_requested: bool,
}

impl Recorded for Status {}

/// What a cancel's row says it cancelled.
#[derive(Serialize)]
struct Cancelled<'a> {
    command: &'a str,
}

impl Recorded for Cancelled<'_> {}

fn no_command(id: i64) -> ServiceError {
    ServiceError::NotFound(format!("no command {id}"))
}

/// The person a command runs for: the user, or the key's owner, with their name now.
async fn person(tx: &mut Tx<'_>, actor: &Actor) -> Result<(Uuid, String), ServiceError> {
    let id = match actor {
        Actor::User { id, .. } => id.0,
        Actor::ApiKey {
            owner: Some(owner), ..
        } => owner.0,
        Actor::ApiKey { owner: None, .. } | Actor::Internal { .. } => {
            return Err(ServiceError::Forbidden(
                "a command runs for a person: start it as a user, or with a key a user owns"
                    .to_owned(),
            ));
        }
    };
    let name = sqlx::query_scalar!(
        r#"SELECT username::text AS "username!" FROM service.users WHERE id = $1"#,
        id
    )
    .fetch_optional(tx.conn())
    .await?
    .ok_or(ServiceError::NoUser(id))?;
    Ok((id, name))
}

macro_rules! run_of {
    ($row:expr) => {{
        let row = $row;
        CommandRun {
            id: row.id,
            command: row.command,
            state: row.state,
            user: row.user_id.map(UserId),
            username: row.username,
            started_by: RecordedActor::from_row(Some(row.started_by))?.ok_or_else(|| {
                ServiceError::InvalidRequest("a command with no starter".to_owned())
            })?,
            timeout_seconds: u32::try_from(row.timeout_seconds).unwrap_or_default(),
            exit_code: row.exit_code,
            error: row.error,
            cancel_requested: row.cancel_requested,
            cancelled_by: RecordedActor::from_row(row.cancelled_by)?,
            created_at: row.created_at,
            started_at: row.started_at,
            deadline_at: row.deadline_at,
            finished_at: row.finished_at,
        }
    }};
}

async fn detail_in(tx: &mut Tx<'_>, id: i64) -> Result<CommandDetail, ServiceError> {
    let row = sqlx::query!(
        r#"SELECT id, command, state AS "state: CommandState", user_id, username,
                  started_by AS "started_by!: serde_json::Value",
                  timeout_seconds, exit_code, error, cancel_requested,
                  cancelled_by AS "cancelled_by: serde_json::Value", created_at, started_at,
                  deadline_at, finished_at, output, output_truncated
           FROM queue.commands WHERE id = $1"#,
        id,
    )
    .fetch_optional(tx.conn())
    .await?
    .ok_or_else(|| no_command(id))?;
    let (output, output_truncated) = (row.output.clone(), row.output_truncated);
    Ok(CommandDetail {
        run: run_of!(row),
        output,
        output_truncated,
    })
}

impl Service {
    /// Starts `ace <line>` as a command a pool runs contained, for up to `timeout_seconds` (300 when
    /// None, at most 3600) from when a pool takes it, under `cli:execute`, with its audit row. The
    /// starter is the actor's person, as ace3 records the user.
    pub async fn start_command(
        &self,
        actor: &Actor,
        line: &str,
        timeout_seconds: Option<u32>,
    ) -> Result<CommandDetail, ServiceError> {
        let argv = parse_command(line)?;
        let timeout_seconds = match timeout_seconds.unwrap_or(DEFAULT_COMMAND_TIMEOUT_SECONDS) {
            seconds @ 1..=MAX_COMMAND_TIMEOUT_SECONDS => seconds,
            seconds => {
                return Err(ServiceError::InvalidRequest(format!(
                    "a timeout is 1 to {MAX_COMMAND_TIMEOUT_SECONDS} seconds, not {seconds}"
                )));
            }
        };
        let command = shlex::try_join(argv.iter().map(String::as_str))
            .map_err(|e| ServiceError::InvalidRequest(format!("the command line: {e}")))?;
        let started_by = serde_json::to_value(actor)?;
        let (argv, command, started_by) = (&argv, &command, &started_by);
        self.gate
            .write(actor, "start_command", &CLI_EXECUTE, &|tx| {
                Box::pin(async move {
                    let (user_id, username) = person(tx, actor).await?;
                    let id = queue::enqueue(
                        tx,
                        &NewCommand {
                            argv,
                            command,
                            timeout_seconds,
                            started_by,
                            user_id: Some(user_id),
                            username: &username,
                        },
                    )
                    .await?;
                    let change = Change::added(
                        Target::command(id),
                        &Started {
                            command,
                            timeout_seconds,
                            username: &username,
                        },
                    )?;
                    Ok(Audited::changed(detail_in(tx, id).await?, change))
                })
            })
            .await
    }

    /// Cancels a command under `cli:execute`, with its audit row: a queued one ends at once, and a
    /// running one's pool kills it at its next report, within a few seconds. Asking a running one twice
    /// changes nothing; one that has ended is a conflict.
    pub async fn cancel_command(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<CommandDetail, ServiceError> {
        let by = serde_json::to_value(actor)?;
        let by = &by;
        self.gate
            .write(actor, "cancel_command", &CLI_EXECUTE, &|tx| {
                Box::pin(async move {
                    let before = match queue::cancel(tx, id, by).await? {
                        Cancel::NotFound => return Err(no_command(id)),
                        Cancel::Over(state) => {
                            return Err(ServiceError::Conflict(format!(
                                "command {id} has ended: it's {state}"
                            )));
                        }
                        Cancel::AlreadyRequested => {
                            return Ok(Audited::unchanged(detail_in(tx, id).await?));
                        }
                        Cancel::Ended => CommandState::Queued,
                        Cancel::Requested => CommandState::Running,
                    };
                    let detail = detail_in(tx, id).await?;
                    let change = Change::updated(
                        Target::command(id),
                        &Status {
                            state: before,
                            cancel_requested: false,
                        },
                        &Status {
                            state: detail.run.state,
                            cancel_requested: true,
                        },
                    )?
                    .details(&Cancelled {
                        command: &detail.run.command,
                    })?;
                    Ok(Audited::changed(detail, change))
                })
            })
            .await
    }

    /// A page of runs, newest first, of up to `limit` (50 when None, at most `MAX_COMMANDS_PAGE`),
    /// after the run `after` names, without their output, under `cli:execute`.
    pub async fn commands(
        &self,
        actor: &Actor,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<CommandPage, ServiceError> {
        let limit = match limit.unwrap_or(DEFAULT_COMMANDS_PAGE) {
            limit @ 1..=MAX_COMMANDS_PAGE => i64::from(limit),
            limit => {
                return Err(ServiceError::InvalidRequest(format!(
                    "a page holds 1 to {MAX_COMMANDS_PAGE}, not {limit}"
                )));
            }
        };
        self.gate
            .read(actor, "commands", &CLI_EXECUTE, &|tx| {
                Box::pin(async move {
                    let rows = sqlx::query!(
                        r#"SELECT id, command, state AS "state: CommandState", user_id, username,
                                  started_by AS "started_by!: serde_json::Value",
                                  timeout_seconds, exit_code, error, cancel_requested,
                                  cancelled_by AS "cancelled_by: serde_json::Value", created_at,
                                  started_at, deadline_at, finished_at
                           FROM queue.commands
                           WHERE $2::bigint IS NULL OR id < $2
                           ORDER BY id DESC
                           LIMIT $1"#,
                        limit + 1,
                        after,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let mut commands = Vec::with_capacity(rows.len());
                    for row in rows {
                        commands.push(run_of!(row));
                    }
                    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                    let next = if commands.len() > limit {
                        commands.truncate(limit);
                        commands.last().map(|run| run.id)
                    } else {
                        None
                    };
                    Ok(CommandPage { commands, next })
                })
            })
            .await
    }

    /// One run with its output so far, under `cli:execute`.
    pub async fn command(&self, actor: &Actor, id: i64) -> Result<CommandDetail, ServiceError> {
        self.gate
            .read(actor, "command", &CLI_EXECUTE, &|tx| {
                Box::pin(async move { detail_in(tx, id).await })
            })
            .await
    }
}
