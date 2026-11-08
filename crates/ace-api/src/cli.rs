//! `/api/cli/v1`: the commands analysts run from the GUI (PLAN.md 5.12), started, followed and cancelled.

use ace_service::{CommandDetail, CommandRun};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// One run of a command, without its output.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommandBody {
    id: i64,
    /// The words after `ace`, quoted as a shell would take them.
    command: String,
    /// `queued`, `running`, `completed`, `timed_out`, `cancelled`, `failed` or `abandoned`.
    state: String,
    /// Who it runs for; null once that user is deleted, and `username` stays.
    user_id: Option<Uuid>,
    username: String,
    /// The actor that started it.
    started_by: ActorBody,
    timeout_seconds: u32,
    /// How it exited, once it has completed.
    exit_code: Option<i32>,
    /// Why it didn't complete. It can quote what the command wrote: show it as text.
    error: Option<String>,
    cancel_requested: bool,
    cancelled_by: Option<ActorBody>,
    created_at: DateTime<Utc>,
    /// When a pool took it.
    started_at: Option<DateTime<Utc>>,
    /// When its pool kills it, if it's still running then: `started_at` plus its timeout.
    deadline_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
}

impl From<CommandRun> for CommandBody {
    fn from(run: CommandRun) -> Self {
        CommandBody {
            id: run.id,
            command: run.command,
            state: run.state.as_str().to_owned(),
            user_id: run.user.map(|user| user.0),
            username: run.username,
            started_by: ActorBody::from(run.started_by),
            timeout_seconds: run.timeout_seconds,
            exit_code: run.exit_code,
            error: run.error,
            cancel_requested: run.cancel_requested,
            cancelled_by: run.cancelled_by.map(ActorBody::from),
            created_at: run.created_at,
            started_at: run.started_at,
            deadline_at: run.deadline_at,
            finished_at: run.finished_at,
        }
    }
}

/// One run with what it has written so far.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommandDetailBody {
    #[serde(flatten)]
    run: CommandBody,
    /// Its stdout and stderr, interleaved, up to 1 MiB, with NUL as U+FFFD. Show it as text.
    output: String,
    /// It wrote more than the 1 MiB kept.
    output_truncated: bool,
}

impl From<CommandDetail> for CommandDetailBody {
    fn from(detail: CommandDetail) -> Self {
        CommandDetailBody {
            run: CommandBody::from(detail.run),
            output: detail.output,
            output_truncated: detail.output_truncated,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommandPageBody {
    commands: Vec<CommandBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewCommandRequest {
    /// The command line after `ace`, such as `--help`; a leading `ace` is dropped. It splits as a
    /// shell would, and can't start with an option but `-h`, `--help`, `-V` or `--version`.
    command: String,
    /// How long it may run once a pool takes it, 1 to 3600 seconds; 300 when left out.
    timeout_seconds: Option<u32>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CommandsQuery {
    /// How many, 1 to 200; 50 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

/// Starts `ace <command>` for a parser pool to run, contained, with no paths, ports or credentials, until
/// it exits or its deadline: when a pool takes it, plus its timeout. Closing the session that started it
/// doesn't stop it. Follow it at `GET /api/cli/v1/commands/{id}`.
#[utoipa::path(
    post,
    path = "/api/cli/v1/commands",
    tag = "cli",
    request_body = NewCommandRequest,
    responses(
        (status = 202, description = "The command, queued for a pool", body = CommandDetailBody),
        (status = 400, description = "A command line that's empty, doesn't split, starts with an option or is too long, a timeout out of range, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold cli:execute, isn't a person (an API key with no owner), or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn start(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<NewCommandRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CommandDetailBody>), ApiError> {
    let Json(body) = body?;
    let detail = web
        .service
        .start_command(&actor, &body.command, body.timeout_seconds)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(CommandDetailBody::from(detail))))
}

/// Every run, newest first, without its output, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/cli/v1/commands",
    tag = "cli",
    params(CommandsQuery),
    responses(
        (status = 200, description = "A page of runs", body = CommandPageBody),
        (status = 400, description = "A limit out of range, or a cursor that isn't a number", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold cli:execute", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<CommandsQuery>, QueryRejection>,
) -> Result<Json<CommandPageBody>, ApiError> {
    let Query(query) = query?;
    let page = web
        .service
        .commands(&actor, query.limit, query.after)
        .await?;
    Ok(Json(CommandPageBody {
        commands: page.commands.into_iter().map(CommandBody::from).collect(),
        next: page.next,
    }))
}

/// One run, with its output so far.
#[utoipa::path(
    get,
    path = "/api/cli/v1/commands/{id}",
    tag = "cli",
    params(("id" = i64, Path, description = "The run's id")),
    responses(
        (status = 200, description = "The run", body = CommandDetailBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold cli:execute", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<CommandDetailBody>, ApiError> {
    let Path(id) = id?;
    let detail = web.service.command(&actor, id).await?;
    Ok(Json(CommandDetailBody::from(detail)))
}

/// Cancels a run: a queued one ends at once, and a running one's pool kills it within a few seconds,
/// when it next reports. Cancelling a run that was asked to stop already changes nothing.
#[utoipa::path(
    post,
    path = "/api/cli/v1/commands/{id}/cancel",
    tag = "cli",
    params(("id" = i64, Path, description = "The run's id")),
    responses(
        (status = 200, description = "The run as it is now", body = CommandDetailBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold cli:execute, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 409, description = "The run has ended", body = ErrorBody),
    )
)]
pub(crate) async fn cancel(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<CommandDetailBody>, ApiError> {
    let Path(id) = id?;
    let detail = web.service.cancel_command(&actor, id).await?;
    Ok(Json(CommandDetailBody::from(detail)))
}
