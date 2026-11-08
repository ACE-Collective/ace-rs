//! Administration's CLI (PLAN.md 5.12): ace3's `admin/cli.html`, `app/admin/views/cli.py` and
//! `admin_cli.js`, over the `commands` service.
//!
//! The area's `admin:read` gates every route, as the rest of `crate::admin` does, and the service checks
//! `cli:execute` on each read and write, as ace3's view and its `/api/v2/cli` routes do. The hub shows the
//! CLI's tile to whoever holds `cli:execute`, as ace3's hub does.
//!
//! ace3's page is a script: it posts to `/api/v2/cli/executions`, polls each run every 1.5 seconds and
//! fills the history from the API. Here:
//! - `GET /admin/cli` is the console: the form, and the history newest first, 25 a page, First and Next.
//! - `POST /admin/cli` starts a command (`Service::start_command`) from this site's own page only, and
//!   goes to the run's page. A line the service refuses draws the console again at 400 with what was typed.
//! - `GET /admin/cli/{id}` is a run: its state, who started it, its times and its output in a `<pre>`,
//!   escaped, since it's what a process wrote. While it runs, its output fragment polls
//!   `GET /admin/cli/{id}/output` every `REFRESH_SECONDS` while the tab is visible, with Datastar's
//!   `data-on-interval`, as the alert list refreshes (5.10), and the fragment Datastar morphs in has no
//!   interval once the run has ended. Its bounds are the list's: at most `REFRESH_LIMITS` at once in all
//!   and for one user, past which it's 503 and the page stays as it was, and each authenticates again, so
//!   a logout ends it. A command doesn't need the page: closing it, or the session, leaves the command to
//!   end at its deadline (`ace_pool::commands`).
//! - `POST /admin/cli/{id}/cancel` cancels it (`Service::cancel_command`), which ace3 has no control for.
//!
//! What differs, and why: ace3's node checkboxes, since one node runs here and any pool that runs
//! commands takes a run; its script's history "Load more", which is the Next link. Nothing else in ace3's
//! page is left out.

use ace_service::{ADMIN_READ, CommandDetail, CommandRun, CommandState, ServiceError};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::Gui;
use crate::list::{one, pairs};
use crate::session::{Failure, SignedIn, render, see_other};
use crate::templates::Layout;

/// How often an open run's page reads its output again, as ace3's 1.5-second poll, rounded up.
pub const REFRESH_SECONDS: u32 = 2;
/// How many output refreshes run at once, in all and for one user.
pub const REFRESH_LIMITS: (usize, usize) = (64, 4);
/// The history's page.
pub const HISTORY_PAGE: u32 = 25;

/// A run as the pages list it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRow {
    pub id: i64,
    pub href: String,
    pub command: String,
    pub state: &'static str,
    /// The state as the page says it, with the exit code once it has completed.
    pub status: String,
    pub username: String,
    pub created: String,
    pub started: String,
    pub deadline: String,
    pub finished: String,
    pub timeout_seconds: u32,
    pub error: Option<String>,
    pub cancel_requested: bool,
    pub cancelled_by: Option<String>,
    /// It hasn't ended, so it can be cancelled and its page polls.
    pub active: bool,
}

fn time(at: Option<chrono::DateTime<chrono::Utc>>) -> String {
    at.map(|at| at.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_default()
}

/// A run's row.
pub fn run_row(run: &CommandRun) -> RunRow {
    let state = run.state.as_str();
    let status = match (run.state, run.exit_code) {
        (CommandState::Completed, Some(code)) => format!("completed (exit {code})"),
        (CommandState::Running, _) if run.cancel_requested => "running, cancelling".to_owned(),
        (state, _) => state.as_str().replace('_', " "),
    };
    RunRow {
        id: run.id,
        href: format!("/admin/cli/{}", run.id),
        command: run.command.clone(),
        state,
        status,
        username: run.username.clone(),
        created: time(Some(run.created_at)),
        started: time(run.started_at),
        deadline: time(run.deadline_at),
        finished: time(run.finished_at),
        timeout_seconds: run.timeout_seconds,
        error: run.error.clone(),
        cancel_requested: run.cancel_requested,
        cancelled_by: run
            .cancelled_by
            .as_ref()
            .map(|actor| actor.name.clone().unwrap_or_else(|| actor.id.clone())),
        active: run.state.is_active(),
    }
}

/// `/admin/cli`.
#[derive(Debug, Template)]
#[template(path = "admin/cli.html")]
pub struct ConsolePage {
    pub layout: Layout,
    pub view: ConsoleView,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleView {
    /// The line as typed, when the form is drawn again.
    pub draft: String,
    pub timeout: String,
    pub problem: Option<String>,
    pub runs: Vec<RunRow>,
    /// The next page's link, and whether this is a later page.
    pub next: Option<String>,
    pub later: bool,
    pub default_timeout: u32,
    pub max_timeout: u32,
    pub max_chars: usize,
}

/// `/admin/cli/{id}`.
#[derive(Debug, Template)]
#[template(path = "admin/cli_run.html")]
pub struct RunPage {
    pub layout: Layout,
    pub run: RunView,
    pub problem: Option<String>,
}

/// `/admin/cli/{id}/output`: the run's state and output, which its page morphs in.
#[derive(Debug, Template)]
#[template(path = "admin/cli_output.html")]
pub struct RunFragment {
    pub run: RunView,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunView {
    pub row: RunRow,
    pub output: String,
    pub output_truncated: bool,
    /// The fragment's URL, for the poll.
    pub refresh: String,
    pub refresh_seconds: u32,
}

/// A run with its output.
pub fn run_view(detail: &CommandDetail) -> RunView {
    RunView {
        row: run_row(&detail.run),
        output: detail.output.clone(),
        output_truncated: detail.output_truncated,
        refresh: format!("/admin/cli/{}/output", detail.run.id),
        refresh_seconds: REFRESH_SECONDS,
    }
}

/// The console's history.
pub fn console_view(page: &ace_service::CommandPage, later: bool) -> ConsoleView {
    ConsoleView {
        draft: String::new(),
        timeout: ace_service::DEFAULT_COMMAND_TIMEOUT_SECONDS.to_string(),
        problem: None,
        runs: page.commands.iter().map(run_row).collect(),
        next: page.next.map(|after| format!("/admin/cli?after={after}")),
        later,
        default_timeout: ace_service::DEFAULT_COMMAND_TIMEOUT_SECONDS,
        max_timeout: ace_service::MAX_COMMAND_TIMEOUT_SECONDS,
        max_chars: ace_service::MAX_COMMAND_CHARS,
    }
}

async fn enter(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    match gui.service.allowed(&viewer.actor, &ADMIN_READ).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::new(
            StatusCode::FORBIDDEN,
            "The administration area needs admin:read. Ask an administrator.",
            parts,
        )),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsoleQuery {
    after: Option<i64>,
}

async fn console_with(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    after: Option<i64>,
    status: StatusCode,
    change: impl FnOnce(&mut ConsoleView),
) -> Response {
    let page = match gui
        .service
        .commands(&viewer.actor, Some(HISTORY_PAGE), after)
        .await
    {
        Ok(page) => page,
        Err(error) => return Failure::from_service(error, parts).into_response(),
    };
    let mut view = console_view(&page, after.is_some());
    change(&mut view);
    let mut response = render(&ConsolePage {
        layout: viewer.layout,
        view,
    });
    *response.status_mut() = status;
    response
}

/// `GET /admin/cli`.
pub(crate) async fn console(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    query: Result<Query<ConsoleQuery>, QueryRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Ok(Query(query)) = query else {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            "A page's cursor is a run's id.",
            &parts,
        )
        .into_response();
    };
    console_with(&gui, viewer, &parts, query.after, StatusCode::OK, |_| {}).await
}

/// `POST /admin/cli`: starts a command.
pub(crate) async fn start(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let line = one(&form, "command").unwrap_or("").to_owned();
    let timeout_text = one(&form, "timeout_seconds")
        .unwrap_or("")
        .trim()
        .to_owned();
    let timeout = if timeout_text.is_empty() {
        Ok(None)
    } else {
        timeout_text.parse::<u32>().map(Some)
    };
    let started = match timeout {
        Ok(timeout) => {
            gui.service
                .start_command(&viewer.actor, &line, timeout)
                .await
        }
        Err(_) => Err(ServiceError::InvalidRequest(format!(
            "a timeout is a number of seconds, 1 to {}",
            ace_service::MAX_COMMAND_TIMEOUT_SECONDS
        ))),
    };
    match started {
        Ok(detail) => see_other(&format!("/admin/cli/{}", detail.run.id), None),
        Err(ServiceError::InvalidRequest(why)) => {
            let problem = format!("Nothing ran: {why}.");
            console_with(
                &gui,
                viewer,
                &parts,
                None,
                StatusCode::BAD_REQUEST,
                |view| {
                    view.problem = Some(problem);
                    view.draft = line;
                    view.timeout = timeout_text;
                },
            )
            .await
        }
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// A run's id from its path, or None for one that isn't a number.
fn id_of(id: Result<Path<i64>, PathRejection>) -> Option<i64> {
    id.ok().map(|Path(id)| id)
}

fn bad_id(parts: &Parts) -> Response {
    Failure::new(StatusCode::BAD_REQUEST, "A run's id is a number.", parts).into_response()
}

/// `GET /admin/cli/{id}`.
pub(crate) async fn run_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<i64>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = id_of(id) else {
        return bad_id(&parts);
    };
    match gui.service.command(&viewer.actor, id).await {
        Ok(detail) => render(&RunPage {
            layout: viewer.layout,
            run: run_view(&detail),
            problem: None,
        }),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// `GET /admin/cli/{id}/output`: the run's fragment, for its page's poll.
pub(crate) async fn output(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<i64>, PathRejection>,
) -> Response {
    let Some(_place) = gui.cli_refreshes.admit(&viewer.actor) else {
        tracing::warn!(actor = %viewer.actor, "a run's refresh was refused: too many are running");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match gui.service.allowed(&viewer.actor, &ADMIN_READ).await {
        Ok(true) => {}
        Ok(false) => return StatusCode::FORBIDDEN.into_response(),
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    }
    let Ok(Path(id)) = id else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match gui.service.command(&viewer.actor, id).await {
        Ok(detail) => render(&RunFragment {
            run: run_view(&detail),
        }),
        Err(ServiceError::PermissionDenied { .. }) => StatusCode::FORBIDDEN.into_response(),
        Err(ServiceError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            tracing::error!("a run's refresh failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `POST /admin/cli/{id}/cancel`.
pub(crate) async fn cancel(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<i64>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = id_of(id) else {
        return bad_id(&parts);
    };
    match gui.service.cancel_command(&viewer.actor, id).await {
        Ok(_) => see_other(&format!("/admin/cli/{id}"), None),
        Err(ServiceError::Conflict(why)) => match gui.service.command(&viewer.actor, id).await {
            Ok(detail) => {
                let mut response = render(&RunPage {
                    layout: viewer.layout,
                    run: run_view(&detail),
                    problem: Some(format!("Nothing was cancelled: {why}.")),
                });
                *response.status_mut() = StatusCode::CONFLICT;
                response
            }
            Err(error) => Failure::from_service(error, &parts).into_response(),
        },
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
