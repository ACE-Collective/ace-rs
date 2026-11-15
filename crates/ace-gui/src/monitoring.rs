//! Administration's Monitoring page (PLAN.md 7.12): what the monitoring checks last found and how the
//! scheduled tasks ran, over `Service::monitoring_state`.
//!
//! ace3 has no such page. Its `monitoring` service's records and its cron runs' outcomes go to
//! fluent-bit, and its GUI shows neither; 6.7 left `scheduler.runs` for this step to read. The area's
//! `admin:read` gates the route, as the rest of `crate::admin` does, and the service checks
//! `monitoring:read`. The hub shows the page's tile to whoever holds `monitoring:read`.
//!
//! `GET /admin/monitoring` is the page: every scheduled task with its schedule, when it's due, how its
//! last run ended and how many have failed since one succeeded, each a link to its runs; the runs,
//! newest first, of every task or of the one `?task=` names, 50 unless `?runs=` asks for up to 500; and
//! the records each check last emitted, its value as JSON text. The page has no form and writes nothing.
//! A record's value, a run's error and its summary are text other code wrote, some of it holding what
//! people typed, such as a module's or a pool's name: the template escapes each.

use ace_service::{ADMIN_READ, MonitorRecord, MonitoringState, ScheduledRun, ScheduledTask};
use askama::Template;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::Gui;
use crate::session::{Failure, SignedIn, render};
use crate::templates::Layout;

/// The page's path.
pub const PAGE: &str = "/admin/monitoring";
/// The runs the page lists unless it's asked for more.
pub const DEFAULT_RUNS: i64 = 50;
/// The most runs the page lists.
pub const MAX_RUNS: i64 = 500;
/// The most records the page draws; the rest are counted.
pub const MAX_RECORDS_SHOWN: usize = 1000;

/// A scheduled task, as the page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRow {
    pub name: String,
    /// The page with only this task's runs.
    pub href: String,
    pub schedule: String,
    pub due: String,
    pub running: bool,
    /// How far behind it is, when that is more than a minute: nothing has run it.
    pub overdue: Option<String>,
    pub last_outcome: String,
    /// The last run didn't succeed.
    pub last_failed: bool,
    pub last_ended: String,
    pub last_error: String,
    pub failures: i64,
}

/// A run, as the page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRow {
    pub task: String,
    pub scheduled_for: String,
    pub node: String,
    pub started: String,
    /// When it ended, or empty while it runs.
    pub ended: String,
    /// Its outcome, or `running`.
    pub outcome: String,
    pub failed: bool,
    pub error: String,
    /// What the task said it did, as JSON text.
    pub summary: String,
}

/// A monitor record, as the page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRow {
    pub task: String,
    pub path: String,
    pub identifier: String,
    /// The value, as JSON text.
    pub value: String,
    pub emitted: String,
}

/// What the page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitoringView {
    pub tasks: Vec<TaskRow>,
    /// The task whose runs are listed, or empty for every task's.
    pub selected_task: String,
    pub runs: Vec<RunRow>,
    pub records: Vec<RecordRow>,
    /// How many records aren't drawn.
    pub records_left_out: usize,
}

/// `/admin/monitoring`.
#[derive(Debug, Template)]
#[template(path = "admin/monitoring.html")]
pub struct MonitoringPage {
    pub layout: Layout,
    pub view: MonitoringView,
}

fn time(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

/// A length of time in its two largest units, such as `3h 12m`.
fn span(seconds: i64) -> String {
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3600,
        seconds % 3600 / 60,
    );
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {}s", seconds % 60)
    } else {
        format!("{seconds}s")
    }
}

fn task_row(task: ScheduledTask) -> TaskRow {
    let href = format!(
        "{PAGE}?{}",
        serde_urlencoded::to_string([("task", task.name.as_str())]).unwrap_or_default()
    );
    TaskRow {
        href,
        schedule: task.schedule,
        due: time(task.due_at),
        running: task.running,
        overdue: (task.overdue_seconds > 60).then(|| span(task.overdue_seconds)),
        last_failed: task
            .last_outcome
            .as_deref()
            .is_some_and(|outcome| outcome != "succeeded"),
        last_outcome: task.last_outcome.unwrap_or_default(),
        last_ended: task.last_ended_at.map(time).unwrap_or_default(),
        last_error: task.last_error.unwrap_or_default(),
        failures: task.failures_since_success,
        name: task.name,
    }
}

fn run_row(run: ScheduledRun) -> RunRow {
    RunRow {
        task: run.task,
        scheduled_for: time(run.scheduled_for),
        node: run.node,
        started: time(run.started_at),
        ended: run.ended_at.map(time).unwrap_or_default(),
        failed: run
            .outcome
            .as_deref()
            .is_some_and(|outcome| outcome != "succeeded"),
        outcome: run.outcome.unwrap_or_else(|| "running".to_owned()),
        error: run.error.unwrap_or_default(),
        summary: run.summary.map(|s| s.to_string()).unwrap_or_default(),
    }
}

fn record_row(record: MonitorRecord) -> RecordRow {
    RecordRow {
        task: record.task,
        path: record.path,
        identifier: record.identifier.unwrap_or_default(),
        value: record.value.to_string(),
        emitted: time(record.emitted_at),
    }
}

/// The page's view of the state, with `task`'s runs asked for.
pub fn monitoring_view(state: MonitoringState, task: Option<&str>) -> MonitoringView {
    let records_left_out = state.records.len().saturating_sub(MAX_RECORDS_SHOWN);
    MonitoringView {
        tasks: state.tasks.into_iter().map(task_row).collect(),
        selected_task: task.unwrap_or_default().to_owned(),
        runs: state.runs.into_iter().map(run_row).collect(),
        records: state
            .records
            .into_iter()
            .take(MAX_RECORDS_SHOWN)
            .map(record_row)
            .collect(),
        records_left_out,
    }
}

/// The page's query: anything that doesn't read takes its default.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageQuery {
    task: Option<String>,
    runs: Option<String>,
}

/// `GET /admin/monitoring`.
pub(crate) async fn page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    match gui.service.allowed(&viewer.actor, &ADMIN_READ).await {
        Ok(true) => {}
        Ok(false) => {
            return Failure::new(
                StatusCode::FORBIDDEN,
                "The administration area needs admin:read. Ask an administrator.",
                &parts,
            )
            .into_response();
        }
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    }
    let query = query.map(|Query(q)| q).unwrap_or_default();
    // a name that couldn't be a task's lists every task's runs
    let task = query.task.as_deref().filter(|task| {
        !task.is_empty()
            && task.len() <= 64
            && task
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    });
    let runs = query
        .runs
        .as_deref()
        .and_then(|runs| runs.parse::<i64>().ok())
        .map_or(DEFAULT_RUNS, |runs| runs.clamp(1, MAX_RUNS));
    match gui
        .service
        .monitoring_state(&viewer.actor, task, runs)
        .await
    {
        Ok(state) => render(&MonitoringPage {
            layout: viewer.layout,
            view: monitoring_view(state, task),
        }),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
