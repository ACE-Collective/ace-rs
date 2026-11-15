//! `/api/monitoring/v1/state`: what the monitoring checks last found and how the scheduled tasks ran
//! (PLAN.md 7.12, `ace_service`'s `monitoring` docs). It needs `monitoring:read`. A record's value and a
//! run's error and summary are returned as they were stored: show them as text.

use ace_service::{MonitorRecord, MonitoringState, ScheduledRun, ScheduledTask};
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// The most runs one request returns.
pub(crate) const MAX_RUNS: i64 = 500;

/// A scheduled task's state.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ScheduledTaskBody {
    name: String,
    /// Its cron schedule, in UTC.
    schedule: String,
    due_at: DateTime<Utc>,
    /// A run holds it now.
    running: bool,
    /// How long ago it was due, when no run holds it.
    overdue_seconds: i64,
    /// How its last run that ended did: `succeeded`, `failed`, `timed_out`, `stopped` or `abandoned`.
    last_outcome: Option<String>,
    last_started_at: Option<DateTime<Utc>>,
    last_ended_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    /// The process that ran it: host and process id.
    last_node: Option<String>,
    /// How many runs have ended otherwise than `succeeded` since the last that did.
    failures_since_success: i64,
}

impl From<ScheduledTask> for ScheduledTaskBody {
    fn from(task: ScheduledTask) -> Self {
        ScheduledTaskBody {
            name: task.name,
            schedule: task.schedule,
            due_at: task.due_at,
            running: task.running,
            overdue_seconds: task.overdue_seconds,
            last_outcome: task.last_outcome,
            last_started_at: task.last_started_at,
            last_ended_at: task.last_ended_at,
            last_error: task.last_error,
            last_node: task.last_node,
            failures_since_success: task.failures_since_success,
        }
    }
}

/// A run of a scheduled task.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ScheduledRunBody {
    id: i64,
    task: String,
    /// The due time the run was claimed for.
    scheduled_for: DateTime<Utc>,
    node: String,
    started_at: DateTime<Utc>,
    /// Null while it runs.
    ended_at: Option<DateTime<Utc>>,
    outcome: Option<String>,
    error: Option<String>,
    /// What the task said it did.
    summary: Option<serde_json::Value>,
}

impl From<ScheduledRun> for ScheduledRunBody {
    fn from(run: ScheduledRun) -> Self {
        ScheduledRunBody {
            id: run.id,
            task: run.task,
            scheduled_for: run.scheduled_for,
            node: run.node,
            started_at: run.started_at,
            ended_at: run.ended_at,
            outcome: run.outcome,
            error: run.error,
            summary: run.summary,
        }
    }
}

/// A record a monitoring check last emitted.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MonitorRecordBody {
    /// The check: the scheduled task that emitted it.
    task: String,
    /// What it measures, such as `workload.distributed` or `cas.pool`.
    path: String,
    /// What it's about, when its check emits several, such as a pool's name.
    identifier: Option<String>,
    value: serde_json::Value,
    emitted_at: DateTime<Utc>,
}

impl From<MonitorRecord> for MonitorRecordBody {
    fn from(record: MonitorRecord) -> Self {
        MonitorRecordBody {
            task: record.task,
            path: record.path,
            identifier: record.identifier,
            value: record.value,
            emitted_at: record.emitted_at,
        }
    }
}

/// The scheduled tasks, their runs and the monitoring checks' records.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MonitoringStateBody {
    /// Every scheduled task, by name.
    tasks: Vec<ScheduledTaskBody>,
    /// The runs asked for, newest first.
    runs: Vec<ScheduledRunBody>,
    /// The records each check last emitted, by check.
    records: Vec<MonitorRecordBody>,
}

impl From<MonitoringState> for MonitoringStateBody {
    fn from(state: MonitoringState) -> Self {
        MonitoringStateBody {
            tasks: state.tasks.into_iter().map(Into::into).collect(),
            runs: state.runs.into_iter().map(Into::into).collect(),
            records: state.records.into_iter().map(Into::into).collect(),
        }
    }
}

fn default_runs() -> i64 {
    50
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct StateQuery {
    /// Only this task's runs.
    task: Option<String>,
    /// How many runs, newest first: 1 to 500.
    #[serde(default = "default_runs")]
    #[param(default = 50, minimum = 1, maximum = 500)]
    runs: i64,
}

/// Every scheduled task's state, the runs of all of them or of one, newest first, and the records the
/// monitoring checks last emitted.
#[utoipa::path(
    get,
    path = "/api/monitoring/v1/state",
    tag = "monitoring",
    params(StateQuery),
    responses(
        (status = 200, description = "The tasks, the runs and the records", body = MonitoringStateBody),
        (status = 400, description = "A count of runs outside 1 to 500, a task's name that isn't one, or a parameter that doesn't read", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold monitoring:read", body = ErrorBody),
    )
)]
pub(crate) async fn state(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<StateQuery>, QueryRejection>,
) -> Result<Json<MonitoringStateBody>, ApiError> {
    let Query(query) = query?;
    if !(1..=MAX_RUNS).contains(&query.runs) {
        return Err(ApiError::bad_request(format!(
            "runs is 1 to {MAX_RUNS}, not {}",
            query.runs
        )));
    }
    let task = query.task.as_deref().filter(|task| !task.is_empty());
    if let Some(task) = task
        && !task_name(task)
    {
        return Err(ApiError::bad_request(
            "a task's name is lowercase letters, digits and _",
        ));
    }
    let state = web
        .service
        .monitoring_state(&actor, task, query.runs)
        .await?;
    Ok(Json(MonitoringStateBody::from(state)))
}

/// Whether `name` could be a scheduled task's: lowercase letters, digits and `_`, at most 64.
pub(crate) fn task_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
