//! `/api/svs/v1/runs` and `/api/svs/v1/test-hosts`: SVS test runs' launcher calls and the test hosts with
//! their maintenance windows (PLAN.md 7.10 batch 5, part 5a), ace3's `aceapi_v2/svs/runs` and
//! `aceapi_v2/svs/test_hosts` routers, over `ace_service`'s `svs_runs` and `svs`. A launcher's key holds
//! `svs:run_register`; reading needs `svs:run_read`; the test hosts' writes need `svs:admin`.
//!
//! From ace3: a refused parameter or registration that can't be accepted as sent is 400 where ace3 answers
//! 422; a failure's body is `{"error": ...}`, so a busy host's holders and a conflict's state are in its
//! text, where ace3's detail is an object; and a run's detail doesn't yet carry its review's blockers,
//! which batch 7b brings. Part 5b's reads are `svs_run_reads`: the runs' list, feeds, exports, results,
//! history and comments. The test hosts page by name with `changed_since`, export, and take `If-Match` on
//! a change. Batch 6 brought a run's attributions and batch 7a association (`svs_association`); batch 7b
//! brings a run's alerts, a person's bulk actions and review.

use ace_core::svs::hosts::HostFields;
use ace_service::{
    HostHolder, MAX_MAINTENANCE_PAGE, MAX_RUN_EVENTS_PAGE, MaintenanceWindow, Registration,
    RegistrationDecision, Run, RunDetail, RunEvent, RunValidation, TargetSpec, TestHost,
};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::params::Params;

/// The longest error and output a launcher may report, as ace3's schema has them.
const MAX_ERROR_CHARS: usize = 8192;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// A host and user to run the test on.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunTargetRequest {
    /// A test host's short or fully qualified name.
    hostname: String,
    /// The user the test runs as: required when the test host lists its users.
    #[serde(default)]
    username: Option<String>,
}

/// A run to register.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunRegistrationBody {
    /// The `auto_generated_guid` of a test in the catalog (`/api/svs/v1/tests`).
    test_guid: String,
    /// The test hosts the test runs on.
    targets: Vec<RunTargetRequest>,
    /// The name of the launcher registering the run, 1 to 256 characters.
    launcher: String,
    /// A label shared by runs registered together, 1 to 256 characters.
    #[serde(default)]
    batch_id: Option<String>,
    /// Anything else the launcher wants kept with the run: an object, at most `svs.runs.max_extra_bytes`
    /// as JSON.
    #[serde(default)]
    #[schema(value_type = Object)]
    extra: Option<Value>,
}

impl RunRegistrationBody {
    fn into_registration(self) -> Result<Registration, ApiError> {
        let sized = |what: &str, value: &str| {
            if value.is_empty() || value.chars().count() > 256 {
                return Err(ApiError::bad_request(format!(
                    "{what} must be 1 to 256 characters"
                )));
            }
            Ok(())
        };
        sized("launcher", &self.launcher)?;
        if let Some(batch) = &self.batch_id {
            sized("batch_id", batch)?;
        }
        Ok(Registration {
            test_guid: self.test_guid,
            targets: self
                .targets
                .into_iter()
                .map(|target| TargetSpec {
                    hostname: target.hostname,
                    username: target.username,
                })
                .collect(),
            launcher: self.launcher,
            batch_id: self.batch_id,
            extra: self
                .extra
                .unwrap_or_else(|| Value::Object(Default::default())),
        })
    }
}

/// How the test executed.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunExecutedBody {
    /// The test's exit code; anything but 0 moves the run to error.
    exit_code: i32,
    /// What went wrong, when the launcher knows; it moves the run to error. At most 8192 characters.
    #[serde(default)]
    error: Option<String>,
    /// What the test printed (stdout and stderr), at most 4 MiB; kept up to 64 KiB, longer output as its
    /// start and its last 16 KiB around a marker.
    #[serde(default)]
    output: Option<String>,
}

/// A host and user a run targets.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunTargetBody {
    /// As registered.
    pub(crate) hostname: String,
    pub(crate) username: Option<String>,
    /// The short host name, lower case.
    host: String,
    fqdn: Option<String>,
    /// The bare user name, lower case.
    user: Option<String>,
}

impl From<ace_service::RunTarget> for RunTargetBody {
    fn from(target: ace_service::RunTarget) -> Self {
        RunTargetBody {
            hostname: target.hostname,
            username: target.username,
            host: target.host,
            fqdn: target.fqdn,
            user: target.user,
        }
    }
}

/// A run as the launcher's calls return it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunLifecycleBody {
    /// The run's uuid.
    run_id: Uuid,
    /// Put this where the test's process telemetry shows it.
    marker: String,
    /// `created`, `started`, `ended`, `reviewed`, `canceled`, `error` or `closed`.
    state: String,
    test_guid: Uuid,
    /// The platform the run is on, an ATT&CK platform slug: its targets' test hosts' platform, else the
    /// test's only supported platform.
    platform: String,
    targets: Vec<RunTargetBody>,
    /// How long after start the run waits for its alerts before it ends.
    observation_seconds: i32,
    /// How long after start its alerts are still attributed to it.
    attribution_seconds: i32,
    /// The run holds its hosts until its attribution window ends, not its observation window.
    holds_host: bool,
    /// What the registration warned of: that no hunter had recorded its hunts yet, so the observation
    /// window is the floor and not the hunts' latency. Empty when there was nothing to warn of.
    warnings: Vec<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    /// When the launcher said the test's cleanup began.
    cleanup_at: Option<DateTime<Utc>>,
    observation_ends_at: Option<DateTime<Utc>>,
    attribution_ends_at: Option<DateTime<Utc>>,
    error_reason: Option<String>,
    close_reason: Option<String>,
}

impl From<Run> for RunLifecycleBody {
    fn from(run: Run) -> Self {
        RunLifecycleBody {
            run_id: run.uuid,
            marker: run.marker,
            state: run.state.as_str().to_owned(),
            test_guid: run.test_guid,
            platform: run.platform,
            targets: run.targets.into_iter().map(Into::into).collect(),
            observation_seconds: run.observation_seconds,
            attribution_seconds: run.attribution_seconds,
            holds_host: run.holds_host,
            warnings: run.warnings,
            created_at: run.created_at,
            started_at: run.started_at,
            cleanup_at: run.cleanup_at,
            observation_ends_at: run.observation_ends_at,
            attribution_ends_at: run.attribution_ends_at,
            error_reason: run.error_reason,
            close_reason: run.close_reason,
        }
    }
}

/// One run, whole.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunDetailBody {
    #[serde(flatten)]
    run: RunLifecycleBody,
    launcher: String,
    batch_id: Option<String>,
    /// What the launcher sent to be kept with the run.
    #[schema(value_type = Object)]
    extra: Value,
    registered_by: Option<ActorBody>,
    /// The test's content hash and its repository's commit, as they were at registration.
    test_content_hash: String,
    catalog_commit: String,
    executed_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    launcher_error: Option<String>,
    /// What the test printed, as kept.
    launcher_output: Option<String>,
    ended_at: Option<DateTime<Utc>>,
    /// Why a person ended it before its observation window passed.
    end_reason: Option<String>,
    canceled_at: Option<DateTime<Utc>>,
    closed_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    /// What the runs screen shows of it, and its log search.
    #[serde(flatten)]
    seen: crate::svs_run_reads::RunDetailSeenBody,
}

impl RunDetailBody {
    fn of(detail: RunDetail, seen: crate::svs_run_reads::RunDetailSeenBody) -> Self {
        let run = detail.run;
        RunDetailBody {
            seen,
            launcher: run.launcher.clone(),
            batch_id: run.batch_id.clone(),
            extra: run.extra.clone(),
            registered_by: run.registered_by.clone().map(ActorBody::from),
            test_content_hash: run.test_content_hash.clone(),
            catalog_commit: run.catalog_commit.clone(),
            executed_at: run.executed_at,
            exit_code: run.exit_code,
            launcher_error: run.launcher_error.clone(),
            launcher_output: detail.launcher_output,
            ended_at: run.ended_at,
            end_reason: run.end_reason.clone(),
            canceled_at: run.canceled_at,
            closed_at: run.closed_at,
            updated_at: run.updated_at,
            run: run.into(),
        }
    }
}

/// A run or a maintenance window holding a test host.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HostHolderBody {
    /// The test host, by its short name.
    host: String,
    /// The run holding it; null for a maintenance window.
    run_id: Option<Uuid>,
    /// The run's state, or `maintenance`.
    state: String,
    /// When its claim on the host ends; null while a run hasn't started.
    until: Option<DateTime<Utc>>,
    /// The maintenance window holding it.
    maintenance_id: Option<Uuid>,
}

impl From<HostHolder> for HostHolderBody {
    fn from(holder: HostHolder) -> Self {
        HostHolderBody {
            host: holder.host,
            run_id: holder.run,
            state: holder.state,
            until: holder.until,
            maintenance_id: holder.maintenance,
        }
    }
}

/// A target of a registration, judged as registering would.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ValidatedTargetBody {
    /// As sent.
    hostname: String,
    username: Option<String>,
    /// The target is a test host and a user it lists.
    accepted: bool,
    /// Why the target would be refused.
    reason: Option<String>,
    /// The test host it names, by its short name, and that host's platform.
    test_host: Option<String>,
    platform: Option<String>,
    /// What holds that test host.
    held_by: Vec<HostHolderBody>,
}

/// What registering the same body would decide, decided without changing anything.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunValidationBody {
    /// `accepted`, `refused`, `invalid` or `host_busy`.
    decision: String,
    /// What registering would answer: 201, 403, 409 or 400.
    status_code: u16,
    /// Why the registration is invalid.
    message: Option<String>,
    /// Every target; empty when the registration is invalid before its targets are judged.
    targets: Vec<ValidatedTargetBody>,
    /// When accepted: the platform the run would be on, its windows, where its observation window comes
    /// from (`override`, `expected` or `all_hunts`) and whether it would hold its hosts until its
    /// attribution window ends.
    platform: Option<String>,
    observation_seconds: Option<i64>,
    observation_source: Option<String>,
    attribution_seconds: Option<i64>,
    holds_host: Option<bool>,
    /// What registering would warn of: that no hunter has recorded its hunts yet, so the observation
    /// window would be the floor and not the hunts' latency. Empty when there is nothing to warn of.
    warnings: Vec<String>,
}

impl From<RunValidation> for RunValidationBody {
    fn from(v: RunValidation) -> Self {
        RunValidationBody {
            status_code: match v.decision {
                RegistrationDecision::Accepted => 201,
                RegistrationDecision::Refused => 403,
                RegistrationDecision::HostBusy => 409,
                RegistrationDecision::Invalid => 400,
            },
            decision: match v.decision {
                RegistrationDecision::Accepted => "accepted",
                RegistrationDecision::Refused => "refused",
                RegistrationDecision::HostBusy => "host_busy",
                RegistrationDecision::Invalid => "invalid",
            }
            .to_owned(),
            message: v.message,
            targets: v
                .targets
                .into_iter()
                .map(|target| ValidatedTargetBody {
                    hostname: target.hostname,
                    username: target.username,
                    accepted: target.accepted,
                    reason: target.reason,
                    test_host: target.test_host,
                    platform: target.platform,
                    held_by: target.held_by.into_iter().map(Into::into).collect(),
                })
                .collect(),
            platform: v.platform,
            observation_seconds: v.observation_seconds,
            observation_source: v.observation_source.map(|s| s.as_str().to_owned()),
            attribution_seconds: v.attribution_seconds,
            holds_host: v.holds_host,
            warnings: v.warnings,
        }
    }
}

/// One row of a run's event log.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunEventBody {
    id: i64,
    /// `registered`, `transition`, `launcher_call` and the kinds later parts write.
    kind: String,
    from_state: Option<String>,
    to_state: Option<String>,
    actor: Option<ActorBody>,
    /// A registration's request, a transition's reason, or a launcher call's name, outcome and payload.
    #[schema(value_type = Option<Object>)]
    details: Option<Value>,
    created_at: DateTime<Utc>,
}

impl From<RunEvent> for RunEventBody {
    fn from(event: RunEvent) -> Self {
        RunEventBody {
            id: event.id,
            kind: event.kind,
            from_state: event.from_state.map(|state| state.as_str().to_owned()),
            to_state: event.to_state.map(|state| state.as_str().to_owned()),
            actor: event.actor.map(ActorBody::from),
            details: event.details,
            created_at: event.created_at,
        }
    }
}

/// A page of a run's events, oldest first.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunEventPageBody {
    events: Vec<RunEventBody>,
    /// Pass it as `after` for the next page; null on the last.
    next: Option<i64>,
}

/// A page of a run's events.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct RunEventsQuery {
    /// The `next` of the page before.
    after: Option<i64>,
    /// At most this many, 1 to 1000; 100 when left out.
    limit: Option<i64>,
}

/// A test host's fields.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestHostRequest {
    /// The short or fully qualified host name; a fully qualified one sets the fqdn too.
    hostname: String,
    #[serde(default)]
    fqdn: Option<String>,
    /// The users runs may use, in any of `CORP\alice`, `alice@corp.example` or `alice`; none means any.
    #[serde(default)]
    usernames: Vec<String>,
    /// The host's addresses.
    #[serde(default)]
    ips: Vec<String>,
    /// `windows`, `linux` or `macos`, when known.
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    notes: Option<String>,
}

impl From<TestHostRequest> for HostFields {
    fn from(body: TestHostRequest) -> Self {
        HostFields {
            hostname: body.hostname,
            fqdn: body.fqdn,
            usernames: body.usernames,
            ips: body.ips,
            platform: body.platform,
            notes: body.notes,
        }
    }
}

/// A host test runs may target.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TestHostBody {
    id: i64,
    /// The short host name, lower case.
    hostname: String,
    fqdn: Option<String>,
    /// The bare user names runs may use, lower case and sorted; none means any user.
    usernames: Vec<String>,
    ips: Vec<String>,
    platform: Option<String>,
    notes: Option<String>,
    created_by: Option<ActorBody>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<TestHost> for TestHostBody {
    fn from(host: TestHost) -> Self {
        TestHostBody {
            id: host.id,
            hostname: host.hostname,
            fqdn: host.fqdn,
            usernames: host.usernames,
            ips: host.ips,
            platform: host.platform,
            notes: host.notes,
            created_by: host.created_by.map(ActorBody::from),
            created_at: host.created_at,
            updated_at: host.updated_at,
        }
    }
}

/// A maintenance window to open.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MaintenanceRequest {
    /// How long the window lasts unless it's ended sooner, 1 to `svs.runs.max_maintenance_minutes`.
    minutes: i64,
    /// Why, such as what is being staged.
    reason: String,
}

/// A maintenance window on a test host.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MaintenanceWindowBody {
    /// The window's uuid.
    maintenance_id: Uuid,
    /// Its place in the host's windows: the `before` of a page.
    id: i64,
    /// The test host's id; null once the host is removed.
    test_host_id: Option<i64>,
    host: String,
    fqdn: Option<String>,
    reason: String,
    opened_by: Option<ActorBody>,
    opened_at: DateTime<Utc>,
    /// When it ends unless it's ended sooner.
    ends_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    ended_by: Option<ActorBody>,
    /// `ended` or `expired`.
    end_reason: Option<String>,
}

impl From<MaintenanceWindow> for MaintenanceWindowBody {
    fn from(window: MaintenanceWindow) -> Self {
        MaintenanceWindowBody {
            maintenance_id: window.uuid,
            id: window.id,
            test_host_id: window.test_host_id,
            host: window.host,
            fqdn: window.fqdn,
            reason: window.reason,
            opened_by: window.opened_by.map(ActorBody::from),
            opened_at: window.opened_at,
            ends_at: window.ends_at,
            ended_at: window.ended_at,
            ended_by: window.ended_by.map(ActorBody::from),
            end_reason: window.end_reason,
        }
    }
}

/// A page of a test host's maintenance windows, latest first.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MaintenancePageBody {
    windows: Vec<MaintenanceWindowBody>,
    /// Pass it as `before` for the next page; null on the last.
    next: Option<i64>,
}

/// A page of a test host's maintenance windows.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct MaintenanceQuery {
    /// The `next` of the page before.
    before: Option<i64>,
    /// At most this many, 1 to 1000; 100 when left out.
    limit: Option<i64>,
}

fn run_id(path: Result<Path<String>, PathRejection>) -> Result<Uuid, ApiError> {
    let Path(text) = path?;
    text.parse()
        .map_err(|_| ApiError::bad_request(format!("{text:?} isn't a run's uuid")))
}

fn host_id(path: Result<Path<String>, PathRejection>) -> Result<i64, ApiError> {
    let Path(text) = path?;
    text.parse()
        .map_err(|_| ApiError::bad_request(format!("{text:?} isn't a test host's id")))
}

/// `limit`, 100 when it's left out, and at most `most`.
fn page_limit(params: &Params, most: i64) -> Result<i64, ApiError> {
    let limit = params.parsed::<i64>("limit", "a number")?.unwrap_or(100);
    if !(1..=most).contains(&limit) {
        return Err(ApiError::bad_request(format!(
            "limit is from 1 to {most}, not {limit}"
        )));
    }
    Ok(limit)
}

/// Registers a run in state created and gives its marker. A target that isn't a test host, or not a user
/// its host lists, is refused, which also alerts, once an hour for each caller and host.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs",
    tag = "svs",
    request_body = RunRegistrationBody,
    responses(
        (status = 201, description = "The run, created", body = RunLifecycleBody),
        (status = 400, description = "A body that isn't one, a test that isn't in the catalog, a target whose platform the test doesn't support, or an extra that is too large", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_register, or a target isn't a test host or a user its host lists", body = ErrorBody),
        (status = 409, description = "Another run or a maintenance window holds a target's test host", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn register(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<RunRegistrationBody>, JsonRejection>,
) -> Result<(StatusCode, Json<RunLifecycleBody>), ApiError> {
    let Json(body) = body?;
    let registration = body.into_registration()?;
    let run = web
        .service
        .register_svs_run(&actor, &registration, Utc::now())
        .await?;
    Ok((StatusCode::CREATED, Json(run.into())))
}

/// What registering this body would decide: accepted, with the run's platform and windows, refused, with
/// the reason for each target, invalid, or a host that is busy. It creates no run, event, refusal or alert,
/// so a launcher's dry run is invisible to triage.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/validate",
    tag = "svs",
    request_body = RunRegistrationBody,
    responses(
        (status = 200, description = "The decision", body = RunValidationBody),
        (status = 400, description = "A body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_register", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn validate(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<RunRegistrationBody>, JsonRejection>,
) -> Result<Json<RunValidationBody>, ApiError> {
    let Json(body) = body?;
    let registration = body.into_registration()?;
    let validation = web
        .service
        .validate_svs_run(&actor, &registration, Utc::now())
        .await?;
    Ok(Json(validation.into()))
}

/// One run, with what its launcher sent, what its test printed, and what the runs screen shows of it: its
/// test's name, who owns and reviewed it, whether it needs attention, and its result's and alerts' summary.
/// Its history is `GET .../events`.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid")),
    responses(
        (status = 200, description = "The run", body = RunDetailBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
    )
)]
pub(crate) async fn detail(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<RunDetailBody>, ApiError> {
    let uuid = run_id(path)?;
    let detail = web.service.svs_run(&actor, uuid).await?;
    let row = web.service.svs_run_row(&actor, uuid).await?;
    let log_search_url = web.service.svs_run_log_search_url(&detail.run, Utc::now());
    let seen = crate::svs_run_reads::RunDetailSeenBody::of(&row, log_search_url);
    Ok(Json(RunDetailBody::of(detail, seen)))
}

/// A run's event log, oldest first: its registration, each change of state with its reason, and each of
/// its launcher's calls with its outcome, a call that didn't apply included.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/events",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid"), RunEventsQuery),
    responses(
        (status = 200, description = "A page of events", body = RunEventPageBody),
        (status = 400, description = "An id that isn't a uuid, or a parameter that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
    )
)]
pub(crate) async fn events(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<RunEventPageBody>, ApiError> {
    let uuid = run_id(path)?;
    let params = Params::of(raw)?;
    let after = params.parsed::<i64>("after", "a number")?;
    let limit = page_limit(&params, MAX_RUN_EVENTS_PAGE)?;
    let events = web
        .service
        .svs_run_events(&actor, uuid, after, Some(limit))
        .await?;
    let next = (events.len() as i64 == limit)
        .then(|| events.last().map(|event| event.id))
        .flatten();
    Ok(Json(RunEventPageBody {
        events: events.into_iter().map(Into::into).collect(),
        next,
    }))
}

/// Created to started: the windows start now, at the whole second.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/start",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid")),
    responses(
        (status = 200, description = "The run, started", body = RunLifecycleBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_register", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 409, description = "The run isn't created, or another run or a maintenance window holds one of its hosts; the call is in its event log", body = ErrorBody),
    )
)]
pub(crate) async fn start(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<RunLifecycleBody>, ApiError> {
    let uuid = run_id(path)?;
    let run = web.service.start_svs_run(&actor, uuid, Utc::now()).await?;
    Ok(Json(run.into()))
}

/// Reports how the test executed on a started run. A non-zero exit code or an error moves it to error.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/executed",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid")),
    request_body = RunExecutedBody,
    responses(
        (status = 200, description = "The run", body = RunLifecycleBody),
        (status = 400, description = "An id that isn't a uuid, a body that isn't one, or an error or output that is too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_register", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 409, description = "The run isn't started; the call is in its event log", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn executed(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<RunExecutedBody>, JsonRejection>,
) -> Result<Json<RunLifecycleBody>, ApiError> {
    let uuid = run_id(path)?;
    let Json(body) = body?;
    if body
        .error
        .as_ref()
        .is_some_and(|error| error.chars().count() > MAX_ERROR_CHARS)
    {
        return Err(ApiError::bad_request(format!(
            "error is at most {MAX_ERROR_CHARS} characters"
        )));
    }
    if body
        .output
        .as_ref()
        .is_some_and(|output| output.len() > MAX_OUTPUT_BYTES)
    {
        return Err(ApiError::bad_request(format!(
            "output is at most {MAX_OUTPUT_BYTES} bytes"
        )));
    }
    let run = web
        .service
        .svs_run_executed(
            &actor,
            uuid,
            body.exit_code,
            body.error.as_deref(),
            body.output.as_deref(),
            Utc::now(),
        )
        .await?;
    Ok(Json(run.into()))
}

/// The test's cleanup begins now, on a started run: detections whose event time is at or after it are the
/// cleanup's. Once per run.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/cleanup",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid")),
    responses(
        (status = 200, description = "The run", body = RunLifecycleBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_register", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 409, description = "The run isn't started, or its cleanup already began; the call is in its event log", body = ErrorBody),
    )
)]
pub(crate) async fn cleanup(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<RunLifecycleBody>, ApiError> {
    let uuid = run_id(path)?;
    let run = web
        .service
        .svs_run_cleanup(&actor, uuid, Utc::now())
        .await?;
    Ok(Json(run.into()))
}

/// Created or started to canceled. A canceled run keeps attributing until its attribution window ends; one
/// canceled before it started is closed at once.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/cancel",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid")),
    responses(
        (status = 200, description = "The run", body = RunLifecycleBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_register", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 409, description = "The run is neither created nor started; the call is in its event log", body = ErrorBody),
    )
)]
pub(crate) async fn cancel(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<RunLifecycleBody>, ApiError> {
    let uuid = run_id(path)?;
    let run = web.service.cancel_svs_run(&actor, uuid, Utc::now()).await?;
    Ok(Json(run.into()))
}

/// A page of test hosts.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TestHostPageBody {
    hosts: Vec<TestHostBody>,
    /// Pass it as `cursor` for the next page; null on the last.
    next: Option<String>,
}

/// The test hosts' list's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct TestHostsQuery {
    /// Only test hosts added or changed at or after this time.
    changed_since: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// An export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct TestHostsExportQuery {
    /// Only test hosts added or changed at or after this time.
    changed_since: Option<String>,
}

impl crate::export::ExportRow for TestHostBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "hostname",
        "fqdn",
        "usernames",
        "ips",
        "platform",
        "notes",
        "created_by",
        "created_at",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.hostname.clone(),
            self.fqdn.clone().unwrap_or_default(),
            // joined with ",", as ace3's CSV writes them
            self.usernames.join(","),
            self.ips.join(","),
            self.platform.clone().unwrap_or_default(),
            self.notes.clone().unwrap_or_default(),
            self.created_by
                .as_ref()
                .map(ActorBody::shown)
                .unwrap_or_default(),
            crate::export::time_cell(Some(self.created_at)),
            crate::export::time_cell(Some(self.updated_at)),
        ]
    }
}

/// The test hosts, by host name, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/test-hosts",
    tag = "svs",
    params(TestHostsQuery),
    responses(
        (status = 200, description = "A page of test hosts", body = TestHostPageBody),
        (status = 400, description = "A time, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn test_hosts(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<TestHostPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let page = web
        .service
        .test_hosts_page(
            &actor,
            params.time("changed_since")?,
            params.one("cursor")?,
            params.parsed("limit", "a number from 1 to 1000")?,
        )
        .await?;
    Ok(Json(TestHostPageBody {
        hosts: page.hosts.into_iter().map(Into::into).collect(),
        next: page.next_cursor,
    }))
}

/// Every test host, by host name, as CSV (usernames and ips joined with `,`) or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/test-hosts/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), TestHostsExportQuery),
    responses(
        (status = 200, description = "The test hosts, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format or time that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More test hosts than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_test_hosts(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<axum::response::Response, ApiError> {
    use crate::export::EXPORT_PAGE;
    let Path(format) = path?;
    let format = crate::svs_run_reads::format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let changed_since = Params::of(raw)?.time("changed_since")?;
    let total = service
        .svs_feed_count(&actor, &ace_service::SvsFeed::TestHosts(changed_since), max)
        .await?;
    let first = service
        .test_hosts_page(&actor, changed_since, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.hosts.into_iter().map(TestHostBody::from).collect(),
        first.next_cursor,
    );
    crate::export::respond(
        format,
        "svs-test-hosts",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor) = (service.clone(), actor.clone());
            async move {
                let page = service
                    .test_hosts_page(&actor, changed_since, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.hosts.into_iter().map(TestHostBody::from).collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// Adds a test host.
#[utoipa::path(
    post,
    path = "/api/svs/v1/test-hosts",
    tag = "svs",
    request_body = TestHostRequest,
    responses(
        (status = 201, description = "The test host", body = TestHostBody),
        (status = 400, description = "A body that isn't one, or a field that can't be used", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:admin", body = ErrorBody),
        (status = 409, description = "Its short name is already a test host", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn create_test_host(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<TestHostRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<TestHostBody>), ApiError> {
    let Json(body) = body?;
    let host = web.service.create_test_host(&actor, &body.into()).await?;
    Ok((StatusCode::CREATED, Json(host.into())))
}

/// One test host.
#[utoipa::path(
    get,
    path = "/api/svs/v1/test-hosts/{host}",
    tag = "svs",
    params(("host" = i64, Path, description = "The test host's id")),
    responses(
        (status = 200, description = "The test host", body = TestHostBody),
        (status = 400, description = "An id that isn't a number", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No test host with that id", body = ErrorBody),
    )
)]
pub(crate) async fn test_host(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<TestHostBody>, ApiError> {
    let id = host_id(path)?;
    Ok(Json(web.service.test_host(&actor, id).await?.into()))
}

/// Replaces a test host's fields. With `If-Match`, the host's `updated_at` as it was last read, the change
/// applies only while the host is unchanged since.
#[utoipa::path(
    put,
    path = "/api/svs/v1/test-hosts/{host}",
    tag = "svs",
    params(
        ("host" = i64, Path, description = "The test host's id"),
        ("If-Match" = Option<String>, Header, description = "The host's updated_at as last read"),
    ),
    request_body = TestHostRequest,
    responses(
        (status = 200, description = "The test host", body = TestHostBody),
        (status = 400, description = "An id that isn't a number, a body that isn't one, or a field that can't be used", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:admin", body = ErrorBody),
        (status = 404, description = "No test host with that id", body = ErrorBody),
        (status = 409, description = "Its new short name is already a test host", body = ErrorBody),
        (status = 412, description = "The host changed since the `If-Match` it was read with; read it again", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn update_test_host(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    headers: axum::http::HeaderMap,
    body: Result<Json<TestHostRequest>, JsonRejection>,
) -> Result<Json<TestHostBody>, ApiError> {
    let id = host_id(path)?;
    let precondition = crate::svs_decisions::precondition(&headers)?;
    let Json(body) = body?;
    let host = web
        .service
        .update_test_host(&actor, id, &body.into(), precondition)
        .await?;
    Ok(Json(host.into()))
}

/// Removes a test host. Runs already registered keep their targets, and its open maintenance window ends.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/test-hosts/{host}",
    tag = "svs",
    params(("host" = i64, Path, description = "The test host's id")),
    responses(
        (status = 204, description = "Removed"),
        (status = 400, description = "An id that isn't a number", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:admin", body = ErrorBody),
        (status = 404, description = "No test host with that id", body = ErrorBody),
    )
)]
pub(crate) async fn delete_test_host(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let id = host_id(path)?;
    web.service.delete_test_host(&actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Opens a maintenance window on the test host, which is named by its id or its short or fully qualified
/// name. A name that isn't a test host's is refused, which also alerts.
#[utoipa::path(
    post,
    path = "/api/svs/v1/test-hosts/{host}/maintenance",
    tag = "svs",
    params(("host" = String, Path, description = "The test host's id, or its short or fully qualified name")),
    request_body = MaintenanceRequest,
    responses(
        (status = 201, description = "The window", body = MaintenanceWindowBody),
        (status = 400, description = "A body that isn't one, no reason, or minutes out of range", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_register, or the host isn't a test host", body = ErrorBody),
        (status = 404, description = "No test host with that id", body = ErrorBody),
        (status = 409, description = "A run or another window holds the host", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn open_maintenance(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<MaintenanceRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<MaintenanceWindowBody>), ApiError> {
    let Path(host) = path?;
    let Json(body) = body?;
    let window = web
        .service
        .open_svs_maintenance(&actor, &host, body.minutes, &body.reason, Utc::now())
        .await?;
    Ok((StatusCode::CREATED, Json(window.into())))
}

/// Ends the test host's open maintenance window now.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/test-hosts/{host}/maintenance",
    tag = "svs",
    params(("host" = String, Path, description = "The test host's id, or its short or fully qualified name")),
    responses(
        (status = 200, description = "The window, ended", body = MaintenanceWindowBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_register, or the host isn't a test host", body = ErrorBody),
        (status = 404, description = "No test host with that id, or the host has no open window", body = ErrorBody),
    )
)]
pub(crate) async fn end_maintenance(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<MaintenanceWindowBody>, ApiError> {
    let Path(host) = path?;
    let window = web
        .service
        .end_svs_maintenance(&actor, &host, Utc::now())
        .await?;
    Ok(Json(window.into()))
}

/// The test host's maintenance windows, latest first.
#[utoipa::path(
    get,
    path = "/api/svs/v1/test-hosts/{host}/maintenance",
    tag = "svs",
    params(
        ("host" = String, Path, description = "The test host's id, or its short or fully qualified name"),
        MaintenanceQuery,
    ),
    responses(
        (status = 200, description = "A page of windows", body = MaintenancePageBody),
        (status = 400, description = "A parameter that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No test host with that id, or a name that isn't a host name", body = ErrorBody),
    )
)]
pub(crate) async fn list_maintenance(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<MaintenancePageBody>, ApiError> {
    let Path(host) = path?;
    let params = Params::of(raw)?;
    let before = params.parsed::<i64>("before", "a number")?;
    let limit = page_limit(&params, MAX_MAINTENANCE_PAGE)?;
    let windows = web
        .service
        .svs_maintenance_windows(&actor, &host, limit, before)
        .await?;
    let next = (windows.len() as i64 == limit)
        .then(|| windows.last().map(|window| window.id))
        .flatten();
    Ok(Json(MaintenancePageBody {
        windows: windows.into_iter().map(Into::into).collect(),
        next,
    }))
}
