//! A person's actions on SVS test runs, and a run's alerts (PLAN.md 7.10 batch 7b): the rest of ace3's
//! `aceapi_v2/svs/runs` router, over `ace_service`'s `svs_review` and `svs_run_reads`.
//!
//! | ace3 (`aceapi_v2/svs/runs`) | ace-rs |
//! |---|---|
//! | `POST /bulk/take-ownership` | `POST /api/svs/v1/runs/bulk/take-ownership` |
//! | `POST /bulk/cancel` | `POST /api/svs/v1/runs/bulk/cancel` |
//! | `POST /bulk/end` | `POST /api/svs/v1/runs/bulk/end` |
//! | `POST /bulk/close` | `POST /api/svs/v1/runs/bulk/close` |
//! | `POST /{run_id}/review` | `POST /api/svs/v1/runs/{run_id}/review` |
//! | `GET /{run_id}/alerts?cursor=&limit=` | `GET /api/svs/v1/runs/{run_id}/alerts?after=&limit=` |
//! | `GET /{run_id}/alerts/export/ndjson` | `GET /api/svs/v1/runs/{run_id}/alerts/export/{format}` |
//! | `GET /{run_id}`'s `review_blockers` | the same field of `GET /api/svs/v1/runs/{run_id}` |
//!
//! The actions need `svs:run_manage`, the reads `svs:run_read`, as ace3's. What differs: a refused body or
//! id is 400 where ace3 answers 422; a review takes a JSON body, `{}` when there's nothing to confirm,
//! where ace3 lets it be left out; a review that can't go through is 409 with `error` and, beside it, what
//! stands in the way (`owner`, `state`, or `stale`, `candidates` and `context_alerts`), where ace3 nests
//! them under `detail`; a run's alerts page by `after`, as its results do, and export as CSV too, with
//! each alert's detections as one JSON cell; a detection is its id, not a content hash; and an alert's
//! row is never null, since an attribution goes with its alert. A key that belongs to nobody is refused
//! with 400, as ace3 refuses it with 422: these actions record the person who took them.

use std::collections::BTreeMap;

use ace_service::{BulkResult, ReviewBlockers, ReviewOutcome, RunAlert, SvsFeed};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Web;
use crate::alerts::AlertBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow};
use crate::params::Params;
use crate::svs_run_reads::{
    RunAttributionBody, RunResultsQuery, after_limit, cell, format_of, uuid_of,
};
use crate::svs_runs::RunDetailBody;

/// What a review would be refused for right now.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ReviewBlockersBody {
    /// The result is being recomputed, or was never computed.
    stale: bool,
    /// The undecided signatures' uuids.
    candidates: Vec<String>,
    /// The alerts with context attributions neither kept nor marked not a test.
    context_alerts: Vec<Uuid>,
}

impl From<ReviewBlockers> for ReviewBlockersBody {
    fn from(blockers: ReviewBlockers) -> Self {
        ReviewBlockersBody {
            stale: blockers.stale,
            candidates: blockers.candidates,
            context_alerts: blockers.context_alerts,
        }
    }
}

/// A bulk action on runs, as the runs screen sends it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BulkRunRequest {
    /// The runs' uuids, from 1 to 500.
    run_ids: Vec<String>,
    /// Run uuid to the username of the person the caller agreed to take the run from; a run someone
    /// else owns is left alone without it.
    #[serde(default)]
    confirmed_takes: BTreeMap<String, String>,
    /// End and close only: why, at most 4096 characters. Required to end a run, and to close an ended
    /// run, which waits for a review.
    #[serde(default)]
    reason: Option<String>,
}

/// What a bulk action did to each run.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct BulkRunBody {
    /// The runs the action was applied to.
    done: Vec<Uuid>,
    /// Run uuid to the username of whoever owns it, for the runs someone else owns. Sent back as
    /// `confirmed_takes`, it takes them.
    left_alone: BTreeMap<String, String>,
    /// Run uuid to why the action doesn't apply to it: its state, or a missing reason.
    conflicts: BTreeMap<String, String>,
    /// Run uuids that don't exist.
    unknown: Vec<Uuid>,
}

impl From<BulkResult> for BulkRunBody {
    fn from(result: BulkResult) -> Self {
        let keyed = |map: BTreeMap<Uuid, String>| {
            map.into_iter()
                .map(|(run, text)| (run.to_string(), text))
                .collect()
        };
        BulkRunBody {
            done: result.done,
            left_alone: keyed(result.left_alone),
            conflicts: keyed(result.conflicts),
            unknown: result.unknown,
        }
    }
}

/// A bulk request's runs and confirmations, each id a uuid.
type Bulk = (Vec<Uuid>, BTreeMap<Uuid, String>, Option<String>);

fn bulk_of(body: Result<Json<BulkRunRequest>, JsonRejection>) -> Result<Bulk, ApiError> {
    let Json(body) = body?;
    let runs = body
        .run_ids
        .iter()
        .map(|run| uuid_of(run))
        .collect::<Result<Vec<_>, _>>()?;
    let mut confirmed = BTreeMap::new();
    for (run, owner) in body.confirmed_takes {
        confirmed.insert(uuid_of(&run)?, owner);
    }
    Ok((runs, confirmed, body.reason))
}

/// Makes the caller the owner of the runs. A run someone else owns is left alone, and named in
/// `left_alone`, unless `confirmed_takes` names its owner.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/bulk/take-ownership",
    tag = "svs",
    request_body = BulkRunRequest,
    responses(
        (status = 200, description = "What it did to each run", body = BulkRunBody),
        (status = 400, description = "A body that isn't one, no runs or too many, an id that isn't a uuid, or a key that belongs to nobody", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn take_ownership(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<BulkRunRequest>, JsonRejection>,
) -> Result<Json<BulkRunBody>, ApiError> {
    let (runs, confirmed, _) = bulk_of(body)?;
    let result = web
        .service
        .take_svs_runs(&actor, &runs, &confirmed, Utc::now())
        .await?;
    Ok(Json(result.into()))
}

/// Cancels the runs, as their launcher would: created or started to canceled, and one canceled before it
/// started is closed at once. A run in any other state is in `conflicts`.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/bulk/cancel",
    tag = "svs",
    request_body = BulkRunRequest,
    responses(
        (status = 200, description = "What it did to each run", body = BulkRunBody),
        (status = 400, description = "A body that isn't one, no runs or too many, an id that isn't a uuid, or a key that belongs to nobody", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn cancel_runs(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<BulkRunRequest>, JsonRejection>,
) -> Result<Json<BulkRunBody>, ApiError> {
    let (runs, confirmed, _) = bulk_of(body)?;
    let result = web
        .service
        .cancel_svs_runs(&actor, &runs, &confirmed, Utc::now())
        .await?;
    Ok(Json(result.into()))
}

/// Ends the started runs now, before their observation windows pass, so they can be reviewed. It needs
/// `reason`: without it each run is in `conflicts`.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/bulk/end",
    tag = "svs",
    request_body = BulkRunRequest,
    responses(
        (status = 200, description = "What it did to each run", body = BulkRunBody),
        (status = 400, description = "A body that isn't one, no runs or too many, an id that isn't a uuid, a reason that is too long, or a key that belongs to nobody", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn end_runs(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<BulkRunRequest>, JsonRejection>,
) -> Result<Json<BulkRunBody>, ApiError> {
    let (runs, confirmed, reason) = bulk_of(body)?;
    let result = web
        .service
        .end_svs_runs(&actor, &runs, reason.as_deref(), &confirmed, Utc::now())
        .await?;
    Ok(Json(result.into()))
}

/// Closes the ended, canceled or failed runs: nothing is learned from them, and their alerts become
/// SIMULATED. An ended run needs `reason`, since it waited for a review.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/bulk/close",
    tag = "svs",
    request_body = BulkRunRequest,
    responses(
        (status = 200, description = "What it did to each run", body = BulkRunBody),
        (status = 400, description = "A body that isn't one, no runs or too many, an id that isn't a uuid, a reason that is too long, or a key that belongs to nobody", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn close_runs(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<BulkRunRequest>, JsonRejection>,
) -> Result<Json<BulkRunBody>, ApiError> {
    let (runs, confirmed, reason) = bulk_of(body)?;
    let result = web
        .service
        .close_svs_runs(&actor, &runs, reason.as_deref(), &confirmed, Utc::now())
        .await?;
    Ok(Json(result.into()))
}

/// A review's body.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewRequest {
    /// The username of the run's owner the caller agreed to take it from, when someone else owns it.
    #[serde(default)]
    confirmed_take_from: Option<String>,
}

/// A review that went through.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ReviewBody {
    run: RunDetailBody,
    /// The run had been reviewed before; this sign-off replaces that one.
    re_review: bool,
    /// Signatures per result status, as signed off.
    counts: BTreeMap<String, i64>,
    /// Alerts that became SIMULATED.
    alerts_closed: usize,
    /// Detections of ignored signatures given an FP verdict.
    fp_verdicts: usize,
}

/// Why a review didn't go through: `error`, and what stands in the way.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ReviewRefusedBody {
    /// What went wrong, for a person to read.
    error: String,
    /// Someone else owns the run: their username. Send it as `confirmed_take_from` to take it.
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    /// The run's state, when it is neither ended nor reviewed.
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    /// The result is being recomputed, or was never computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    stale: Option<bool>,
    /// The undecided signatures' uuids.
    #[serde(skip_serializing_if = "Option::is_none")]
    candidates: Option<Vec<String>>,
    /// The alerts with context attributions neither kept nor marked not a test.
    #[serde(skip_serializing_if = "Option::is_none")]
    context_alerts: Option<Vec<Uuid>>,
}

impl ReviewRefusedBody {
    fn new(error: String) -> Self {
        ReviewRefusedBody {
            error,
            owner: None,
            state: None,
            stale: None,
            candidates: None,
            context_alerts: None,
        }
    }
}

/// Signs the run's result off: an ended run becomes reviewed, and a reviewed run is reviewed again. Its
/// fully attributed open alerts nobody has taken become SIMULATED, and the detections of signatures
/// ignored for its test get an FP verdict. It needs the result to be current, every candidate decided and
/// every context-only alert kept or marked not a test: `GET /api/svs/v1/runs/{run_id}`'s
/// `review_blockers` says what's missing.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/review",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid")),
    request_body = ReviewRequest,
    responses(
        (status = 200, description = "The run as reviewed, and what the review did", body = ReviewBody),
        (status = 400, description = "An id that isn't a uuid, a body that isn't one, or a key that belongs to nobody", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 409, description = "Someone else owns the run, it is neither ended nor reviewed, or something blocks the review", body = ReviewRefusedBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn review(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<ReviewRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Path(run) = path?;
    let uuid = uuid_of(&run)?;
    let Json(body) = body?;
    let outcome = web
        .service
        .review_svs_run(
            &actor,
            uuid,
            body.confirmed_take_from.as_deref(),
            Utc::now(),
        )
        .await?;
    let refused = match outcome {
        ReviewOutcome::Reviewed(reviewed) => {
            let run = crate::svs_runs::run_detail(&web, &actor, uuid).await?;
            return Ok(Json(ReviewBody {
                run,
                re_review: reviewed.re_review,
                counts: reviewed.counts,
                alerts_closed: reviewed.alerts_closed,
                fp_verdicts: reviewed.fp_verdicts,
            })
            .into_response());
        }
        ReviewOutcome::Owned { owner } => ReviewRefusedBody {
            owner: Some(owner.clone()),
            ..ReviewRefusedBody::new(format!(
                "run {uuid} is owned by {owner}: confirm taking it from them"
            ))
        },
        ReviewOutcome::State(state) => ReviewRefusedBody {
            state: Some(state.as_str().to_owned()),
            ..ReviewRefusedBody::new(format!("run {uuid} is {state}; review does not apply"))
        },
        ReviewOutcome::Blocked(blockers) => ReviewRefusedBody {
            error: blockers.message(uuid),
            owner: None,
            state: None,
            stale: Some(blockers.stale),
            candidates: Some(blockers.candidates),
            context_alerts: Some(blockers.context_alerts),
        },
    };
    Ok((StatusCode::CONFLICT, Json(refused)).into_response())
}

/// One detection of an alert the run holds or held, and its attribution to the run.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunAlertDetectionBody {
    /// The detection's id, as the alert's detections list it.
    detection: i64,
    /// As its module wrote it. Show it as text.
    description: String,
    signature_uuid: Option<String>,
    signature_family: Option<String>,
    /// Its attribution to this run, removed or not; null when it never had one.
    attribution: Option<RunAttributionBody>,
}

/// An alert attributed to the run, now or before.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunAlertBody {
    alert_uuid: Uuid,
    /// The alert as `GET /api/alerts/v1/alerts` lists it, with its SVS status over every run.
    alert: AlertBody,
    /// Some attribution of it to the run holds.
    holds: bool,
    /// Of those that hold: `marker` when any is (a person's association is `marker`), else `context`.
    confidence: Option<String>,
    /// An attribution that holds is late.
    late: bool,
    /// Every attribution that holds is the test's cleanup's.
    cleanup: bool,
    /// An attribution that holds was judged by a fallback event time.
    fallback_time: bool,
    /// An attribution that holds was made by a person.
    manual: bool,
    /// A person kept its context attributions.
    kept: bool,
    /// It has a context attribution that holds and nobody kept: a review waits for keep or not-a-test.
    undecided_context: bool,
    /// Every detection of the alert.
    detections: Vec<RunAlertDetectionBody>,
}

impl From<RunAlert> for RunAlertBody {
    fn from(row: RunAlert) -> Self {
        RunAlertBody {
            alert_uuid: row.alert.id,
            alert: row.alert.into(),
            holds: row.holds,
            confidence: row
                .confidence
                .map(|confidence| confidence.as_str().to_owned()),
            late: row.late,
            cleanup: row.cleanup,
            fallback_time: row.fallback_time,
            manual: row.manual,
            kept: row.kept,
            undecided_context: row.undecided_context,
            detections: row
                .detections
                .into_iter()
                .map(|detection| RunAlertDetectionBody {
                    detection: detection.detection,
                    description: detection.description,
                    signature_uuid: detection.signature_uuid,
                    signature_family: detection.signature_family,
                    attribution: detection.attribution.map(Into::into),
                })
                .collect(),
        }
    }
}

impl ExportRow for RunAlertBody {
    const HEADER: &'static [&'static str] = &[
        "alert_uuid",
        "title",
        "disposition",
        "queue",
        "svs_status",
        "holds",
        "confidence",
        "late",
        "cleanup",
        "fallback_time",
        "manual",
        "kept",
        "undecided_context",
        "detections",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.alert_uuid.to_string(),
            self.alert.title.clone(),
            cell(&self.alert.disposition),
            self.alert.queue.clone(),
            cell(&self.alert.svs_status),
            self.holds.to_string(),
            cell(&self.confidence),
            self.late.to_string(),
            self.cleanup.to_string(),
            self.fallback_time.to_string(),
            self.manual.to_string(),
            self.kept.to_string(),
            self.undecided_context.to_string(),
            serde_json::to_string(&self.detections).unwrap_or_default(),
        ]
    }
}

/// A page of a run's alerts.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunAlertPageBody {
    alerts: Vec<RunAlertBody>,
    /// Pass it as `after` for the next page; null on the last.
    next: Option<i64>,
}

/// The alerts the run holds or held, in the order they were first attributed to it, each with every
/// detection it has and that detection's attribution to the run, removed ones included.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/alerts",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid"), RunResultsQuery),
    responses(
        (status = 200, description = "A page of the run's alerts", body = RunAlertPageBody),
        (status = 400, description = "An id that isn't a uuid, or a parameter that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
    )
)]
pub(crate) async fn run_alerts(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<RunAlertPageBody>, ApiError> {
    let Path(run) = path?;
    let uuid = uuid_of(&run)?;
    let (after, limit) = after_limit(&Params::of(raw)?)?;
    let page = web
        .service
        .svs_run_alerts(&actor, uuid, after, Some(limit))
        .await?;
    Ok(Json(RunAlertPageBody {
        alerts: page.alerts.into_iter().map(Into::into).collect(),
        next: page.next,
    }))
}

/// A run's alerts, as CSV (each alert's detections as one JSON cell) or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/alerts/export/{format}",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("format" = String, Path, description = "`csv` or `ndjson`"),
    ),
    responses(
        (status = 200, description = "The alerts, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "An id that isn't a uuid, or a format that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 413, description = "More alerts than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_run_alerts(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((run, format)) = path?;
    let (uuid, format) = (uuid_of(&run)?, format_of(&format)?);
    let (service, max) = (web.service, web.config.max_export_rows);
    let total = service
        .svs_feed_count(&actor, &SvsFeed::RunAlerts(uuid), max)
        .await?;
    let page = i64::from(EXPORT_PAGE);
    let rows = |page: ace_service::RunAlertPage| {
        (
            page.alerts
                .into_iter()
                .map(RunAlertBody::from)
                .collect::<Vec<_>>(),
            page.next,
        )
    };
    let first = rows(
        service
            .svs_run_alerts(&actor, uuid, None, Some(page))
            .await?,
    );
    export::respond(
        format,
        &format!("svs-run-{uuid}-alerts"),
        max,
        total,
        first,
        move |after: i64| {
            let (service, actor) = (service.clone(), actor.clone());
            async move {
                Ok(rows(
                    service
                        .svs_run_alerts(&actor, uuid, Some(after), Some(page))
                        .await?,
                ))
            }
        },
    )
}
