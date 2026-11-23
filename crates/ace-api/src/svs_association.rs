//! SVS's association routes (PLAN.md 7.10 batch 7a): what SVS makes of an alert, and a person's changes
//! to which alerts belong to a test run, over `ace_service`'s `svs_association`.
//!
//! | ace3 (`aceapi_v2/svs`) | ace-rs |
//! |---|---|
//! | `GET /alerts/{alert_uuid}/svs` | `GET /api/alerts/v1/alerts/{id}/svs` |
//! | `POST /alerts/{alert_uuid}/svs/disassociate` | `POST /api/alerts/v1/alerts/{id}/svs/disassociate` |
//! | `POST /alerts/{alert_uuid}/svs/not-a-test` | `POST /api/alerts/v1/alerts/{id}/svs/not-a-test` |
//! | `POST /runs/{run_id}/alerts/{alert_uuid}/associate` | `POST /api/svs/v1/runs/{run_id}/alerts/{uuid}/associate` |
//! | `POST /runs/{run_id}/alerts/{alert_uuid}/disassociate` | `POST /api/svs/v1/runs/{run_id}/alerts/{uuid}/disassociate` |
//! | `POST /runs/{run_id}/alerts/{alert_uuid}/not-a-test` | `POST /api/svs/v1/runs/{run_id}/alerts/{uuid}/not-a-test` |
//! | `POST /runs/{run_id}/alerts/{alert_uuid}/keep` | `POST /api/svs/v1/runs/{run_id}/alerts/{uuid}/keep` |
//!
//! The alert's routes need `alert:read` and `alert:write`, the run's `svs:run_manage`, as ace3's. What
//! differs: an alert with no SVS status answers `status: null` with empty lists where ace3 answers the same
//! shape; a detection is named by its id, not a content hash; associate and disassociate take a JSON body,
//! `{}` for no reason, where ace3 lets the body be left out; and a key that belongs to nobody is an actor
//! here and may make these changes, where ace3 refuses a config key.

use std::collections::BTreeMap;

use ace_core::svs::{RunState, SvsStatus};
use ace_service::{AlertRelease, Association, AssociationResult};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// A run, as an alert names it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertRunBody {
    uuid: Uuid,
    #[schema(value_type = String)]
    state: RunState,
    test_guid: Uuid,
    /// The catalog's name of the test; null when the catalog no longer has it.
    test_name: Option<String>,
}

/// A marker in the alert that doesn't agree with its run.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MarkerMismatchBody {
    marker: String,
    /// How it disagrees: `unknown`, `other host` or `outside window`.
    result: String,
    /// The run the marker belongs to; null when no run has it.
    run: Option<AlertRunBody>,
}

/// What SVS makes of an alert.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertSvsBody {
    /// `test`, `test?`, `partial` or `mismatch`; null when SVS never touched the alert.
    #[schema(value_type = Option<String>)]
    status: Option<SvsStatus>,
    /// The runs whose attributions of the alert hold, oldest first.
    runs: Vec<AlertRunBody>,
    /// Each attributed detection's id, and the uuids of the runs it's attributed to.
    detections: BTreeMap<String, Vec<Uuid>>,
    mismatches: Vec<MarkerMismatchBody>,
}

fn run_body(run: ace_service::RunRef) -> AlertRunBody {
    AlertRunBody {
        uuid: run.uuid,
        state: run.state,
        test_guid: run.test_guid,
        test_name: run.test_name,
    }
}

/// What SVS makes of an alert: its status, the runs it's attributed to, which detections each holds, and
/// the markers that disagree with their run.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/svs",
    tag = "svs",
    params(("id" = Uuid, Path, description = "The alert's id")),
    responses(
        (status = 200, description = "What SVS makes of it", body = AlertSvsBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn alert_svs(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<AlertSvsBody>, ApiError> {
    let Path(id) = id?;
    let view = web.service.alert_svs_view(&actor, id).await?;
    Ok(Json(match view {
        None => AlertSvsBody {
            status: None,
            runs: Vec::new(),
            detections: BTreeMap::new(),
            mismatches: Vec::new(),
        },
        Some(view) => AlertSvsBody {
            status: Some(view.status),
            runs: view.runs.into_iter().map(run_body).collect(),
            detections: view
                .detections
                .into_iter()
                .map(|(detection, runs)| (detection.to_string(), runs))
                .collect(),
            mismatches: view
                .mismatches
                .into_iter()
                .map(|mismatch| MarkerMismatchBody {
                    marker: mismatch.marker,
                    result: mismatch.result,
                    run: mismatch.run.map(run_body),
                })
                .collect(),
        },
    }))
}

/// Why a person makes the change, for the run's event log.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReasonRequest {
    /// At most 512 characters.
    #[serde(default)]
    reason: Option<String>,
}

/// What releasing an alert left.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertDisassociationBody {
    alert_uuid: Uuid,
    /// The runs the alert was disassociated from, oldest first.
    runs: Vec<Uuid>,
    /// The alert's SVS status after the change; null when it has none.
    #[schema(value_type = Option<String>)]
    svs_status: Option<SvsStatus>,
    queue: String,
    /// The alert moved to another queue.
    moved: bool,
    /// The alert was SIMULATED and is OPEN again.
    reopened: bool,
}

impl From<AlertRelease> for AlertDisassociationBody {
    fn from(release: AlertRelease) -> Self {
        AlertDisassociationBody {
            alert_uuid: release.alert,
            runs: release.runs,
            svs_status: release.svs_status,
            queue: release.queue,
            moved: release.moved,
            reopened: release.reopened,
        }
    }
}

/// Disassociates the alert from every test run that holds it, so it's given back to analysts: OPEN if it
/// was SIMULATED, and in the queue SVS took it from. The core never attributes it to those runs again.
#[utoipa::path(
    post,
    path = "/api/alerts/v1/alerts/{id}/svs/disassociate",
    tag = "svs",
    params(("id" = Uuid, Path, description = "The alert's id")),
    request_body = ReasonRequest,
    responses(
        (status = 200, description = "What it left", body = AlertDisassociationBody),
        (status = 400, description = "An id that isn't a uuid, a body that isn't one, or a reason that is too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
        (status = 409, description = "No test run holds the alert", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn release_alert(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<ReasonRequest>, JsonRejection>,
) -> Result<Json<AlertDisassociationBody>, ApiError> {
    let Path(id) = id?;
    let Json(body) = body?;
    let release = web
        .service
        .release_alert_from_svs(&actor, id, body.reason.as_deref(), false, Utc::now())
        .await?;
    Ok(Json(release.into()))
}

/// Marks a `test?` alert, which its runs hold by context alone, not a test: it's disassociated from them.
#[utoipa::path(
    post,
    path = "/api/alerts/v1/alerts/{id}/svs/not-a-test",
    tag = "svs",
    params(("id" = Uuid, Path, description = "The alert's id")),
    responses(
        (status = 200, description = "What it left", body = AlertDisassociationBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
        (status = 409, description = "No test run holds the alert, or one holds it by more than context", body = ErrorBody),
    )
)]
pub(crate) async fn alert_not_a_test(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<AlertDisassociationBody>, ApiError> {
    let Path(id) = id?;
    let release = web
        .service
        .release_alert_from_svs(&actor, id, None, true, Utc::now())
        .await?;
    Ok(Json(release.into()))
}

/// What a change to a run's hold on an alert left.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AssociationBody {
    alert_uuid: Uuid,
    /// The alert's SVS status after the change; null when it has none.
    #[schema(value_type = Option<String>)]
    svs_status: Option<SvsStatus>,
    queue: String,
    /// The alert moved to another queue.
    moved: bool,
    /// The alert was SIMULATED and is OPEN again.
    reopened: bool,
}

impl From<AssociationResult> for AssociationBody {
    fn from(result: AssociationResult) -> Self {
        AssociationBody {
            alert_uuid: result.alert,
            svs_status: result.svs_status,
            queue: result.queue,
            moved: result.moved,
            reopened: result.reopened,
        }
    }
}

fn run_and_alert(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(Uuid, Uuid), ApiError> {
    let Path((run, alert)) = path?;
    let run = run
        .parse()
        .map_err(|_| ApiError::bad_request(format!("{run:?} isn't a run's uuid")))?;
    let alert = alert
        .parse()
        .map_err(|_| ApiError::bad_request(format!("{alert:?} isn't an alert's uuid")))?;
    Ok((run, alert))
}

async fn change(
    web: &Web,
    actor: &ace_service::Actor,
    path: Result<Path<(String, String)>, PathRejection>,
    change: Association,
) -> Result<Json<AssociationBody>, ApiError> {
    let (run, alert) = run_and_alert(path)?;
    let result = web
        .service
        .change_svs_association(actor, run, alert, &change, Utc::now())
        .await?;
    Ok(Json(result.into()))
}

/// Attributes every detection of the alert to the run, by hand, as certain as a marker that agrees, and
/// moves the alert to the test queue when it's then fully attributed, open and nobody else's.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/alerts/{uuid}/associate",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("uuid" = String, Path, description = "The alert's id"),
    ),
    request_body = ReasonRequest,
    responses(
        (status = 200, description = "What it left", body = AssociationBody),
        (status = 400, description = "An id that isn't a uuid, a body that isn't one, a reason that is too long, or an alert with no detections", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such run, or no such alert", body = ErrorBody),
        (status = 409, description = "The run never started", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn associate(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<Json<ReasonRequest>, JsonRejection>,
) -> Result<Json<AssociationBody>, ApiError> {
    let Json(body) = body?;
    change(
        &web,
        &actor,
        path,
        Association::Associate {
            reason: body.reason,
        },
    )
    .await
}

/// Removes the alert's attributions to the run, by hand: the core never attributes the alert to the run
/// again, and an alert no longer fully attributed is given back to analysts.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/alerts/{uuid}/disassociate",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("uuid" = String, Path, description = "The alert's id"),
    ),
    request_body = ReasonRequest,
    responses(
        (status = 200, description = "What it left", body = AssociationBody),
        (status = 400, description = "An id that isn't a uuid, a body that isn't one, or a reason that is too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such run, or no such alert", body = ErrorBody),
        (status = 409, description = "The alert isn't attributed to the run", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn disassociate(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<Json<ReasonRequest>, JsonRejection>,
) -> Result<Json<AssociationBody>, ApiError> {
    let Json(body) = body?;
    change(
        &web,
        &actor,
        path,
        Association::Disassociate {
            reason: body.reason,
            not_a_test: false,
        },
    )
    .await
}

/// Marks an alert the run holds by context alone not a test: a disassociation.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/alerts/{uuid}/not-a-test",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("uuid" = String, Path, description = "The alert's id"),
    ),
    responses(
        (status = 200, description = "What it left", body = AssociationBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such run, or no such alert", body = ErrorBody),
        (status = 409, description = "The alert isn't attributed to the run, or by more than context", body = ErrorBody),
    )
)]
pub(crate) async fn not_a_test(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<AssociationBody>, ApiError> {
    change(
        &web,
        &actor,
        path,
        Association::Disassociate {
            reason: None,
            not_a_test: true,
        },
    )
    .await
}

/// Confirms the alert's context attributions to the run: it is the run's. A run's review asks for it.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/alerts/{uuid}/keep",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("uuid" = String, Path, description = "The alert's id"),
    ),
    responses(
        (status = 200, description = "What it left", body = AssociationBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such run, or no such alert", body = ErrorBody),
        (status = 409, description = "The alert has no context attribution to the run to keep", body = ErrorBody),
    )
)]
pub(crate) async fn keep(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Json<AssociationBody>, ApiError> {
    change(&web, &actor, path, Association::Keep).await
}
