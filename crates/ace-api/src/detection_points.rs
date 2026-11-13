//! `/api/alerts/v1/detections`: every alert's detections with their verdicts, filtered, a page at a time,
//! and their exports; and the verdict writes under `/api/alerts/v1/alerts/{id}/detections` (PLAN.md 7.14).

use ace_service::filters::{FilterScreen, decode};
use ace_service::{Actor, DetectionPoint, DetectionPointFilter, Verdict, VerdictSource};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::params::Params;

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionObservableBody {
    /// The observable's id in its alert.
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    /// A file's value is its sha256.
    value: String,
}

/// A detection: what made an alert worth an analyst's time.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionPointBody {
    /// The detection's id, for `after`.
    id: i64,
    alert: Uuid,
    /// The observable it's on, or null for a detection on the alert itself, such as a tag configured as
    /// alertable makes.
    observable: Option<DetectionObservableBody>,
    /// The module whose result raised it, or null for one a submission or the core added.
    module: Option<String>,
    /// As a module, a rule or a submission wrote it. Show it as text.
    description: String,
    /// Structured facts, such as the rule a YARA match came from, as they were written. Treat them as data.
    details: Option<Value>,
    /// The alert queue it asks for.
    queue: Option<String>,
    signature_uuid: Option<String>,
    signature_version: Option<String>,
    /// The kind of signature, such as `yara`.
    signature_family: Option<String>,
    created_at: DateTime<Utc>,
    /// The effective verdict, `tp` or `fp`; null when the alert's disposition is unclassified.
    verdict: Option<VerdictBody>,
    /// `explicit`: set or confirmed by someone. `inherited_single`: inherited from the alert, which
    /// covered this detection directly (an FP alert, or a TP alert with one signature). `inherited_multi`:
    /// an inherited TP on an alert where several signatures fired, unconfirmed.
    verdict_source: Option<VerdictSourceBody>,
    /// The stored verdict, if any; masked on an FP alert.
    #[serde(rename = "override")]
    override_verdict: Option<VerdictBody>,
    /// Who stored it.
    override_by: Option<ActorBody>,
    override_set_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerdictBody {
    Tp,
    Fp,
}

impl From<Verdict> for VerdictBody {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Tp => VerdictBody::Tp,
            Verdict::Fp => VerdictBody::Fp,
        }
    }
}

impl From<VerdictBody> for Verdict {
    fn from(verdict: VerdictBody) -> Self {
        match verdict {
            VerdictBody::Tp => Verdict::Tp,
            VerdictBody::Fp => Verdict::Fp,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VerdictSourceBody {
    Explicit,
    InheritedSingle,
    InheritedMulti,
}

impl From<VerdictSource> for VerdictSourceBody {
    fn from(source: VerdictSource) -> Self {
        match source {
            VerdictSource::Explicit => VerdictSourceBody::Explicit,
            VerdictSource::InheritedSingle => VerdictSourceBody::InheritedSingle,
            VerdictSource::InheritedMulti => VerdictSourceBody::InheritedMulti,
        }
    }
}

impl From<DetectionPoint> for DetectionPointBody {
    fn from(detection: DetectionPoint) -> Self {
        DetectionPointBody {
            id: detection.id,
            alert: detection.alert,
            observable: detection
                .observable
                .map(|(id, kind, value)| DetectionObservableBody { id, kind, value }),
            module: detection.module,
            description: detection.description,
            details: detection.details,
            queue: detection.queue,
            signature_uuid: detection.signature_uuid,
            signature_version: detection.signature_version,
            signature_family: detection.signature_family,
            created_at: detection.created_at,
            verdict: detection.verdict.map(VerdictBody::from),
            verdict_source: detection.verdict_source.map(VerdictSourceBody::from),
            override_verdict: detection.override_verdict.map(VerdictBody::from),
            override_by: detection.override_by.map(ActorBody::from),
            override_set_at: detection.override_set_at,
        }
    }
}

impl ExportRow for DetectionPointBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "alert",
        "observable_id",
        "observable_type",
        "observable_value",
        "module",
        "description",
        "details",
        "queue",
        "signature_uuid",
        "signature_version",
        "signature_family",
        "created_at",
        "verdict",
        "verdict_source",
        "override",
        "override_by",
        "override_set_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.alert.to_string(),
            self.observable
                .as_ref()
                .map(|o| o.id.to_string())
                .unwrap_or_default(),
            self.observable
                .as_ref()
                .map(|o| o.kind.clone())
                .unwrap_or_default(),
            self.observable
                .as_ref()
                .map(|o| o.value.clone())
                .unwrap_or_default(),
            self.module.clone().unwrap_or_default(),
            self.description.clone(),
            self.details
                .as_ref()
                .map(|details| details.to_string())
                .unwrap_or_default(),
            self.queue.clone().unwrap_or_default(),
            self.signature_uuid.clone().unwrap_or_default(),
            self.signature_version.clone().unwrap_or_default(),
            self.signature_family.clone().unwrap_or_default(),
            time_cell(Some(self.created_at)),
            self.verdict
                .map(|v| Verdict::from(v).as_str().to_owned())
                .unwrap_or_default(),
            self.verdict_source
                .map(|s| match s {
                    VerdictSourceBody::Explicit => "explicit",
                    VerdictSourceBody::InheritedSingle => "inherited_single",
                    VerdictSourceBody::InheritedMulti => "inherited_multi",
                })
                .unwrap_or_default()
                .to_owned(),
            self.override_verdict
                .map(|v| Verdict::from(v).as_str().to_owned())
                .unwrap_or_default(),
            self.override_by
                .as_ref()
                .map(ActorBody::shown)
                .unwrap_or_default(),
            time_cell(self.override_set_at),
        ]
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionPointPageBody {
    detections: Vec<DetectionPointBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

/// The list's parameters. The handler reads them from the query itself, since `f` repeats.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct DetectionPointsQuery {
    /// Only this alert's detections.
    alert: Option<Uuid>,
    /// A filter in the share-link encoding, `[!]<slug>:<value>,<value>`, with the detection points
    /// screen's slugs (`GET /api/filters/v1/screens/detection_points`); repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only detections made, whose alert became one or was dispositioned, or whose stored verdict was set or
    /// cleared, at or after this time, UTC when it has no offset. Pass the time the previous pull started.
    changed_since: Option<String>,
    /// The IANA timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

/// The export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct DetectionPointExportQuery {
    /// Only this alert's detections.
    alert: Option<Uuid>,
    /// A filter, as the list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// As the list takes it.
    changed_since: Option<String>,
    /// The IANA timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
}

fn filter(params: &Params) -> Result<DetectionPointFilter, ApiError> {
    let (filters, _) = decode(FilterScreen::DetectionPoints, &params.all("f"), true)?;
    Ok(DetectionPointFilter {
        alert: params.parsed("alert", "an alert's id")?,
        filters,
        changed_since: params.time("changed_since")?,
        tz: params.tz()?,
    })
}

/// Detections on alerts that the filters match, oldest first, a page at a time. Follow `next` until it's
/// null.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/detections",
    tag = "alerts",
    params(DetectionPointsQuery),
    responses(
        (status = 200, description = "A page of detections", body = DetectionPointPageBody),
        (status = 400, description = "A filter, time, timezone or limit that isn't one, an alert or cursor that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "The alert filter names no alert", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<DetectionPointPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let filter = filter(&params)?;
    let page = web
        .service
        .detection_points(
            &actor,
            &filter,
            params.parsed("limit", "a number from 1 to 1000")?,
            params.parsed("after", "a detection's id")?,
        )
        .await?;
    Ok(Json(DetectionPointPageBody {
        detections: page
            .detections
            .into_iter()
            .map(DetectionPointBody::from)
            .collect(),
        next: page.next,
    }))
}

async fn export_detections(
    format: Format,
    actor: Actor,
    web: Web,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let filter = filter(&params)?;
    let total = service.detection_point_count(&actor, &filter, max).await?;
    let first = service
        .detection_points(&actor, &filter, Some(EXPORT_PAGE), None)
        .await?;
    let first = (
        first
            .detections
            .into_iter()
            .map(DetectionPointBody::from)
            .collect(),
        first.next,
    );
    export::respond(
        format,
        "detections",
        max,
        total,
        first,
        move |after: i64| {
            let (service, actor, filter) = (service.clone(), actor.clone(), filter.clone());
            async move {
                let page = service
                    .detection_points(&actor, &filter, Some(EXPORT_PAGE), Some(after))
                    .await?;
                Ok((
                    page.detections
                        .into_iter()
                        .map(DetectionPointBody::from)
                        .collect(),
                    page.next,
                ))
            }
        },
    )
}

/// Every detection the list's filters match, oldest first, as CSV: a header line, then a row per detection
/// with its details as JSON, and a cell a spreadsheet would read as a formula behind a `'`. A failure
/// part-way ends the file there.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/detections/export/csv",
    tag = "alerts",
    params(DetectionPointExportQuery),
    responses(
        (status = 200, description = "The detections", content_type = "text/csv", body = String),
        (status = 400, description = "A filter, time, timezone or alert that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "The alert filter names no alert", body = ErrorBody),
        (status = 413, description = "More detections than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_detections(Format::Csv, actor, web, raw).await
}

/// Every detection the list's filters match, oldest first, as NDJSON: a detection as the list gives it on
/// each line. A failure part-way ends it with an `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/detections/export/ndjson",
    tag = "alerts",
    params(DetectionPointExportQuery),
    responses(
        (status = 200, description = "The detections", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A filter, time, timezone or alert that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "The alert filter names no alert", body = ErrorBody),
        (status = 413, description = "More detections than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_detections(Format::Ndjson, actor, web, raw).await
}

/// A verdict to store.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerdictRequest {
    verdict: VerdictBody,
}

/// What a confirm did.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ConfirmedBody {
    /// How many unconfirmed (inherited_multi) detections were confirmed.
    confirmed: usize,
}

/// Stores a verdict on one detection of a TP alert: `fp` marks it as noise, `tp` confirms it. Storing what's
/// stored already changes nothing and writes no audit row.
#[utoipa::path(
    put,
    path = "/api/alerts/v1/alerts/{id}/detections/{detection}/verdict",
    tag = "alerts",
    params(
        ("id" = Uuid, Path, description = "The alert's id"),
        ("detection" = i64, Path, description = "The detection's id"),
    ),
    request_body = VerdictRequest,
    responses(
        (status = 200, description = "The detection, with its verdict", body = DetectionPointBody),
        (status = 400, description = "A verdict that isn't `tp` or `fp`, a body that isn't one, or an id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such alert, or the alert has no such detection", body = ErrorBody),
        (status = 409, description = "The alert's disposition doesn't take the actor's verdicts: an FP or unclassified alert, whose disposition is what to correct, or one only ACE sets", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_verdict(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(Uuid, i64)>, PathRejection>,
    body: Result<Json<VerdictRequest>, JsonRejection>,
) -> Result<Json<DetectionPointBody>, ApiError> {
    let (Path((alert, detection)), Json(body)) = (path?, body?);
    web.service
        .set_detection_verdict(&actor, alert, detection, body.verdict.into())
        .await?;
    let detection = web
        .service
        .detection_point(&actor, alert, detection)
        .await?;
    Ok(Json(detection.into()))
}

/// Removes the stored verdict on one detection, so it inherits from the alert again. Removing none changes
/// nothing and writes no audit row.
#[utoipa::path(
    delete,
    path = "/api/alerts/v1/alerts/{id}/detections/{detection}/verdict",
    tag = "alerts",
    params(
        ("id" = Uuid, Path, description = "The alert's id"),
        ("detection" = i64, Path, description = "The detection's id"),
    ),
    responses(
        (status = 200, description = "The detection, with its verdict", body = DetectionPointBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such alert, or the alert has no such detection", body = ErrorBody),
        (status = 409, description = "The alert's disposition doesn't take the actor's verdicts", body = ErrorBody),
    )
)]
pub(crate) async fn clear_verdict(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(Uuid, i64)>, PathRejection>,
) -> Result<Json<DetectionPointBody>, ApiError> {
    let Path((alert, detection)) = path?;
    web.service
        .clear_detection_verdict(&actor, alert, detection)
        .await?;
    let detection = web
        .service
        .detection_point(&actor, alert, detection)
        .await?;
    Ok(Json(detection.into()))
}

/// Confirms every unconfirmed inherited TP of the alert (source `inherited_multi`): each becomes an explicit
/// TP, which weighs more when signature changes are tested.
#[utoipa::path(
    post,
    path = "/api/alerts/v1/alerts/{id}/detections/confirm",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    responses(
        (status = 200, description = "How many it confirmed", body = ConfirmedBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
        (status = 409, description = "The alert's disposition doesn't take the actor's verdicts", body = ErrorBody),
    )
)]
pub(crate) async fn confirm(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<ConfirmedBody>, ApiError> {
    let Path(alert) = path?;
    let confirmed = web.service.confirm_detections(&actor, alert).await?;
    Ok(Json(ConfirmedBody { confirmed }))
}
