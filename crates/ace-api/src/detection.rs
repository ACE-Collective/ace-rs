//! `/api/observables/v1/detections`: the observables ACE detects wherever they appear (PLAN.md 7.6,
//! `ace_service`'s `detection` docs), entries of the `observable_detection` list that module reads.
//! Reading needs `detection:read`, and adding, removing and setting an expiry need `detection:write`,
//! each write audited. A detection applies to the next task that checks an observable. A value is
//! returned as it was stored: show it as text.

use ace_service::{
    Detection, DetectionExpiry, DetectionFilter, DetectionPage, DetectionStatus, DetectionTypes,
    NewDetection,
};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::observable_comments::CommentBody;

/// An observable ACE detects.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionBody {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    /// The value as it's matched, exactly and with case. Show it as text.
    value: String,
    /// After this it detects nothing; null never expires.
    expires_on: Option<DateTime<Utc>>,
    /// Its expiry passed.
    expired: bool,
    /// Why it's there.
    detection_context: String,
    created_by: ActorBody,
    created_at: DateTime<Utc>,
    modified_by: ActorBody,
    modified_at: DateTime<Utc>,
    /// The observable's comments, oldest first.
    comments: Vec<CommentBody>,
}

impl From<Detection> for DetectionBody {
    fn from(detection: Detection) -> Self {
        DetectionBody {
            id: detection.id,
            kind: detection.observable_type,
            value: detection.value,
            expires_on: detection.expires_at,
            expired: detection.expired,
            detection_context: detection.context,
            created_by: ActorBody::from(detection.created_by),
            created_at: detection.created_at,
            modified_by: ActorBody::from(detection.modified_by),
            modified_at: detection.modified_at,
            comments: detection
                .comments
                .into_iter()
                .map(CommentBody::from)
                .collect(),
        }
    }
}

/// A page of detections.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionPageBody {
    items: Vec<DetectionBody>,
    /// How many match the filters, on every page.
    total: i64,
    /// The page, clamped to the pages there are.
    page: i64,
    page_size: i64,
    total_pages: i64,
}

impl From<DetectionPage> for DetectionPageBody {
    fn from(page: DetectionPage) -> Self {
        DetectionPageBody {
            items: page.items.into_iter().map(DetectionBody::from).collect(),
            total: page.total,
            page: page.page,
            page_size: page.page_size,
            total_pages: page.total_pages,
        }
    }
}

/// The types for a filter and for a new detection.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionTypesBody {
    /// The types that have a detection.
    present: Vec<String>,
    /// Every type a detection can be of.
    all: Vec<String>,
}

impl From<DetectionTypes> for DetectionTypesBody {
    fn from(types: DetectionTypes) -> Self {
        DetectionTypesBody {
            present: types.present,
            all: types.all,
        }
    }
}

fn first_page() -> i64 {
    1
}

fn default_page_size() -> i64 {
    ace_service::DEFAULT_DETECTION_PAGE_SIZE
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct DetectionsQuery {
    /// Part of the value, ignoring case; with `*`, a pattern, each `*` any run of characters.
    search: Option<String>,
    /// Only detections of this type.
    #[serde(rename = "type")]
    #[param(rename = "type")]
    kind: Option<String>,
    /// `active` (the default: no expiry, or one still to come), `expired` or `all`.
    status: Option<String>,
    /// 1-based, clamped to the pages there are.
    #[serde(default = "first_page")]
    #[param(default = 1)]
    page: i64,
    /// 25, 50, 100 or 200; anything else is 50.
    #[serde(default = "default_page_size")]
    #[param(default = 50)]
    page_size: i64,
}

/// A field that's present, null or not, as against one left out.
fn present<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<DateTime<Utc>>>, D::Error> {
    Option::<DateTime<Utc>>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewDetectionRequest {
    /// An observable type this server has.
    #[serde(rename = "type")]
    kind: String,
    /// The value, matched exactly and with case; a file's is its sha256.
    value: String,
    /// Left out, the type's default lifetime: 90 days, or never for `sha256` and `md5`. Null never
    /// expires. Otherwise it has to be in the future.
    #[serde(default, deserialize_with = "present")]
    #[schema(value_type = Option<DateTime<Utc>>)]
    expires_on: Option<Option<DateTime<Utc>>>,
    /// Why, up to 1024 characters; `manually added by <name>` when left out.
    #[serde(default)]
    detection_context: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpirationRequest {
    /// When it stops detecting, in the future; null never.
    expires_on: Option<DateTime<Utc>>,
}

/// A page of the detections, ordered by type, value and id, each with its observable's comments.
#[utoipa::path(
    get,
    path = "/api/observables/v1/detections",
    tag = "observables",
    params(DetectionsQuery),
    responses(
        (status = 200, description = "A page of detections", body = DetectionPageBody),
        (status = 400, description = "A status that isn't one, or a parameter that doesn't read", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold detection:read", body = ErrorBody),
        (status = 404, description = "This server's modules don't detect observables", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<DetectionsQuery>, QueryRejection>,
) -> Result<Json<DetectionPageBody>, ApiError> {
    let Query(query) = query?;
    let status = match query.status.as_deref() {
        None | Some("") => DetectionStatus::Active,
        Some(text) => DetectionStatus::parse(text).ok_or_else(|| {
            ApiError::bad_request(format!("status is active, expired or all, not {text:?}"))
        })?,
    };
    let filter = DetectionFilter {
        search: query.search,
        observable_type: query.kind,
        status,
        page: query.page,
        page_size: query.page_size,
    };
    let page = web.service.detections(&actor, &filter).await?;
    Ok(Json(DetectionPageBody::from(page)))
}

/// The types that have a detection, and every type a new one can be of.
#[utoipa::path(
    get,
    path = "/api/observables/v1/detections/types",
    tag = "observables",
    responses(
        (status = 200, description = "The types", body = DetectionTypesBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold detection:read", body = ErrorBody),
        (status = 404, description = "This server's modules don't detect observables", body = ErrorBody),
    )
)]
pub(crate) async fn types(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<DetectionTypesBody>, ApiError> {
    let types = web.service.detection_types(&actor).await?;
    Ok(Json(DetectionTypesBody::from(types)))
}

/// Adds a detection: every alert holding the observable gets a detection point from the next task that
/// checks it. The observable needn't have been seen.
#[utoipa::path(
    post,
    path = "/api/observables/v1/detections",
    tag = "observables",
    request_body = NewDetectionRequest,
    responses(
        (status = 201, description = "The detection", body = DetectionBody),
        (status = 400, description = "A type this server doesn't have, a value that isn't one for it or is too long, a context that's too long, an expiry that passed, a list that would hold too many entries, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold detection:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "This server's modules don't detect observables", body = ErrorBody),
        (status = 409, description = "A detection of this type and value exists already", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn create(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<NewDetectionRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<DetectionBody>), ApiError> {
    let Json(body) = body?;
    let detection = NewDetection {
        observable_type: body.kind,
        value: body.value,
        expires: match body.expires_on {
            None => DetectionExpiry::Default,
            Some(None) => DetectionExpiry::Never,
            Some(Some(at)) => DetectionExpiry::At(at),
        },
        context: body.detection_context,
    };
    let created = web.service.create_detection(&actor, &detection).await?;
    Ok((StatusCode::CREATED, Json(DetectionBody::from(created))))
}

/// Removes a detection, which is how one is turned off. Its audit row keeps what it was.
#[utoipa::path(
    delete,
    path = "/api/observables/v1/detections/{id}",
    tag = "observables",
    params(("id" = i64, Path, description = "The detection's id")),
    responses(
        (status = 204, description = "The detection is gone"),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold detection:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such detection", body = ErrorBody),
    )
)]
pub(crate) async fn delete(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    web.service.delete_detection(&actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Sets when a detection expires, or that it never does. Setting what it has changes nothing.
#[utoipa::path(
    patch,
    path = "/api/observables/v1/detections/{id}/expiration",
    tag = "observables",
    params(("id" = i64, Path, description = "The detection's id")),
    request_body = ExpirationRequest,
    responses(
        (status = 200, description = "The detection as it is now", body = DetectionBody),
        (status = 400, description = "An id that isn't one, an expiry that passed, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold detection:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such detection", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_expiration(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
    body: Result<Json<ExpirationRequest>, JsonRejection>,
) -> Result<Json<DetectionBody>, ApiError> {
    let Path(id) = id?;
    let Json(body) = body?;
    let detection = web
        .service
        .set_detection_expiration(&actor, id, body.expires_on)
        .await?;
    Ok(Json(DetectionBody::from(detection)))
}
