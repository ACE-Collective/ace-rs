//! `/api/alerts/v1/detections`: every alert's detections, a page at a time.

use ace_service::{DetectionPoint, DetectionPointFilter};
use axum::Json;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

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
    /// The observable it's on.
    observable: DetectionObservableBody,
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
}

impl From<DetectionPoint> for DetectionPointBody {
    fn from(detection: DetectionPoint) -> Self {
        DetectionPointBody {
            id: detection.id,
            alert: detection.alert,
            observable: DetectionObservableBody {
                id: detection.observable_id,
                kind: detection.observable_type,
                value: detection.observable_value,
            },
            module: detection.module,
            description: detection.description,
            details: detection.details,
            queue: detection.queue,
            signature_uuid: detection.signature_uuid,
            signature_version: detection.signature_version,
            signature_family: detection.signature_family,
            created_at: detection.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionPointPageBody {
    detections: Vec<DetectionPointBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct DetectionPointsQuery {
    /// Only this alert's detections.
    alert: Option<Uuid>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

/// Detections on alerts, oldest first, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/detections",
    tag = "alerts",
    params(DetectionPointsQuery),
    responses(
        (status = 200, description = "A page of detections", body = DetectionPointPageBody),
        (status = 400, description = "A limit out of range, or an alert or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "The alert filter names no alert", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<DetectionPointsQuery>, QueryRejection>,
) -> Result<Json<DetectionPointPageBody>, ApiError> {
    let Query(query) = query?;
    let filter = DetectionPointFilter { alert: query.alert };
    let page = web
        .service
        .detection_points(&actor, &filter, query.limit, query.after)
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
