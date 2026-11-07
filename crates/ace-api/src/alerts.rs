//! `/api/alerts/v1`: the alert list, one alert, its observables, a file's download and the disposition.

use std::io::{Seek, SeekFrom};

use ace_core::bucket::ALERT_FILES;
use ace_results::Sha256;
use ace_service::{
    AlertDetection, AlertFile, AlertObservable, AlertSummary, AnalysisState, ModuleResult,
    RecordedActor, Relationship,
};
use axum::Json;
use axum::body::Body;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// The password of a download's zip, as ace3's. It's there so that a scanner on the analyst's machine
/// leaves the file alone, not to keep it secret.
pub(crate) const ZIP_PASSWORD: &str = "infected";

/// A download's bytes, as the document shows them.
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
#[allow(dead_code)]
pub(crate) struct ZipBody(Vec<u8>);

/// Who did something, as the row recorded them then.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ActorBody {
    /// `user`, `api_key` or `internal`.
    kind: String,
    id: String,
    /// The user's or key's name at the time. An internal component's id is its name.
    name: Option<String>,
}

impl From<RecordedActor> for ActorBody {
    fn from(actor: RecordedActor) -> Self {
        ActorBody {
            kind: actor.kind,
            id: actor.id,
            name: actor.name,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AnalysisBody {
    /// Tasks are queued or running.
    Running,
    /// The current pass completed.
    Complete,
    /// Analysis was cancelled and hasn't started again.
    Cancelled,
}

/// An alert: a root that a detection made worth an analyst's time.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertBody {
    id: Uuid,
    /// The submission's description, as its sender wrote it. Show it as text.
    title: String,
    analysis_mode: String,
    event_time: Option<DateTime<Utc>>,
    /// `event`, `query_time`, `now` or `unset`: where `event_time` came from.
    event_time_source: String,
    created_at: DateTime<Utc>,
    /// When a detection made the root an alert.
    alerted_at: DateTime<Utc>,
    disposition: Option<String>,
    dispositioned_at: Option<DateTime<Utc>>,
    dispositioned_by: Option<ActorBody>,
    submitted_by: Option<ActorBody>,
    analysis: AnalysisBody,
}

impl From<AlertSummary> for AlertBody {
    fn from(alert: AlertSummary) -> Self {
        AlertBody {
            id: alert.id,
            title: alert.title,
            analysis_mode: alert.analysis_mode,
            event_time: alert.event_time,
            event_time_source: alert.event_time_source,
            created_at: alert.created_at,
            alerted_at: alert.alerted_at,
            disposition: alert.disposition,
            dispositioned_at: alert.dispositioned_at,
            dispositioned_by: alert.dispositioned_by.map(ActorBody::from),
            submitted_by: alert.submitted_by.map(ActorBody::from),
            analysis: match alert.analysis {
                AnalysisState::Running => AnalysisBody::Running,
                AnalysisState::Complete => AnalysisBody::Complete,
                AnalysisState::Cancelled => AnalysisBody::Cancelled,
            },
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertPageBody {
    alerts: Vec<AlertBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<Uuid>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertDetailBody {
    alert: AlertBody,
    observables: i64,
    files: i64,
    detections: i64,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AlertsQuery {
    /// How many alerts, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<Uuid>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ObservablesQuery {
    /// How many observables, 1 to 500; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FileBody {
    /// The file's path in the alert, such as `email.rfc822.parts/invoice.zip`.
    path: String,
    yara_meta: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RelationshipBody {
    kind: String,
    target_type: String,
    target_value: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ResultBody {
    module: String,
    analysis_type: String,
    schema_version: i32,
    summary: Option<String>,
    tags: Vec<String>,
    /// The result's details, as the analysis type's JSON Schema (`ace schema export`) says.
    details: Value,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionBody {
    description: String,
    details: Option<Value>,
    /// The module whose result raised it.
    module: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RedirectionBody {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

/// An observable of an alert and everything recorded about it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ObservableBody {
    /// The observable's id in this alert, for `after` and for its file.
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    /// A file's value is its sha256.
    value: String,
    time: Option<DateTime<Utc>>,
    tags: Vec<String>,
    directives: Vec<String>,
    exclude_modules: Vec<String>,
    /// The observable an analyst should look at instead.
    redirection: Option<RedirectionBody>,
    files: Vec<FileBody>,
    relationships: Vec<RelationshipBody>,
    results: Vec<ResultBody>,
    detections: Vec<DetectionBody>,
}

impl From<AlertObservable> for ObservableBody {
    fn from(observable: AlertObservable) -> Self {
        ObservableBody {
            id: observable.id,
            kind: observable.kind,
            value: observable.value,
            time: observable.time,
            tags: observable.tags,
            directives: observable.directives,
            exclude_modules: observable.exclude_modules,
            redirection: observable
                .redirection
                .map(|(kind, value)| RedirectionBody { kind, value }),
            files: observable
                .files
                .into_iter()
                .map(|AlertFile { path, yara_meta }| FileBody { path, yara_meta })
                .collect(),
            relationships: observable
                .relationships
                .into_iter()
                .map(
                    |Relationship {
                         kind,
                         target_type,
                         target_value,
                     }| RelationshipBody {
                        kind,
                        target_type,
                        target_value,
                    },
                )
                .collect(),
            results: observable
                .results
                .into_iter()
                .map(|result: ModuleResult| ResultBody {
                    module: result.module,
                    analysis_type: result.analysis_type,
                    schema_version: result.schema_version,
                    summary: result.summary,
                    tags: result.tags,
                    details: result.details,
                    created_at: result.created_at,
                })
                .collect(),
            detections: observable
                .detections
                .into_iter()
                .map(
                    |AlertDetection {
                         description,
                         details,
                         module,
                     }| DetectionBody {
                        description,
                        details,
                        module,
                    },
                )
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ObservablePageBody {
    observables: Vec<ObservableBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispositionRequest {
    /// Such as `FALSE_POSITIVE`: up to 64 uppercase ASCII letters, digits and `_`.
    disposition: String,
}

/// What the disposition did to the alert's analysis.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DispositionedBody {
    /// Queued and delayed tasks it cancelled.
    cancelled: usize,
    /// Running tasks it asked to stop.
    stopped: usize,
    /// The dispositioned mode's tasks it queued.
    queued: usize,
}

/// The alerts, newest first, a page at a time. Follow `next` until it's null: an alert that arrives
/// meanwhile is on the first page and never shifts a later one.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts",
    tag = "alerts",
    params(AlertsQuery),
    responses(
        (status = 200, description = "A page of alerts", body = AlertPageBody),
        (status = 400, description = "A limit out of range, or a cursor that names no alert", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<AlertsQuery>, QueryRejection>,
) -> Result<Json<AlertPageBody>, ApiError> {
    let Query(query) = query?;
    let page = web.service.alerts(&actor, query.limit, query.after).await?;
    Ok(Json(AlertPageBody {
        alerts: page.alerts.into_iter().map(AlertBody::from).collect(),
        next: page.next,
    }))
}

/// One alert, with how many observables, files and detections it holds.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    responses(
        (status = 200, description = "The alert", body = AlertDetailBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<AlertDetailBody>, ApiError> {
    let Path(id) = id?;
    let alert = web.service.alert(&actor, id).await?;
    Ok(Json(AlertDetailBody {
        alert: alert.summary.into(),
        observables: alert.observables,
        files: alert.files,
        detections: alert.detections,
    }))
}

/// An alert's observables in the order they were added, each with its files, relationships, results
/// and detections, a page at a time.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/observables",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id"), ObservablesQuery),
    responses(
        (status = 200, description = "A page of observables", body = ObservablePageBody),
        (status = 400, description = "A limit out of range, or an id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn observables(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<ObservablesQuery>, QueryRejection>,
) -> Result<Json<ObservablePageBody>, ApiError> {
    let (Path(id), Query(query)) = (id?, query?);
    let page = web
        .service
        .alert_observables(&actor, id, query.limit, query.after)
        .await?;
    Ok(Json(ObservablePageBody {
        observables: page
            .observables
            .into_iter()
            .map(ObservableBody::from)
            .collect(),
        next: page.next,
    }))
}

/// A file observable's bytes, as a zip encrypted with AES-256 and the password `infected`, as ace3's
/// downloads are, holding the file under its name in the alert. The download is in the audit record.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/observables/{observable}/file",
    tag = "alerts",
    params(
        ("id" = Uuid, Path, description = "The alert's id"),
        ("observable" = i64, Path, description = "The file observable's id in the alert"),
    ),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "An observable that isn't a file, or an id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert or observable", body = ErrorBody),
    )
)]
pub(crate) async fn file(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    ids: Result<Path<(Uuid, i64)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((id, observable)) = ids?;
    let download = web.service.download_file(&actor, id, observable).await?;
    let sha256: Sha256 = download.sha256.parse().map_err(ApiError::internal)?;
    let cached = web
        .bucket
        .get(ALERT_FILES, &sha256)
        .await
        .map_err(ApiError::internal)?;
    let name = download
        .path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("file")
        .to_owned();
    let mut source = cached.file;
    let zipped = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        let out = tempfile::tempfile()?;
        let mut zip = zip::ZipWriter::new(out);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .large_file(cached.size >= u64::from(u32::MAX))
            .with_aes_encryption(zip::AesMode::Aes256, ZIP_PASSWORD);
        zip.start_file(name, options)
            .map_err(std::io::Error::other)?;
        std::io::copy(&mut source, &mut zip)?;
        let mut out = zip.finish().map_err(std::io::Error::other)?;
        out.seek(SeekFrom::Start(0))?;
        Ok(out)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    let length = zipped.metadata().map_err(ApiError::internal)?.len();
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(
        tokio::fs::File::from_std(zipped),
    ));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zip".to_owned()),
            (header::CONTENT_LENGTH, length.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{sha256}.zip\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        body,
    )
        .into_response())
}

/// Records an analyst's verdict on the alert. Its analysis is cancelled and it moves to the
/// dispositioned mode. A later disposition replaces the earlier one and who made it. A root that no
/// detection made an alert can be dispositioned too, as the service allows.
#[utoipa::path(
    put,
    path = "/api/alerts/v1/alerts/{id}/disposition",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    request_body = DispositionRequest,
    responses(
        (status = 200, description = "The disposition is recorded", body = DispositionedBody),
        (status = 400, description = "A disposition of the wrong shape, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such root", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn disposition(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<DispositionRequest>, JsonRejection>,
) -> Result<Json<DispositionedBody>, ApiError> {
    let (Path(id), Json(body)) = (id?, body?);
    let done = web
        .service
        .disposition(&actor, id, &body.disposition)
        .await?;
    Ok(Json(DispositionedBody {
        cancelled: done.cancelled.cancelled.len(),
        stopped: done.cancelled.signalled.len(),
        queued: done.queued.len(),
    }))
}
