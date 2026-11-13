//! `/api/file-collections/v1`: file collections (PLAN.md 7.9, `ace_service`'s `file_collections` docs).
//! Reading needs `file_collection:read`, and stopping, retrying and deleting need `file_collection:write`,
//! each write audited. A value is returned as it was stored: show it as text.

use ace_service::filters::FilterScreen;
use ace_service::{Actor, FileCollection};
use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::params::Params;
use crate::remediation::{
    ActionSummaryBody, AttemptBody, ExportQuery, HistoryBody, HistoryQuery, ListQuery,
    history_limit, query,
};

/// A collected file.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CollectedFileBody {
    sha256: String,
    size: i64,
    /// Its name as the collector saved it. Show it as text.
    name: String,
}

/// One file collection, as the list gives it. Times are UTC.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FileCollectionBody {
    id: i64,
    collector: String,
    /// Null when this server has no collector by that name.
    collector_display_name: Option<String>,
    observable_type: String,
    observable_value: String,
    /// `NEW`, `IN_PROGRESS` (waiting to be tried again) or `COMPLETED`.
    status: String,
    /// How the latest try ended, such as `SUCCESS` or `HOST_OFFLINE`.
    result: Option<String>,
    result_message: Option<String>,
    /// The tries so far.
    attempts: i32,
    max_attempts: Option<i32>,
    /// The alerts it belongs to, each holding its file.
    alerts: Vec<Uuid>,
    /// Who asked for it when no alert did.
    requested_by: Option<String>,
    /// The file, once collected.
    file: Option<CollectedFileBody>,
    created_at: DateTime<Utc>,
    updated_at: Option<DateTime<Utc>>,
}

impl From<FileCollection> for FileCollectionBody {
    fn from(c: FileCollection) -> Self {
        FileCollectionBody {
            id: c.id,
            collector: c.collector,
            collector_display_name: c.display_name,
            observable_type: c.observable_type,
            observable_value: c.observable_value,
            status: c.status,
            result: c.result,
            result_message: c.result_message,
            attempts: c.attempts,
            max_attempts: c.max_attempts,
            alerts: c.alerts,
            requested_by: c.requested_by,
            file: c
                .file
                .map(|(sha256, size, name)| CollectedFileBody { sha256, size, name }),
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

impl ExportRow for FileCollectionBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "collector",
        "observable_type",
        "observable_value",
        "status",
        "result",
        "result_message",
        "attempts",
        "max_attempts",
        "alerts",
        "requested_by",
        "file_sha256",
        "created_at",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.collector.clone(),
            self.observable_type.clone(),
            self.observable_value.clone(),
            self.status.clone(),
            self.result.clone().unwrap_or_default(),
            self.result_message.clone().unwrap_or_default(),
            self.attempts.to_string(),
            self.max_attempts.map(|m| m.to_string()).unwrap_or_default(),
            self.alerts
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            self.requested_by.clone().unwrap_or_default(),
            self.file
                .as_ref()
                .map(|f| f.sha256.clone())
                .unwrap_or_default(),
            time_cell(Some(self.created_at)),
            time_cell(self.updated_at),
        ]
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FileCollectionPageBody {
    collections: Vec<FileCollectionBody>,
    /// How many the filters match, on every page.
    total: i64,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

/// File collections the filters match, newest first, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/file-collections/v1/collections",
    tag = "file_collections",
    params(ListQuery),
    responses(
        (status = 200, description = "A page of collections", body = FileCollectionPageBody),
        (status = 400, description = "A filter, timezone, limit or cursor that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold file_collection:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<FileCollectionPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = query(&params, FilterScreen::FileCollections)?;
    let page = web
        .service
        .file_collections(
            &actor,
            &query,
            params.parsed("limit", "a number from 1 to 1000")?,
            params.parsed("after", "a collection's id")?,
        )
        .await?;
    Ok(Json(FileCollectionPageBody {
        collections: page
            .collections
            .into_iter()
            .map(FileCollectionBody::from)
            .collect(),
        total: page.total,
        next: page.next,
    }))
}

async fn export_collections(
    format: Format,
    actor: Actor,
    web: Web,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let query = query(&params, FilterScreen::FileCollections)?;
    let first = service
        .file_collections(&actor, &query, Some(EXPORT_PAGE), None)
        .await?;
    let total = first.total;
    let first = (
        first
            .collections
            .into_iter()
            .map(FileCollectionBody::from)
            .collect(),
        first.next,
    );
    export::respond(
        format,
        "file-collections",
        max,
        total,
        first,
        move |after: i64| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .file_collections(&actor, &query, Some(EXPORT_PAGE), Some(after))
                    .await?;
                Ok((
                    page.collections
                        .into_iter()
                        .map(FileCollectionBody::from)
                        .collect(),
                    page.next,
                ))
            }
        },
    )
}

/// Every collection the list's filters match, newest first, as CSV, a cell a spreadsheet would read as a
/// formula behind a `'`. A failure part-way ends the file there.
#[utoipa::path(
    get,
    path = "/api/file-collections/v1/collections/export/csv",
    tag = "file_collections",
    params(ExportQuery),
    responses(
        (status = 200, description = "The collections", content_type = "text/csv", body = String),
        (status = 400, description = "A filter or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold file_collection:read", body = ErrorBody),
        (status = 413, description = "More collections than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_collections(Format::Csv, actor, web, raw).await
}

/// Every collection the list's filters match, newest first, as NDJSON. A failure part-way ends it with an
/// `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/file-collections/v1/collections/export/ndjson",
    tag = "file_collections",
    params(ExportQuery),
    responses(
        (status = 200, description = "The collections", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A filter or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold file_collection:read", body = ErrorBody),
        (status = 413, description = "More collections than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_collections(Format::Ndjson, actor, web, raw).await
}

/// One file collection.
#[utoipa::path(
    get,
    path = "/api/file-collections/v1/collections/{id}",
    tag = "file_collections",
    params(("id" = i64, Path, description = "The collection's id")),
    responses(
        (status = 200, description = "The collection", body = FileCollectionBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold file_collection:read", body = ErrorBody),
        (status = 404, description = "No such collection", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<FileCollectionBody>, ApiError> {
    let Path(id) = id?;
    let collection = web.service.file_collection(&actor, id).await?;
    Ok(Json(FileCollectionBody::from(collection)))
}

/// Each try at a collection, newest first.
#[utoipa::path(
    get,
    path = "/api/file-collections/v1/collections/{id}/history",
    tag = "file_collections",
    params(("id" = i64, Path, description = "The collection's id"), HistoryQuery),
    responses(
        (status = 200, description = "Its tries", body = HistoryBody),
        (status = 400, description = "An id or a limit that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold file_collection:read", body = ErrorBody),
        (status = 404, description = "No such collection", body = ErrorBody),
    )
)]
pub(crate) async fn history(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<HistoryBody>, ApiError> {
    let Path(id) = id?;
    let limit = history_limit(raw)?;
    let attempts = web
        .service
        .file_collection_history(&actor, id, limit)
        .await?;
    Ok(Json(HistoryBody::of(
        attempts.into_iter().map(AttemptBody::from).collect(),
    )))
}

/// Stops a collection that hasn't completed; it completes `CANCELLED`. Audited.
#[utoipa::path(
    post,
    path = "/api/file-collections/v1/collections/{id}/cancel",
    tag = "file_collections",
    params(("id" = i64, Path, description = "The collection's id")),
    responses(
        (status = 200, description = "The collection as it is now", body = ActionSummaryBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold file_collection:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such collection", body = ErrorBody),
        (status = 409, description = "It has completed: its result stands", body = ErrorBody),
    )
)]
pub(crate) async fn cancel(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<ActionSummaryBody>, ApiError> {
    let Path(id) = id?;
    let summary = web.service.cancel_file_collection(&actor, id).await?;
    Ok(Json(ActionSummaryBody::from(summary)))
}

/// Starts a collection over: queued again with no tries counted, whatever its state. Audited.
#[utoipa::path(
    post,
    path = "/api/file-collections/v1/collections/{id}/retry",
    tag = "file_collections",
    params(("id" = i64, Path, description = "The collection's id")),
    responses(
        (status = 200, description = "The collection as it is now", body = ActionSummaryBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold file_collection:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such collection", body = ErrorBody),
    )
)]
pub(crate) async fn retry(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<ActionSummaryBody>, ApiError> {
    let Path(id) = id?;
    let summary = web.service.retry_file_collection(&actor, id).await?;
    Ok(Json(ActionSummaryBody::from(summary)))
}

/// Deletes a collection and its history, and its own hold on its file, which its alerts keep. Audited.
#[utoipa::path(
    delete,
    path = "/api/file-collections/v1/collections/{id}",
    tag = "file_collections",
    params(("id" = i64, Path, description = "The collection's id")),
    responses(
        (status = 204, description = "It's gone"),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold file_collection:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such collection", body = ErrorBody),
    )
)]
pub(crate) async fn delete(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    web.service.delete_file_collection(&actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
