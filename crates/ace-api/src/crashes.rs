//! `/api/crashes/v1`: failed tasks, one with its inputs, and its download.

use std::io::{Seek, SeekFrom, Write};

use ace_core::bucket::{ALERT_FILES, BucketError};
use ace_results::Sha256;
use ace_service::{Crash, CrashDetail, CrashFilter, CrashInput};
use axum::Json;
use axum::body::Body;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::{ZIP_PASSWORD, ZipBody};
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CrashObservableBody {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    /// As the observable holds it; a file's is its sha256.
    value: String,
}

/// A task that failed: its module raised, panicked, hung past its deadline or was killed, or its lease
/// expired on every attempt.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CrashBody {
    /// The task's id, which `ace task replay` takes.
    id: i64,
    root: Uuid,
    /// Whether the root is an alert.
    alerted: bool,
    /// The module's key.
    module: String,
    observable: CrashObservableBody,
    attempts: i32,
    max_attempts: i32,
    /// Why it failed, as the pool or the core wrote it. It can quote a file the module read, such as its
    /// name: show it as text.
    error: String,
    /// The sha256 of each input it read from the bucket.
    input_hashes: Vec<String>,
    created_at: DateTime<Utc>,
    failed_at: DateTime<Utc>,
}

impl From<Crash> for CrashBody {
    fn from(crash: Crash) -> Self {
        CrashBody {
            id: crash.id,
            root: crash.root,
            alerted: crash.alerted,
            module: crash.module,
            observable: CrashObservableBody {
                id: crash.observable_id,
                kind: crash.observable_type,
                value: crash.observable_value,
            },
            attempts: crash.attempts,
            max_attempts: crash.max_attempts,
            error: crash.error,
            input_hashes: crash.input_hashes,
            created_at: crash.created_at,
            failed_at: crash.failed_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CrashPageBody {
    crashes: Vec<CrashBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CrashInputBody {
    sha256: String,
    /// Whether the bucket still has its bytes, which a download then holds.
    present: bool,
    size: Option<i64>,
    mime_type: Option<String>,
}

impl From<CrashInput> for CrashInputBody {
    fn from(input: CrashInput) -> Self {
        CrashInputBody {
            present: input.size.is_some(),
            sha256: input.sha256,
            size: input.size,
            mime_type: input.mime_type,
        }
    }
}

/// Everything recorded about a failed task.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CrashDetailBody {
    crash: CrashBody,
    /// The root's description, up to 1024 characters. Show it as text.
    root_title: String,
    analysis_mode: String,
    /// The paths a file observable has in its root.
    paths: Vec<String>,
    inputs: Vec<CrashInputBody>,
}

impl From<CrashDetail> for CrashDetailBody {
    fn from(detail: CrashDetail) -> Self {
        CrashDetailBody {
            crash: CrashBody::from(detail.crash),
            root_title: detail.root_title,
            analysis_mode: detail.analysis_mode,
            paths: detail.paths,
            inputs: detail
                .inputs
                .into_iter()
                .map(CrashInputBody::from)
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CrashesQuery {
    /// Only this root's failed tasks.
    root: Option<Uuid>,
    /// Only this module's failed tasks, by its key, such as `yara`.
    module: Option<String>,
    /// How many, 1 to 500; 50 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

/// Failed tasks, newest failure first, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/crashes/v1/crashes",
    tag = "crashes",
    params(CrashesQuery),
    responses(
        (status = 200, description = "A page of failed tasks", body = CrashPageBody),
        (status = 400, description = "A limit out of range, or a cursor that names no failed task", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold crash:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<CrashesQuery>, QueryRejection>,
) -> Result<Json<CrashPageBody>, ApiError> {
    let Query(query) = query?;
    let filter = CrashFilter {
        root: query.root,
        module: query.module,
    };
    let page = web
        .service
        .crashes(&actor, &filter, query.limit, query.after)
        .await?;
    Ok(Json(CrashPageBody {
        crashes: page.crashes.into_iter().map(CrashBody::from).collect(),
        next: page.next,
    }))
}

/// One failed task, with its file's paths in the root and whether the bucket still has each input.
#[utoipa::path(
    get,
    path = "/api/crashes/v1/crashes/{id}",
    tag = "crashes",
    params(("id" = i64, Path, description = "The task's id")),
    responses(
        (status = 200, description = "The failed task", body = CrashDetailBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold crash:read", body = ErrorBody),
        (status = 404, description = "No failed task with that id", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<CrashDetailBody>, ApiError> {
    let Path(id) = id?;
    let detail = web.service.crash(&actor, id).await?;
    Ok(Json(CrashDetailBody::from(detail)))
}

/// An input the bucket no longer has, or never did.
#[derive(Debug, Serialize)]
struct Omitted {
    sha256: String,
    reason: &'static str,
}

/// `task.json` in a download: the detail, and what the archive leaves out.
#[derive(Debug, Serialize)]
struct Manifest {
    #[serde(flatten)]
    detail: CrashDetailBody,
    omitted: Vec<Omitted>,
}

/// The failed task as a zip encrypted with AES-256 and the password `infected`, as ace3's crash report
/// download is: `task-<id>/task.json`, which is this task's detail and the inputs left out, and each input
/// the bucket has as `task-<id>/inputs/<sha256>`. The download is in the audit record.
#[utoipa::path(
    get,
    path = "/api/crashes/v1/crashes/{id}/download",
    tag = "crashes",
    params(("id" = i64, Path, description = "The task's id")),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold crash:read", body = ErrorBody),
        (status = 404, description = "No failed task with that id", body = ErrorBody),
    )
)]
pub(crate) async fn download(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(id) = id?;
    let detail = web.service.download_crash(&actor, id).await?;
    let mut files = Vec::new();
    let mut omitted = Vec::new();
    for hash in &detail.crash.input_hashes {
        let Ok(sha256) = hash.parse::<Sha256>() else {
            omitted.push(Omitted {
                sha256: hash.clone(),
                reason: "not a sha256",
            });
            continue;
        };
        // one entry a hash, since a zip can't hold two of one name
        if files.iter().any(|(had, _)| *had == sha256) {
            continue;
        }
        match web.bucket.get(ALERT_FILES, &sha256).await {
            Ok(cached) => files.push((sha256, cached)),
            Err(BucketError::NotFound { .. }) => omitted.push(Omitted {
                sha256: hash.clone(),
                reason: "the bucket doesn't have it",
            }),
            Err(e) => return Err(ApiError::internal(e)),
        }
    }
    let manifest = serde_json::to_vec_pretty(&Manifest {
        detail: CrashDetailBody::from(detail),
        omitted,
    })
    .map_err(ApiError::internal)?;
    let folder = format!("task-{id}");
    let zipped = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        let out = tempfile::tempfile()?;
        let mut zip = zip::ZipWriter::new(out);
        let options = |size: u64| {
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .large_file(size >= u64::from(u32::MAX))
                .with_aes_encryption(zip::AesMode::Aes256, ZIP_PASSWORD)
        };
        zip.start_file(format!("{folder}/task.json"), options(0))
            .map_err(std::io::Error::other)?;
        zip.write_all(&manifest)?;
        for (sha256, mut cached) in files {
            zip.start_file(format!("{folder}/inputs/{sha256}"), options(cached.size))
                .map_err(std::io::Error::other)?;
            std::io::copy(&mut cached.file, &mut zip)?;
        }
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
                format!("attachment; filename=\"crash-{id}.zip\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        body,
    )
        .into_response())
}
