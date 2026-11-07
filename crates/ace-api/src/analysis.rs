//! `POST /api/analysis/v1/submit`: a multipart form with the submission as JSON in its `analysis` field
//! and each file in a `file` field, whose file name is its path in the alert. It moved here from the
//! lease API (PLAN.md 5.5), and takes an API key where it took a shared token.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use ace_core::submit::{Submission, SubmittedFile};
use ace_results::AlertPath;
use ace_service::ALERT_CREATE;
use axum::Json;
use axum::extract::{Multipart, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// The submission in the `analysis` field. This is `ace_core::submit::Submission` as the document shows
/// it, and `tests/api.rs` checks that the two take the same fields.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmissionBody {
    /// The root's title.
    description: String,
    /// The root's analysis mode, such as `email` or `correlation`; the default mode when left out.
    #[serde(default)]
    analysis_mode: Option<String>,
    /// When the event happened; the time of the submission when left out.
    #[serde(default)]
    event_time: Option<DateTime<Utc>>,
    #[serde(default)]
    observables: Vec<SubmittedObservableBody>,
    /// `yara_meta` tags for submitted files, by the file's path in the alert, such as
    /// `{"invoice.zip": ["type=email.attachment"]}`.
    #[serde(default)]
    file_yara_meta: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmittedObservableBody {
    /// An observable type, such as `fqdn` or `ipv4`.
    #[serde(rename = "type")]
    kind: String,
    value: String,
    #[serde(default)]
    time: Option<DateTime<Utc>>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    directives: Vec<String>,
    /// Modules that must not analyze it.
    #[serde(default)]
    exclude_modules: Vec<String>,
}

/// The form, as the document shows it.
#[derive(ToSchema)]
#[allow(dead_code)]
pub(crate) struct SubmitForm {
    /// The submission, as JSON text.
    analysis: SubmissionBody,
    /// Each file, repeated; its file name is its path in the alert.
    #[schema(value_type = Option<Vec<String>>, format = Binary)]
    file: Option<Vec<Vec<u8>>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SubmittedBody {
    /// The new root's id.
    id: Uuid,
    /// The tasks it queued.
    queued: Vec<i64>,
}

/// Reads a form field into memory, refusing one past `limit` bytes.
async fn text_field(
    field: axum::extract::multipart::Field<'_>,
    limit: usize,
) -> Result<String, ApiError> {
    let mut bytes = Vec::new();
    let mut stream = field;
    while let Some(chunk) = stream
        .chunk()
        .await
        .map_err(|e| ApiError::bad_request(format!("the analysis field: {e}")))?
    {
        if bytes.len() + chunk.len() > limit {
            return Err(ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("the analysis field is over {limit} bytes"),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| ApiError::bad_request("the analysis field isn't UTF-8"))
}

/// Creates a root from a submission and queues its first tasks. Its files are spooled on this node as
/// they arrive, and the root records who submitted it.
#[utoipa::path(
    post,
    path = "/api/analysis/v1/submit",
    tag = "analysis",
    request_body(content = SubmitForm, content_type = "multipart/form-data"),
    responses(
        (status = 201, description = "The root is created and its tasks queued", body = SubmittedBody),
        (status = 400, description = "A form or submission that can't be taken, such as a mode that doesn't exist; nothing was written", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:create, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The form, or its analysis field, is too large", body = ErrorBody),
    )
)]
pub(crate) async fn submit(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    form: Result<Multipart, axum::extract::multipart::MultipartRejection>,
) -> Result<(StatusCode, Json<SubmittedBody>), ApiError> {
    // before the body is read, so a key that can't submit can't make the node spool it
    if !web.service.allowed(&actor, &ALERT_CREATE).await? {
        return Err(ace_service::ServiceError::PermissionDenied {
            actor: actor.to_string(),
            permission: ALERT_CREATE,
        }
        .into());
    }
    let mut form = form.map_err(|e| ApiError::bad_request(e.body_text()))?;
    let too_large = |e: axum::extract::multipart::MultipartError| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "the form is too large")
        } else {
            ApiError::bad_request(format!("the form doesn't read: {e}"))
        }
    };
    let mut submission: Option<Submission> = None;
    let mut files = Vec::new();
    while let Some(field) = form.next_field().await.map_err(too_large)? {
        match field.name() {
            Some("analysis") if submission.is_none() => {
                let text = text_field(field, web.config.max_json_bytes).await?;
                submission = Some(serde_json::from_str(&text).map_err(|e| {
                    ApiError::bad_request(format!("the analysis field isn't a submission: {e}"))
                })?);
            }
            Some("analysis") => return Err(ApiError::bad_request("two analysis fields")),
            Some("file") => {
                if files.len() >= web.config.max_submitted_files {
                    return Err(ApiError::bad_request(format!(
                        "a submission holds at most {} files",
                        web.config.max_submitted_files
                    )));
                }
                let name = field.file_name().unwrap_or_default().to_owned();
                let path = AlertPath::new(name.clone())
                    .map_err(|e| ApiError::bad_request(format!("file name {name:?}: {e}")))?;
                let over = AtomicBool::new(false);
                let stream = field.map_err(|e| {
                    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
                        over.store(true, Ordering::Relaxed);
                    }
                    std::io::Error::other(e)
                });
                let mut reader = tokio_util::io::StreamReader::new(stream);
                let spooled = web.bucket.store().spool_reader(&mut reader).await;
                drop(reader);
                let spooled = spooled.map_err(|e| {
                    if over.load(Ordering::Relaxed) {
                        ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "the form is too large")
                    } else {
                        ApiError::bad_request(format!("file {name:?} didn't arrive: {e}"))
                    }
                })?;
                files.push(SubmittedFile { path, spooled });
            }
            other => {
                return Err(ApiError::bad_request(format!(
                    "an unexpected form field {other:?}"
                )));
            }
        }
    }
    let submission = submission.ok_or_else(|| ApiError::bad_request("no analysis field"))?;
    let submitted = web
        .service
        .submit(&actor, &web.bucket, &submission, &files)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(SubmittedBody {
            id: submitted.uuid,
            queued: submitted.queued,
        }),
    ))
}
