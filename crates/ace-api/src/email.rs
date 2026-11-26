//! `/api/email/v1`: an archived email, decrypted, by its Message-ID or its hash, every archived email
//! of many Message-IDs, and a zip of them.

use std::io::{Seek, SeekFrom, Write};

use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::Web;
use crate::alerts::{ZIP_PASSWORD, ZipBody};
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// The zip's name and its top-level directory, ace3's `DOWNLOAD_LABEL`.
const DOWNLOAD_LABEL: &str = "archived-emails";

/// Which archived email to read.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ArchiveQuery {
    /// The Message-ID, with or without its `<` and `>`. A query parameter, as in ace3, since a
    /// Message-ID can hold a `/`.
    message_id: String,
}

/// An email as it arrived, RFC 822.
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
pub(crate) struct Rfc822Body(#[allow(dead_code)] Vec<u8>);

/// The newest archived email with this Message-ID, decrypted, as ace3's `GET /email/archive`. The
/// read is in the audit record.
#[utoipa::path(
    get,
    path = "/api/email/v1/archive",
    tag = "email",
    params(ArchiveQuery),
    responses(
        (status = 200, description = "The email", content_type = "message/rfc822", body = Rfc822Body),
        (status = 400, description = "No message_id", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold email:read", body = ErrorBody),
        (status = 404, description = "No archived email has that Message-ID", body = ErrorBody),
        (status = 500, description = "This node has no encryption key, so archived emails can't be decrypted", body = ErrorBody),
    )
)]
pub(crate) async fn archive(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<ArchiveQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    let archive = archive_of(&web)?;
    let email = web
        .service
        .archived_email(&actor, archive, &query.message_id)
        .await?;
    Ok(rfc822(email))
}

fn archive_of(web: &Web) -> Result<&ace_core::email_archive::EmailArchive, ApiError> {
    web.archive.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "this node has no email archive",
        )
    })
}

fn rfc822(email: ace_service::ArchivedEmail) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "message/rfc822".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}.eml\"", email.hash),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        email.bytes,
    )
        .into_response()
}

/// Message-IDs, with or without their angle brackets.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct MessageIdsRequest {
    /// 1 to 1000 Message-IDs of 1 to 998 characters, white space around each ignored.
    #[schema(min_items = 1, max_items = 1000)]
    message_ids: Vec<String>,
}

/// One archived email of a Message-ID.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ArchivedCopyBody {
    /// The email's sha256, which `GET /api/email/v1/archive/{sha256}` takes.
    sha256: String,
    /// The last time it was archived under this Message-ID.
    archived_at: DateTime<Utc>,
    /// Its size in bytes; null for one archived before ace-rs recorded sizes.
    size: Option<i64>,
}

/// One requested Message-ID, at its index in the request. No copies and no expired copies: nothing
/// was archived under it, or it was archived too long ago for its row to be kept. No copies and some
/// expired: it was archived, and has expired from the archive since.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ArchiveLookupBody {
    index: usize,
    /// The Message-ID as the archive stores it, in angle brackets.
    message_id: String,
    /// Every archived email with this Message-ID, newest first.
    copies: Vec<ArchivedCopyBody>,
    /// How many emails archived under it have expired.
    expired_copies: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ArchiveLookupsBody {
    results: Vec<ArchiveLookupBody>,
}

fn copy_body(copy: &ace_service::EmailCopy) -> ArchivedCopyBody {
    ArchivedCopyBody {
        sha256: copy.hash.clone(),
        archived_at: copy.archived_at,
        size: copy.size,
    }
}

/// Every archived email of each Message-ID, newest first, in request order, as ace3's `POST
/// /email/archive/lookup`: its sha256, when it was last archived and its size. It opens nothing, so
/// it isn't audited.
#[utoipa::path(
    post,
    path = "/api/email/v1/archive/lookup",
    tag = "email",
    request_body = MessageIdsRequest,
    responses(
        (status = 200, description = "Each Message-ID's archived emails", body = ArchiveLookupsBody),
        (status = 400, description = "No Message-IDs, more than 1000, or one that's empty or longer than 998 characters", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold email:read", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn lookup(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<MessageIdsRequest>, JsonRejection>,
) -> Result<Json<ArchiveLookupsBody>, ApiError> {
    let Json(body) = body?;
    let found = web
        .service
        .archived_email_copies(&actor, &body.message_ids)
        .await?;
    Ok(Json(ArchiveLookupsBody {
        results: found
            .into_iter()
            .map(|found| ArchiveLookupBody {
                index: found.index,
                copies: found.copies.iter().map(copy_body).collect(),
                message_id: found.message_id,
                expired_copies: found.expired,
            })
            .collect(),
    }))
}

/// One archived email by its sha256, from `POST /api/email/v1/archive/lookup`, decrypted and as it
/// arrived: any copy of a Message-ID, not only the newest, as ace3's `GET /email/archive/{sha256}`.
/// The read is in the audit record.
#[utoipa::path(
    get,
    path = "/api/email/v1/archive/{sha256}",
    tag = "email",
    params(("sha256" = String, Path, description = "The email's sha256, 64 lower-case hex digits")),
    responses(
        (status = 200, description = "The email", content_type = "message/rfc822", body = Rfc822Body),
        (status = 400, description = "Not a sha256", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold email:read", body = ErrorBody),
        (status = 404, description = "No archived email has that sha256", body = ErrorBody),
        (status = 500, description = "This node has no encryption key, so archived emails can't be decrypted", body = ErrorBody),
    )
)]
pub(crate) async fn by_hash(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    sha256: Result<Path<String>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path(sha256) = sha256?;
    let archive = archive_of(&web)?;
    let email = web
        .service
        .archived_email_by_hash(&actor, archive, &sha256)
        .await?;
    Ok(rfc822(email))
}

/// What `manifest.json` says of a Message-ID with emails.
#[derive(Serialize)]
struct ManifestEntry {
    index: usize,
    message_id: String,
    copies: Vec<ManifestCopy>,
}

#[derive(Serialize)]
struct ManifestCopy {
    sha256: String,
    archived_at: DateTime<Utc>,
    size: Option<i64>,
    path: String,
}

#[derive(Serialize)]
struct Skipped {
    index: usize,
    message_id: String,
    /// `expired` or `not_archived`.
    reason: &'static str,
}

#[derive(Serialize)]
struct Manifest {
    emails: Vec<ManifestEntry>,
    skipped: Vec<Skipped>,
}

/// Every archived email of each Message-ID, with a manifest, as one zip encrypted with AES-256 and the
/// password `infected`, as ace3's `POST /email/archive/download`: `archived-emails/manifest.json`, the
/// emails and every Message-ID with none and why, and `archived-emails/<index>-<n>/<sha256>.eml` for
/// each email, the index its Message-ID's place in the request. At most 500 emails and 1 GiB. The
/// download is in the audit record with every email it holds.
#[utoipa::path(
    post,
    path = "/api/email/v1/archive/download",
    tag = "email",
    request_body = MessageIdsRequest,
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "No Message-IDs, more than 1000, or one that's empty or longer than 998 characters", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold email:read", body = ErrorBody),
        (status = 404, description = "None of the Message-IDs has an archived email", body = ErrorBody),
        (status = 413, description = "The body is too large, or the emails are more than 500 or 1 GiB", body = ErrorBody),
        (status = 500, description = "This node has no encryption key, so archived emails can't be decrypted", body = ErrorBody),
    )
)]
pub(crate) async fn download(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<MessageIdsRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body?;
    let archive = archive_of(&web)?;
    let download = web
        .service
        .archived_email_download(&actor, archive, &body.message_ids)
        .await?;
    let mut manifest = Manifest {
        emails: Vec::new(),
        skipped: download
            .skipped
            .iter()
            .map(|(index, message_id, reason)| Skipped {
                index: *index,
                message_id: message_id.clone(),
                reason,
            })
            .collect(),
    };
    let options = || {
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .with_aes_encryption(zip::AesMode::Aes256, ZIP_PASSWORD)
    };
    let mut zip = Some(zip::ZipWriter::new(
        tempfile::tempfile().map_err(ApiError::internal)?,
    ));
    for found in &download.found {
        // the index keeps two Message-IDs apart, and nothing a Message-ID holds names an entry
        let directory = format!("{DOWNLOAD_LABEL}/{:04}", found.index);
        let mut copies = Vec::new();
        for copy in &found.copies {
            // one email in memory at a time: each is at most the core's 64 MiB
            let email = web.service.open_archived_copy(archive, copy).await?;
            let path = format!("{directory}/{}.eml", copy.hash);
            let mut writer = zip.take().ok_or_else(|| ApiError::internal("no zip"))?;
            let name = path.clone();
            writer = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
                writer
                    .start_file(name, options())
                    .map_err(std::io::Error::other)?;
                writer.write_all(&email)?;
                Ok(writer)
            })
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)?;
            zip = Some(writer);
            copies.push(ManifestCopy {
                sha256: copy.hash.clone(),
                archived_at: copy.archived_at,
                size: copy.size,
                path,
            });
        }
        manifest.emails.push(ManifestEntry {
            index: found.index,
            message_id: found.message_id.clone(),
            copies,
        });
    }
    let manifest = serde_json::to_vec_pretty(&manifest).map_err(ApiError::internal)?;
    let mut writer = zip.take().ok_or_else(|| ApiError::internal("no zip"))?;
    let zipped = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        writer
            .start_file(format!("{DOWNLOAD_LABEL}/manifest.json"), options())
            .map_err(std::io::Error::other)?;
        writer.write_all(&manifest)?;
        let mut out = writer.finish().map_err(std::io::Error::other)?;
        out.seek(SeekFrom::Start(0))?;
        Ok(out)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    crate::alerts::zip_download(zipped, DOWNLOAD_LABEL)
}
