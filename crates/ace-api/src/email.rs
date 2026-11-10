//! `/api/email/v1`: an archived email, decrypted, by its Message-ID.

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

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
    let Some(archive) = web.archive.as_ref() else {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "this node has no email archive",
        ));
    };
    let email = web
        .service
        .archived_email(&actor, archive, &query.message_id)
        .await?;
    Ok((
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
        .into_response())
}
