//! `/api/observables/v1/comments`: analysts' comments on an observable by its type and value, across
//! alerts (`ace_service`'s `observable_comments` docs). Reading needs `observable:read`; adding, editing
//! and deleting need `observable:write`, and only a comment's author edits or deletes it. A comment's text
//! is returned as it was sent: show it as text.

use ace_service::ObservableComment;
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// The user a comment is by, as they're called now.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AuthorBody {
    id: Uuid,
    username: String,
    display_name: Option<String>,
}

/// A comment on an observable, which applies to it in every alert.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommentBody {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    /// The value as it's matched, such as a lowercased sha256.
    value: String,
    author: AuthorBody,
    /// What wrote it: the author, or one of their API keys.
    created_by: ActorBody,
    /// The text as it was sent. Show it as text.
    comment: String,
    created_at: DateTime<Utc>,
    /// When the text last changed; null when it never has.
    edited_at: Option<DateTime<Utc>>,
}

impl From<ObservableComment> for CommentBody {
    fn from(comment: ObservableComment) -> Self {
        CommentBody {
            id: comment.id,
            kind: comment.kind,
            value: comment.value,
            author: AuthorBody {
                id: comment.author.id.0,
                username: comment.author.username,
                display_name: comment.author.display_name,
            },
            created_by: ActorBody::from(comment.created_by),
            comment: comment.comment,
            created_at: comment.created_at,
            edited_at: comment.edited_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CommentsBody {
    comments: Vec<CommentBody>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct CommentsQuery {
    /// The observable's type, such as `ipv4`.
    #[serde(rename = "type")]
    #[param(rename = "type")]
    kind: String,
    /// Its value; a file's is its sha256.
    value: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewCommentRequest {
    /// The observable's type, such as `ipv4`.
    #[serde(rename = "type")]
    kind: String,
    /// Its value; a file's is its sha256.
    value: String,
    /// 1 to 16384 characters, not all whitespace.
    comment: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EditCommentRequest {
    /// 1 to 16384 characters, not all whitespace.
    comment: String,
}

/// The comments on an observable, oldest first, whichever alerts hold it.
#[utoipa::path(
    get,
    path = "/api/observables/v1/comments",
    tag = "observables",
    params(CommentsQuery),
    responses(
        (status = 200, description = "The observable's comments", body = CommentsBody),
        (status = 400, description = "A type that doesn't exist, a value that isn't one for it, or a missing parameter", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold observable:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<CommentsQuery>, QueryRejection>,
) -> Result<Json<CommentsBody>, ApiError> {
    let Query(query) = query?;
    let comments = web
        .service
        .observable_comments(&actor, &query.kind, &query.value)
        .await?;
    Ok(Json(CommentsBody {
        comments: comments.into_iter().map(CommentBody::from).collect(),
    }))
}

/// Comments on an observable, whether or not an alert holds it yet. The caller is the author: a user, or
/// the owner of the API key.
#[utoipa::path(
    post,
    path = "/api/observables/v1/comments",
    tag = "observables",
    request_body = NewCommentRequest,
    responses(
        (status = 201, description = "The comment", body = CommentBody),
        (status = 400, description = "A type that doesn't exist, a value that isn't one for it, a comment that's empty or too long, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold observable:write, isn't a person (an API key with no owner), or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn add(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<NewCommentRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CommentBody>), ApiError> {
    let Json(body) = body?;
    let comment = web
        .service
        .add_observable_comment(&actor, &body.kind, &body.value, &body.comment)
        .await?;
    Ok((StatusCode::CREATED, Json(CommentBody::from(comment))))
}

/// Replaces a comment's text and marks it edited. Text that differs only in line endings or the
/// whitespace at its ends changes nothing.
#[utoipa::path(
    patch,
    path = "/api/observables/v1/comments/{id}",
    tag = "observables",
    params(("id" = i64, Path, description = "The comment's id")),
    request_body = EditCommentRequest,
    responses(
        (status = 200, description = "The comment as it is now", body = CommentBody),
        (status = 400, description = "An id that isn't one, a comment that's empty or too long, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold observable:write, isn't the comment's author, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such comment", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn edit(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
    body: Result<Json<EditCommentRequest>, JsonRejection>,
) -> Result<Json<CommentBody>, ApiError> {
    let Path(id) = id?;
    let Json(body) = body?;
    let comment = web
        .service
        .edit_observable_comment(&actor, id, &body.comment)
        .await?;
    Ok(Json(CommentBody::from(comment)))
}

/// Deletes a comment. Its audit row keeps what it said.
#[utoipa::path(
    delete,
    path = "/api/observables/v1/comments/{id}",
    tag = "observables",
    params(("id" = i64, Path, description = "The comment's id")),
    responses(
        (status = 204, description = "The comment is gone"),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold observable:write, isn't the comment's author, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such comment", body = ErrorBody),
    )
)]
pub(crate) async fn delete(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    web.service.delete_observable_comment(&actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
