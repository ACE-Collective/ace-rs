//! `/api/lists/v1`: the analyst-edited lists (PLAN.md 5.14, `ace_service`'s `lists` docs), such as the
//! email whitelists. Reading needs `list:read`, and adding, replacing and deleting entries need
//! `list:write`, each write audited. An edit applies to the next task that reads its list, with no
//! restart. A value is returned as it was sent: show it as text.

use ace_service::{ListEntry, ListSummary, ListView, MatchKind, NewListEntry};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// How an entry matches a value.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MatchBody {
    /// The whole value.
    Exact,
    /// Anywhere in the value.
    Substring,
    /// A regular expression in the Rust `regex` crate's syntax, found anywhere in the value. It has no
    /// lookaround or backreferences, and matches in time linear in the value.
    Regex,
}

impl From<MatchKind> for MatchBody {
    fn from(kind: MatchKind) -> Self {
        match kind {
            MatchKind::Exact => MatchBody::Exact,
            MatchKind::Substring => MatchBody::Substring,
            MatchKind::Regex => MatchBody::Regex,
        }
    }
}

impl From<MatchBody> for MatchKind {
    fn from(kind: MatchBody) -> Self {
        match kind {
            MatchBody::Exact => MatchKind::Exact,
            MatchBody::Substring => MatchKind::Substring,
            MatchBody::Regex => MatchKind::Regex,
        }
    }
}

/// A list this server's modules read.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ListSummaryBody {
    name: String,
    /// What it's for, and what its entries are matched against.
    description: String,
    /// Each entry names an observable type.
    typed: bool,
    /// How many entries it has.
    entries: i64,
}

impl From<ListSummary> for ListSummaryBody {
    fn from(list: ListSummary) -> Self {
        ListSummaryBody {
            name: list.spec.name.to_owned(),
            description: list.spec.description.to_owned(),
            typed: list.spec.typed,
            entries: list.entries,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ListsBody {
    lists: Vec<ListSummaryBody>,
}

/// An entry on a list.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EntryBody {
    id: i64,
    list: String,
    #[serde(rename = "match")]
    kind: MatchBody,
    /// The value or the pattern, as it was sent. Show it as text.
    value: String,
    ignore_case: bool,
    /// On a typed list, the observable type it applies to.
    observable_type: Option<String>,
    /// Why it's there.
    note: String,
    /// After this it matches nothing; null never expires.
    expires_at: Option<DateTime<Utc>>,
    created_by: ActorBody,
    created_at: DateTime<Utc>,
    updated_by: ActorBody,
    updated_at: DateTime<Utc>,
}

impl From<ListEntry> for EntryBody {
    fn from(entry: ListEntry) -> Self {
        EntryBody {
            id: entry.id,
            list: entry.list,
            kind: entry.kind.into(),
            value: entry.value,
            ignore_case: entry.ignore_case,
            observable_type: entry.observable_type,
            note: entry.note,
            expires_at: entry.expires_at,
            created_by: ActorBody::from(entry.created_by),
            created_at: entry.created_at,
            updated_by: ActorBody::from(entry.updated_by),
            updated_at: entry.updated_at,
        }
    }
}

/// A list and its entries, in the order a module tries them.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ListBody {
    name: String,
    description: String,
    typed: bool,
    /// The lists' version: every committed edit to any list raises it.
    version: i64,
    entries: Vec<EntryBody>,
}

impl From<ListView> for ListBody {
    fn from(list: ListView) -> Self {
        ListBody {
            name: list.spec.name.to_owned(),
            description: list.spec.description.to_owned(),
            typed: list.spec.typed,
            version: list.version,
            entries: list.entries.into_iter().map(EntryBody::from).collect(),
        }
    }
}

fn ignore_case_by_default() -> bool {
    true
}

/// An entry, new or in place of one.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntryRequest {
    #[serde(rename = "match")]
    kind: MatchBody,
    /// The value, up to 4096 bytes, or a pattern, up to 1024, which has to compile.
    value: String,
    /// Compare without case; true unless false is sent, as ace3's whitelist did.
    #[serde(default = "ignore_case_by_default")]
    #[schema(default = true)]
    ignore_case: bool,
    /// On a typed list, the observable type it applies to; on another, leave it out.
    #[serde(default)]
    observable_type: Option<String>,
    /// Why it's there, up to 1024 characters.
    #[serde(default)]
    note: String,
    /// After this it matches nothing. It has to be in the future, unless it's the entry's own.
    #[serde(default)]
    expires_at: Option<DateTime<Utc>>,
}

impl From<EntryRequest> for NewListEntry {
    fn from(body: EntryRequest) -> Self {
        NewListEntry {
            kind: body.kind.into(),
            value: body.value,
            ignore_case: body.ignore_case,
            observable_type: body.observable_type,
            note: body.note,
            expires_at: body.expires_at,
        }
    }
}

/// The lists this server's modules read, with how many entries each has.
#[utoipa::path(
    get,
    path = "/api/lists/v1/lists",
    tag = "lists",
    responses(
        (status = 200, description = "The lists", body = ListsBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold list:read", body = ErrorBody),
    )
)]
pub(crate) async fn lists(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<ListsBody>, ApiError> {
    let lists = web.service.lists(&actor).await?;
    Ok(Json(ListsBody {
        lists: lists.into_iter().map(ListSummaryBody::from).collect(),
    }))
}

/// One list and its entries.
#[utoipa::path(
    get,
    path = "/api/lists/v1/lists/{list}",
    tag = "lists",
    params(("list" = String, Path, description = "The list's name")),
    responses(
        (status = 200, description = "The list", body = ListBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold list:read", body = ErrorBody),
        (status = 404, description = "No such list", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    Path(name): Path<String>,
) -> Result<Json<ListBody>, ApiError> {
    let list = web.service.list(&actor, &name).await?;
    Ok(Json(ListBody::from(list)))
}

/// Adds an entry to the end of a list. It applies to the next task that reads the list.
#[utoipa::path(
    post,
    path = "/api/lists/v1/lists/{list}/entries",
    tag = "lists",
    params(("list" = String, Path, description = "The list's name")),
    request_body = EntryRequest,
    responses(
        (status = 201, description = "The entry", body = EntryBody),
        (status = 400, description = "A value that's empty or too long, a pattern that doesn't compile or compiles too large alone or with the list's others, a list that would hold too many entries, a type the list doesn't take or one it needs, an expiry that passed, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold list:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such list", body = ErrorBody),
        (status = 409, description = "The list has an entry with this match, case, type and value already", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn add(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    Path(name): Path<String>,
    body: Result<Json<EntryRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<EntryBody>), ApiError> {
    let Json(body) = body?;
    let entry = web
        .service
        .add_list_entry(&actor, &name, &body.into())
        .await?;
    Ok((StatusCode::CREATED, Json(EntryBody::from(entry))))
}

/// Replaces what an entry holds, keeping its place on the list. A body that changes nothing changes
/// nothing.
#[utoipa::path(
    put,
    path = "/api/lists/v1/lists/{list}/entries/{id}",
    tag = "lists",
    params(
        ("list" = String, Path, description = "The list's name"),
        ("id" = i64, Path, description = "The entry's id"),
    ),
    request_body = EntryRequest,
    responses(
        (status = 200, description = "The entry as it is now", body = EntryBody),
        (status = 400, description = "An id that isn't one, or an entry that can't be stored, as for adding one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold list:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such list, or no such entry on it", body = ErrorBody),
        (status = 409, description = "Another entry on the list has this match, case, type and value", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn replace(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, i64)>, PathRejection>,
    body: Result<Json<EntryRequest>, JsonRejection>,
) -> Result<Json<EntryBody>, ApiError> {
    let Path((name, id)) = path?;
    let Json(body) = body?;
    let entry = web
        .service
        .edit_list_entry(&actor, &name, id, &body.into())
        .await?;
    Ok(Json(EntryBody::from(entry)))
}

/// Deletes an entry. Its audit row keeps what it was.
#[utoipa::path(
    delete,
    path = "/api/lists/v1/lists/{list}/entries/{id}",
    tag = "lists",
    params(
        ("list" = String, Path, description = "The list's name"),
        ("id" = i64, Path, description = "The entry's id"),
    ),
    responses(
        (status = 204, description = "The entry is gone"),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold list:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such list, or no such entry on it", body = ErrorBody),
    )
)]
pub(crate) async fn delete(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, i64)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path((name, id)) = path?;
    web.service.delete_list_entry(&actor, &name, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
