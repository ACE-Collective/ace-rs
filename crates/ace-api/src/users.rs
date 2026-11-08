//! `/api/users/v1`: users, groups, grants, the permission catalog, API keys, and the caller's own
//! account, password and keys (PLAN.md 5.6's `users` router).
//!
//! An administrator's routes need `user:read` to look and `user:write` to change, as ace3's do. The
//! `/me` routes are the caller's own account, which only a user has, so an API key is refused with 403
//! as not holding `user:self`: reading and changing your profile and password need no grant, and
//! managing your own keys needs `user:self`. A token appears once, in the response that made it, with
//! `Cache-Control: no-store`, as ace3 sends it. A grant, revoke or group change that would take
//! `user:write` from the caller is 400, as disabling yourself is; ace3 refuses only the second.

use ace_service::{
    ApiKey, ApiKeyId, CatalogEntry, Effect, Grant, Group, GroupId, Holder, NewApiKey, Password,
    PermissionPattern, Profile, SessionCookie, User, UserDetail, UserId, Username,
};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EffectBody {
    Allow,
    Deny,
}

impl From<Effect> for EffectBody {
    fn from(effect: Effect) -> Self {
        match effect {
            Effect::Allow => EffectBody::Allow,
            Effect::Deny => EffectBody::Deny,
        }
    }
}

impl From<EffectBody> for Effect {
    fn from(effect: EffectBody) -> Self {
        match effect {
            EffectBody::Allow => Effect::Allow,
            EffectBody::Deny => Effect::Deny,
        }
    }
}

/// A user. Never their password or its hash.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct UserBody {
    id: Uuid,
    username: String,
    display_name: Option<String>,
    email: Option<String>,
    /// An IANA name, such as `Europe/London`.
    timezone: String,
    enabled: bool,
    created_at: DateTime<Utc>,
    /// How many API keys they own.
    api_keys: i64,
}

impl From<User> for UserBody {
    fn from(user: User) -> Self {
        UserBody {
            id: user.id.0,
            username: user.username,
            display_name: user.display_name,
            email: user.email,
            timezone: user.timezone,
            enabled: user.enabled,
            created_at: user.created_at,
            api_keys: user.api_keys,
        }
    }
}

/// One grant: an effect on a pattern of `major:minor`, whose parts may hold fnmatch wildcards. A deny
/// wins over any allow.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GrantBody {
    id: i64,
    major: String,
    minor: String,
    effect: EffectBody,
}

impl From<Grant> for GrantBody {
    fn from(grant: Grant) -> Self {
        GrantBody {
            id: grant.id,
            major: grant.major,
            minor: grant.minor,
            effect: grant.effect.into(),
        }
    }
}

fn grants(grants: Vec<Grant>) -> Vec<GrantBody> {
    grants.into_iter().map(GrantBody::from).collect()
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GroupBody {
    id: Uuid,
    name: String,
    /// Its members' ids, by username.
    members: Vec<Uuid>,
    /// What its members hold through it.
    grants: Vec<GrantBody>,
}

impl From<Group> for GroupBody {
    fn from(group: Group) -> Self {
        GroupBody {
            id: group.id.0,
            name: group.name,
            members: group.members.into_iter().map(|member| member.0).collect(),
            grants: grants(group.grants),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct UserDetailBody {
    user: UserBody,
    /// Their own grants.
    grants: Vec<GrantBody>,
    /// Their groups, whose grants they hold too.
    groups: Vec<GroupBody>,
}

impl From<UserDetail> for UserDetailBody {
    fn from(detail: UserDetail) -> Self {
        UserDetailBody {
            user: detail.user.into(),
            grants: grants(detail.grants),
            groups: detail.groups.into_iter().map(GroupBody::from).collect(),
        }
    }
}

/// An API key, never its token.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ApiKeyBody {
    id: Uuid,
    name: String,
    /// The user it belongs to, or null for a key that stands for a service.
    owner: Option<Uuid>,
    /// Its own grants: its scope's allows, and any deny. A key with an owner holds only what the owner
    /// holds too.
    grants: Vec<GrantBody>,
    created_at: DateTime<Utc>,
    created_by: ActorBody,
}

impl From<ApiKey> for ApiKeyBody {
    fn from(key: ApiKey) -> Self {
        ApiKeyBody {
            id: key.id.0,
            name: key.name,
            owner: key.owner.map(|owner| owner.0),
            grants: grants(key.grants),
            created_at: key.created_at,
            created_by: key.created_by.into(),
        }
    }
}

/// A key just made, with its token, which this response is the only one to show.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct NewApiKeyBody {
    id: Uuid,
    /// `Authorization: Bearer <token>`.
    token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CatalogEntryBody {
    major: String,
    minor: String,
    description: String,
}

impl From<&CatalogEntry> for CatalogEntryBody {
    fn from(entry: &CatalogEntry) -> Self {
        CatalogEntryBody {
            major: entry.name.major().to_owned(),
            minor: entry.name.minor().to_owned(),
            description: entry.description.to_owned(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CreatedBody {
    id: Uuid,
}

/// Whether the request changed anything. Asking for what's already so is a success that changed nothing.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ChangedBody {
    changed: bool,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct UsersQuery {
    /// Whether to list disabled users too; true when left out.
    include_disabled: Option<bool>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct KeysQuery {
    /// Only this user's keys. Every key, those with no owner included, when left out.
    owner: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewUserRequest {
    /// 1 to 64 ASCII letters, digits and `_ . @ + -`, stored lowercase.
    username: String,
    /// At least 12 characters.
    password: String,
    display_name: Option<String>,
    email: Option<String>,
    /// An IANA name; `UTC` when left out.
    timezone: Option<String>,
}

/// A profile change. A field left out stays as it is, and an empty display name or email clears it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileRequest {
    display_name: Option<String>,
    email: Option<String>,
    timezone: Option<String>,
}

/// What a user changes on their own account. The email is an administrator's to change, as in ace3.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnProfileRequest {
    display_name: Option<String>,
    timezone: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnabledRequest {
    /// False ends their sessions and stops their keys. Nobody can disable themselves.
    enabled: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordRequest {
    /// At least 12 characters.
    password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnPasswordRequest {
    current: String,
    /// At least 12 characters.
    new: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupRequest {
    /// 1 to 255 characters, unique.
    name: String,
}

#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HolderKind {
    User,
    Group,
    ApiKey,
}

/// Who a grant is for. A component's grants come with the migration that adds it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct HolderBody {
    kind: HolderKind,
    id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantRequest {
    holder: HolderBody,
    /// The pattern's halves, in any case: stored lowercase. `*`, `?` and `[...]` are fnmatch wildcards.
    major: String,
    minor: String,
    effect: EffectBody,
}

/// One pattern of a key's scope, which the key is allowed.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopeEntry {
    major: String,
    minor: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewApiKeyRequest {
    /// 1 to 255 characters.
    name: String,
    /// The user it belongs to; left out, it stands for a service.
    owner: Option<Uuid>,
    /// Up to 64 patterns it's allowed. `*:*` is ace3's key that inherits its owner's permissions. Never
    /// `user:self`.
    scope: Vec<ScopeEntry>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApiKeyRequest {
    /// 1 to 255 characters.
    name: String,
    /// The patterns it's allowed, replacing the ones it had; a deny on it stays.
    scope: Vec<ScopeEntry>,
}

fn pattern(major: &str, minor: &str) -> Result<PermissionPattern, ApiError> {
    PermissionPattern::new(major, minor).map_err(|error| ApiError::bad_request(error.to_string()))
}

fn scope(entries: &[ScopeEntry]) -> Result<Vec<PermissionPattern>, ApiError> {
    entries
        .iter()
        .map(|entry| pattern(&entry.major, &entry.minor))
        .collect()
}

/// A new key's token, which no cache may keep.
fn new_key(key: NewApiKey) -> Response {
    (
        StatusCode::CREATED,
        [(header::CACHE_CONTROL, "no-store")],
        Json(NewApiKeyBody {
            id: key.id.0,
            token: key.token.expose().to_owned(),
        }),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/api/users/v1/users",
    tag = "users",
    params(UsersQuery),
    responses(
        (status = 200, description = "Every user, by username", body = Vec<UserBody>),
        (status = 400, description = "A query that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:read", body = ErrorBody),
    )
)]
pub(crate) async fn list_users(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<UsersQuery>, QueryRejection>,
) -> Result<Json<Vec<UserBody>>, ApiError> {
    let Query(query) = query?;
    let users = web
        .service
        .users(&actor, query.include_disabled.unwrap_or(true))
        .await?;
    Ok(Json(users.into_iter().map(UserBody::from).collect()))
}

/// Makes a user with no grants.
#[utoipa::path(
    post,
    path = "/api/users/v1/users",
    tag = "users",
    request_body = NewUserRequest,
    responses(
        (status = 201, description = "The user is made", body = CreatedBody),
        (status = 400, description = "A username, password or profile that isn't allowed, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 409, description = "The username is taken", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn create_user(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<NewUserRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CreatedBody>), ApiError> {
    let Json(body) = body?;
    let username =
        Username::new(&body.username).map_err(|error| ApiError::bad_request(error.to_string()))?;
    let profile = Profile {
        display_name: body.display_name,
        email: body.email,
        timezone: body.timezone,
    };
    let id = web
        .service
        .create_user(&actor, &username, Password::new(body.password), &profile)
        .await?;
    Ok((StatusCode::CREATED, Json(CreatedBody { id: id.0 })))
}

#[utoipa::path(
    get,
    path = "/api/users/v1/users/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "The user's id")),
    responses(
        (status = 200, description = "The user, their grants and their groups", body = UserDetailBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:read", body = ErrorBody),
        (status = 404, description = "No such user", body = ErrorBody),
    )
)]
pub(crate) async fn user(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<UserDetailBody>, ApiError> {
    let Path(id) = id?;
    Ok(Json(web.service.user(&actor, UserId(id)).await?.into()))
}

#[utoipa::path(
    patch,
    path = "/api/users/v1/users/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "The user's id")),
    request_body = ProfileRequest,
    responses(
        (status = 200, description = "The profile is as asked", body = ChangedBody),
        (status = 400, description = "A field that isn't allowed, an id that isn't a uuid, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such user", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn update_user(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<ProfileRequest>, JsonRejection>,
) -> Result<Json<ChangedBody>, ApiError> {
    let (Path(id), Json(body)) = (id?, body?);
    let profile = Profile {
        display_name: body.display_name,
        email: body.email,
        timezone: body.timezone,
    };
    let changed = web
        .service
        .update_user(&actor, UserId(id), &profile)
        .await?;
    Ok(Json(ChangedBody { changed }))
}

/// Turns a user on or off. Off ends their sessions and stops their keys; on brings back the keys.
#[utoipa::path(
    put,
    path = "/api/users/v1/users/{id}/enabled",
    tag = "users",
    params(("id" = Uuid, Path, description = "The user's id")),
    request_body = EnabledRequest,
    responses(
        (status = 200, description = "The user is as asked", body = ChangedBody),
        (status = 400, description = "Disabling yourself, an id that isn't a uuid, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such user", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_enabled(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<EnabledRequest>, JsonRejection>,
) -> Result<Json<ChangedBody>, ApiError> {
    let (Path(id), Json(body)) = (id?, body?);
    let changed = web
        .service
        .set_user_enabled(&actor, UserId(id), body.enabled)
        .await?;
    Ok(Json(ChangedBody { changed }))
}

/// Sets someone's password without the old one, and ends their sessions.
#[utoipa::path(
    put,
    path = "/api/users/v1/users/{id}/password",
    tag = "users",
    params(("id" = Uuid, Path, description = "The user's id")),
    request_body = PasswordRequest,
    responses(
        (status = 204, description = "The password is set"),
        (status = 400, description = "A password too short or too long, an id that isn't a uuid, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such user", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn reset_password(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<PasswordRequest>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let (Path(id), Json(body)) = (id?, body?);
    web.service
        .reset_password(&actor, UserId(id), Password::new(body.password))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/users/v1/groups",
    tag = "users",
    responses(
        (status = 200, description = "Every group, by name, with its members and grants", body = Vec<GroupBody>),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:read", body = ErrorBody),
    )
)]
pub(crate) async fn list_groups(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<Vec<GroupBody>>, ApiError> {
    let groups = web.service.groups(&actor).await?;
    Ok(Json(groups.into_iter().map(GroupBody::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/users/v1/groups",
    tag = "users",
    request_body = GroupRequest,
    responses(
        (status = 201, description = "The group is made, with no members or grants", body = CreatedBody),
        (status = 400, description = "A name that isn't allowed, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 409, description = "The name is taken", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn create_group(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<GroupRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<CreatedBody>), ApiError> {
    let Json(body) = body?;
    let id = web.service.create_group(&actor, &body.name).await?;
    Ok((StatusCode::CREATED, Json(CreatedBody { id: id.0 })))
}

/// Deletes a group with its memberships and grants, which its members stop holding.
#[utoipa::path(
    delete,
    path = "/api/users/v1/groups/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "The group's id")),
    responses(
        (status = 204, description = "The group is gone"),
        (status = 400, description = "An id that isn't a uuid, or a group you hold user:write through", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such group", body = ErrorBody),
    )
)]
pub(crate) async fn delete_group(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    if web.service.delete_group(&actor, GroupId(id)).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no group {id}"),
        ))
    }
}

/// Puts a user in a group. Putting them in again changes nothing.
#[utoipa::path(
    put,
    path = "/api/users/v1/groups/{id}/members/{user}",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "The group's id"),
        ("user" = Uuid, Path, description = "The user's id"),
    ),
    responses(
        (status = 204, description = "The user is a member"),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such group or user", body = ErrorBody),
    )
)]
pub(crate) async fn add_member(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    ids: Result<Path<(Uuid, Uuid)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path((group, user)) = ids?;
    web.service
        .add_group_member(&actor, GroupId(group), UserId(user))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/users/v1/groups/{id}/members/{user}",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "The group's id"),
        ("user" = Uuid, Path, description = "The user's id"),
    ),
    responses(
        (status = 204, description = "The user is no longer a member"),
        (status = 400, description = "An id that isn't a uuid, or taking yourself out of the group you hold user:write through", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "The user isn't a member of such a group", body = ErrorBody),
    )
)]
pub(crate) async fn remove_member(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    ids: Result<Path<(Uuid, Uuid)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path((group, user)) = ids?;
    if web
        .service
        .remove_group_member(&actor, GroupId(group), UserId(user))
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("{user} isn't a member of group {group}"),
        ))
    }
}

fn holder(body: &HolderBody) -> Holder {
    match body.kind {
        HolderKind::User => Holder::User(UserId(body.id)),
        HolderKind::Group => Holder::Group(GroupId(body.id)),
        HolderKind::ApiKey => Holder::ApiKey(ApiKeyId(body.id)),
    }
}

/// Gives a user, group or key an allow or a deny on a pattern. A grant that's there already changes
/// nothing. One that covers no permission ACE checks is allowed, as ace3 allows it, and logged.
#[utoipa::path(
    post,
    path = "/api/users/v1/grants",
    tag = "users",
    request_body = GrantRequest,
    responses(
        (status = 200, description = "The holder has the grant", body = ChangedBody),
        (status = 400, description = "A pattern that isn't one, a deny that would take user:write from you, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such holder", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn grant(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<GrantRequest>, JsonRejection>,
) -> Result<Json<ChangedBody>, ApiError> {
    let Json(body) = body?;
    let pattern = pattern(&body.major, &body.minor)?;
    let changed = web
        .service
        .grant(&actor, &holder(&body.holder), &pattern, body.effect.into())
        .await?;
    Ok(Json(ChangedBody { changed }))
}

/// Removes the grant `POST /api/users/v1/grants` would add.
#[utoipa::path(
    post,
    path = "/api/users/v1/grants/revoke",
    tag = "users",
    request_body = GrantRequest,
    responses(
        (status = 200, description = "The holder hasn't the grant", body = ChangedBody),
        (status = 400, description = "A pattern that isn't one, revoking your own user:write, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn revoke(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<GrantRequest>, JsonRejection>,
) -> Result<Json<ChangedBody>, ApiError> {
    let Json(body) = body?;
    let pattern = pattern(&body.major, &body.minor)?;
    let changed = web
        .service
        .revoke(&actor, &holder(&body.holder), &pattern, body.effect.into())
        .await?;
    Ok(Json(ChangedBody { changed }))
}

/// The permissions ACE checks, for choosing what to grant.
#[utoipa::path(
    get,
    path = "/api/users/v1/catalog",
    tag = "users",
    responses(
        (status = 200, description = "The catalog", body = Vec<CatalogEntryBody>),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:read", body = ErrorBody),
    )
)]
pub(crate) async fn catalog(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<Vec<CatalogEntryBody>>, ApiError> {
    let catalog = web.service.permission_catalog(&actor).await?;
    Ok(Json(catalog.iter().map(CatalogEntryBody::from).collect()))
}

#[utoipa::path(
    get,
    path = "/api/users/v1/keys",
    tag = "users",
    params(KeysQuery),
    responses(
        (status = 200, description = "The keys, oldest first", body = Vec<ApiKeyBody>),
        (status = 400, description = "An owner that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:read", body = ErrorBody),
    )
)]
pub(crate) async fn list_keys(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<KeysQuery>, QueryRejection>,
) -> Result<Json<Vec<ApiKeyBody>>, ApiError> {
    let Query(query) = query?;
    let keys = web
        .service
        .api_keys(&actor, query.owner.map(UserId))
        .await?;
    Ok(Json(keys.into_iter().map(ApiKeyBody::from).collect()))
}

/// Makes a key holding its scope, for a user or standing for a service.
#[utoipa::path(
    post,
    path = "/api/users/v1/keys",
    tag = "users",
    request_body = NewApiKeyRequest,
    responses(
        (status = 201, description = "The key, with its token, shown this once", body = NewApiKeyBody),
        (status = 400, description = "A name or scope that isn't allowed, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such owner", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn create_key(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<NewApiKeyRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body?;
    let scope = scope(&body.scope)?;
    let key = web
        .service
        .create_api_key(&actor, &body.name, body.owner.map(UserId), &scope)
        .await?;
    Ok(new_key(key))
}

/// Renames a key and replaces its scope. Its token stays the same, so a key in use picks up the change.
#[utoipa::path(
    put,
    path = "/api/users/v1/keys/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "The key's id")),
    request_body = ApiKeyRequest,
    responses(
        (status = 200, description = "The key is as asked", body = ChangedBody),
        (status = 400, description = "A name or scope that isn't allowed, an id that isn't a uuid, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such key", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn update_key(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<ApiKeyRequest>, JsonRejection>,
) -> Result<Json<ChangedBody>, ApiError> {
    let (Path(id), Json(body)) = (id?, body?);
    let scope = scope(&body.scope)?;
    let changed = web
        .service
        .set_api_key_scope(&actor, ApiKeyId(id), &body.name, &scope)
        .await?;
    Ok(Json(ChangedBody { changed }))
}

/// Deletes a key and its grants. Nothing brings it back.
#[utoipa::path(
    delete,
    path = "/api/users/v1/keys/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "The key's id")),
    responses(
        (status = 204, description = "The key is gone"),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such key", body = ErrorBody),
    )
)]
pub(crate) async fn revoke_key(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    if web.service.revoke_api_key(&actor, ApiKeyId(id)).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(no_key(id))
    }
}

fn no_key(id: Uuid) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, format!("no API key {id}"))
}

/// The caller's own account.
#[utoipa::path(
    get,
    path = "/api/users/v1/me",
    tag = "users",
    responses(
        (status = 200, description = "The caller's account", body = UserBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "An API key, which has no account of its own", body = ErrorBody),
    )
)]
pub(crate) async fn me(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<UserBody>, ApiError> {
    Ok(Json(web.service.own_account(&actor).await?.into()))
}

/// Changes the caller's own display name or timezone, which needs no grant.
#[utoipa::path(
    patch,
    path = "/api/users/v1/me",
    tag = "users",
    request_body = OwnProfileRequest,
    responses(
        (status = 200, description = "The caller's account, as changed", body = UserBody),
        (status = 400, description = "A field that isn't allowed, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "An API key, or a session's request from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn update_me(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<OwnProfileRequest>, JsonRejection>,
) -> Result<Json<UserBody>, ApiError> {
    let Json(body) = body?;
    let profile = Profile {
        display_name: body.display_name,
        email: None,
        timezone: body.timezone,
    };
    web.service.update_own_profile(&actor, &profile).await?;
    Ok(Json(web.service.own_account(&actor).await?.into()))
}

/// Changes the caller's own password, proving the current one, and ends every session of theirs, this
/// one too, so the response clears the cookie and they log in again, as in ace3.
#[utoipa::path(
    put,
    path = "/api/users/v1/me/password",
    tag = "users",
    request_body = OwnPasswordRequest,
    responses(
        (status = 204, description = "The password is changed and the caller logged out"),
        (status = 400, description = "A new password too short or too long, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, one that isn't valid, or the wrong current password", body = ErrorBody),
        (status = 403, description = "An API key, or a session's request from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn change_password(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<OwnPasswordRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body?;
    web.service
        .change_own_password(&actor, Password::new(body.current), Password::new(body.new))
        .await?;
    let clear = SessionCookie::new(web.config.transport).clear();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear).map_err(ApiError::internal)?,
    );
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

/// The caller's own keys.
#[utoipa::path(
    get,
    path = "/api/users/v1/me/keys",
    tag = "users",
    responses(
        (status = 200, description = "The caller's keys, oldest first", body = Vec<ApiKeyBody>),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "An API key, which has no account of its own", body = ErrorBody),
    )
)]
pub(crate) async fn my_keys(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<Vec<ApiKeyBody>>, ApiError> {
    let keys = web.service.own_api_keys(&actor).await?;
    Ok(Json(keys.into_iter().map(ApiKeyBody::from).collect()))
}

/// Makes a key for the caller, which needs `user:self`. Its scope has to list at least one pattern, each
/// covering permissions ACE checks that the caller holds.
#[utoipa::path(
    post,
    path = "/api/users/v1/me/keys",
    tag = "users",
    request_body = ApiKeyRequest,
    responses(
        (status = 201, description = "The key, with its token, shown this once", body = NewApiKeyBody),
        (status = 400, description = "A name or scope that isn't allowed, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:self, which no API key does, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn create_my_key(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<ApiKeyRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(body) = body?;
    let scope = scope(&body.scope)?;
    let key = web
        .service
        .create_own_api_key(&actor, &body.name, &scope)
        .await?;
    Ok(new_key(key))
}

/// Renames one of the caller's keys and replaces its scope, under the rules for making one.
#[utoipa::path(
    put,
    path = "/api/users/v1/me/keys/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "The key's id")),
    request_body = ApiKeyRequest,
    responses(
        (status = 200, description = "The key is as asked", body = ChangedBody),
        (status = 400, description = "A name or scope that isn't allowed, an id that isn't a uuid, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:self, which no API key does, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "The caller has no such key", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn update_my_key(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<ApiKeyRequest>, JsonRejection>,
) -> Result<Json<ChangedBody>, ApiError> {
    let (Path(id), Json(body)) = (id?, body?);
    let scope = scope(&body.scope)?;
    let changed = web
        .service
        .set_own_api_key_scope(&actor, ApiKeyId(id), &body.name, &scope)
        .await?;
    Ok(Json(ChangedBody { changed }))
}

/// Deletes one of the caller's keys.
#[utoipa::path(
    delete,
    path = "/api/users/v1/me/keys/{id}",
    tag = "users",
    params(("id" = Uuid, Path, description = "The key's id")),
    responses(
        (status = 204, description = "The key is gone"),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold user:self, which no API key does, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "The caller has no such key", body = ErrorBody),
    )
)]
pub(crate) async fn revoke_my_key(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    if web.service.revoke_own_api_key(&actor, ApiKeyId(id)).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(no_key(id))
    }
}
