//! ace3's `user_preferences` router (PLAN.md 5.6, 5.7): the caller's own GUI preferences, under
//! `/api/users/v1/me/preferences` (the crate's docs map ace3's routes). Only a user has them, and they
//! need no grant. The GUI reads them itself through the service, as ace3's Flask views do.

use ace_service::{Preference, PreferenceKey};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// One of the caller's preferences.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PreferenceBody {
    /// The preference's name, such as `theme`.
    key: &'static str,
    /// Its value, in the shape its key has. `theme`'s is `{"mode": "system" | "light" | "dark" | "jd" |
    /// "halloween"}`. `alert_sections`' is `{"sections": {"<section id>": true | false}}`, whether each
    /// section of the alert page starts open, with at most 100 ids of 1 to 64 of `a-z`, `0-9` and `_`.
    /// `manage_columns`' is `{"order": [...], "hidden": [...]}`, the alert list's column ids (`date`,
    /// `description`, `queue`, `owner`, `disposition`, `status`) in the order they show and those hidden, normalized: an
    /// unknown id dropped, a missing one appended, and `description` never hidden.
    #[schema(value_type = Object)]
    value: Value,
    /// When the stored value last changed, or null when nothing is stored.
    updated_at: Option<DateTime<Utc>>,
    /// Whether this is the default rather than a value the caller set. A stored value this release can't
    /// read is given as the default too.
    is_default: bool,
}

impl From<Preference> for PreferenceBody {
    fn from(preference: Preference) -> Self {
        PreferenceBody {
            key: preference.value.key().name(),
            value: preference.value.to_json(),
            updated_at: preference.updated_at,
            is_default: preference.is_default,
        }
    }
}

/// Every preference the caller has, defaults filled in.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PreferencesBody {
    preferences: Vec<PreferenceBody>,
}

fn key(key: Result<Path<String>, PathRejection>) -> Result<PreferenceKey, ApiError> {
    let Path(name) = key?;
    PreferenceKey::named(&name).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no preference is named {name:?}"),
        )
    })
}

/// Every preference the caller has, each key's default where they set none.
#[utoipa::path(
    get,
    path = "/api/users/v1/me/preferences",
    tag = "users",
    responses(
        (status = 200, description = "The caller's preferences", body = PreferencesBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "An API key, which has no preferences", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<PreferencesBody>, ApiError> {
    let preferences = web.service.preferences(&actor).await?;
    Ok(Json(PreferencesBody {
        preferences: preferences.into_iter().map(Into::into).collect(),
    }))
}

/// One of the caller's preferences, its default if they set none.
#[utoipa::path(
    get,
    path = "/api/users/v1/me/preferences/{key}",
    tag = "users",
    params(("key" = String, Path, description = "The preference's name, such as `theme`")),
    responses(
        (status = 200, description = "The preference", body = PreferenceBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "An API key, which has no preferences", body = ErrorBody),
        (status = 404, description = "No preference has that name", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    name: Result<Path<String>, PathRejection>,
) -> Result<Json<PreferenceBody>, ApiError> {
    let key = key(name)?;
    Ok(Json(web.service.preference(&actor, key).await?.into()))
}

/// Sets one of the caller's preferences. The body is the value, in its key's shape; a field the key
/// doesn't have is refused, and one left out takes its default.
#[utoipa::path(
    put,
    path = "/api/users/v1/me/preferences/{key}",
    tag = "users",
    params(("key" = String, Path, description = "The preference's name, such as `theme`")),
    request_body(content = Object, description = "The value, such as `{\"mode\": \"dark\"}` for `theme`"),
    responses(
        (status = 200, description = "The preference, as stored", body = PreferenceBody),
        (status = 400, description = "A value that isn't this key's, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "An API key, or a session's request from another site", body = ErrorBody),
        (status = 404, description = "No preference has that name", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    name: Result<Path<String>, PathRejection>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<PreferenceBody>, ApiError> {
    let key = key(name)?;
    let Json(body) = body?;
    let value = key.parse(body)?;
    Ok(Json(
        web.service.set_preference(&actor, &value).await?.into(),
    ))
}

/// Forgets the caller's value for a preference, so its default applies again.
#[utoipa::path(
    delete,
    path = "/api/users/v1/me/preferences/{key}",
    tag = "users",
    params(("key" = String, Path, description = "The preference's name, such as `theme`")),
    responses(
        (status = 200, description = "The preference's default, which now applies", body = PreferenceBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "An API key, or a session's request from another site", body = ErrorBody),
        (status = 404, description = "No preference has that name", body = ErrorBody),
    )
)]
pub(crate) async fn reset(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    name: Result<Path<String>, PathRejection>,
) -> Result<Json<PreferenceBody>, ApiError> {
    let key = key(name)?;
    Ok(Json(
        web.service.reset_preference(&actor, key).await?.into(),
    ))
}
