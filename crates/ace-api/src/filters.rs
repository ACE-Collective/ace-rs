//! `/api/filters/v1`: ace3's `filter_screens` and `saved_filters` routers (PLAN.md 5.6, 5.10). A screen's
//! descriptor and its share-link encoding, and the caller's saved filters (`ace_service`'s `filters` and
//! `saved_filters` docs). Every route needs the permission that reads the screen's data, `alert:read` for
//! both screens here, and a saved filter is its owner's alone.

use ace_service::filters::FilterSpec;
use ace_service::{FilterEntry, FilterScreen, NewSavedFilter, SavedFilter, SavedFilterChange};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::params::Params;

/// One filter a screen has.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FilterDescriptorBody {
    /// Its name in a filter entry.
    name: &'static str,
    /// Its name in a share link's `f`, which doesn't change.
    slug: &'static str,
    /// `text`, `multi`, `date_range` or `pair`: how an editor edits it.
    kind: &'static str,
    /// The values a `multi` filter offers. The alert list's `Disposition` offers the site's dispositions,
    /// which its overlay configures, in their order.
    options: Vec<String>,
    /// What a value looks like.
    hint: &'static str,
}

impl FilterDescriptorBody {
    fn of(spec: &FilterSpec, dispositions: &ace_service::Dispositions) -> Self {
        FilterDescriptorBody {
            name: spec.name,
            slug: spec.slug,
            kind: spec.kind.as_str(),
            options: ace_service::filters::options(spec, dispositions),
            hint: spec.hint,
        }
    }
}

/// One of ace3's filters this screen doesn't have yet.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct LeftOutBody {
    name: &'static str,
    slug: &'static str,
    /// Why, and the step that brings what it reads.
    why: &'static str,
}

/// What a screen filters on, for an editor.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FilterScreenBody {
    name: &'static str,
    filters: Vec<FilterDescriptorBody>,
    left_out: Vec<LeftOutBody>,
}

/// A filter list.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct FiltersRequest {
    /// Entries `{"name", "inverted", "values"}`, each value a string, or for `Observable` a `[type, value]`
    /// pair.
    #[schema(value_type = Vec<Object>)]
    filters: Value,
}

/// A share link's `f` values.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EncodedBody {
    /// The `f` query values of a share link, in order.
    f: Vec<String>,
}

/// A share link's filter list.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DecodedBody {
    #[schema(value_type = Vec<Object>)]
    filters: Value,
    /// A filter the link names that this screen doesn't have, which was left out.
    warnings: Vec<String>,
}

#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct DecodeQuery {
    /// The `f` values of a share link; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
}

#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ScreenQuery {
    /// The screen, `alerts` when left out, or `detection_points`.
    screen: Option<String>,
}

/// One of the caller's saved filters.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SavedFilterBody {
    id: Uuid,
    screen: &'static str,
    /// Show it as text.
    name: String,
    description: Option<String>,
    #[schema(value_type = Vec<Object>)]
    filters: Value,
    /// Its place among the screen's quick filters, from 0, or null.
    quick_filter_order: Option<i32>,
    quick_filter_indicator: bool,
    owner: Uuid,
    owner_name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<SavedFilter> for SavedFilterBody {
    fn from(saved: SavedFilter) -> Self {
        SavedFilterBody {
            id: saved.id,
            screen: saved.screen.name(),
            name: saved.name,
            description: saved.description,
            filters: serde_json::to_value(&saved.filters).expect("filters are JSON"),
            quick_filter_order: saved.quick_filter_order,
            quick_filter_indicator: saved.quick_filter_indicator,
            owner: saved.owner.0,
            owner_name: saved.owner_name,
            created_at: saved.created_at,
            updated_at: saved.updated_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SavedFiltersBody {
    saved_filters: Vec<SavedFilterBody>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewSavedFilterRequest {
    /// 1 to 255 characters, the caller's own on the screen.
    name: String,
    /// At most 1024 characters.
    description: Option<String>,
    /// At least one entry, as `POST /screens/{screen}/encode` takes them.
    #[schema(value_type = Vec<Object>)]
    filters: Value,
    /// Pin it as the last quick filter.
    #[serde(default)]
    quick_filter: bool,
    /// Show how many alerts it matches on its badge.
    #[serde(default)]
    quick_filter_indicator: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SavedFilterChangeRequest {
    name: Option<String>,
    description: Option<String>,
    #[schema(value_type = Option<Vec<Object>>)]
    filters: Option<Value>,
    quick_filter_indicator: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuickFiltersRequest {
    /// The quick filters, in order. Any of the caller's saved filters on the screen not listed is unpinned.
    ids: Vec<Uuid>,
}

fn entries(value: Value) -> Result<Vec<FilterEntry>, ApiError> {
    serde_json::from_value(value).map_err(|e| {
        ApiError::bad_request(format!(
            "filters are entries {{\"name\", \"inverted\", \"values\"}}: {e}"
        ))
    })
}

fn screen_of(params: &Params) -> Result<FilterScreen, ApiError> {
    match params.one("screen")? {
        None => Ok(FilterScreen::Alerts),
        Some(name) => FilterScreen::named(name).ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, format!("no filter screen {name:?}"))
        }),
    }
}

/// What a screen filters on: each filter's name, share-link slug, kind and options, and ace3's filters
/// that aren't here yet, with why.
#[utoipa::path(
    get,
    path = "/api/filters/v1/screens/{screen}",
    tag = "filters",
    params(("screen" = String, Path, description = "`alerts` or `detection_points`")),
    responses(
        (status = 200, description = "The screen's filters", body = FilterScreenBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold the screen's permission", body = ErrorBody),
        (status = 404, description = "No such screen", body = ErrorBody),
    )
)]
pub(crate) async fn screen(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    name: Result<Path<String>, PathRejection>,
) -> Result<Json<FilterScreenBody>, ApiError> {
    let Path(name) = name?;
    let screen = web.service.filter_screen(&actor, &name).await?;
    Ok(Json(FilterScreenBody {
        name: screen.name(),
        filters: screen
            .filters()
            .iter()
            .map(|spec| FilterDescriptorBody::of(spec, web.service.dispositions()))
            .collect(),
        left_out: screen
            .left_out()
            .iter()
            .map(|gone| LeftOutBody {
                name: gone.name,
                slug: gone.slug,
                why: gone.why,
            })
            .collect(),
    }))
}

/// A filter list as a share link's `f` values. The filters are checked for the screen first, so a link
/// isn't made from one it would refuse.
#[utoipa::path(
    post,
    path = "/api/filters/v1/screens/{screen}/encode",
    tag = "filters",
    params(("screen" = String, Path, description = "`alerts` or `detection_points`")),
    request_body = FiltersRequest,
    responses(
        (status = 200, description = "The share link's values", body = EncodedBody),
        (status = 400, description = "A filter the screen can't take, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold the screen's permission, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such screen", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn encode(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    name: Result<Path<String>, PathRejection>,
    body: Result<Json<FiltersRequest>, JsonRejection>,
) -> Result<Json<EncodedBody>, ApiError> {
    let Path(name) = name?;
    let Json(body) = body?;
    let f = web
        .service
        .encode_filters(&actor, &name, &entries(body.filters)?)
        .await?;
    Ok(Json(EncodedBody { f }))
}

/// The filter list a share link names. A filter that this screen doesn't have is left out and named in
/// `warnings`, so an old link still opens; a malformed one is refused.
#[utoipa::path(
    get,
    path = "/api/filters/v1/screens/{screen}/decode",
    tag = "filters",
    params(("screen" = String, Path, description = "`alerts` or `detection_points`"), DecodeQuery),
    responses(
        (status = 200, description = "The filter list", body = DecodedBody),
        (status = 400, description = "A value that's malformed or the screen can't take", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold the screen's permission", body = ErrorBody),
        (status = 404, description = "No such screen", body = ErrorBody),
    )
)]
pub(crate) async fn decode(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    name: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<DecodedBody>, ApiError> {
    let Path(name) = name?;
    let params = Params::of(raw)?;
    let (filters, warnings) = web
        .service
        .decode_filters(&actor, &name, &params.all("f"))
        .await?;
    Ok(Json(DecodedBody {
        filters: serde_json::to_value(&filters).expect("filters are JSON"),
        warnings,
    }))
}

/// The caller's saved filters on a screen: the quick filters first, in order, then the rest by name.
#[utoipa::path(
    get,
    path = "/api/filters/v1/saved",
    tag = "filters",
    params(ScreenQuery),
    responses(
        (status = 200, description = "The caller's saved filters", body = SavedFiltersBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold the screen's permission, or isn't a person (an API key with no owner)", body = ErrorBody),
        (status = 404, description = "No such screen", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<SavedFiltersBody>, ApiError> {
    let screen = screen_of(&Params::of(raw)?)?;
    let saved = web.service.saved_filters(&actor, screen).await?;
    Ok(Json(SavedFiltersBody {
        saved_filters: saved.into_iter().map(Into::into).collect(),
    }))
}

/// Saves a filter list on a screen for the caller.
#[utoipa::path(
    post,
    path = "/api/filters/v1/saved",
    tag = "filters",
    params(ScreenQuery),
    request_body = NewSavedFilterRequest,
    responses(
        (status = 201, description = "The saved filter", body = SavedFilterBody),
        (status = 400, description = "A name, description or filter that isn't one, too many saved filters, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold the screen's permission, isn't a person, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such screen", body = ErrorBody),
        (status = 409, description = "The caller has a saved filter with that name on the screen", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn create(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
    body: Result<Json<NewSavedFilterRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<SavedFilterBody>), ApiError> {
    let screen = screen_of(&Params::of(raw)?)?;
    let Json(body) = body?;
    let new = NewSavedFilter {
        name: body.name,
        description: body.description,
        filters: entries(body.filters)?,
        quick_filter: body.quick_filter,
        quick_filter_indicator: body.quick_filter_indicator,
    };
    let saved = web
        .service
        .create_saved_filter(&actor, screen, &new)
        .await?;
    Ok((StatusCode::CREATED, Json(saved.into())))
}

/// One of the caller's saved filters. Another user's isn't found.
#[utoipa::path(
    get,
    path = "/api/filters/v1/saved/{id}",
    tag = "filters",
    params(("id" = Uuid, Path, description = "The saved filter's id")),
    responses(
        (status = 200, description = "The saved filter", body = SavedFilterBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read, or isn't a person", body = ErrorBody),
        (status = 404, description = "No such saved filter of the caller's", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<SavedFilterBody>, ApiError> {
    let Path(id) = id?;
    Ok(Json(web.service.saved_filter(&actor, id).await?.into()))
}

/// Changes one of the caller's saved filters: each field the body has. Its filters are checked for its own
/// screen.
#[utoipa::path(
    patch,
    path = "/api/filters/v1/saved/{id}",
    tag = "filters",
    params(("id" = Uuid, Path, description = "The saved filter's id")),
    request_body = SavedFilterChangeRequest,
    responses(
        (status = 200, description = "The saved filter as it is now", body = SavedFilterBody),
        (status = 400, description = "A name, description or filter that isn't one, an id that isn't a uuid, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read, isn't the filter's owner, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such saved filter", body = ErrorBody),
        (status = 409, description = "The caller has another saved filter with that name on the screen", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn update(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<SavedFilterChangeRequest>, JsonRejection>,
) -> Result<Json<SavedFilterBody>, ApiError> {
    let Path(id) = id?;
    let Json(body) = body?;
    let change = SavedFilterChange {
        name: body.name,
        description: body.description,
        filters: body.filters.map(entries).transpose()?,
        quick_filter_indicator: body.quick_filter_indicator,
    };
    Ok(Json(
        web.service
            .update_saved_filter(&actor, id, &change)
            .await?
            .into(),
    ))
}

/// Deletes one of the caller's saved filters.
#[utoipa::path(
    delete,
    path = "/api/filters/v1/saved/{id}",
    tag = "filters",
    params(("id" = Uuid, Path, description = "The saved filter's id")),
    responses(
        (status = 204, description = "The saved filter is gone"),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read, isn't the filter's owner, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such saved filter", body = ErrorBody),
    )
)]
pub(crate) async fn delete(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    web.service.delete_saved_filter(&actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Makes these of the caller's saved filters the screen's quick filters, in this order, and unpins the
/// rest. Sending the same list again changes nothing.
#[utoipa::path(
    put,
    path = "/api/filters/v1/saved/quick",
    tag = "filters",
    params(ScreenQuery),
    request_body = QuickFiltersRequest,
    responses(
        (status = 200, description = "The caller's saved filters on the screen", body = SavedFiltersBody),
        (status = 400, description = "An id that isn't one of the caller's filters on the screen, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold the screen's permission, isn't a person, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such screen", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn quick(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
    body: Result<Json<QuickFiltersRequest>, JsonRejection>,
) -> Result<Json<SavedFiltersBody>, ApiError> {
    let screen = screen_of(&Params::of(raw)?)?;
    let Json(body) = body?;
    let saved = web
        .service
        .set_quick_filters(&actor, screen, &body.ids)
        .await?;
    Ok(Json(SavedFiltersBody {
        saved_filters: saved.into_iter().map(Into::into).collect(),
    }))
}
