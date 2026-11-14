//! The preferences page (PLAN.md 5.11's `preferences` area), ace3's `preferences.html` and its view
//! `main.preferences`, and the theme menu and section pins that 5.7 and 5.8 brought.
//!
//! ace3's page renders in Flask and saves from the browser: `preferences.js` patches `/api/v2/users/me`,
//! `ace.js` saves the theme, `manage_columns.js` the columns, and `preferences_api_keys.js` lists and
//! changes the keys through `/api/v2/users/me/apikeys`. Here the page is drawn on the server and every
//! control is a link or a form, each writing through the service, which checks it and writes its audit
//! row. Every post is a `SignedIn` request, so `Service::authenticate_request` has checked it came from
//! this site (5.7's CSRF check). ace3's views and their places here:
//! - `GET /preferences` (`main.preferences`): `page`, over `Service::own_account`, `own_api_keys`,
//!   `own_permissions` (ace3's `list_held_catalog`) and `manage_columns`.
//! - The profile form, `PATCH /users/me`: `POST /preferences/profile`, over `Service::update_own_profile`.
//!   Its fields are what 5.6 lets a user change about themself: the display name, the timezone and, since
//!   7.13, the default queue, ace3's `users.queue`, which the alert list's `$USER_QUEUE` stands for. The
//!   username and email are shown, not edited, as ace3's page says an administrator sets them. The
//!   timezones are chrono-tz's list, the one the service checks against, where ace3 offers pytz's.
//! - The link to the password change, `/login/change` (5.11's auth area).
//! - The theme radios, `save_theme`: a form posting to `/preferences/theme`, 5.7's `set_theme`.
//! - The column chooser, `_manage_column_chooser.html`: the alert list's own forms (5.10), coming back
//!   here.
//! - The API keys card. Listing them needs no grant; making, changing and revoking need `user:self`, and
//!   a user without it sees their keys and no controls, as in ace3:
//!   - `POST /users/me/apikeys`: `POST /preferences/keys`, over `Service::create_own_api_key`. The answer
//!     is a page with the token, shown this once: `Cache-Control: no-store`, never a redirect, so the
//!     token is in no URL, and nothing here logs it. ace3 shows it in a modal and drops it when it closes.
//!   - `PUT /users/me/apikeys/{id}`: `GET` and `POST /preferences/keys/{id}`, over
//!     `Service::set_own_api_key_scope`.
//!   - `DELETE /users/me/apikeys/{id}`: `POST /preferences/keys/{id}/revoke`, over
//!     `Service::revoke_own_api_key`, where ace3 asks to confirm first.
//!
//!   A scope is boxes for the permissions the user holds, but `user:self`, as ace3's picker offers, and a
//!   box for other patterns, such as `signature:*`, ace3's "custom" row. The service checks it as ace3's
//!   `_check_scope_within_grants` does (5.6), and a refusal comes back as 400 with the form as it was and
//!   the service's reason, such as `alert:* covers alert:create, which you don't hold`. A key whose scope
//!   is `*:*`, ace3's `inherit_user_scope`, which only an administrator sets, isn't offered for editing,
//!   as in ace3.
//!
//! Left out: ace3's copy button for a new key,
//! which needs a script (the token is in a read-only field to select); its confirm dialog before a revoke.
//!
//! The theme menu of the base layout, ace3's theme switcher, is a form that posts to `/preferences/theme`,
//! which works without a script and comes back to the page it was on. It writes through
//! `Service::set_preference`, which audits it.
//!
//! The alert page's section pins are ace3's `alert_sections.js`, as a form: it reads the stored choices,
//! sets the one section and stores them again, as that script does, so a pin in another tab since this
//! page loaded is kept.

use ace_service::{
    AlertSectionsPreference, ApiKey, ApiKeyId, CatalogEntry, Effect, ManageColumnsPreference,
    PermissionPattern, PreferenceValue, Profile, ServiceError, Theme, ThemePreference, User,
    is_section_id,
};
use askama::Template;
use axum::Form;
use axum::body::Bytes;
use axum::extract::rejection::{FormRejection, PathRejection};
use axum::extract::{Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono_tz::Tz;
use serde::Deserialize;
use uuid::Uuid;

use crate::Gui;
use crate::list::{ColumnChoice, all, column_choices, one, pairs};
use crate::session::{Failure, SignedIn, local_path, render, see_other};
use crate::templates::Layout;

/// Where the page's forms come back to.
const HERE: &str = "/preferences";

/// A permission a key's scope may name, as a box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered {
    /// `major:minor`.
    pub name: String,
    pub description: &'static str,
    pub checked: bool,
}

/// One of the user's keys, as the card lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRow {
    pub id: Uuid,
    pub name: String,
    /// Its allows, `major:minor`, and any deny an administrator set on it.
    pub scope: Vec<String>,
    /// When it was made, in the user's timezone.
    pub created: String,
    /// Whether the user may change its scope: they hold `user:self` and it isn't `*:*`.
    pub editable: bool,
}

/// A key form's fields as they were sent, to draw again with a refusal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyDraft {
    pub name: String,
    /// The boxes ticked, `major:minor`.
    pub ticked: Vec<String>,
    /// The other patterns, as typed.
    pub other: String,
}

/// What the preferences page shows.
#[derive(Debug, Clone)]
pub struct PreferencesView {
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub timezone: String,
    pub timezones: Vec<&'static str>,
    /// The queue they work (PLAN.md 7.13).
    pub queue: String,
    pub themes: &'static [Theme],
    /// The column chooser's rows, which `column_chooser.html` reads.
    pub columns: Vec<ColumnChoice>,
    /// Where the chooser's forms come back to.
    pub here: &'static str,
    pub keys: Vec<KeyRow>,
    /// Whether the user holds `user:self`, which making, changing and revoking a key need.
    pub can_manage_keys: bool,
    /// The new key form's boxes.
    pub offered: Vec<Offered>,
    pub draft: KeyDraft,
    /// Why the profile form was refused.
    pub profile_problem: Option<String>,
    /// Why the new key form was refused.
    pub key_problem: Option<String>,
    /// What the last form did.
    pub notice: Option<&'static str>,
}

impl PreferencesView {
    /// Whether the timezone select marks this one as the user's.
    pub fn is_timezone(&self, zone: &str) -> bool {
        zone == self.timezone
    }
}

/// `/preferences`.
#[derive(Debug, Template)]
#[template(path = "preferences.html")]
pub struct PreferencesPage {
    pub layout: Layout,
    pub view: PreferencesView,
}

/// `/preferences/keys/{id}`: changing one of the user's keys.
#[derive(Debug, Template)]
#[template(path = "api_key.html")]
pub struct KeyPage {
    pub layout: Layout,
    pub id: Uuid,
    pub offered: Vec<Offered>,
    pub draft: KeyDraft,
    /// The key's denies, which stay whatever the scope.
    pub denies: Vec<String>,
    pub problem: Option<String>,
}

/// The answer to making a key: its token, this once.
#[derive(Template)]
#[template(path = "new_api_key.html")]
pub struct NewKeyPage {
    pub layout: Layout,
    pub name: String,
    pub token: String,
}

impl std::fmt::Debug for NewKeyPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewKeyPage")
            .field("name", &self.name)
            .field("token", &"[hidden]")
            .finish_non_exhaustive()
    }
}

/// Every timezone chrono-tz knows, which is what the service accepts.
pub fn timezones() -> Vec<&'static str> {
    chrono_tz::TZ_VARIANTS
        .iter()
        .map(|zone| zone.name())
        .collect()
}

/// The boxes for the permissions the user holds, ticked as the draft says.
pub fn offered(held: &[&'static CatalogEntry], ticked: &[String]) -> Vec<Offered> {
    held.iter()
        .map(|entry| {
            let name = entry.name.to_string();
            Offered {
                checked: ticked.contains(&name),
                name,
                description: entry.description,
            }
        })
        .collect()
}

/// A key's rows for the card, with its creation in the user's timezone.
pub fn key_row(key: &ApiKey, can_manage: bool, tz: Tz) -> KeyRow {
    KeyRow {
        id: key.id.0,
        name: key.name.clone(),
        scope: key
            .grants
            .iter()
            .map(|grant| match grant.effect {
                Effect::Allow => format!("{}:{}", grant.major, grant.minor),
                Effect::Deny => format!("deny {}:{}", grant.major, grant.minor),
            })
            .collect(),
        created: key
            .created_at
            .with_timezone(&tz)
            .format("%Y-%m-%d %H:%M %Z")
            .to_string(),
        editable: can_manage && !inherits(key),
    }
}

/// Whether a key's scope is `*:*`, ace3's `inherit_user_scope`.
pub(crate) fn inherits(key: &ApiKey) -> bool {
    key.grants
        .iter()
        .any(|grant| grant.effect == Effect::Allow && grant.major == "*" && grant.minor == "*")
}

/// The page's view from what the service read.
pub fn preferences_view(
    user: &User,
    keys: &[ApiKey],
    held: &[&'static CatalogEntry],
    can_manage_keys: bool,
    columns: &ManageColumnsPreference,
) -> PreferencesView {
    let tz: Tz = user.timezone.parse().unwrap_or(Tz::UTC);
    PreferencesView {
        username: user.username.clone(),
        display_name: user.display_name.clone().unwrap_or_default(),
        email: user.email.clone().unwrap_or_default(),
        timezone: user.timezone.clone(),
        timezones: timezones(),
        queue: user.queue.clone(),
        themes: Theme::ALL,
        columns: column_choices(columns),
        here: HERE,
        keys: keys
            .iter()
            .map(|key| key_row(key, can_manage_keys, tz))
            .collect(),
        can_manage_keys,
        offered: offered(held, &[]),
        draft: KeyDraft::default(),
        profile_problem: None,
        key_problem: None,
        notice: None,
    }
}

/// What the page reads, through the service.
async fn read_view(gui: &Gui, viewer: &SignedIn) -> Result<PreferencesView, ServiceError> {
    let actor = &viewer.actor;
    let user = gui.service.own_account(actor).await?;
    let keys = gui.service.own_api_keys(actor).await?;
    let held = gui.service.own_permissions(actor).await?;
    let can_manage = gui.service.allowed(actor, &ace_service::USER_SELF).await?;
    let columns = gui.service.manage_columns(actor).await.unwrap_or_else(|error| {
        tracing::warn!(%actor, "reading manage_columns failed, so the chooser has the default: {error}");
        ManageColumnsPreference::default()
    });
    Ok(preferences_view(&user, &keys, &held, can_manage, &columns))
}

/// The page with a change made to its view, at a status.
async fn page_with(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    status: StatusCode,
    change: impl FnOnce(&mut PreferencesView),
) -> Response {
    let mut view = match read_view(gui, &viewer).await {
        Ok(view) => view,
        Err(error) => return Failure::from_service(error, parts).into_response(),
    };
    change(&mut view);
    let mut response = render(&PreferencesPage {
        layout: viewer.layout,
        view,
    });
    *response.status_mut() = status;
    response
}

#[derive(Debug, Deserialize)]
pub(crate) struct PageQuery {
    /// What the last form did: `profile`, `key` or `revoked`.
    done: Option<String>,
}

/// `GET /preferences`.
pub(crate) async fn page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Query(query): Query<PageQuery>,
) -> Response {
    let notice = match query.done.as_deref() {
        Some("profile") => Some("Your profile is saved."),
        Some("key") => Some("The key is changed."),
        Some("revoked") => Some("The key is revoked. Anything using it stops working."),
        _ => None,
    };
    page_with(&gui, viewer, &parts, StatusCode::OK, |view| {
        view.notice = notice;
    })
    .await
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProfileForm {
    display_name: String,
    timezone: String,
    /// Left out, the queue stays as it is.
    queue: Option<String>,
}

/// `POST /preferences/profile`: the user's own display name, timezone and default queue.
pub(crate) async fn save_profile(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    form: Result<Form<ProfileForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return Failure::new(StatusCode::BAD_REQUEST, "The form wasn't complete.", &parts)
            .into_response();
    };
    let profile = Profile {
        display_name: Some(form.display_name),
        email: None,
        timezone: Some(form.timezone),
        queue: form.queue,
    };
    match gui
        .service
        .update_own_profile(&viewer.actor, &profile)
        .await
    {
        Ok(_) => see_other("/preferences?done=profile", None),
        Err(ServiceError::InvalidRequest(problem)) => {
            page_with(&gui, viewer, &parts, StatusCode::BAD_REQUEST, |view| {
                view.profile_problem = Some(format!("Not saved: {problem}."));
            })
            .await
        }
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// A key form's fields: `name`, `scope` once for each box ticked, and `other`, more patterns separated
/// by spaces, commas or lines.
pub(crate) fn draft_of(body: &[u8]) -> KeyDraft {
    let form = pairs(body);
    KeyDraft {
        name: one(&form, "name").unwrap_or("").to_owned(),
        ticked: all(&form, "scope"),
        other: one(&form, "other").unwrap_or("").to_owned(),
    }
}

/// The draft's scope, or why a pattern isn't one.
pub(crate) fn scope_of(draft: &KeyDraft) -> Result<Vec<PermissionPattern>, String> {
    draft
        .ticked
        .iter()
        .map(String::as_str)
        .chain(
            draft
                .other
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|part| !part.is_empty()),
        )
        .map(|text| {
            let (major, minor) = text
                .split_once(':')
                .ok_or_else(|| format!("{text} isn't a pattern, which is major:minor"))?;
            PermissionPattern::new(major, minor).map_err(|error| format!("{text}: {error}"))
        })
        .collect()
}

/// Why a key form was refused, if the service's answer is a refusal of the form.
fn key_refusal(error: &ServiceError) -> Option<String> {
    matches!(
        error,
        ServiceError::InvalidRequest(_) | ServiceError::InvalidKeyName
    )
    .then(|| error.to_string())
}

/// A 403 for a user without `user:self`, before a form is read.
fn needs_user_self(parts: &Parts) -> Failure {
    Failure::new(
        StatusCode::FORBIDDEN,
        "Changing your API keys needs user:self. Ask an administrator.",
        parts,
    )
}

/// The page again, with the new key form as it was sent and why it was refused.
async fn new_key_refused(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    problem: String,
    draft: KeyDraft,
) -> Response {
    page_with(gui, viewer, parts, StatusCode::BAD_REQUEST, |view| {
        view.key_problem = Some(format!("No key was made: {problem}."));
        for offered in &mut view.offered {
            offered.checked = draft.ticked.contains(&offered.name);
        }
        view.draft = draft;
    })
    .await
}

/// `POST /preferences/keys`: makes a key for the user, and shows its token this once.
pub(crate) async fn create_key(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let draft = draft_of(&body);
    let scope = match scope_of(&draft) {
        Ok(scope) => scope,
        Err(problem) => return new_key_refused(&gui, viewer, &parts, problem, draft).await,
    };
    let made = gui
        .service
        .create_own_api_key(&viewer.actor, &draft.name, &scope)
        .await;
    match made {
        Ok(key) => {
            let mut response = render(&NewKeyPage {
                layout: viewer.layout,
                name: draft.name.trim().to_owned(),
                token: key.token.expose().to_owned(),
            });
            *response.status_mut() = StatusCode::CREATED;
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => match key_refusal(&error) {
            Some(problem) => new_key_refused(&gui, viewer, &parts, problem, draft).await,
            None => Failure::from_service(error, &parts).into_response(),
        },
    }
}

/// One of the user's own keys, or the answer saying they have none such.
async fn own_key(
    gui: &Gui,
    viewer: &SignedIn,
    id: Result<Path<Uuid>, PathRejection>,
    parts: &Parts,
) -> Result<ApiKey, Failure> {
    let Ok(Path(id)) = id else {
        return Err(Failure::new(
            StatusCode::BAD_REQUEST,
            "A key's id is a uuid.",
            parts,
        ));
    };
    let keys = gui
        .service
        .own_api_keys(&viewer.actor)
        .await
        .map_err(|error| Failure::from_service(error, parts))?;
    keys.into_iter()
        .find(|key| key.id.0 == id)
        .ok_or_else(|| no_key(parts))
}

fn no_key(parts: &Parts) -> Failure {
    Failure::new(StatusCode::NOT_FOUND, "You have no such API key.", parts)
}

/// The edit page for a key, with a draft and a problem.
async fn key_page_with(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    key: &ApiKey,
    draft: Option<KeyDraft>,
    problem: Option<String>,
    status: StatusCode,
) -> Response {
    let held = match gui.service.own_permissions(&viewer.actor).await {
        Ok(held) => held,
        Err(error) => return Failure::from_service(error, parts).into_response(),
    };
    let draft = draft.unwrap_or_else(|| {
        let allows: Vec<String> = key
            .grants
            .iter()
            .filter(|grant| grant.effect == Effect::Allow)
            .map(|grant| format!("{}:{}", grant.major, grant.minor))
            .collect();
        let offered_names: Vec<String> = held.iter().map(|entry| entry.name.to_string()).collect();
        let (ticked, other): (Vec<String>, Vec<String>) = allows
            .into_iter()
            .partition(|name| offered_names.contains(name));
        KeyDraft {
            name: key.name.clone(),
            ticked,
            other: other.join("\n"),
        }
    });
    let mut response = render(&KeyPage {
        layout: viewer.layout,
        id: key.id.0,
        offered: offered(&held, &draft.ticked),
        draft,
        denies: key
            .grants
            .iter()
            .filter(|grant| grant.effect == Effect::Deny)
            .map(|grant| format!("{}:{}", grant.major, grant.minor))
            .collect(),
        problem,
    });
    *response.status_mut() = status;
    response
}

/// Whether the viewer may change their keys, or the answer saying they may not.
async fn may_manage(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    match gui
        .service
        .allowed(&viewer.actor, &ace_service::USER_SELF)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(needs_user_self(parts)),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

/// `GET /preferences/keys/{id}`: the form that changes one of the user's keys.
pub(crate) async fn key_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
) -> Response {
    if let Err(failure) = may_manage(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let key = match own_key(&gui, &viewer, id, &parts).await {
        Ok(key) => key,
        Err(failure) => return failure.into_response(),
    };
    if inherits(&key) {
        return Failure::new(
            StatusCode::FORBIDDEN,
            "This key's scope is *:*, which an administrator set. Ask them to change it.",
            &parts,
        )
        .into_response();
    }
    key_page_with(&gui, viewer, &parts, &key, None, None, StatusCode::OK).await
}

/// `POST /preferences/keys/{id}`: renames one of the user's keys and replaces its scope.
pub(crate) async fn save_key(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    let Ok(Path(id)) = id else {
        return Failure::new(StatusCode::BAD_REQUEST, "A key's id is a uuid.", &parts)
            .into_response();
    };
    let draft = draft_of(&body);
    let problem = match scope_of(&draft) {
        Ok(scope) => {
            match gui
                .service
                .set_own_api_key_scope(&viewer.actor, ApiKeyId(id), &draft.name, &scope)
                .await
            {
                Ok(_) => return see_other("/preferences?done=key", None),
                Err(ServiceError::NotFound(_)) => return no_key(&parts).into_response(),
                Err(error) => match key_refusal(&error) {
                    Some(problem) => problem,
                    None => return Failure::from_service(error, &parts).into_response(),
                },
            }
        }
        Err(problem) => problem,
    };
    let key = match own_key(&gui, &viewer, Ok(Path(id)), &parts).await {
        Ok(key) => key,
        Err(failure) => return failure.into_response(),
    };
    key_page_with(
        &gui,
        viewer,
        &parts,
        &key,
        Some(draft),
        Some(format!("Not changed: {problem}.")),
        StatusCode::BAD_REQUEST,
    )
    .await
}

/// `POST /preferences/keys/{id}/revoke`: deletes one of the user's keys.
pub(crate) async fn revoke_key(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
) -> Response {
    let Ok(Path(id)) = id else {
        return Failure::new(StatusCode::BAD_REQUEST, "A key's id is a uuid.", &parts)
            .into_response();
    };
    match gui
        .service
        .revoke_own_api_key(&viewer.actor, ApiKeyId(id))
        .await
    {
        Ok(true) => see_other("/preferences?done=revoked", None),
        Ok(false) => no_key(&parts).into_response(),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ThemeForm {
    mode: String,
    next: Option<String>,
}

/// `POST /preferences/theme`.
pub(crate) async fn set_theme(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    form: Result<Form<ThemeForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return Failure::new(StatusCode::BAD_REQUEST, "The form wasn't complete.", &parts)
            .into_response();
    };
    let Some(mode) = Theme::named(&form.mode) else {
        return Failure::new(StatusCode::BAD_REQUEST, "There's no such theme.", &parts)
            .into_response();
    };
    let value = PreferenceValue::Theme(ThemePreference { mode });
    if let Err(error) = gui.service.set_preference(&viewer.actor, &value).await {
        return Failure::from_service(error, &parts).into_response();
    }
    see_other(
        form.next.as_deref().and_then(local_path).unwrap_or("/"),
        None,
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct SectionForm {
    section: String,
    open: String,
    next: Option<String>,
}

/// `POST /preferences/alert-section`: whether one section of the alert page starts open.
pub(crate) async fn set_alert_section(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    form: Result<Form<SectionForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return Failure::new(StatusCode::BAD_REQUEST, "The form wasn't complete.", &parts)
            .into_response();
    };
    let open = match form.open.as_str() {
        "true" => true,
        "false" => false,
        _ => {
            return Failure::new(StatusCode::BAD_REQUEST, "open is true or false.", &parts)
                .into_response();
        }
    };
    if !is_section_id(&form.section) {
        return Failure::new(StatusCode::BAD_REQUEST, "There's no such section.", &parts)
            .into_response();
    }
    let mut sections = match gui.service.alert_sections(&viewer.actor).await {
        Ok(sections) => sections,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    sections.insert(form.section, open);
    let value = PreferenceValue::AlertSections(AlertSectionsPreference { sections });
    // the key's own check, so more sections than it holds is refused as a bad request
    let value = match value.key().parse(value.to_json()) {
        Ok(value) => value,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    if let Err(error) = gui.service.set_preference(&viewer.actor, &value).await {
        return Failure::from_service(error, &parts).into_response();
    }
    see_other(
        form.next.as_deref().and_then(local_path).unwrap_or("/"),
        None,
    )
}
