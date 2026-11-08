//! The administration area (PLAN.md 5.11's `admin` area): ace3's `app/admin/` views and
//! `app/templates/admin/`, the hub and Users & Roles, over the `users` service of 5.6.
//!
//! `admin:read` gates the whole area, as ace3's blueprint-level `require_admin_area_access` does: every
//! route here checks it before anything else, and each page and write then needs its own permission,
//! which the service checks: `user:read` to look and `user:write` to change. ace3's writes go from the
//! page's script to `/api/v2` and skip the umbrella gate; here they're the area's own forms, so they
//! pass it too. A user without `admin:read` gets 403, and a visitor who isn't signed in goes to the
//! login. The base layout links to `/admin` for whoever holds `admin:read`, as ace3's navigation does.
//!
//! ace3's page renders in Flask and changes everything from `manage_users.js` through the `users`
//! router. Here every control is a link or a form, each a `SignedIn` post that has passed 5.7's
//! same-origin check, and each write is one service function, which checks its permission and writes
//! its audit row. A refusal the service gives about the form, such as a taken name, a weak password or
//! disabling yourself, draws the page again at 400 or 409 with the service's reason; anything else is the
//! error page. ace3's views and their places here:
//! - `admin.admin_hub` (`hub.html`): `GET /admin`, the tiles the viewer may open. Only Users & Roles is
//!   here: ace3's Observables tile (`detection.html`) comes with 7.6, its CLI (`cli.html`) with 5.12, and
//!   its Secrets (`secrets.html`) waits for the owner with 5.6's `secrets` router.
//! - `admin.manage_users` (`manage.html`): `GET /admin/users`, every user with their grants and groups,
//!   every group, the keys with no owner, and the forms for a new user and a new group. ace3's "hide
//!   disabled users" cookie is a link, `?disabled=hide`. ace3's page selects users with checkboxes and
//!   acts on the selection from a toolbar; here each user and each group is its own page with its forms:
//!   - `GET /admin/users/{id}`: the profile (`update_user`), enable or disable (`set_user_enabled`), a
//!     password reset (`reset_password`), the user's grants and their revokes (`grant`, `revoke`), the
//!     groups they're in (`add_group_member`, `remove_group_member`), and their keys (`create_api_key`,
//!     `set_api_key_scope`, `revoke_api_key`). A key's edit is `GET /admin/keys/{id}`.
//!   - `GET /admin/groups/{id}`: its members, its grants and its deletion (`delete_group`).
//!
//! A new user's or a reset password left blank is made by `Password::generate`, and a new key's token is
//! the service's: either is shown once, on a page with `Cache-Control: no-store`, never a redirect, so it's
//! in no URL, and nothing here logs it, as the preferences page does with a user's own key. A password the
//! administrator types isn't shown back. ace3 has the administrator type every password.
//!
//! What a grant gives is written beside it: the permissions in `CATALOG` its pattern covers. `*:*` is
//! everything, now and as permissions are added. A pattern that covers `user:write` lets its holder change
//! any grant, so they can give themselves `*:*`, as in ace3 (5.2); the page says so beside the grant form,
//! and an allow covering it is confirmed on a page of its own first, where ace3's script asks to confirm
//! only `*:*`. Self-harm is the service's to refuse: disabling yourself, as in ace3, and a change to grants
//! or groups that would leave you without `user:write` (`ServiceError::CantDropYourOwnUserWrite`), which
//! ace3 allows. The page draws your own Disable as a note instead of a button.
//!
//! Left out: ace3's bulk edit of several selected users at once; its username change in Edit User,
//! which 5.6's service has no write for; its default queue column, with 7.13's
//! queues; its confirm before revoking a key, which needs a script; making a key with no owner, which
//! `ace user create-key` and the API do (the page lists, changes and revokes them).

use std::collections::BTreeMap;

use ace_service::{
    ADMIN_READ, ApiKey, ApiKeyId, CATALOG, Effect, Grant, Group, GroupId, Holder, Password,
    PermissionPattern, Profile, ServiceError, USER_READ, USER_SELF, USER_WRITE, User, UserDetail,
    UserId, Username,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use crate::Gui;
use crate::list::{one, pairs};
use crate::preferences::{KeyDraft, Offered, draft_of, inherits, scope_of, timezones};
use crate::session::{Failure, SignedIn, render, see_other};
use crate::templates::Layout;

/// A page the hub offers, and the permission that shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub href: &'static str,
    pub title: &'static str,
    pub description: &'static str,
}

/// ace3's `ADMIN_MODULES`, of which this area has one so far.
const USERS_AND_ROLES: Module = Module {
    href: "/admin/users",
    title: "Users & Roles",
    description: "Manage users, auth groups, and permission grants.",
};

/// `/admin`.
#[derive(Debug, Template)]
#[template(path = "admin/hub.html")]
pub struct HubPage {
    pub layout: Layout,
    pub modules: Vec<Module>,
}

/// What a pattern gives whoever holds it, as the page says beside a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gives {
    /// The catalog's permissions it covers, `major:minor`.
    pub covers: Vec<String>,
    /// `*:*`: everything ACE checks, now and as permissions are added.
    pub everything: bool,
    /// It covers `user:write`, so an allow of it lets its holder grant anything, to themselves too.
    pub escalates: bool,
}

impl Gives {
    /// What it does, in a sentence: what an allow gives, or what a deny takes away.
    pub fn summary(&self, deny: bool) -> String {
        let list = || self.covers.join(", ");
        match (deny, self.everything, self.covers.is_empty()) {
            (false, true, _) => {
                "Gives everything ACE checks, now and as permissions are added: full administration."
                    .to_owned()
            }
            (true, true, _) => "Takes away everything, whatever else allows it.".to_owned(),
            (_, false, true) => "Covers nothing ACE checks today.".to_owned(),
            (false, false, false) => format!("Gives {}.", list()),
            (true, false, false) => format!("Takes away {}, whatever else allows them.", list()),
        }
    }
}

/// What a pattern gives.
pub fn gives(pattern: &PermissionPattern) -> Gives {
    Gives {
        covers: CATALOG
            .iter()
            .filter(|entry| pattern.matches(&entry.name))
            .map(|entry| entry.name.to_string())
            .collect(),
        everything: pattern.major() == "*" && pattern.minor() == "*",
        escalates: pattern.matches(&USER_WRITE),
    }
}

/// One grant, as a row of the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    /// `allow` or `deny`.
    pub effect: &'static str,
    pub major: String,
    pub minor: String,
    pub gives: Gives,
    /// The group it comes through, or None for the holder's own row.
    pub through: Option<String>,
}

impl GrantRow {
    pub fn pattern(&self) -> String {
        format!("{}:{}", self.major, self.minor)
    }

    pub fn is_deny(&self) -> bool {
        self.effect == "deny"
    }
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    }
}

/// A grant's row, through a group or the holder's own.
pub fn grant_row(grant: &Grant, through: Option<&str>) -> GrantRow {
    let gives = PermissionPattern::new(&grant.major, &grant.minor)
        .map(|pattern| gives(&pattern))
        .unwrap_or(Gives {
            covers: Vec::new(),
            everything: false,
            escalates: false,
        });
    GrantRow {
        effect: effect_name(grant.effect),
        major: grant.major.clone(),
        minor: grant.minor.clone(),
        gives,
        through: through.map(str::to_owned),
    }
}

/// A user or a group, by id and name, for a link or a select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Named {
    pub id: Uuid,
    pub name: String,
}

/// A user's row on the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRow {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub timezone: String,
    pub enabled: bool,
    pub api_keys: i64,
    /// Their own grants, then their groups'.
    pub grants: Vec<GrantRow>,
    pub groups: Vec<String>,
}

/// A group's row on the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<String>,
    pub grants: Vec<GrantRow>,
}

/// A key as the area lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminKeyRow {
    pub id: Uuid,
    pub name: String,
    /// The owner's id, for the forms' way back.
    pub owner: Option<Uuid>,
    /// Its allows, and `deny` before each deny.
    pub scope: Vec<String>,
    pub created: String,
    /// Its scope is `*:*`: all its owner holds.
    pub inherits: bool,
}

/// A key's row, with its creation in UTC.
pub fn admin_key_row(key: &ApiKey) -> AdminKeyRow {
    AdminKeyRow {
        id: key.id.0,
        name: key.name.clone(),
        owner: key.owner.map(|owner| owner.0),
        scope: key
            .grants
            .iter()
            .map(|grant| match grant.effect {
                Effect::Allow => format!("{}:{}", grant.major, grant.minor),
                Effect::Deny => format!("deny {}:{}", grant.major, grant.minor),
            })
            .collect(),
        created: key.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
        inherits: inherits(key),
    }
}

/// The new user form as it was sent, without its password, to draw again with a refusal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserDraft {
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub timezone: String,
}

/// What Users & Roles shows.
#[derive(Debug, Clone)]
pub struct UsersView {
    pub users: Vec<UserRow>,
    pub groups: Vec<GroupRow>,
    /// Keys with no owner, which stand for a service.
    pub service_keys: Vec<AdminKeyRow>,
    pub hide_disabled: bool,
    /// Whether the viewer holds `user:write`, which every form here needs.
    pub can_write: bool,
    pub timezones: Vec<&'static str>,
    pub draft: UserDraft,
    pub group_draft: String,
    pub notice: Option<&'static str>,
    pub problem: Option<String>,
}

impl UsersView {
    pub fn is_timezone(&self, zone: &str) -> bool {
        zone == self.draft.timezone
    }
}

/// `/admin/users`.
#[derive(Debug, Template)]
#[template(path = "admin/users.html")]
pub struct UsersPage {
    pub layout: Layout,
    pub view: UsersView,
}

/// What a user's page shows.
#[derive(Debug, Clone)]
pub struct UserView {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub timezone: String,
    pub enabled: bool,
    /// Whether this is the viewer's own account.
    pub is_you: bool,
    pub grants: Vec<GrantRow>,
    /// What they hold through their groups.
    pub group_grants: Vec<GrantRow>,
    pub groups: Vec<Named>,
    /// The groups they aren't in, to join.
    pub other_groups: Vec<Named>,
    pub keys: Vec<AdminKeyRow>,
    pub can_write: bool,
    pub timezones: Vec<&'static str>,
    /// The grant form's choices: the catalog and `*:*`.
    pub permissions: Vec<Offered>,
    /// The new key form's boxes: the catalog without `user:self`.
    pub scope: Vec<Offered>,
    pub key_draft: KeyDraft,
    pub notice: Option<&'static str>,
    pub problem: Option<String>,
}

impl UserView {
    pub fn is_timezone(&self, zone: &str) -> bool {
        zone == self.timezone
    }
}

/// `/admin/users/{id}`.
#[derive(Debug, Template)]
#[template(path = "admin/user.html")]
pub struct UserPage {
    pub layout: Layout,
    pub view: UserView,
}

/// What a group's page shows.
#[derive(Debug, Clone)]
pub struct GroupView {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<Named>,
    /// The users who aren't members, to add.
    pub others: Vec<Named>,
    pub grants: Vec<GrantRow>,
    pub can_write: bool,
    pub permissions: Vec<Offered>,
    pub notice: Option<&'static str>,
    pub problem: Option<String>,
}

/// `/admin/groups/{id}`.
#[derive(Debug, Template)]
#[template(path = "admin/group.html")]
pub struct GroupPage {
    pub layout: Layout,
    pub view: GroupView,
}

/// An allow covering `user:write`, to confirm before it's made.
#[derive(Debug, Template)]
#[template(path = "admin/confirm_grant.html")]
pub struct ConfirmGrantPage {
    pub layout: Layout,
    /// `user` or `group`.
    pub holder_kind: &'static str,
    pub holder_id: Uuid,
    pub holder_name: String,
    pub pattern: String,
    pub gives: Gives,
    pub back: String,
}

/// `/admin/keys/{id}`: changing a key's name and scope.
#[derive(Debug, Template)]
#[template(path = "admin/key.html")]
pub struct AdminKeyPage {
    pub layout: Layout,
    pub id: Uuid,
    pub owner: Option<Named>,
    pub back: String,
    pub scope: Vec<Offered>,
    pub draft: KeyDraft,
    pub inherit: bool,
    pub denies: Vec<String>,
    pub problem: Option<String>,
}

/// A password or a token, shown this once.
#[derive(Template)]
#[template(path = "admin/secret.html")]
pub struct SecretPage {
    pub layout: Layout,
    pub title: &'static str,
    /// What it is, such as "The password for alice".
    pub what: String,
    pub secret: String,
    pub hint: &'static str,
    pub back: String,
}

impl std::fmt::Debug for SecretPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretPage")
            .field("what", &self.what)
            .field("secret", &"[hidden]")
            .finish_non_exhaustive()
    }
}

/// The grant form's choices: every permission in the catalog, then `*:*`.
pub fn permission_choices() -> Vec<Offered> {
    CATALOG
        .iter()
        .map(|entry| Offered {
            name: entry.name.to_string(),
            description: entry.description,
            checked: false,
        })
        .chain(std::iter::once(Offered {
            name: "*:*".to_owned(),
            description: "Everything ACE checks, now and as permissions are added: an administrator.",
            checked: false,
        }))
        .collect()
}

/// A key's scope boxes: the catalog without `user:self`, which no key holds, ticked as named.
pub fn scope_choices(ticked: &[String]) -> Vec<Offered> {
    CATALOG
        .iter()
        .filter(|entry| entry.name != USER_SELF)
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

fn names(users: &[User]) -> BTreeMap<Uuid, String> {
    users
        .iter()
        .map(|user| (user.id.0, user.username.clone()))
        .collect()
}

fn member_names(group: &Group, names: &BTreeMap<Uuid, String>) -> Vec<String> {
    group
        .members
        .iter()
        .map(|member| names.get(&member.0).cloned().unwrap_or_default())
        .collect()
}

/// Users & Roles from what the service read: the users, each with their detail, the groups and every key.
pub fn users_view(
    users: &[UserDetail],
    groups: &[Group],
    keys: &[ApiKey],
    hide_disabled: bool,
    can_write: bool,
) -> UsersView {
    let all: Vec<User> = users.iter().map(|detail| detail.user.clone()).collect();
    let names = names(&all);
    UsersView {
        users: users
            .iter()
            .filter(|detail| !hide_disabled || detail.user.enabled)
            .map(|detail| UserRow {
                id: detail.user.id.0,
                username: detail.user.username.clone(),
                display_name: detail.user.display_name.clone().unwrap_or_default(),
                email: detail.user.email.clone().unwrap_or_default(),
                timezone: detail.user.timezone.clone(),
                enabled: detail.user.enabled,
                api_keys: detail.user.api_keys,
                grants: detail
                    .grants
                    .iter()
                    .map(|grant| grant_row(grant, None))
                    .chain(detail.groups.iter().flat_map(|group| {
                        group
                            .grants
                            .iter()
                            .map(|grant| grant_row(grant, Some(&group.name)))
                    }))
                    .collect(),
                groups: detail
                    .groups
                    .iter()
                    .map(|group| group.name.clone())
                    .collect(),
            })
            .collect(),
        groups: groups
            .iter()
            .map(|group| GroupRow {
                id: group.id.0,
                name: group.name.clone(),
                members: member_names(group, &names),
                grants: group
                    .grants
                    .iter()
                    .map(|grant| grant_row(grant, None))
                    .collect(),
            })
            .collect(),
        service_keys: keys
            .iter()
            .filter(|key| key.owner.is_none())
            .map(admin_key_row)
            .collect(),
        hide_disabled,
        can_write,
        timezones: timezones(),
        draft: UserDraft {
            timezone: "UTC".to_owned(),
            ..UserDraft::default()
        },
        group_draft: String::new(),
        notice: None,
        problem: None,
    }
}

/// A user's page from what the service read.
pub fn user_view(
    detail: &UserDetail,
    groups: &[Group],
    keys: &[ApiKey],
    viewer: Option<UserId>,
    can_write: bool,
) -> UserView {
    let user = &detail.user;
    let joined: Vec<Uuid> = detail.groups.iter().map(|group| group.id.0).collect();
    UserView {
        id: user.id.0,
        username: user.username.clone(),
        display_name: user.display_name.clone().unwrap_or_default(),
        email: user.email.clone().unwrap_or_default(),
        timezone: user.timezone.clone(),
        enabled: user.enabled,
        is_you: viewer == Some(user.id),
        grants: detail
            .grants
            .iter()
            .map(|grant| grant_row(grant, None))
            .collect(),
        group_grants: detail
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .grants
                    .iter()
                    .map(|grant| grant_row(grant, Some(&group.name)))
            })
            .collect(),
        groups: detail
            .groups
            .iter()
            .map(|group| Named {
                id: group.id.0,
                name: group.name.clone(),
            })
            .collect(),
        other_groups: groups
            .iter()
            .filter(|group| !joined.contains(&group.id.0))
            .map(|group| Named {
                id: group.id.0,
                name: group.name.clone(),
            })
            .collect(),
        keys: keys
            .iter()
            .filter(|key| key.owner == Some(user.id))
            .map(admin_key_row)
            .collect(),
        can_write,
        timezones: timezones(),
        permissions: permission_choices(),
        scope: scope_choices(&[]),
        key_draft: KeyDraft::default(),
        notice: None,
        problem: None,
    }
}

/// A group's page from what the service read.
pub fn group_view(group: &Group, users: &[User], can_write: bool) -> GroupView {
    let names = names(users);
    GroupView {
        id: group.id.0,
        name: group.name.clone(),
        members: group
            .members
            .iter()
            .map(|member| Named {
                id: member.0,
                name: names.get(&member.0).cloned().unwrap_or_default(),
            })
            .collect(),
        others: users
            .iter()
            .filter(|user| !group.members.contains(&user.id))
            .map(|user| Named {
                id: user.id.0,
                name: user.username.clone(),
            })
            .collect(),
        grants: group
            .grants
            .iter()
            .map(|grant| grant_row(grant, None))
            .collect(),
        can_write,
        permissions: permission_choices(),
        notice: None,
        problem: None,
    }
}

// ---- the gate, the reads and the answers every handler shares ----

/// Whether the viewer may enter the area, or the answer saying they may not.
async fn enter(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    match gui.service.allowed(&viewer.actor, &ADMIN_READ).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::new(
            StatusCode::FORBIDDEN,
            "The administration area needs admin:read. Ask an administrator.",
            parts,
        )),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

/// The status a refusal of a form draws its page again at, or None for an error that isn't the form's.
fn refused(error: &ServiceError) -> Option<StatusCode> {
    match error {
        ServiceError::InvalidRequest(_)
        | ServiceError::WeakPassword
        | ServiceError::InvalidKeyName
        | ServiceError::CantDisableYourself
        | ServiceError::CantDropYourOwnUserWrite => Some(StatusCode::BAD_REQUEST),
        ServiceError::UsernameTaken | ServiceError::GroupNameTaken => Some(StatusCode::CONFLICT),
        _ => None,
    }
}

fn bad_request(message: &str, parts: &Parts) -> Response {
    Failure::new(StatusCode::BAD_REQUEST, message, parts).into_response()
}

fn viewer_id(viewer: &SignedIn) -> Option<UserId> {
    match &viewer.actor {
        ace_service::Actor::User { id, .. } => Some(*id),
        _ => None,
    }
}

/// A page answered with its status.
fn answer(page: &impl Template, status: StatusCode) -> Response {
    let mut response = render(page);
    *response.status_mut() = status;
    response
}

/// A secret's page: 201 for something made, 200 for a reset, never cached.
fn shown_once(page: &SecretPage, status: StatusCode) -> Response {
    let mut response = answer(page, status);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn read_users_view(
    gui: &Gui,
    viewer: &SignedIn,
    hide_disabled: bool,
) -> Result<UsersView, ServiceError> {
    let actor = &viewer.actor;
    let users = gui.service.users(actor, true).await?;
    let mut details = Vec::with_capacity(users.len());
    for user in &users {
        details.push(gui.service.user(actor, user.id).await?);
    }
    let groups = gui.service.groups(actor).await?;
    let keys = gui.service.api_keys(actor, None).await?;
    let can_write = gui.service.allowed(actor, &USER_WRITE).await?;
    Ok(users_view(
        &details,
        &groups,
        &keys,
        hide_disabled,
        can_write,
    ))
}

async fn users_page_with(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    hide_disabled: bool,
    status: StatusCode,
    change: impl FnOnce(&mut UsersView),
) -> Response {
    let mut view = match read_users_view(gui, &viewer, hide_disabled).await {
        Ok(view) => view,
        Err(error) => return Failure::from_service(error, parts).into_response(),
    };
    change(&mut view);
    answer(
        &UsersPage {
            layout: viewer.layout,
            view,
        },
        status,
    )
}

async fn read_user_view(
    gui: &Gui,
    viewer: &SignedIn,
    id: UserId,
) -> Result<UserView, ServiceError> {
    let actor = &viewer.actor;
    let detail = gui.service.user(actor, id).await?;
    let groups = gui.service.groups(actor).await?;
    let keys = gui.service.api_keys(actor, Some(id)).await?;
    let can_write = gui.service.allowed(actor, &USER_WRITE).await?;
    Ok(user_view(
        &detail,
        &groups,
        &keys,
        viewer_id(viewer),
        can_write,
    ))
}

async fn user_page_with(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    id: Uuid,
    status: StatusCode,
    change: impl FnOnce(&mut UserView),
) -> Response {
    let mut view = match read_user_view(gui, &viewer, UserId(id)).await {
        Ok(view) => view,
        Err(error) => return Failure::from_service(error, parts).into_response(),
    };
    change(&mut view);
    answer(
        &UserPage {
            layout: viewer.layout,
            view,
        },
        status,
    )
}

async fn read_group_view(
    gui: &Gui,
    viewer: &SignedIn,
    id: Uuid,
) -> Result<GroupView, ServiceError> {
    let actor = &viewer.actor;
    let groups = gui.service.groups(actor).await?;
    let group = groups
        .iter()
        .find(|group| group.id.0 == id)
        .ok_or_else(|| ServiceError::NotFound(format!("no group {id}")))?;
    let users = gui.service.users(actor, true).await?;
    let can_write = gui.service.allowed(actor, &USER_WRITE).await?;
    Ok(group_view(group, &users, can_write))
}

async fn group_page_with(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    id: Uuid,
    status: StatusCode,
    change: impl FnOnce(&mut GroupView),
) -> Response {
    let mut view = match read_group_view(gui, &viewer, id).await {
        Ok(view) => view,
        Err(error) => return Failure::from_service(error, parts).into_response(),
    };
    change(&mut view);
    answer(
        &GroupPage {
            layout: viewer.layout,
            view,
        },
        status,
    )
}

/// What a page's `done` says the last form did.
fn notice(done: Option<&str>) -> Option<&'static str> {
    Some(match done? {
        "created" => "The user is made.",
        "profile" => "The profile is saved.",
        "enabled" => "The user is enabled.",
        "disabled" => {
            "The user is disabled. Their sessions have ended and their keys stop working."
        }
        "password" => "The password is set. Their sessions have ended.",
        "granted" => "The grant is made.",
        "revoked" => "The grant is revoked.",
        "joined" => "The user is in the group.",
        "left" => "The user is out of the group.",
        "group" => "The group is made.",
        "deleted" => "The group is deleted. Its members no longer hold its grants.",
        "key" => "The key is changed. Anything using it has the new scope on its next request.",
        "key-revoked" => "The key is revoked. Anything using it stops working.",
        "unchanged" => "Nothing changed: it was already so.",
        _ => return None,
    })
}

fn uuid_of(id: Result<Path<Uuid>, PathRejection>) -> Option<Uuid> {
    id.ok().map(|Path(id)| id)
}

// ---- the pages ----

#[derive(Debug, Deserialize)]
pub(crate) struct PageQuery {
    done: Option<String>,
    disabled: Option<String>,
}

/// `GET /admin`: the hub.
pub(crate) async fn hub(State(gui): State<Gui>, viewer: SignedIn, parts: Parts) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let mut modules = Vec::new();
    match gui.service.allowed(&viewer.actor, &USER_READ).await {
        Ok(true) => modules.push(USERS_AND_ROLES),
        Ok(false) => {}
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    }
    render(&HubPage {
        layout: viewer.layout,
        modules,
    })
}

/// `GET /admin/users`: Users & Roles.
pub(crate) async fn users_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let (done, hide) = match &query {
        Ok(Query(query)) => (
            query.done.as_deref(),
            query.disabled.as_deref() == Some("hide"),
        ),
        Err(_) => (None, false),
    };
    let notice = notice(done);
    users_page_with(&gui, viewer, &parts, hide, StatusCode::OK, |view| {
        view.notice = notice;
    })
    .await
}

/// `GET /admin/users/{id}`.
pub(crate) async fn user_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A user's id is a uuid.", &parts);
    };
    let notice = notice(
        query
            .as_ref()
            .ok()
            .and_then(|Query(query)| query.done.as_deref()),
    );
    user_page_with(&gui, viewer, &parts, id, StatusCode::OK, |view| {
        view.notice = notice;
    })
    .await
}

/// `GET /admin/groups/{id}`.
pub(crate) async fn group_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A group's id is a uuid.", &parts);
    };
    let notice = notice(
        query
            .as_ref()
            .ok()
            .and_then(|Query(query)| query.done.as_deref()),
    );
    group_page_with(&gui, viewer, &parts, id, StatusCode::OK, |view| {
        view.notice = notice;
    })
    .await
}

// ---- users ----

/// A password the form gives, or one made for the administrator to hand over, with its text to show.
fn password_of(typed: &str) -> Result<(Password, Option<String>), ServiceError> {
    if typed.is_empty() {
        let made = Password::generate()?;
        let shown = made.expose().to_owned();
        Ok((made, Some(shown)))
    } else {
        Ok((Password::new(typed), None))
    }
}

/// `POST /admin/users`: makes a user with no grants.
pub(crate) async fn create_user(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let field = |name: &str| one(&form, name).unwrap_or("").to_owned();
    let draft = UserDraft {
        username: field("username"),
        display_name: field("display_name"),
        email: field("email"),
        timezone: field("timezone"),
    };
    let username = match Username::new(draft.username.trim()) {
        Ok(username) => username,
        Err(error) => {
            return new_user_refused(
                &gui,
                viewer,
                &parts,
                error.to_string(),
                StatusCode::BAD_REQUEST,
                draft,
            )
            .await;
        }
    };
    let (password, shown) = match password_of(one(&form, "password").unwrap_or("")) {
        Ok(password) => password,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let profile = Profile {
        display_name: Some(draft.display_name.clone()),
        email: Some(draft.email.clone()),
        timezone: Some(draft.timezone.clone()),
    };
    let made = gui
        .service
        .create_user(&viewer.actor, &username, password, &profile)
        .await;
    match made {
        Ok(id) => match shown {
            Some(secret) => shown_once(
                &SecretPage {
                    layout: viewer.layout,
                    title: "New user",
                    what: format!("The password for {}", username.as_str()),
                    secret,
                    hint: "Give it to them over a channel you trust, and ask them to change it at Change Password.",
                    back: format!("/admin/users/{}", id.0),
                },
                StatusCode::CREATED,
            ),
            None => see_other(&format!("/admin/users/{}?done=created", id.0), None),
        },
        Err(error) => match refused(&error) {
            Some(status) => {
                new_user_refused(&gui, viewer, &parts, error.to_string(), status, draft).await
            }
            None => Failure::from_service(error, &parts).into_response(),
        },
    }
}

/// Users & Roles again, with the new user form as it was sent and why it was refused.
async fn new_user_refused(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    problem: String,
    status: StatusCode,
    draft: UserDraft,
) -> Response {
    users_page_with(gui, viewer, parts, false, status, |view| {
        view.problem = Some(format!("No user was made: {problem}."));
        view.draft = draft;
    })
    .await
}

/// A user's page again, with the new key form as it was sent and why it was refused.
async fn new_key_refused(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    id: Uuid,
    problem: String,
    draft: KeyDraft,
) -> Response {
    user_page_with(gui, viewer, parts, id, StatusCode::BAD_REQUEST, |view| {
        view.problem = Some(format!("No key was made: {problem}."));
        view.scope = scope_choices(&draft.ticked);
        view.key_draft = draft;
    })
    .await
}

/// The page again after a refused form on a user's page, or the error page.
async fn user_refused(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    id: Uuid,
    error: ServiceError,
    what: &str,
) -> Response {
    match refused(&error) {
        Some(status) => {
            let problem = format!("{what}: {error}.");
            user_page_with(gui, viewer, parts, id, status, |view| {
                view.problem = Some(problem);
            })
            .await
        }
        None => Failure::from_service(error, parts).into_response(),
    }
}

/// `POST /admin/users/{id}/profile`: a user's display name, email and timezone.
pub(crate) async fn save_profile(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A user's id is a uuid.", &parts);
    };
    let form = pairs(&body);
    let profile = Profile {
        display_name: Some(one(&form, "display_name").unwrap_or("").to_owned()),
        email: Some(one(&form, "email").unwrap_or("").to_owned()),
        timezone: Some(one(&form, "timezone").unwrap_or("").to_owned()),
    };
    match gui
        .service
        .update_user(&viewer.actor, UserId(id), &profile)
        .await
    {
        Ok(true) => see_other(&format!("/admin/users/{id}?done=profile"), None),
        Ok(false) => see_other(&format!("/admin/users/{id}?done=unchanged"), None),
        Err(error) => user_refused(&gui, viewer, &parts, id, error, "Not saved").await,
    }
}

/// `POST /admin/users/{id}/enabled`: turns a user on or off.
pub(crate) async fn set_enabled(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A user's id is a uuid.", &parts);
    };
    let form = pairs(&body);
    let enabled = match one(&form, "enabled") {
        Some("true") => true,
        Some("false") => false,
        _ => return bad_request("enabled is true or false.", &parts),
    };
    match gui
        .service
        .set_user_enabled(&viewer.actor, UserId(id), enabled)
        .await
    {
        Ok(true) => {
            let done = if enabled { "enabled" } else { "disabled" };
            see_other(&format!("/admin/users/{id}?done={done}"), None)
        }
        Ok(false) => see_other(&format!("/admin/users/{id}?done=unchanged"), None),
        Err(error) => user_refused(&gui, viewer, &parts, id, error, "Not changed").await,
    }
}

/// `POST /admin/users/{id}/password`: sets a user's password without the old one.
pub(crate) async fn reset_password(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A user's id is a uuid.", &parts);
    };
    let form = pairs(&body);
    let (password, shown) = match password_of(one(&form, "password").unwrap_or("")) {
        Ok(password) => password,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    match gui
        .service
        .reset_password(&viewer.actor, UserId(id), password)
        .await
    {
        Ok(()) => match shown {
            Some(secret) => {
                // the name for the page; the reset is done whatever this read says
                let name = gui
                    .service
                    .user(&viewer.actor, UserId(id))
                    .await
                    .map(|detail| detail.user.username)
                    .unwrap_or_default();
                shown_once(
                    &SecretPage {
                        layout: viewer.layout,
                        title: "Password reset",
                        what: format!("The new password for {name}"),
                        secret,
                        hint: "Their sessions have ended. Give it to them over a channel you trust, and ask them to change it at Change Password.",
                        back: format!("/admin/users/{id}"),
                    },
                    StatusCode::OK,
                )
            }
            None => see_other(&format!("/admin/users/{id}?done=password"), None),
        },
        Err(error) => user_refused(&gui, viewer, &parts, id, error, "Not reset").await,
    }
}

// ---- groups and members ----

/// `POST /admin/groups`: makes a group with no members or grants.
pub(crate) async fn create_group(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let name = one(&form, "name").unwrap_or("").to_owned();
    match gui.service.create_group(&viewer.actor, &name).await {
        Ok(id) => see_other(&format!("/admin/groups/{}?done=group", id.0), None),
        Err(error) => match refused(&error) {
            Some(status) => {
                let problem = format!("No group was made: {error}.");
                users_page_with(&gui, viewer, &parts, false, status, |view| {
                    view.problem = Some(problem);
                    view.group_draft = name;
                })
                .await
            }
            None => Failure::from_service(error, &parts).into_response(),
        },
    }
}

/// `POST /admin/groups/{id}/delete`.
pub(crate) async fn delete_group(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A group's id is a uuid.", &parts);
    };
    match gui.service.delete_group(&viewer.actor, GroupId(id)).await {
        Ok(true) => see_other("/admin/users?done=deleted", None),
        Ok(false) => {
            Failure::new(StatusCode::NOT_FOUND, "There's no such group.", &parts).into_response()
        }
        Err(error) => group_refused(&gui, viewer, &parts, id, error, "Not deleted").await,
    }
}

async fn group_refused(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    id: Uuid,
    error: ServiceError,
    what: &str,
) -> Response {
    match refused(&error) {
        Some(status) => {
            let problem = format!("{what}: {error}.");
            group_page_with(gui, viewer, parts, id, status, |view| {
                view.problem = Some(problem);
            })
            .await
        }
        None => Failure::from_service(error, parts).into_response(),
    }
}

/// Which page a membership form came from, to go back to.
#[derive(Clone, Copy)]
enum Back {
    User(Uuid),
    Group(Uuid),
}

impl Back {
    fn of(form: &[(String, String)], user: Uuid, group: Uuid) -> Self {
        match one(form, "back") {
            Some("group") => Back::Group(group),
            _ => Back::User(user),
        }
    }

    fn page(self) -> String {
        match self {
            Back::User(id) => format!("/admin/users/{id}"),
            Back::Group(id) => format!("/admin/groups/{id}"),
        }
    }

    fn path(self, done: &str) -> String {
        format!("{}?done={done}", self.page())
    }

    async fn refused(
        self,
        gui: &Gui,
        viewer: SignedIn,
        parts: &Parts,
        error: ServiceError,
        what: &str,
    ) -> Response {
        match self {
            Back::User(id) => user_refused(gui, viewer, parts, id, error, what).await,
            Back::Group(id) => group_refused(gui, viewer, parts, id, error, what).await,
        }
    }
}

/// `POST /admin/groups/{id}/members`: puts the form's `user` in the group.
pub(crate) async fn add_member(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let user = one(&form, "user").and_then(|user| user.parse::<Uuid>().ok());
    let (Some(group), Some(user)) = (uuid_of(id), user) else {
        return bad_request("A group's and a user's ids are uuids.", &parts);
    };
    let back = Back::of(&form, user, group);
    match gui
        .service
        .add_group_member(&viewer.actor, GroupId(group), UserId(user))
        .await
    {
        Ok(true) => see_other(&back.path("joined"), None),
        Ok(false) => see_other(&back.path("unchanged"), None),
        Err(error) => back.refused(&gui, viewer, &parts, error, "Not added").await,
    }
}

/// `POST /admin/users/{id}/groups`: puts the user in the form's `group`.
pub(crate) async fn join_group(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let group = one(&form, "group").and_then(|group| group.parse::<Uuid>().ok());
    let (Some(user), Some(group)) = (uuid_of(id), group) else {
        return bad_request("A group's and a user's ids are uuids.", &parts);
    };
    let back = Back::User(user);
    match gui
        .service
        .add_group_member(&viewer.actor, GroupId(group), UserId(user))
        .await
    {
        Ok(true) => see_other(&back.path("joined"), None),
        Ok(false) => see_other(&back.path("unchanged"), None),
        Err(error) => back.refused(&gui, viewer, &parts, error, "Not added").await,
    }
}

/// `POST /admin/groups/{id}/members/{user}/remove`.
pub(crate) async fn remove_member(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    ids: Result<Path<(Uuid, Uuid)>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Ok(Path((group, user))) = ids else {
        return bad_request("A group's and a user's ids are uuids.", &parts);
    };
    let back = Back::of(&pairs(&body), user, group);
    match gui
        .service
        .remove_group_member(&viewer.actor, GroupId(group), UserId(user))
        .await
    {
        Ok(true) => see_other(&back.path("left"), None),
        Ok(false) => Failure::new(
            StatusCode::NOT_FOUND,
            "The user isn't in such a group.",
            &parts,
        )
        .into_response(),
        Err(error) => {
            back.refused(&gui, viewer, &parts, error, "Not removed")
                .await
        }
    }
}

// ---- grants ----

/// A grant form's holder: `holder_kind` of `user` or `group`, and `holder`, its id.
fn holder_of(form: &[(String, String)]) -> Option<(Holder, Back)> {
    let id: Uuid = one(form, "holder")?.parse().ok()?;
    match one(form, "holder_kind")? {
        "user" => Some((Holder::User(UserId(id)), Back::User(id))),
        "group" => Some((Holder::Group(GroupId(id)), Back::Group(id))),
        _ => None,
    }
}

fn effect_of(form: &[(String, String)]) -> Option<Effect> {
    match one(form, "effect")? {
        "allow" => Some(Effect::Allow),
        "deny" => Some(Effect::Deny),
        _ => None,
    }
}

/// The pattern a grant form names: the choice from the list, or the text typed, not both.
fn pattern_of(form: &[(String, String)]) -> Result<PermissionPattern, String> {
    let chosen = one(form, "permission").unwrap_or("").trim();
    let typed = one(form, "other").unwrap_or("").trim();
    let text = match (chosen.is_empty(), typed.is_empty()) {
        (false, true) => chosen,
        (true, false) => typed,
        (true, true) => return Err("choose a permission or type a pattern".to_owned()),
        (false, false) => return Err("choose a permission or type a pattern, not both".to_owned()),
    };
    let (major, minor) = text
        .split_once(':')
        .ok_or_else(|| format!("{text} isn't a pattern, which is major:minor"))?;
    PermissionPattern::new(major, minor).map_err(|error| format!("{text}: {error}"))
}

/// `POST /admin/grants`: gives a user or a group an allow or a deny. An allow covering `user:write`
/// is confirmed first.
pub(crate) async fn grant(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let (Some((holder, back)), Some(effect)) = (holder_of(&form), effect_of(&form)) else {
        return bad_request(
            "A grant names a user or a group, and allow or deny.",
            &parts,
        );
    };
    let pattern = match pattern_of(&form) {
        Ok(pattern) => pattern,
        Err(problem) => {
            return back
                .refused(
                    &gui,
                    viewer,
                    &parts,
                    ServiceError::InvalidRequest(problem),
                    "No grant was made",
                )
                .await;
        }
    };
    let gives = gives(&pattern);
    // Only someone who could make it is asked to confirm it; anyone else gets the service's refusal.
    let confirm = effect == Effect::Allow
        && gives.escalates
        && one(&form, "confirm") != Some("yes")
        && gui
            .service
            .allowed(&viewer.actor, &USER_WRITE)
            .await
            .unwrap_or(false);
    if confirm {
        let (holder_kind, holder_id) = match back {
            Back::User(id) => ("user", id),
            Back::Group(id) => ("group", id),
        };
        let holder_name = match &holder {
            Holder::User(id) => gui
                .service
                .user(&viewer.actor, *id)
                .await
                .map(|detail| detail.user.username),
            _ => gui.service.groups(&viewer.actor).await.and_then(|groups| {
                groups
                    .into_iter()
                    .find(|group| group.id.0 == holder_id)
                    .map(|group| group.name)
                    .ok_or_else(|| ServiceError::NotFound(format!("no group {holder_id}")))
            }),
        };
        let holder_name = match holder_name {
            Ok(name) => name,
            Err(error) => return Failure::from_service(error, &parts).into_response(),
        };
        return render(&ConfirmGrantPage {
            layout: viewer.layout,
            holder_kind,
            holder_id,
            holder_name,
            pattern: pattern.to_string(),
            gives,
            back: back.page(),
        });
    }
    match gui
        .service
        .grant(&viewer.actor, &holder, &pattern, effect)
        .await
    {
        Ok(true) => see_other(&back.path("granted"), None),
        Ok(false) => see_other(&back.path("unchanged"), None),
        Err(error) => {
            back.refused(&gui, viewer, &parts, error, "No grant was made")
                .await
        }
    }
}

/// `POST /admin/grants/revoke`: removes a user's or a group's row, named by its `major`, `minor` and
/// `effect`.
pub(crate) async fn revoke(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let pattern = PermissionPattern::new(
        one(&form, "major").unwrap_or(""),
        one(&form, "minor").unwrap_or(""),
    );
    let (Some((holder, back)), Some(effect), Ok(pattern)) =
        (holder_of(&form), effect_of(&form), pattern)
    else {
        return bad_request(
            "A revoke names a user or a group, a pattern, and allow or deny.",
            &parts,
        );
    };
    match gui
        .service
        .revoke(&viewer.actor, &holder, &pattern, effect)
        .await
    {
        Ok(true) => see_other(&back.path("revoked"), None),
        Ok(false) => Failure::new(
            StatusCode::NOT_FOUND,
            "There's no such grant to revoke.",
            &parts,
        )
        .into_response(),
        Err(error) => {
            back.refused(&gui, viewer, &parts, error, "Not revoked")
                .await
        }
    }
}

// ---- keys ----

/// The scope a key form asks for: `*:*` when its `mode` is `inherit`, as ace3's "full account access",
/// or else its boxes and other patterns.
fn key_scope_of(
    form: &[(String, String)],
    draft: &KeyDraft,
) -> Result<Vec<PermissionPattern>, String> {
    if one(form, "mode") == Some("inherit") {
        return Ok(vec![
            PermissionPattern::new("*", "*").expect("*:* is a pattern"),
        ]);
    }
    scope_of(draft)
}

/// `POST /admin/users/{id}/keys`: makes a key the user owns, and shows its token this once.
pub(crate) async fn create_key(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A user's id is a uuid.", &parts);
    };
    let form = pairs(&body);
    let draft = draft_of(&body);
    let scope = match key_scope_of(&form, &draft) {
        Ok(scope) => scope,
        Err(problem) => return new_key_refused(&gui, viewer, &parts, id, problem, draft).await,
    };
    let made = gui
        .service
        .create_api_key(&viewer.actor, &draft.name, Some(UserId(id)), &scope)
        .await;
    match made {
        Ok(key) => shown_once(
            &SecretPage {
                layout: viewer.layout,
                title: "New API key",
                what: format!("The key {}", draft.name.trim()),
                secret: key.token.expose().to_owned(),
                hint: "It isn't stored and can't be shown again. Send it as Authorization: Bearer followed by the key. It does only what both its scope and its owner's permissions allow.",
                back: format!("/admin/users/{id}"),
            },
            StatusCode::CREATED,
        ),
        Err(error) => match refused(&error) {
            Some(_) => new_key_refused(&gui, viewer, &parts, id, error.to_string(), draft).await,
            None => Failure::from_service(error, &parts).into_response(),
        },
    }
}

/// A key the service lists, or the answer saying there's none such.
async fn find_key(
    gui: &Gui,
    viewer: &SignedIn,
    id: Uuid,
    parts: &Parts,
) -> Result<ApiKey, Failure> {
    gui.service
        .api_keys(&viewer.actor, None)
        .await
        .map_err(|error| Failure::from_service(error, parts))?
        .into_iter()
        .find(|key| key.id.0 == id)
        .ok_or_else(|| Failure::new(StatusCode::NOT_FOUND, "There's no such API key.", parts))
}

fn key_back(owner: Option<Uuid>) -> String {
    match owner {
        Some(owner) => format!("/admin/users/{owner}"),
        None => "/admin/users".to_owned(),
    }
}

async fn key_page_with(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    key: &ApiKey,
    draft: Option<(KeyDraft, bool)>,
    problem: Option<String>,
    status: StatusCode,
) -> Response {
    let owner = match key.owner {
        Some(owner) => match gui.service.user(&viewer.actor, owner).await {
            Ok(detail) => Some(Named {
                id: owner.0,
                name: detail.user.username,
            }),
            Err(error) => return Failure::from_service(error, parts).into_response(),
        },
        None => None,
    };
    let (draft, inherit) = draft.unwrap_or_else(|| {
        let allows: Vec<String> = key
            .grants
            .iter()
            .filter(|grant| grant.effect == Effect::Allow)
            .map(|grant| format!("{}:{}", grant.major, grant.minor))
            .collect();
        let boxes: Vec<String> = scope_choices(&[]).into_iter().map(|b| b.name).collect();
        let (ticked, other): (Vec<String>, Vec<String>) = allows
            .into_iter()
            .filter(|name| name != "*:*")
            .partition(|name| boxes.contains(name));
        (
            KeyDraft {
                name: key.name.clone(),
                ticked,
                other: other.join("\n"),
            },
            inherits(key),
        )
    });
    answer(
        &AdminKeyPage {
            layout: viewer.layout,
            id: key.id.0,
            back: key_back(key.owner.map(|owner| owner.0)),
            owner,
            scope: scope_choices(&draft.ticked),
            draft,
            inherit,
            denies: key
                .grants
                .iter()
                .filter(|grant| grant.effect == Effect::Deny)
                .map(|grant| format!("{}:{}", grant.major, grant.minor))
                .collect(),
            problem,
        },
        status,
    )
}

/// `GET /admin/keys/{id}`: the form that changes a key's name and scope.
pub(crate) async fn key_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A key's id is a uuid.", &parts);
    };
    let key = match find_key(&gui, &viewer, id, &parts).await {
        Ok(key) => key,
        Err(failure) => return failure.into_response(),
    };
    key_page_with(&gui, viewer, &parts, &key, None, None, StatusCode::OK).await
}

/// `POST /admin/keys/{id}`: renames a key and replaces its allows, keeping its token.
pub(crate) async fn save_key(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A key's id is a uuid.", &parts);
    };
    let key = match find_key(&gui, &viewer, id, &parts).await {
        Ok(key) => key,
        Err(failure) => return failure.into_response(),
    };
    let form = pairs(&body);
    let draft = draft_of(&body);
    let inherit = one(&form, "mode") == Some("inherit");
    let problem = match key_scope_of(&form, &draft) {
        Ok(scope) => match gui
            .service
            .set_api_key_scope(&viewer.actor, ApiKeyId(id), &draft.name, &scope)
            .await
        {
            Ok(changed) => {
                let done = if changed { "key" } else { "unchanged" };
                let back = key_back(key.owner.map(|owner| owner.0));
                return see_other(&format!("{back}?done={done}"), None);
            }
            Err(error) => match refused(&error) {
                Some(_) => error.to_string(),
                None => return Failure::from_service(error, &parts).into_response(),
            },
        },
        Err(problem) => problem,
    };
    key_page_with(
        &gui,
        viewer,
        &parts,
        &key,
        Some((draft, inherit)),
        Some(format!("Not changed: {problem}.")),
        StatusCode::BAD_REQUEST,
    )
    .await
}

/// `POST /admin/keys/{id}/revoke`: deletes a key. The form's `owner` is the page to go back to.
pub(crate) async fn revoke_key(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<Uuid>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = uuid_of(id) else {
        return bad_request("A key's id is a uuid.", &parts);
    };
    let owner = one(&pairs(&body), "owner").and_then(|owner| owner.parse::<Uuid>().ok());
    match gui
        .service
        .revoke_api_key(&viewer.actor, ApiKeyId(id))
        .await
    {
        Ok(true) => see_other(&format!("{}?done=key-revoked", key_back(owner)), None),
        Ok(false) => {
            Failure::new(StatusCode::NOT_FOUND, "There's no such API key.", &parts).into_response()
        }
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
