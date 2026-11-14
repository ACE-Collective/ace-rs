//! Users, groups and API keys as the `users` router manages them (PLAN.md 5.6): ace3's
//! `aceapi_v2/users/service.py`. `auth` makes users and keys and checks credentials; this reads them,
//! changes profiles, groups and memberships, and sets what a key holds.
//!
//! Reads need `user:read` and writes `user:write`, as in ace3. A user's own account is the exception: a
//! user reads and edits their own profile with no grant, as ace3's `/users/me` does, and manages their
//! own keys under `user:self`. Only a user has an own account here. ace3 also lets a key that inherits
//! its owner's scope read and edit its owner's profile; an API key here is refused as not holding
//! `user:self`, which only a person can.
//!
//! A key's scope is its own grants (`gate`'s docs): a key with an owner holds what both allow. Setting a
//! scope replaces the key's allows and leaves a deny alone, so a scope can't quietly lift one. ace3's
//! `inherit_user_scope` is a scope of `*:*`. As in ace3, `user:self` can't be in a key's scope, and a
//! key a user makes for themselves (`create_own_api_key`) has to list what it needs, each pattern
//! covering a permission ACE checks (`CATALOG`), and all of it permissions they hold. That isn't what
//! keeps a key inside its owner's grants, which the gate does on every request; it turns a typo or an
//! overreach into an error instead of a key that quietly does less. A user's own key that names another
//! user's key id is told it isn't there, and the attempt is logged, as ace3 does.
//!
//! A change to grants or groups that would leave its actor without `user:write` is refused
//! (`keeps_user_write`), as disabling yourself is. ace3 refuses only the second. Holding `user:write`
//! still lets you grant yourself `*:*`, as in ace3 (5.2).
//!
//! A profile holds ace3's `queue`, the queue a person works (PLAN.md 7.13), `default` until they change it.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use sqlx::types::Json;
use uuid::Uuid;

use crate::actor::{Actor, ApiKeyId, UserId};
use crate::alerts::RecordedActor;
use crate::auth::NewApiKey;
use crate::gate::{Audited, Change, Holder, Recorded, Target, holds};
use crate::permission::{
    CATALOG, CatalogEntry, Effect, PermissionPattern, USER_READ, USER_SELF, USER_WRITE, covered_by,
    is_people_only,
};
use crate::{GroupId, Service, ServiceError};

/// The most patterns a key's scope holds, as ace3's self-service keys.
pub const MAX_KEY_SCOPE: usize = 64;
const MAX_DISPLAY_NAME: usize = 1024;
const MAX_EMAIL: usize = 255;
const MAX_GROUP_NAME: usize = 255;

/// A user's profile as a request gives it. Each field left out is left alone, or unset for a new user;
/// an empty display name or email clears it. A timezone is an IANA name such as `America/New_York`. A queue
/// is the one a person works (PLAN.md 7.13), ace3's `users.queue`, `default` for a new user.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub timezone: Option<String>,
    pub queue: Option<String>,
}

/// A profile's fields after `Profile::checked`: `Some(None)` clears one.
#[derive(Debug, Clone, Default)]
pub(crate) struct CheckedProfile {
    display_name: Option<Option<String>>,
    email: Option<Option<String>>,
    timezone: Option<String>,
    queue: Option<String>,
}

impl Profile {
    pub(crate) fn checked(&self) -> Result<CheckedProfile, ServiceError> {
        let text = |value: &str, field: &str, max: usize| -> Result<Option<String>, ServiceError> {
            let value = value.trim();
            if value.chars().any(char::is_control) || value.chars().count() > max {
                return Err(ServiceError::InvalidRequest(format!(
                    "a {field} is up to {max} characters with no control characters"
                )));
            }
            Ok((!value.is_empty()).then(|| value.to_owned()))
        };
        let display_name = self
            .display_name
            .as_deref()
            .map(|name| text(name, "display name", MAX_DISPLAY_NAME))
            .transpose()?;
        let email = self
            .email
            .as_deref()
            .map(|email| {
                let email = text(email, "email", MAX_EMAIL)?;
                let shaped = email.as_deref().is_none_or(|email| {
                    !email.contains(char::is_whitespace)
                        && email
                            .split_once('@')
                            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
                });
                if !shaped {
                    return Err(ServiceError::InvalidRequest(
                        "an email is a name, an @ and a domain, with no spaces".to_owned(),
                    ));
                }
                Ok(email)
            })
            .transpose()?;
        let timezone = self
            .timezone
            .as_deref()
            .map(|zone| {
                chrono_tz::Tz::from_str(zone.trim())
                    .map(|zone| zone.name().to_owned())
                    .map_err(|_| {
                        ServiceError::InvalidRequest(format!(
                            "{zone:?} isn't an IANA timezone, such as Europe/London"
                        ))
                    })
            })
            .transpose()?;
        let queue = self
            .queue
            .as_deref()
            .map(|queue| {
                let queue = queue.trim();
                ace_core::tree::check_queue_name(queue)
                    .map(|()| queue.to_owned())
                    .map_err(ServiceError::InvalidRequest)
            })
            .transpose()?;
        Ok(CheckedProfile {
            display_name,
            email,
            timezone,
            queue,
        })
    }
}

impl CheckedProfile {
    /// The values a new user starts with: display name, email, timezone and queue.
    pub(crate) fn initial(&self) -> (Option<&str>, Option<&str>, &str, &str) {
        (
            self.display_name.as_ref().and_then(|name| name.as_deref()),
            self.email.as_ref().and_then(|email| email.as_deref()),
            self.timezone.as_deref().unwrap_or("UTC"),
            self.queue
                .as_deref()
                .unwrap_or(ace_core::tree::DEFAULT_QUEUE),
        )
    }
}

/// A user as the management page lists them. Never their password's hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub timezone: String,
    /// The queue they work (PLAN.md 7.13).
    pub queue: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    /// How many API keys they own.
    pub api_keys: i64,
}

/// One row of `service.permissions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub id: i64,
    pub major: String,
    pub minor: String,
    pub effect: Effect,
}

/// A group, its members and its grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
    pub members: Vec<UserId>,
    pub grants: Vec<Grant>,
}

/// A user, their own grants, and the groups whose grants they also hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserDetail {
    pub user: User,
    pub grants: Vec<Grant>,
    pub groups: Vec<Group>,
}

/// An API key, never its secret.
#[derive(Debug, Clone, PartialEq)]
pub struct ApiKey {
    pub id: ApiKeyId,
    pub name: String,
    pub owner: Option<UserId>,
    /// Its own grants. With an owner, it holds only what the owner holds too.
    pub grants: Vec<Grant>,
    pub created_at: DateTime<Utc>,
    pub created_by: RecordedActor,
}

#[derive(Serialize, PartialEq, Eq)]
struct ProfileRecord {
    display_name: Option<String>,
    email: Option<String>,
    timezone: String,
    queue: String,
}

impl Recorded for ProfileRecord {}

#[derive(Serialize)]
struct GroupRecord<'a> {
    name: &'a str,
}

impl Recorded for GroupRecord<'_> {}

#[derive(Serialize)]
struct GroupRemoved {
    members: i64,
    grants: i64,
}

impl Recorded for GroupRemoved {}

#[derive(Serialize)]
struct Membership {
    member: Uuid,
}

impl Recorded for Membership {}

/// A key's name, owner and allows, as its rows are after a change.
#[derive(Serialize, PartialEq, Eq)]
pub(crate) struct KeyRecord {
    pub(crate) name: String,
    pub(crate) owner: Option<Uuid>,
    pub(crate) scope: Vec<String>,
}

impl Recorded for KeyRecord {}

/// A key's name, checked: ace3's column is `String(255)`.
pub(crate) fn key_name(name: &str) -> Result<&str, ServiceError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 255 || name.chars().any(char::is_control) {
        return Err(ServiceError::InvalidKeyName);
    }
    Ok(name)
}

/// A key's scope, checked and with repeats dropped, in a stable order.
pub(crate) fn key_scope(
    scope: &[PermissionPattern],
) -> Result<Vec<PermissionPattern>, ServiceError> {
    if scope.len() > MAX_KEY_SCOPE {
        return Err(ServiceError::InvalidRequest(format!(
            "a key's scope holds up to {MAX_KEY_SCOPE} patterns"
        )));
    }
    let mut seen = BTreeMap::new();
    for pattern in scope {
        if pattern.major() == USER_SELF.major() && pattern.minor() == USER_SELF.minor() {
            return Err(ServiceError::InvalidRequest(
                "user:self is only ever a person's, so a key's scope can't hold it".to_owned(),
            ));
        }
        seen.insert(pattern.to_string(), pattern.clone());
    }
    Ok(seen.into_values().collect())
}

/// Adds a key's allow rows. The key is new or has just lost its allows.
pub(crate) async fn insert_scope(
    conn: &mut PgConnection,
    key: Uuid,
    scope: &[PermissionPattern],
    by: &Actor,
) -> Result<(), ServiceError> {
    for pattern in scope {
        sqlx::query!(
            "INSERT INTO service.permissions (api_key_id, major, minor, effect, created_by)
             VALUES ($1, $2::text, $3::text, 'allow', $4::jsonb)",
            key,
            pattern.major(),
            pattern.minor(),
            Json(by) as _,
        )
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

pub(crate) fn as_user(actor: &Actor) -> Result<(UserId, &str), ServiceError> {
    match actor {
        Actor::User { id, name } => Ok((*id, name)),
        Actor::ApiKey { .. } | Actor::Internal { .. } => Err(ServiceError::PermissionDenied {
            actor: actor.to_string(),
            permission: USER_SELF,
        }),
    }
}

/// Refuses a change that, in its own transaction, has left the actor without `user:write`: revoking
/// your own grant of it, denying it to yourself, or leaving or deleting the group you hold it through.
/// Anyone else with `user:write` could still give it back, but you couldn't, so this is the grants'
/// version of `set_user_enabled` refusing to disable yourself. ace3 has no such check.
pub(crate) async fn keeps_user_write(
    conn: &mut PgConnection,
    actor: &Actor,
) -> Result<(), ServiceError> {
    if holds(conn, actor, &USER_WRITE).await? {
        return Ok(());
    }
    tracing::warn!(%actor, "a change that would take user:write from its actor was refused");
    Err(ServiceError::CantDropYourOwnUserWrite)
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
}

impl Service {
    /// Every user, by username, or only the enabled ones. ace3's list isn't paged either: a site has tens.
    pub async fn users(
        &self,
        actor: &Actor,
        include_disabled: bool,
    ) -> Result<Vec<User>, ServiceError> {
        self.gate
            .read(actor, "users", &USER_READ, &|tx| {
                Box::pin(async move { user_rows(tx.conn(), None, include_disabled).await })
            })
            .await
    }

    /// One user, with their grants and groups. A user that isn't there is `ServiceError::NoUser`.
    pub async fn user(&self, actor: &Actor, id: UserId) -> Result<UserDetail, ServiceError> {
        self.gate
            .read(actor, "user", &USER_READ, &|tx| {
                Box::pin(async move { user_detail(tx.conn(), id).await })
            })
            .await
    }

    /// Every group, with its members and grants.
    pub async fn groups(&self, actor: &Actor) -> Result<Vec<Group>, ServiceError> {
        self.gate
            .read(actor, "groups", &USER_READ, &|tx| {
                Box::pin(async move { group_rows(tx.conn(), None).await })
            })
            .await
    }

    /// API keys with their grants: one owner's, or every key, those with no owner included.
    pub async fn api_keys(
        &self,
        actor: &Actor,
        owner: Option<UserId>,
    ) -> Result<Vec<ApiKey>, ServiceError> {
        self.gate
            .read(actor, "api_keys", &USER_READ, &|tx| {
                Box::pin(async move { key_rows(tx.conn(), owner.map(|owner| owner.0)).await })
            })
            .await
    }

    /// The permissions ACE checks, for whoever grants them.
    pub async fn permission_catalog(
        &self,
        actor: &Actor,
    ) -> Result<&'static [CatalogEntry], ServiceError> {
        self.gate
            .read(actor, "permission_catalog", &USER_READ, &|_| {
                Box::pin(async move { Ok(()) })
            })
            .await?;
        Ok(CATALOG)
    }

    /// The user's own account. It needs no grant, but only a user has one.
    pub async fn own_account(&self, actor: &Actor) -> Result<User, ServiceError> {
        let (id, _) = as_user(actor)?;
        self.gate
            .read_own(&|tx| {
                Box::pin(async move {
                    user_rows(tx.conn(), Some(id), true)
                        .await?
                        .pop()
                        .ok_or(ServiceError::NoUser(id.0))
                })
            })
            .await
    }

    /// The user's own keys. It needs no grant, but only a user has any.
    pub async fn own_api_keys(&self, actor: &Actor) -> Result<Vec<ApiKey>, ServiceError> {
        let (id, _) = as_user(actor)?;
        self.gate
            .read_own(&|tx| Box::pin(async move { key_rows(tx.conn(), Some(id.0)).await }))
            .await
    }

    /// The permissions in the catalog the user holds, but `user:self`, which no key can: what a key they
    /// make for themselves may list, as ace3's `list_held_catalog` without its `SESSION_ONLY_PAIRS`, which
    /// its preferences page offers. It needs no grant, but only a user has any.
    pub async fn own_permissions(
        &self,
        actor: &Actor,
    ) -> Result<Vec<&'static CatalogEntry>, ServiceError> {
        as_user(actor)?;
        self.gate
            .read_own(&|tx| {
                Box::pin(async move {
                    let mut held = Vec::new();
                    for entry in CATALOG {
                        if !is_people_only(&entry.name)
                            && holds(tx.conn(), actor, &entry.name).await?
                        {
                            held.push(entry);
                        }
                    }
                    Ok(held)
                })
            })
            .await
    }

    /// Changes a user's profile. It needs `user:write`. Returns false when nothing changed.
    pub async fn update_user(
        &self,
        actor: &Actor,
        user: UserId,
        profile: &Profile,
    ) -> Result<bool, ServiceError> {
        let profile = profile.checked()?;
        let profile = &profile;
        self.gate
            .write(actor, "update_user", &USER_WRITE, &|tx| {
                Box::pin(async move { change_profile(tx.conn(), user, profile).await })
            })
            .await
    }

    /// A user changing their own display name, timezone or queue, as ace3's `PATCH /users/me`, which needs no
    /// grant. The email stays with `update_user`, as in ace3. Returns false when nothing changed.
    pub async fn update_own_profile(
        &self,
        actor: &Actor,
        profile: &Profile,
    ) -> Result<bool, ServiceError> {
        let (user, _) = as_user(actor)?;
        if profile.email.is_some() {
            return Err(ServiceError::InvalidRequest(
                "a user with user:write changes an email".to_owned(),
            ));
        }
        let profile = profile.checked()?;
        let profile = &profile;
        self.gate
            .write_own(actor, "update_own_profile", &|tx| {
                Box::pin(async move { change_profile(tx.conn(), user, profile).await })
            })
            .await
    }

    /// Makes a group with no members or grants. It needs `user:write`.
    pub async fn create_group(&self, actor: &Actor, name: &str) -> Result<GroupId, ServiceError> {
        let name = name.trim();
        if name.is_empty()
            || name.chars().count() > MAX_GROUP_NAME
            || name.chars().any(char::is_control)
        {
            return Err(ServiceError::InvalidRequest(format!(
                "a group's name is 1 to {MAX_GROUP_NAME} characters with no control characters"
            )));
        }
        let id = Uuid::new_v4();
        self.gate
            .write(actor, "create_group", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    sqlx::query!(
                        "INSERT INTO service.groups (id, name) VALUES ($1, $2)",
                        id,
                        name
                    )
                    .execute(tx.conn())
                    .await
                    .map_err(|error| {
                        if is_unique_violation(&error) {
                            ServiceError::GroupNameTaken
                        } else {
                            error.into()
                        }
                    })?;
                    let change = Change::added(
                        Target::holder(&Holder::Group(GroupId(id))),
                        &GroupRecord { name },
                    )?;
                    Ok(Audited::changed(GroupId(id), change))
                })
            })
            .await
    }

    /// Deletes a group, its memberships and its grants, which its members then stop holding. It needs
    /// `user:write`, which the actor mustn't lose by it. Returns false when there's no such group.
    pub async fn delete_group(&self, actor: &Actor, group: GroupId) -> Result<bool, ServiceError> {
        self.gate
            .write(actor, "delete_group", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let counts = sqlx::query!(
                        r#"SELECT
                             (SELECT count(*) FROM service.group_members WHERE group_id = $1) AS "members!",
                             (SELECT count(*) FROM service.permissions WHERE group_id = $1) AS "grants!""#,
                        group.0,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let removed = sqlx::query_scalar!(
                        "DELETE FROM service.groups WHERE id = $1 RETURNING name",
                        group.0,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(name) = removed else {
                        return Ok(Audited::unchanged(false));
                    };
                    keeps_user_write(tx.conn(), actor).await?;
                    let change = Change::removed(
                        Target::holder(&Holder::Group(group)),
                        &GroupRecord { name: &name },
                    )?
                    .details(&GroupRemoved {
                        members: counts.members,
                        grants: counts.grants,
                    })?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }

    /// Puts a user in a group. It needs `user:write`. Returns false when they were in it already.
    pub async fn add_group_member(
        &self,
        actor: &Actor,
        group: GroupId,
        user: UserId,
    ) -> Result<bool, ServiceError> {
        self.gate
            .write(actor, "add_group_member", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    // Locks both, so neither is deleted between this and the insert's foreign keys.
                    sqlx::query_scalar!(
                        "SELECT id FROM service.groups WHERE id = $1 FOR SHARE",
                        group.0
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| ServiceError::NotFound(format!("no group {}", group.0)))?;
                    sqlx::query_scalar!(
                        "SELECT id FROM service.users WHERE id = $1 FOR SHARE",
                        user.0
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or(ServiceError::NoUser(user.0))?;
                    let added = sqlx::query!(
                        "INSERT INTO service.group_members (group_id, user_id) VALUES ($1, $2)
                         ON CONFLICT DO NOTHING",
                        group.0,
                        user.0,
                    )
                    .execute(tx.conn())
                    .await?;
                    if added.rows_affected() == 0 {
                        return Ok(Audited::unchanged(false));
                    }
                    let change = Change::added(
                        Target::holder(&Holder::Group(group)),
                        &Membership { member: user.0 },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }

    /// Takes a user out of a group. It needs `user:write`, which the actor mustn't lose by it. Returns false
    /// when they weren't in it.
    pub async fn remove_group_member(
        &self,
        actor: &Actor,
        group: GroupId,
        user: UserId,
    ) -> Result<bool, ServiceError> {
        self.gate
            .write(actor, "remove_group_member", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let removed = sqlx::query!(
                        "DELETE FROM service.group_members WHERE group_id = $1 AND user_id = $2",
                        group.0,
                        user.0,
                    )
                    .execute(tx.conn())
                    .await?;
                    if removed.rows_affected() == 0 {
                        return Ok(Audited::unchanged(false));
                    }
                    keeps_user_write(tx.conn(), actor).await?;
                    let change = Change::removed(
                        Target::holder(&Holder::Group(group)),
                        &Membership { member: user.0 },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }

    /// Renames a key and replaces its allows with `scope`, keeping its secret, so a key in use picks up
    /// the change on its next request, as ace3's does. A deny on the key stays. It needs `user:write`.
    /// Returns false when nothing changed; a key that isn't there is `ServiceError::NotFound`.
    pub async fn set_api_key_scope(
        &self,
        actor: &Actor,
        key: ApiKeyId,
        name: &str,
        scope: &[PermissionPattern],
    ) -> Result<bool, ServiceError> {
        let (name, scope) = (key_name(name)?, key_scope(scope)?);
        let scope = &scope;
        self.gate
            .write(actor, "set_api_key_scope", &USER_WRITE, &|tx| {
                Box::pin(
                    async move { replace_scope(tx.conn(), actor, key, None, name, scope).await },
                )
            })
            .await
    }

    /// Makes a key for the user themselves, as ace3's `POST /users/me/apikeys`. It needs `user:self`, which
    /// only a person holds, so a key can't make another. The scope has to name at least one pattern, each
    /// covering permissions ACE checks that the user holds. The token is here once.
    pub async fn create_own_api_key(
        &self,
        actor: &Actor,
        name: &str,
        scope: &[PermissionPattern],
    ) -> Result<NewApiKey, ServiceError> {
        let (name, scope) = (key_name(name)?, own_scope(scope)?);
        let scope = &scope;
        let minted = crate::auth::mint_api_key()?;
        let (id, hash) = (minted.id, minted.hash.as_bytes());
        self.gate
            .write(actor, "create_own_api_key", &USER_SELF, &|tx| {
                Box::pin(async move {
                    let (user, _) = as_user(actor)?;
                    within_grants(tx.conn(), actor, scope).await?;
                    sqlx::query!(
                        "INSERT INTO service.api_keys (id, name, owner_id, secret_hash, created_by)
                         VALUES ($1, $2, $3, $4, $5::jsonb)",
                        id,
                        name,
                        user.0,
                        hash,
                        Json(actor) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                    insert_scope(tx.conn(), id, scope, actor).await?;
                    let change = Change::added(
                        Target::holder(&Holder::ApiKey(ApiKeyId(id))),
                        &KeyRecord {
                            name: name.to_owned(),
                            owner: Some(user.0),
                            scope: scope.iter().map(ToString::to_string).collect(),
                        },
                    )?;
                    Ok(Audited::changed((), change))
                })
            })
            .await?;
        Ok(NewApiKey {
            id: ApiKeyId(id),
            token: minted.token,
        })
    }

    /// `set_api_key_scope` on one of the user's own keys, under `create_own_api_key`'s rules for the whole
    /// new scope, so a pattern they no longer hold has to go before anything else about the key changes,
    /// as in ace3. Another user's key is `ServiceError::NotFound`, as if it weren't there.
    pub async fn set_own_api_key_scope(
        &self,
        actor: &Actor,
        key: ApiKeyId,
        name: &str,
        scope: &[PermissionPattern],
    ) -> Result<bool, ServiceError> {
        let (name, scope) = (key_name(name)?, own_scope(scope)?);
        let scope = &scope;
        self.gate
            .write(actor, "set_own_api_key_scope", &USER_SELF, &|tx| {
                Box::pin(async move {
                    let (user, _) = as_user(actor)?;
                    within_grants(tx.conn(), actor, scope).await?;
                    replace_scope(tx.conn(), actor, key, Some(user), name, scope).await
                })
            })
            .await
    }

    /// Deletes one of the user's own keys. It needs `user:self`. Returns false when they have no such
    /// key, which is also what another user's key gets.
    pub async fn revoke_own_api_key(
        &self,
        actor: &Actor,
        key: ApiKeyId,
    ) -> Result<bool, ServiceError> {
        self.gate
            .write(actor, "revoke_own_api_key", &USER_SELF, &|tx| {
                Box::pin(async move {
                    let (user, _) = as_user(actor)?;
                    let scope = key_allows(tx.conn(), key).await?;
                    let removed = sqlx::query!(
                        "DELETE FROM service.api_keys WHERE id = $1 AND owner_id = $2 RETURNING name",
                        key.0,
                        user.0,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(removed) = removed else {
                        foreign_key_attempt(tx.conn(), key, user, "revoke").await?;
                        return Ok(Audited::unchanged(false));
                    };
                    let change = Change::removed(
                        Target::holder(&Holder::ApiKey(key)),
                        &KeyRecord {
                            name: removed.name,
                            owner: Some(user.0),
                            scope,
                        },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }
}

/// A scope for a user's own key: `key_scope`, and not empty, as ace3's self-service keys must list what
/// they need.
fn own_scope(scope: &[PermissionPattern]) -> Result<Vec<PermissionPattern>, ServiceError> {
    let scope = key_scope(scope)?;
    if scope.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "a key you make yourself has to list the permissions it needs".to_owned(),
        ));
    }
    Ok(scope)
}

/// ace3's `_check_scope_within_grants`: each pattern covers something in the catalog, and the actor holds
/// all it covers.
async fn within_grants(
    conn: &mut PgConnection,
    actor: &Actor,
    scope: &[PermissionPattern],
) -> Result<(), ServiceError> {
    let mut problems = Vec::new();
    for pattern in scope {
        let covered: Vec<_> = covered_by(pattern).collect();
        if covered.is_empty() {
            problems.push(format!("{pattern} matches no permission ACE checks"));
            continue;
        }
        let mut unheld = Vec::new();
        for name in covered {
            if !holds(conn, actor, name).await? {
                unheld.push(name.to_string());
            }
        }
        if !unheld.is_empty() {
            problems.push(format!(
                "{pattern} covers {}, which you don't hold",
                unheld.join(", ")
            ));
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    let detail = problems.join("; ");
    tracing::warn!(%actor, %detail, "a key's scope was refused");
    Err(ServiceError::InvalidRequest(detail))
}

/// Logs a user naming another user's key, which the caller then reports as missing, so the answer
/// doesn't say the key exists. The log is the only trace of the attempt, as in ace3.
async fn foreign_key_attempt(
    conn: &mut PgConnection,
    key: ApiKeyId,
    user: UserId,
    action: &str,
) -> Result<(), ServiceError> {
    let owner = sqlx::query_scalar!("SELECT owner_id FROM service.api_keys WHERE id = $1", key.0)
        .fetch_optional(conn)
        .await?;
    if let Some(owner) = owner {
        tracing::warn!(
            user = %user.0, key = %key.0, owner = ?owner, action,
            "a user named an API key that isn't theirs"
        );
    }
    Ok(())
}

/// A key's allows, as `major:minor` in order.
pub(crate) async fn key_allows(
    conn: &mut PgConnection,
    key: ApiKeyId,
) -> Result<Vec<String>, ServiceError> {
    let rows = sqlx::query!(
        r#"SELECT major::text AS "major!", minor::text AS "minor!"
           FROM service.permissions WHERE api_key_id = $1 AND effect = 'allow'"#,
        key.0,
    )
    .fetch_all(conn)
    .await?;
    let scope: BTreeSet<String> = rows
        .iter()
        .map(|row| format!("{}:{}", row.major, row.minor))
        .collect();
    Ok(scope.into_iter().collect())
}

/// Renames a key and replaces its allows, in the write's transaction. With `owner`, only that user's key.
async fn replace_scope(
    conn: &mut PgConnection,
    by: &Actor,
    key: ApiKeyId,
    owner: Option<UserId>,
    name: &str,
    scope: &[PermissionPattern],
) -> Result<Audited<bool>, ServiceError> {
    // Locks the key, so two changes at once replace the scope one after the other.
    let found = sqlx::query!(
        "SELECT name, owner_id FROM service.api_keys
         WHERE id = $1 AND ($2::uuid IS NULL OR owner_id = $2) FOR UPDATE",
        key.0,
        owner.map(|owner| owner.0),
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(found) = found else {
        if let Some(owner) = owner {
            foreign_key_attempt(conn, key, owner, "change").await?;
        }
        return Err(ServiceError::NotFound(format!("no API key {}", key.0)));
    };
    let before = KeyRecord {
        name: found.name,
        owner: found.owner_id,
        scope: key_allows(&mut *conn, key).await?,
    };
    let after = KeyRecord {
        name: name.to_owned(),
        owner: found.owner_id,
        scope: scope
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    };
    if before == after {
        return Ok(Audited::unchanged(false));
    }
    sqlx::query!(
        "DELETE FROM service.permissions WHERE api_key_id = $1 AND effect = 'allow'",
        key.0
    )
    .execute(&mut *conn)
    .await?;
    insert_scope(conn, key.0, scope, by).await?;
    sqlx::query!(
        "UPDATE service.api_keys SET name = $2 WHERE id = $1",
        key.0,
        name
    )
    .execute(&mut *conn)
    .await?;
    let change = Change::updated(Target::holder(&Holder::ApiKey(key)), &before, &after)?;
    Ok(Audited::changed(true, change))
}

async fn change_profile(
    conn: &mut PgConnection,
    user: UserId,
    profile: &CheckedProfile,
) -> Result<Audited<bool>, ServiceError> {
    let found = sqlx::query!(
        r#"SELECT display_name, email, timezone, queue AS "queue!: String"
           FROM service.users WHERE id = $1 FOR UPDATE"#,
        user.0,
    )
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ServiceError::NoUser(user.0))?;
    let before = ProfileRecord {
        display_name: found.display_name,
        email: found.email,
        timezone: found.timezone,
        queue: found.queue,
    };
    let after = ProfileRecord {
        display_name: profile
            .display_name
            .clone()
            .unwrap_or_else(|| before.display_name.clone()),
        email: profile
            .email
            .clone()
            .unwrap_or_else(|| before.email.clone()),
        timezone: profile
            .timezone
            .clone()
            .unwrap_or_else(|| before.timezone.clone()),
        queue: profile
            .queue
            .clone()
            .unwrap_or_else(|| before.queue.clone()),
    };
    if before == after {
        return Ok(Audited::unchanged(false));
    }
    sqlx::query!(
        "UPDATE service.users SET display_name = $2, email = $3, timezone = $4, queue = $5::text
         WHERE id = $1",
        user.0,
        after.display_name,
        after.email,
        after.timezone,
        after.queue,
    )
    .execute(&mut *conn)
    .await?;
    let change = Change::updated(Target::holder(&Holder::User(user)), &before, &after)?;
    Ok(Audited::changed(true, change))
}

async fn user_rows(
    conn: &mut PgConnection,
    only: Option<UserId>,
    include_disabled: bool,
) -> Result<Vec<User>, ServiceError> {
    let rows = sqlx::query!(
        r#"SELECT u.id, u.username::text AS "username!", u.display_name, u.email, u.timezone,
                  u.queue AS "queue!: String", u.enabled, u.created_at,
                  (SELECT count(*) FROM service.api_keys k WHERE k.owner_id = u.id) AS "api_keys!"
           FROM service.users u
           WHERE ($1::uuid IS NULL OR u.id = $1) AND ($2 OR u.enabled)
           ORDER BY u.username"#,
        only.map(|user| user.0),
        include_disabled,
    )
    .fetch_all(conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| User {
            id: UserId(row.id),
            username: row.username,
            display_name: row.display_name,
            email: row.email,
            timezone: row.timezone,
            queue: row.queue,
            enabled: row.enabled,
            created_at: row.created_at,
            api_keys: row.api_keys,
        })
        .collect())
}

async fn user_detail(conn: &mut PgConnection, id: UserId) -> Result<UserDetail, ServiceError> {
    let user = user_rows(&mut *conn, Some(id), true)
        .await?
        .pop()
        .ok_or(ServiceError::NoUser(id.0))?;
    let grants = sqlx::query!(
        r#"SELECT id, major::text AS "major!", minor::text AS "minor!", effect AS "effect: Effect"
           FROM service.permissions WHERE user_id = $1 ORDER BY major, minor, effect"#,
        id.0,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| Grant {
        id: row.id,
        major: row.major,
        minor: row.minor,
        effect: row.effect,
    })
    .collect();
    let groups = group_rows(conn, Some(id)).await?;
    Ok(UserDetail {
        user,
        grants,
        groups,
    })
}

/// Every group, or only a member's.
async fn group_rows(
    conn: &mut PgConnection,
    member: Option<UserId>,
) -> Result<Vec<Group>, ServiceError> {
    let groups = sqlx::query!(
        "SELECT id, name FROM service.groups
         WHERE $1::uuid IS NULL
            OR id IN (SELECT group_id FROM service.group_members WHERE user_id = $1)
         ORDER BY name",
        member.map(|member| member.0),
    )
    .fetch_all(&mut *conn)
    .await?;
    let ids: Vec<Uuid> = groups.iter().map(|group| group.id).collect();
    let mut members: BTreeMap<Uuid, Vec<UserId>> = BTreeMap::new();
    for row in sqlx::query!(
        "SELECT m.group_id, m.user_id FROM service.group_members m
         JOIN service.users u ON u.id = m.user_id
         WHERE m.group_id = ANY($1) ORDER BY u.username",
        &ids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        members
            .entry(row.group_id)
            .or_default()
            .push(UserId(row.user_id));
    }
    let mut grants: BTreeMap<Uuid, Vec<Grant>> = BTreeMap::new();
    for row in sqlx::query!(
        r#"SELECT id, group_id AS "group_id!", major::text AS "major!", minor::text AS "minor!",
                  effect AS "effect: Effect"
           FROM service.permissions WHERE group_id = ANY($1) ORDER BY major, minor, effect"#,
        &ids,
    )
    .fetch_all(conn)
    .await?
    {
        grants.entry(row.group_id).or_default().push(Grant {
            id: row.id,
            major: row.major,
            minor: row.minor,
            effect: row.effect,
        });
    }
    Ok(groups
        .into_iter()
        .map(|group| Group {
            id: GroupId(group.id),
            members: members.remove(&group.id).unwrap_or_default(),
            grants: grants.remove(&group.id).unwrap_or_default(),
            name: group.name,
        })
        .collect())
}

async fn key_rows(
    conn: &mut PgConnection,
    owner: Option<Uuid>,
) -> Result<Vec<ApiKey>, ServiceError> {
    let keys = sqlx::query!(
        r#"SELECT id, name, owner_id, created_at, created_by AS "created_by: Value"
           FROM service.api_keys WHERE $1::uuid IS NULL OR owner_id = $1
           ORDER BY created_at, id"#,
        owner,
    )
    .fetch_all(&mut *conn)
    .await?;
    let ids: Vec<Uuid> = keys.iter().map(|key| key.id).collect();
    let mut grants: BTreeMap<Uuid, Vec<Grant>> = BTreeMap::new();
    for row in sqlx::query!(
        r#"SELECT id, api_key_id AS "api_key_id!", major::text AS "major!", minor::text AS "minor!",
                  effect AS "effect: Effect"
           FROM service.permissions WHERE api_key_id = ANY($1) ORDER BY major, minor, effect"#,
        &ids,
    )
    .fetch_all(conn)
    .await?
    {
        grants.entry(row.api_key_id).or_default().push(Grant {
            id: row.id,
            major: row.major,
            minor: row.minor,
            effect: row.effect,
        });
    }
    keys.into_iter()
        .map(|key| {
            Ok(ApiKey {
                id: ApiKeyId(key.id),
                grants: grants.remove(&key.id).unwrap_or_default(),
                name: key.name,
                owner: key.owner_id.map(UserId),
                created_at: key.created_at,
                created_by: RecordedActor::from_row(Some(key.created_by))?
                    .ok_or_else(|| ServiceError::NotFound("a key's maker".to_owned()))?,
            })
        })
        .collect()
}
