//! Who a request is (PLAN.md 5.4): a GUI session and an API key each become the `Actor` of 5.1, or no
//! actor at all. An adapter calls `Service::authenticate_request` and passes the actor to a service
//! function, which is where 5.2's check and 5.3's audit happen.
//!
//! From ace3, and what differs:
//! - Passwords: `password`'s docs. A wrong password, an unknown user and a disabled user all get
//!   `ServiceError::NotAuthenticated` after the same hashing. ace3 skips the hash for an unknown user and
//!   says "User is disabled." to whoever has that user's password.
//! - Keys are a SHA-256 of a token shown once, as in ace3, and `token`'s docs say what's added. A key with
//!   no rows holds nothing, and ace3's `inherit_user_scope` is a grant of `*:*` to it (`gate`'s docs).
//! - A session is a row, where ace3's is a signed cookie it can't revoke. It ends
//!   `SESSION_LIFETIME_SECONDS` after a login, whatever happens in between. ace3 has no limit of its own:
//!   a browser session, or a year with "remember me", which has no equivalent here.
//! - Disabling a user deletes their sessions and stops their keys, in one transaction, and re-enabling
//!   brings back the keys only. ace3 stops both while the user is disabled. A password change deletes the
//!   sessions, as ace3 logs its user out, and leaves the keys alone, as ace3 does.
//! - A login and a logout each have an audit row, with the session's id as the target. ace3 writes a
//!   plain log line for a login and nothing for a logout, because neither changes a row there. A failed
//!   login is a warning in the log and no row, for the reason `gate::audit` gives for a refusal.
//! - The log names a failed login's user id if the name was a user's, and nothing otherwise. ace3 logs
//!   the submitted name, which is sometimes a password typed into the wrong box. An adapter adds the
//!   source address, which ace3 logs and this crate doesn't know.
//! - No lockout, as in ace3: one would let anyone lock the admin out by failing on purpose. Guessing is
//!   slowed by the hash, `HASHES_AT_ONCE` and a longer minimum password. Throttling by address, if a
//!   production deployment wants it, belongs in front of the adapter, which is where the address is.
//! - No OIDC, SAML or LDAP, as ace3 has none.
//!
//! An actor is only as current as its authentication, so an adapter authenticates every request and
//! doesn't keep one. `Gate` doesn't look at `enabled` (its docs say so).

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::types::Json;
use uuid::Uuid;

use crate::actor::{Actor, ApiKeyId, Component, UserId};
use crate::gate::{Audited, Change, Holder, Recorded, Target};
use crate::permission::{Effect, PermissionPattern, USER_SELF, USER_WRITE};
use crate::{Service, ServiceError};

mod password;
mod token;
mod web;

pub(crate) use password::Passwords;
pub use password::{MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS, Password};
pub use token::IssuedToken;
pub use web::{RequestParts, SessionCookie, Transport};

use token::Kind;

/// How long a session lasts from its login: a long shift.
pub const SESSION_LIFETIME_SECONDS: i32 = 12 * 60 * 60;

/// ace3's column is `String(255)`.
const MAX_KEY_NAME: usize = 255;

/// A username: ASCII and lowercase, by the same reasoning as a permission's parts, with migration 0022
/// holding a stored one to the same rule. ace3 leaves case to its database's collation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Username(String);

/// Says nothing of what was typed, which might be a password in the wrong box.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a username is 1 to 64 ASCII letters, digits and _ . @ + -")]
pub struct InvalidUsername;

impl Username {
    pub fn new(name: &str) -> Result<Self, InvalidUsername> {
        let name = name.to_ascii_lowercase();
        let allowed = |byte: u8| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'.' | b'@' | b'+' | b'-')
        };
        if name.is_empty() || name.len() > 64 || !name.bytes().all(allowed) {
            return Err(InvalidUsername);
        }
        Ok(Username(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A session just made by a login.
#[derive(Debug)]
pub struct NewSession {
    pub actor: Actor,
    pub expires_at: DateTime<Utc>,
    pub token: IssuedToken,
}

/// An API key just made. The token is here once. The key holds nothing until it's granted something.
#[derive(Debug)]
pub struct NewApiKey {
    pub id: ApiKeyId,
    pub token: IssuedToken,
}

#[derive(Serialize)]
struct UserRecord<'a> {
    username: &'a str,
    enabled: bool,
}

impl Recorded for UserRecord<'_> {}

#[derive(Serialize)]
struct FirstUserDetails {
    grants: &'static str,
    forced: bool,
}

impl Recorded for FirstUserDetails {}

#[derive(Serialize)]
struct Enabled {
    enabled: bool,
}

impl Recorded for Enabled {}

#[derive(Serialize)]
struct SessionsEnded {
    sessions_ended: u64,
}

impl Recorded for SessionsEnded {}

#[derive(Serialize)]
struct SessionRecord {
    user: Uuid,
    expires_at: DateTime<Utc>,
}

impl Recorded for SessionRecord {}

#[derive(Serialize)]
struct LoginDetails {
    replaced_session: Option<Uuid>,
}

impl Recorded for LoginDetails {}

#[derive(Serialize)]
struct ApiKeyRecord<'a> {
    name: &'a str,
    owner: Option<Uuid>,
}

impl Recorded for ApiKeyRecord<'_> {}

/// That a password changed. Nothing about the password is in a row, not even its hash.
#[derive(Serialize)]
struct PasswordChanged {
    password_changed: bool,
}

impl Recorded for PasswordChanged {}

/// Whether an insert failed on a unique constraint, which here is only ever the username.
fn is_taken(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
}

impl Service {
    /// Checks a username and password and, if they're an enabled user's, makes a session and returns its
    /// token, once. Any other outcome is the same `NotAuthenticated` after the same hashing. `previous` is
    /// the session cookie the request came with, if any, and it stops working here, so a login always
    /// ends in a new id. This needs no permission: a user with no grants can still log in.
    pub async fn login(
        &self,
        username: &str,
        password: Password,
        previous: Option<&str>,
    ) -> Result<NewSession, ServiceError> {
        let account = match Username::new(username) {
            Ok(name) => self.gate.account_named(name.as_str()).await?,
            Err(_) => None,
        };
        let stored = account.as_ref().map(|found| found.password_hash.clone());
        let verified = self.passwords.verify(stored, password).await?;
        let account = match account {
            Some(found) if verified && found.enabled => found,
            Some(found) => {
                tracing::warn!(user = %found.id.0, "a login failed");
                return Err(ServiceError::NotAuthenticated);
            }
            None => {
                tracing::warn!("a login failed for a name that isn't a user's");
                return Err(ServiceError::NotAuthenticated);
            }
        };

        let replaced = match previous {
            Some(presented) => self.session_named_by(presented).await?.map(|(id, _)| id),
            None => None,
        };
        let minted = token::mint(Kind::Session)?;
        let (id, hash) = (minted.id, minted.hash.as_bytes());
        let user = account.id.0;
        let password_hash = account.password_hash.as_str();
        let actor = Actor::User {
            id: account.id,
            name: account.username.clone(),
        };
        let expires_at = self
            .gate
            .write_own(&actor, "login", &|tx| {
                Box::pin(async move {
                    // Locks the user against a disable or a password change that began after the
                    // password was checked. Whichever commits first, no session outlives it.
                    let current = sqlx::query_scalar!(
                        "SELECT id FROM service.users
                         WHERE id = $1 AND enabled AND password_hash = $2 FOR SHARE",
                        user,
                        password_hash,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    if current.is_none() {
                        return Err(ServiceError::NotAuthenticated);
                    }
                    // Expired rows have no other way out, and this keeps a user's few.
                    sqlx::query!(
                        "DELETE FROM service.sessions
                         WHERE id = $1 OR (user_id = $2 AND expires_at <= now())",
                        replaced,
                        user,
                    )
                    .execute(tx.conn())
                    .await?;
                    let expires_at = sqlx::query_scalar!(
                        "INSERT INTO service.sessions (id, user_id, secret_hash, expires_at)
                         VALUES ($1, $2, $3, now() + make_interval(secs => $4))
                         RETURNING expires_at",
                        id,
                        user,
                        hash,
                        f64::from(SESSION_LIFETIME_SECONDS),
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let change =
                        Change::added(Target::session(id), &SessionRecord { user, expires_at })?
                            .details(&LoginDetails {
                                replaced_session: replaced,
                            })?;
                    Ok(Audited::changed(expires_at, change))
                })
            })
            .await?;
        Ok(NewSession {
            actor,
            expires_at,
            token: minted.token,
        })
    }

    /// Ends the session a token names. Returns false when it names no live session, so a second logout,
    /// or one with a stale cookie, isn't an error. This needs no permission beyond holding the token.
    pub async fn logout(&self, session_token: &str) -> Result<bool, ServiceError> {
        let Some((id, actor)) = self.session_named_by(session_token).await? else {
            return Ok(false);
        };
        self.gate
            .write_own(&actor, "logout", &|tx| {
                Box::pin(async move {
                    let ended = sqlx::query!(
                        "DELETE FROM service.sessions WHERE id = $1 RETURNING user_id, expires_at",
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(ended) = ended else {
                        return Ok(Audited::unchanged(false));
                    };
                    let change = Change::removed(
                        Target::session(id),
                        &SessionRecord {
                            user: ended.user_id,
                            expires_at: ended.expires_at,
                        },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }

    /// The id and user of the live session a token names, comparing its secret in constant time.
    async fn session_named_by(
        &self,
        presented: &str,
    ) -> Result<Option<(Uuid, Actor)>, ServiceError> {
        let Some((id, hash)) = token::parse(Kind::Session, presented) else {
            return Ok(None);
        };
        Ok(self
            .gate
            .live_session(id)
            .await?
            .filter(|stored| hash.matches(&stored.secret_hash))
            .map(|stored| (id, stored.actor)))
    }

    /// The user a session token stands for.
    pub async fn authenticate_session(&self, presented: &str) -> Result<Actor, ServiceError> {
        match self.session_named_by(presented).await? {
            Some((_, actor)) => Ok(actor),
            None => Err(ServiceError::NotAuthenticated),
        }
    }

    /// The key an API key's token stands for, carrying its name and owner.
    pub async fn authenticate_api_key(&self, presented: &str) -> Result<Actor, ServiceError> {
        let found = match token::parse(Kind::ApiKey, presented) {
            Some((id, hash)) => self
                .gate
                .usable_api_key(ApiKeyId(id))
                .await?
                .filter(|stored| hash.matches(&stored.secret_hash)),
            None => None,
        };
        match found {
            Some(stored) => Ok(stored.actor),
            None => Err(ServiceError::NotAuthenticated),
        }
    }

    /// The actor a request authenticates as, for an adapter's extractor (5.5, 5.7). A request with an
    /// `Authorization` header is judged by that alone: ace3 falls back to its cookie, but a client sending
    /// a bad key should find out. A session must also pass `RequestParts::same_origin`, or this is
    /// `ServiceError::CrossSiteRequest`.
    pub async fn authenticate_request(
        &self,
        request: &RequestParts<'_>,
    ) -> Result<Actor, ServiceError> {
        if let Some(authorization) = request.authorization {
            let presented =
                RequestParts::bearer(authorization).ok_or(ServiceError::NotAuthenticated)?;
            return self.authenticate_api_key(presented).await;
        }
        let presented = request
            .cookie
            .and_then(|header| SessionCookie::new(request.transport).read(header))
            .ok_or(ServiceError::NotAuthenticated)?;
        let actor = self.authenticate_session(presented).await?;
        if !request.same_origin() {
            tracing::warn!(%actor, method = request.method, "a cross-site request was refused");
            return Err(ServiceError::CrossSiteRequest);
        }
        Ok(actor)
    }

    /// Adds a user with no grants. It needs `user:write`.
    pub async fn create_user(
        &self,
        actor: &Actor,
        username: &Username,
        password: Password,
    ) -> Result<UserId, ServiceError> {
        let password_hash = self.passwords.hash(password).await?;
        let id = Uuid::new_v4();
        let (name, hash) = (username.as_str(), password_hash.as_str());
        self.gate
            .write(actor, "create_user", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    insert_user(tx.conn(), id, name, hash, actor).await?;
                    let change = Change::added(
                        Target::holder(&Holder::User(UserId(id))),
                        &UserRecord {
                            username: name,
                            enabled: true,
                        },
                    )?;
                    Ok(Audited::changed(UserId(id), change))
                })
            })
            .await
    }

    /// Makes the first user, holding `*:*`, for an operator with database access. ace4 ships no default
    /// account. It acts as the component `bootstrap`, which migration 0022 gives `user:write`. If any user
    /// exists it's `ServiceError::UsersExist`, unless `force`, which is how an operator who has lost every
    /// admin's password makes a new admin.
    pub async fn create_first_user(
        &self,
        username: &Username,
        password: Password,
        force: bool,
    ) -> Result<UserId, ServiceError> {
        let actor = Actor::Internal {
            id: Component::new("bootstrap").expect("a valid name"),
        };
        let password_hash = self.passwords.hash(password).await?;
        let id = Uuid::new_v4();
        let (name, hash, by) = (username.as_str(), password_hash.as_str(), &actor);
        self.gate
            .write(&actor, "create_first_user", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    // So two of these at once can't each find no users. Reads and logins go on.
                    sqlx::query!("LOCK TABLE service.users IN SHARE ROW EXCLUSIVE MODE")
                        .execute(tx.conn())
                        .await?;
                    let exists = sqlx::query_scalar!(
                        r#"SELECT EXISTS (SELECT FROM service.users) AS "exists!""#
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    if exists && !force {
                        return Err(ServiceError::UsersExist);
                    }
                    insert_user(tx.conn(), id, name, hash, by).await?;
                    let every = PermissionPattern::new("*", "*")?;
                    sqlx::query!(
                        "INSERT INTO service.permissions (user_id, major, minor, effect, created_by)
                         VALUES ($1, $2::text, $3::text, $4, $5::jsonb)",
                        id,
                        every.major(),
                        every.minor(),
                        Effect::Allow as Effect,
                        Json(by) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                    let change = Change::added(
                        Target::holder(&Holder::User(UserId(id))),
                        &UserRecord {
                            username: name,
                            enabled: true,
                        },
                    )?
                    .details(&FirstUserDetails {
                        grants: "*:*",
                        forced: exists,
                    })?;
                    Ok(Audited::changed(UserId(id), change))
                })
            })
            .await
    }

    /// Turns a user on or off. It needs `user:write`. Disabling ends their sessions in the same
    /// transaction and stops their keys, and they can't disable themselves, as in ace3. Returns false if
    /// the user was already in that state.
    pub async fn set_user_enabled(
        &self,
        actor: &Actor,
        user: UserId,
        enabled: bool,
    ) -> Result<bool, ServiceError> {
        let own = match actor {
            Actor::User { id, .. } => Some(*id),
            Actor::ApiKey { owner, .. } => *owner,
            Actor::Internal { .. } => None,
        };
        self.gate
            .write(actor, "set_user_enabled", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    if !enabled && own == Some(user) {
                        return Err(ServiceError::CantDisableYourself);
                    }
                    let was = sqlx::query_scalar!(
                        "SELECT enabled FROM service.users WHERE id = $1 FOR UPDATE",
                        user.0,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or(ServiceError::NoUser(user.0))?;
                    if was == enabled {
                        return Ok(Audited::unchanged(false));
                    }
                    sqlx::query!(
                        "UPDATE service.users SET enabled = $2 WHERE id = $1",
                        user.0,
                        enabled,
                    )
                    .execute(tx.conn())
                    .await?;
                    let sessions_ended = if enabled {
                        0
                    } else {
                        end_sessions(tx.conn(), user).await?
                    };
                    let change = Change::updated(
                        Target::holder(&Holder::User(user)),
                        &Enabled { enabled: was },
                        &Enabled { enabled },
                    )?
                    .details(&SessionsEnded { sessions_ended })?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }

    /// Sets someone's password without asking for the old one, as ace3's user editing does. It needs
    /// `user:write`, and ends their sessions.
    pub async fn reset_password(
        &self,
        actor: &Actor,
        user: UserId,
        password: Password,
    ) -> Result<(), ServiceError> {
        let password_hash = self.passwords.hash(password).await?;
        let hash = password_hash.as_str();
        self.gate
            .write(actor, "reset_password", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let changed = sqlx::query!(
                        "UPDATE service.users SET password_hash = $2 WHERE id = $1",
                        user.0,
                        hash,
                    )
                    .execute(tx.conn())
                    .await?;
                    if changed.rows_affected() == 0 {
                        return Err(ServiceError::NoUser(user.0));
                    }
                    let sessions_ended = end_sessions(tx.conn(), user).await?;
                    let change = Change::added(
                        Target::holder(&Holder::User(user)),
                        &PasswordChanged {
                            password_changed: true,
                        },
                    )?
                    .details(&SessionsEnded { sessions_ended })?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }

    /// A user changing their own password, proving the current one. It needs no grant, as in ace3, where
    /// any logged-in user can. Only a user can: an API key refused here can't turn a leak into an account.
    /// It ends every session of theirs, including the one asking, so they log in again, as in ace3. A
    /// wrong current password is `NotAuthenticated`.
    pub async fn change_own_password(
        &self,
        actor: &Actor,
        current: Password,
        new: Password,
    ) -> Result<(), ServiceError> {
        let Actor::User { id: user, .. } = actor else {
            return Err(ServiceError::PermissionDenied {
                actor: actor.to_string(),
                permission: USER_SELF,
            });
        };
        new.check_strength()?;
        let account = self.gate.account(*user).await?;
        let stored = account.as_ref().map(|found| found.password_hash.clone());
        if !self.passwords.verify(stored.clone(), current).await? {
            tracing::warn!(%actor, "a password change gave the wrong current password");
            return Err(ServiceError::NotAuthenticated);
        }
        let password_hash = self.passwords.hash(new).await?;
        let (user, old, hash) = (*user, stored.as_deref(), password_hash.as_str());
        self.gate
            .write_own(actor, "change_own_password", &|tx| {
                Box::pin(async move {
                    // Only over the hash that was checked, so of two changes at once one fails.
                    let changed = sqlx::query!(
                        "UPDATE service.users SET password_hash = $2
                         WHERE id = $1 AND enabled AND password_hash = $3",
                        user.0,
                        hash,
                        old,
                    )
                    .execute(tx.conn())
                    .await?;
                    if changed.rows_affected() == 0 {
                        return Err(ServiceError::NotAuthenticated);
                    }
                    let sessions_ended = end_sessions(tx.conn(), user).await?;
                    let change = Change::added(
                        Target::holder(&Holder::User(user)),
                        &PasswordChanged {
                            password_changed: true,
                        },
                    )?
                    .details(&SessionsEnded { sessions_ended })?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }

    /// Makes an API key, with an owner or standing for a service, and returns its token, once. It needs
    /// `user:write`. A key holds nothing until `grant` gives it something, and with an owner it never
    /// holds more than the owner does. ace3's self-service for one's own keys, under `user:self`, comes
    /// with the users router (5.6).
    pub async fn create_api_key(
        &self,
        actor: &Actor,
        name: &str,
        owner: Option<UserId>,
    ) -> Result<NewApiKey, ServiceError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_KEY_NAME {
            return Err(ServiceError::InvalidKeyName);
        }
        let minted = token::mint(Kind::ApiKey)?;
        let (id, hash) = (minted.id, minted.hash.as_bytes());
        let owner_id = owner.map(|owner| owner.0);
        self.gate
            .write(actor, "create_api_key", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    if let Some(owner) = owner_id {
                        // Locks it, so a deletion can't come between this and the foreign key's check.
                        sqlx::query_scalar!(
                            "SELECT id FROM service.users WHERE id = $1 FOR SHARE",
                            owner,
                        )
                        .fetch_optional(tx.conn())
                        .await?
                        .ok_or(ServiceError::NoUser(owner))?;
                    }
                    sqlx::query!(
                        "INSERT INTO service.api_keys (id, name, owner_id, secret_hash, created_by)
                         VALUES ($1, $2, $3, $4, $5::jsonb)",
                        id,
                        name,
                        owner_id,
                        hash,
                        Json(actor) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                    let change = Change::added(
                        Target::holder(&Holder::ApiKey(ApiKeyId(id))),
                        &ApiKeyRecord {
                            name,
                            owner: owner_id,
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

    /// Deletes an API key, as ace3 does, and its grants with it. It needs `user:write`. Returns false when
    /// there's no such key.
    pub async fn revoke_api_key(&self, actor: &Actor, key: ApiKeyId) -> Result<bool, ServiceError> {
        self.gate
            .write(actor, "revoke_api_key", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let removed = sqlx::query!(
                        "DELETE FROM service.api_keys WHERE id = $1 RETURNING name, owner_id",
                        key.0,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(removed) = removed else {
                        return Ok(Audited::unchanged(false));
                    };
                    let change = Change::removed(
                        Target::holder(&Holder::ApiKey(key)),
                        &ApiKeyRecord {
                            name: &removed.name,
                            owner: removed.owner_id,
                        },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }
}

async fn insert_user(
    conn: &mut sqlx::PgConnection,
    id: Uuid,
    name: &str,
    hash: &str,
    by: &Actor,
) -> Result<(), ServiceError> {
    sqlx::query!(
        "INSERT INTO service.users (id, username, password_hash, created_by)
         VALUES ($1, $2::text, $3, $4::jsonb)",
        id,
        name,
        hash,
        Json(by) as _,
    )
    .execute(conn)
    .await
    .map_err(|error| {
        if is_taken(&error) {
            ServiceError::UsernameTaken
        } else {
            error.into()
        }
    })?;
    Ok(())
}

async fn end_sessions(conn: &mut sqlx::PgConnection, user: UserId) -> Result<u64, ServiceError> {
    let ended = sqlx::query!("DELETE FROM service.sessions WHERE user_id = $1", user.0)
        .execute(conn)
        .await?;
    Ok(ended.rows_affected())
}
