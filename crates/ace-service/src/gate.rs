//! The only holder of the database in this crate, so a function here can't write without naming a
//! permission and an action: `Gate::write` opens the transaction, checks before anything else runs
//! in it, and records what the body says it changed before the commit (`audit`).
//!
//! Who holds what (PLAN.md 5.2), which is ace3's model plus a decision for components:
//! - A user holds their own rows and their groups' rows.
//! - An API key with an owner holds what its own rows and its owner's rows both allow, so a key is
//!   never more than its owner, and it loses what its owner loses. ace3's `inherit_user_scope` is a
//!   key with an allow on `*:*`, so it has no column of its own. A key with no rows holds nothing.
//! - An API key without an owner holds what its own rows allow, as ace3's config keys do. ace3's
//!   legacy bare-string key, which skips the check, has no equivalent here.
//! - A deny on a key's own row counts. ace3 mints only allows, and ignores a deny it finds there.
//! - A component holds its own rows and goes through this same check. ace3 has no check here: its
//!   timers call `set_dispositions` directly, and `seed.py` gives the automation user `*:*`. In ace4
//!   a component with no rows is refused, so the step that adds an internal caller adds its grants
//!   in a migration.
//! - `user:self` is only ever a user's, whatever a key's or a component's rows say.
//!
//! Whether a user is enabled, and whether an API key is still valid, is decided by authentication
//! (5.4) before an `Actor` exists, as in ace3.
//!
//! A read goes through `Gate::read`, which checks the same way and writes no row. ace3 audits some reads,
//! such as a download: those go through `Gate::write` with `Change::read`, so they have a row like any
//! write and the audit tests cover them.
//!
//! Three writes are a person's own and ask for no permission, because a user with no grants still has
//! to be able to do them: `login`, `logout` and `change_own_password`, through `Gate::write_own`. Each
//! still has its audit row, and `tests/service.rs` fails if a fourth function calls it.

use ace_core::db::{Db, Isolation, Tx, TxFuture};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::actor::{Actor, ApiKeyId, Component, UserId};
use crate::permission::{Effect, PermissionName, PermissionPattern, allows, is_people_only};
use crate::{GroupId, ServiceError};

mod audit;
mod lookup;

pub(crate) use audit::{Audited, Change, Recorded, TITLE_LIMIT, Target};

/// Who a row belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    User(UserId),
    Group(GroupId),
    ApiKey(ApiKeyId),
    Component(Component),
}

impl Holder {
    /// `service.permissions`' four holder columns, of which one is set.
    pub(crate) fn columns(&self) -> (Option<Uuid>, Option<Uuid>, Option<Uuid>, Option<&str>) {
        match self {
            Holder::User(id) => (Some(id.0), None, None, None),
            Holder::Group(id) => (None, Some(id.0), None, None),
            Holder::ApiKey(id) => (None, None, Some(id.0), None),
            Holder::Component(id) => (None, None, None, Some(id.as_str())),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Gate {
    db: Db,
}

impl Gate {
    pub(crate) fn new(db: Db) -> Self {
        Gate { db }
    }

    /// Runs `body` in a transaction once `actor` holds `permission`, and records what it changed in
    /// that transaction. A refusal is `ServiceError::PermissionDenied`, before `body` has looked at
    /// anything, and leaves no audit row. `action` is the name of the service function calling this,
    /// which `tests/service.rs` checks, so a new write has to bring its audit test.
    pub(crate) async fn write<'a, T, F>(
        &'a self,
        actor: &'a Actor,
        action: &'static str,
        permission: &'a PermissionName,
        body: &'a F,
    ) -> Result<T, ServiceError>
    where
        T: Send + 'a,
        F: for<'t> Fn(&'t mut Tx<'a>) -> TxFuture<'t, Audited<T>, ServiceError> + Sync,
    {
        self.run(actor, action, Some(permission), body).await
    }

    /// `write` for what an actor does to its own account, which no grant is needed for. The module's docs
    /// list its callers.
    pub(crate) async fn write_own<'a, T, F>(
        &'a self,
        actor: &'a Actor,
        action: &'static str,
        body: &'a F,
    ) -> Result<T, ServiceError>
    where
        T: Send + 'a,
        F: for<'t> Fn(&'t mut Tx<'a>) -> TxFuture<'t, Audited<T>, ServiceError> + Sync,
    {
        self.run(actor, action, None, body).await
    }

    async fn run<'a, T, F>(
        &'a self,
        actor: &'a Actor,
        action: &'static str,
        permission: Option<&'a PermissionName>,
        body: &'a F,
    ) -> Result<T, ServiceError>
    where
        T: Send + 'a,
        F: for<'t> Fn(&'t mut Tx<'a>) -> TxFuture<'t, Audited<T>, ServiceError> + Sync,
    {
        let (value, target) = self
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    if let Some(permission) = permission
                        && !holds(tx.conn(), actor, permission).await?
                    {
                        tracing::warn!(%actor, %permission, action, "permission denied");
                        return Err(ServiceError::PermissionDenied {
                            actor: actor.to_string(),
                            permission: permission.clone(),
                        });
                    }
                    let Audited { value, change } = body(tx).await?;
                    let target = match change {
                        Some(change) => {
                            Some(audit::record(tx.conn(), actor, action, change).await?)
                        }
                        None => None,
                    };
                    Ok((value, target))
                })
            })
            .await?;
        // After the commit, so nothing is logged for a rollback or for a retried attempt. These are
        // identities only: a row's text stays out of the log.
        match target {
            Some(target) => tracing::info!(%actor, action, %target, "AUDIT: a write was recorded"),
            None => tracing::info!(%actor, action, "a write changed nothing"),
        }
        Ok(value)
    }

    /// Runs `body` in a read-only snapshot once `actor` holds `permission`, so a read of several
    /// queries sees one moment. A refusal is `ServiceError::PermissionDenied` before `body` runs, and
    /// `action` names the function in its log line.
    pub(crate) async fn read<'a, T, F>(
        &'a self,
        actor: &'a Actor,
        action: &'static str,
        permission: &'a PermissionName,
        body: &'a F,
    ) -> Result<T, ServiceError>
    where
        T: Send + 'a,
        F: for<'t> Fn(&'t mut Tx<'a>) -> TxFuture<'t, T, ServiceError> + Sync,
    {
        self.db
            .transaction(Isolation::RepeatableRead, |tx| {
                Box::pin(async move {
                    sqlx::raw_sql("SET TRANSACTION READ ONLY")
                        .execute(tx.conn())
                        .await?;
                    if !holds(tx.conn(), actor, permission).await? {
                        tracing::warn!(%actor, %permission, action, "permission denied");
                        return Err(ServiceError::PermissionDenied {
                            actor: actor.to_string(),
                            permission: permission.clone(),
                        });
                    }
                    body(tx).await
                })
            })
            .await
    }

    pub(crate) async fn allowed(
        &self,
        actor: &Actor,
        permission: &PermissionName,
    ) -> Result<bool, ServiceError> {
        let mut conn = self.db.pool().acquire().await?;
        holds(&mut conn, actor, permission).await
    }
}

async fn holds(
    conn: &mut PgConnection,
    actor: &Actor,
    name: &PermissionName,
) -> Result<bool, ServiceError> {
    Ok(match actor {
        Actor::User { id, .. } => rows_allow(conn, &Holder::User(*id), name).await?,
        Actor::ApiKey { id, owner, .. } => {
            !is_people_only(name)
                && rows_allow(conn, &Holder::ApiKey(*id), name).await?
                && match owner {
                    Some(owner) => rows_allow(conn, &Holder::User(*owner), name).await?,
                    None => true,
                }
        }
        Actor::Internal { id } => {
            !is_people_only(name) && rows_allow(conn, &Holder::Component(id.clone()), name).await?
        }
    })
}

/// Reads rows through `PermissionPattern::new`, so a row that somehow breaks the rule is an error
/// and not a row to skip: skipping it could skip a deny.
async fn rows_allow(
    conn: &mut PgConnection,
    holder: &Holder,
    name: &PermissionName,
) -> Result<bool, ServiceError> {
    let (user, group, api_key, component) = holder.columns();
    let rows = sqlx::query!(
        r#"SELECT major::text AS "major!", minor::text AS "minor!", effect AS "effect: Effect"
           FROM service.permissions
           WHERE user_id = $1
              OR group_id = $2
              OR group_id IN (SELECT group_id FROM service.group_members WHERE user_id = $1)
              OR api_key_id = $3
              OR component = $4"#,
        user,
        group,
        api_key,
        component,
    )
    .fetch_all(conn)
    .await?;
    let grants = rows
        .into_iter()
        .map(|row| Ok((PermissionPattern::new(&row.major, &row.minor)?, row.effect)))
        .collect::<Result<Vec<_>, ServiceError>>()?;
    Ok(allows(&grants, name))
}
