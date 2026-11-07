//! The service layer: the writes people and ACE's own components make, each carrying who made it.
//!
//! `Actor` is the one value for who is acting (PLAN.md 5.1, ace3 #1089). Every function here that
//! writes takes `&Actor` as its first argument, with no default and no `Option`, so a caller can't
//! forget it. The type lives below the adapters, so nothing has to import an API crate to name it
//! (ace3 #953).
//!
//! `ace-service` depends on `ace-core`, and the core doesn't know about actors. A write here opens
//! the transaction, calls the core's functions with it, and records the actor in the same
//! transaction. So what records an analyst's decision lives here, and the core keeps what the
//! decision does to the queue.
//!
//! Every write also names the permission it needs. `gate` holds the database, so a function here
//! can only write through `Gate::write`, which refuses an actor without that permission before the
//! write looks at anything. `gate`'s docs say who holds what, and `permission`'s say what a name is.
//!
//! Not here yet from ace3's permissions: the catalog of known names, which warns about a typo and
//! feeds the management screens, group management and API key scopes, all with the `users` router in
//! 5.6. A 403 saying which half of a key's check refused comes with the routes. A grant holding a
//! typo allows nothing.
//!
//! Writes outside this crate today:
//! - `POST /api/analysis/v1/submit` (`ace_core::api`, `ace_core::submit`) carries a shared token and
//!   records no actor. `ace-core` can't call this crate, so it moves with its route to `ace-api` in
//!   PLAN.md 5.5, using 5.4's actors.
//! - `Orchestrator::set_mode` and `queue::cancel_root` have no caller outside the core's own flows
//!   and tests. Each gets a function here when a route for it appears (5.5, 5.6).
//! - The lease API, `Orchestrator::land_result`, the reaper, the ruleset builder and the QA recorder
//!   stay out for good. They are the engine's own writes, not requests: a pool authenticates with
//!   its token, and a task's row names its `lease_owner`.

mod actor;
mod gate;
mod permission;

use ace_core::db::{Db, DbError, Retryable};
use ace_core::orchestrator::{Dispositioned, Orchestrator, OrchestratorError};
use sqlx::types::Json;
use uuid::Uuid;

use gate::Gate;

pub use actor::{Actor, ApiKeyId, Component, InvalidComponent, UserId};
pub use gate::Holder;
pub use permission::{
    ALERT_WRITE, Effect, InvalidPermission, PermissionName, PermissionPattern, USER_SELF,
    USER_WRITE,
};

/// A group's id. Groups hold users, and their rows apply to their members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub Uuid);

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
    #[error("{actor} doesn't hold {permission}")]
    PermissionDenied {
        actor: String,
        permission: PermissionName,
    },
    /// A stored row that breaks the rules of a permission, which migration 0020 should prevent.
    #[error(transparent)]
    InvalidPermission(#[from] InvalidPermission),
}

impl From<DbError> for ServiceError {
    fn from(error: DbError) -> Self {
        ServiceError::Orchestrator(OrchestratorError::Db(error))
    }
}

impl From<sqlx::Error> for ServiceError {
    fn from(error: sqlx::Error) -> Self {
        ServiceError::Orchestrator(OrchestratorError::from(error))
    }
}

impl Retryable for ServiceError {
    fn is_retryable(&self) -> bool {
        match self {
            ServiceError::Orchestrator(e) => e.is_retryable(),
            ServiceError::PermissionDenied { .. } | ServiceError::InvalidPermission(_) => false,
        }
    }
}

/// The service layer over one database. The adapters hold one of these.
#[derive(Debug, Clone)]
pub struct Service {
    gate: Gate,
    orchestrator: Orchestrator,
}

impl Service {
    pub fn new(db: Db, orchestrator: Orchestrator) -> Self {
        Service {
            gate: Gate::new(db),
            orchestrator,
        }
    }

    /// Whether the actor holds a permission, for an adapter deciding what to show. A write doesn't
    /// need this: `Gate::write` checks for itself.
    pub async fn allowed(
        &self,
        actor: &Actor,
        permission: &PermissionName,
    ) -> Result<bool, ServiceError> {
        self.gate.allowed(actor, permission).await
    }

    /// Records a disposition of an alert and who made it. Its analysis is cancelled and it moves
    /// to dispositioned mode, all in one transaction. A later disposition replaces the earlier one
    /// and its actor, as in ace3, where an analyst, an API key and SVS's maintenance timers all
    /// call `set_dispositions`. It needs `alert:write`, as ace3's route does, and an actor without
    /// it learns nothing about the alert.
    pub async fn disposition(
        &self,
        actor: &Actor,
        root: Uuid,
        disposition: &str,
    ) -> Result<Dispositioned, ServiceError> {
        let dispositioned = self
            .gate
            .write(actor, &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let dispositioned = self.orchestrator.stop_for_disposition(tx, root).await?;
                    sqlx::query!(
                        "UPDATE analysis.roots
                         SET disposition = $2, dispositioned_at = now(), dispositioned_by = $3::jsonb
                         WHERE id = $1",
                        root,
                        disposition,
                        Json(actor) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                    Ok(dispositioned)
                })
            })
            .await?;
        tracing::info!(%root, %actor, disposition, "an alert was dispositioned");
        Ok(dispositioned)
    }

    /// Adds a row giving a holder an effect on a pattern, as ace3's `add_user_permission`,
    /// `add_group_permission` and API key scopes do. It needs `user:write`. Adding a row that exists,
    /// in any case, changes nothing and returns false. The row records who made it.
    pub async fn grant(
        &self,
        actor: &Actor,
        holder: &Holder,
        pattern: &PermissionPattern,
        effect: Effect,
    ) -> Result<bool, ServiceError> {
        let (user, group, api_key, component) = holder.columns();
        let added = self
            .gate
            .write(actor, &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let added = sqlx::query!(
                        "INSERT INTO service.permissions
                             (user_id, group_id, api_key_id, component, major, minor, effect, created_by)
                         VALUES ($1, $2, $3, $4, $5::text, $6::text, $7, $8::jsonb)
                         ON CONFLICT ON CONSTRAINT permissions_are_unique DO NOTHING",
                        user,
                        group,
                        api_key,
                        component,
                        pattern.major(),
                        pattern.minor(),
                        effect as Effect,
                        Json(actor) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                    Ok(added.rows_affected() == 1)
                })
            })
            .await?;
        tracing::info!(%actor, ?holder, %pattern, ?effect, added, "a permission was granted");
        Ok(added)
    }

    /// Removes the row `grant` would add, as ace3's `delete_user_permission` and
    /// `delete_group_permission` do. It needs `user:write`. Returns false when there's no such row.
    pub async fn revoke(
        &self,
        actor: &Actor,
        holder: &Holder,
        pattern: &PermissionPattern,
        effect: Effect,
    ) -> Result<bool, ServiceError> {
        let (user, group, api_key, component) = holder.columns();
        let removed = self
            .gate
            .write(actor, &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let removed = sqlx::query!(
                        "DELETE FROM service.permissions
                         WHERE user_id IS NOT DISTINCT FROM $1
                           AND group_id IS NOT DISTINCT FROM $2
                           AND api_key_id IS NOT DISTINCT FROM $3
                           AND component IS NOT DISTINCT FROM $4
                           AND major = $5::text AND minor = $6::text AND effect = $7",
                        user,
                        group,
                        api_key,
                        component,
                        pattern.major(),
                        pattern.minor(),
                        effect as Effect,
                    )
                    .execute(tx.conn())
                    .await?;
                    Ok(removed.rows_affected() == 1)
                })
            })
            .await?;
        tracing::info!(%actor, ?holder, %pattern, ?effect, removed, "a permission was revoked");
        Ok(removed)
    }
}
