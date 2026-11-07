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

use ace_core::db::{Db, DbError, Isolation, Retryable};
use ace_core::orchestrator::{Dispositioned, Orchestrator, OrchestratorError};
use sqlx::types::Json;
use uuid::Uuid;

pub use actor::{Actor, ApiKeyId, Component, InvalidComponent, UserId};

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
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
        }
    }
}

/// The service layer over one database. The adapters hold one of these.
#[derive(Debug, Clone)]
pub struct Service {
    db: Db,
    orchestrator: Orchestrator,
}

impl Service {
    pub fn new(db: Db, orchestrator: Orchestrator) -> Self {
        Service { db, orchestrator }
    }

    /// Records a disposition of an alert and who made it. Its analysis is cancelled and it moves
    /// to dispositioned mode, all in one transaction. A later disposition replaces the earlier one
    /// and its actor, as in ace3, where an analyst, an API key and SVS's maintenance timers all
    /// call `set_dispositions`.
    pub async fn disposition(
        &self,
        actor: &Actor,
        root: Uuid,
        disposition: &str,
    ) -> Result<Dispositioned, ServiceError> {
        let dispositioned = self
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
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
                    Ok::<_, ServiceError>(dispositioned)
                })
            })
            .await?;
        tracing::info!(%root, %actor, disposition, "an alert was dispositioned");
        Ok(dispositioned)
    }
}
