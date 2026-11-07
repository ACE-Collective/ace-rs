//! What a write says it changed, and the one function that stores it (PLAN.md 5.3, ace3 #830).
//!
//! `Gate::write`'s body has to return `Audited`, so a write can't compile without saying what it
//! changed or that it changed nothing. The gate stores the change in the write's own transaction, so
//! the two commit or roll back together, and a failure to store it fails the write.
//!
//! A row is who (`actor`), what (`action`, the service function's name), when (`created_at`, the
//! transaction's time), the target, and the before, after and details below. As in ace3:
//! - A write that changed nothing has no row, because in ace3's words a no-op "must not look like an
//!   event". `Audited::unchanged` is the claim, and only review and a test catch a body that wrote and
//!   claims it didn't. A repeated disposition isn't one here: it replaces the actor and the time, where
//!   ace3's UPDATE skips it, so it has a row.
//! - An actor refused a permission has a warning in the log and no row, as ace3's 403s do. A row would
//!   need its own transaction, since the refusal rolls this one back, and an actor with no permissions
//!   could then fill a table nothing can delete from.
//! - A row is kept when its target is gone. ace3 keeps an alert's title in its line because "the only
//!   lasting record" of an ignored alert is that line.
//!
//! A row goes on being read for years, so what goes in has to be safe to keep and to show:
//! - No credentials. `Actor` holds a key's id and name, never the key. `before`, `after` and `details`
//!   take only `Recorded` types, each a closed struct, so a request's body or a `serde_json::Value`
//!   can't be passed through. A type holding a credential must not implement `Recorded`.
//! - Text that came from an alert, such as its title, is whatever its sender wrote, and may be a secret
//!   someone pasted. It's data: it's bound as a parameter here, and an adapter must escape it when it
//!   shows it, which askama does (5.7). The text is capped, so an alert can't grow this table by more
//!   than `TITLE_LIMIT`.

use serde::Serialize;
use serde_json::Value;
use sqlx::types::Json;
use uuid::Uuid;

use crate::ServiceError;
use crate::actor::Actor;
use crate::gate::Holder;

/// A value that may be stored in an audit row for as long as the row lasts. See the module's docs:
/// implement it only on a struct of named fields that holds no credential.
pub(crate) trait Recorded: Serialize {}

/// How much of an alert's title a row keeps. ace3's own column, `alerts.description`, is this size.
pub(crate) const TITLE_LIMIT: i32 = 1024;

/// What a change was made to.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    kind: &'static str,
    id: String,
}

impl Target {
    pub(crate) fn root(id: Uuid) -> Self {
        Target {
            kind: "root",
            id: id.to_string(),
        }
    }

    pub(crate) fn holder(holder: &Holder) -> Self {
        let (kind, id) = match holder {
            Holder::User(id) => ("user", id.0.to_string()),
            Holder::Group(id) => ("group", id.0.to_string()),
            Holder::ApiKey(id) => ("api_key", id.0.to_string()),
            Holder::Component(id) => ("component", id.as_str().to_owned()),
        };
        Target { kind, id }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.kind, self.id)
    }
}

/// One change, as a row stores it.
#[derive(Debug)]
pub(crate) struct Change {
    target: Target,
    before: Option<Value>,
    after: Option<Value>,
    details: Option<Value>,
}

impl Change {
    pub(crate) fn added(target: Target, after: &impl Recorded) -> Result<Self, ServiceError> {
        Ok(Change {
            target,
            before: None,
            after: Some(serde_json::to_value(after)?),
            details: None,
        })
    }

    pub(crate) fn removed(target: Target, before: &impl Recorded) -> Result<Self, ServiceError> {
        Ok(Change {
            target,
            before: Some(serde_json::to_value(before)?),
            after: None,
            details: None,
        })
    }

    pub(crate) fn updated(
        target: Target,
        before: &impl Recorded,
        after: &impl Recorded,
    ) -> Result<Self, ServiceError> {
        Ok(Change {
            target,
            before: Some(serde_json::to_value(before)?),
            after: Some(serde_json::to_value(after)?),
            details: None,
        })
    }

    pub(crate) fn details(mut self, details: &impl Recorded) -> Result<Self, ServiceError> {
        self.details = Some(serde_json::to_value(details)?);
        Ok(self)
    }
}

/// What a write's body returns: its value, and what it changed.
#[derive(Debug)]
pub(crate) struct Audited<T> {
    pub(super) value: T,
    pub(super) change: Option<Change>,
}

impl<T> Audited<T> {
    pub(crate) fn changed(value: T, change: Change) -> Self {
        Audited {
            value,
            change: Some(change),
        }
    }

    /// The write found nothing to do, and so changed nothing.
    pub(crate) fn unchanged(value: T) -> Self {
        Audited {
            value,
            change: None,
        }
    }
}

/// The one writer of `service.audit`. Only the gate can call it.
pub(super) async fn record(
    conn: &mut sqlx::PgConnection,
    actor: &Actor,
    action: &str,
    change: Change,
) -> Result<Target, ServiceError> {
    sqlx::query!(
        "INSERT INTO service.audit (actor, action, target_kind, target_id, before, after, details)
         VALUES ($1::jsonb, $2, $3, $4, $5, $6, COALESCE($7, '{}'::jsonb))",
        Json(actor) as _,
        action,
        change.target.kind,
        change.target.id,
        change.before,
        change.after,
        change.details,
    )
    .execute(conn)
    .await?;
    Ok(change.target)
}
