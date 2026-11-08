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
//! `auth` turns a GUI session or an API key into an `Actor`, or refuses it, and an adapter calls it before
//! anything else. It also holds the first admin and the writes on users and keys.
//!
//! Every write says what it changed too, because `Gate::write`'s body has to return `Audited`. The
//! gate writes the row in the write's transaction (`gate::audit`). To add a write: call `Gate::write`
//! once, with the function's own name as its action, and add the function to
//! `every_write_function_has_an_audit_test` and `every_write_fails_when_its_audit_fails` in
//! `tests/service.rs`, which read this crate's source and fail until both cover it.
//!
//! Reads go through `Gate::read`, which checks a permission the same way and writes no row: `alerts` and
//! `observables`. A read ace3 audits, such as a file's download, goes through `Gate::write` with a row
//! that says what was read. A row records the request's source address when an adapter gives one
//! (`source`). Nothing reads `service.audit` yet. ace3's reader is Splunk searching log lines, and
//! `Gate::write`'s log line keeps that search working.
//!
//! `users` reads users, groups and keys, and changes profiles, groups and keys' scopes, for 5.6's `users`
//! router. `permission::CATALOG` is ace3's catalog of the names ACE checks. Not here from ace3: a 403
//! saying which half of a key's check refused.
//!
//! `crashes` reads failed tasks for 5.6's `crashes` router, and audits their download as a read.
//!
//! `yara_qa` reads the rules in QA mode and what they matched for 5.6's `yara_qa` router, audits a download
//! of the files as a read, and purges matches as a write.
//!
//! `observable_comments` keeps analysts' comments on an observable by its type and value, across alerts,
//! for 5.6's `observable_comments` router, and reads an alert's for 5.8's alert view.
//!
//! Writes outside this crate today:
//! - `Orchestrator::set_mode` and `queue::cancel_root` have no caller outside the core's own flows
//!   and tests. Each gets a function here when a route for it appears (5.5, 5.6).
//! - The lease API, `Orchestrator::land_result`, the reaper, the ruleset builder and the QA recorder
//!   stay out for good. They are the engine's own writes, not requests: a pool authenticates with
//!   its token, and a task's row names its `lease_owner`.

mod actor;
mod alerts;
mod auth;
mod crashes;
mod gate;
mod observable_comments;
mod observables;
mod permission;
mod source;
mod submit;
mod users;
mod yara_qa;

use ace_core::bucket::BucketError;
use ace_core::db::{Db, DbError, Retryable};
use ace_core::orchestrator::{Dispositioned, Orchestrator, OrchestratorError};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::types::Json;
use uuid::Uuid;

use gate::{Audited, Change, Gate, Recorded, TITLE_LIMIT, Target};

pub use actor::{Actor, ApiKeyId, Component, InvalidComponent, UserId};
pub use alerts::{
    Alert, AlertDetection, AlertFile, AlertObservable, AlertPage, AlertSummary, AnalysisState,
    FileDownload, MAX_ALERTS_PAGE, MAX_OBSERVABLES_PAGE, ModuleResult, ObservablePage,
    RecordedActor, Relationship,
};
pub use auth::{
    InvalidUsername, IssuedToken, MAX_PASSWORD_BYTES, MIN_PASSWORD_CHARS, NewApiKey, NewSession,
    Password, RequestParts, SESSION_LIFETIME_SECONDS, SessionCookie, Transport, Username,
};
pub use crashes::{Crash, CrashDetail, CrashFilter, CrashInput, CrashPage, MAX_CRASHES_PAGE};
pub use gate::Holder;
pub use observable_comments::{CommentAuthor, MAX_COMMENT_CHARS, ObservableComment};
pub use observables::{
    Lookup, MAX_EXCLUDED_ALERTS, MAX_LOOKUP_PAIRS, MAX_RECENT_ALERTS, OPEN, Prevalence, RecentAlert,
};
pub use permission::{
    ALERT_CREATE, ALERT_READ, ALERT_WRITE, CATALOG, CRASH_READ, CatalogEntry, Effect,
    InvalidPermission, OBSERVABLE_READ, OBSERVABLE_WRITE, PermissionName, PermissionPattern,
    SIGNATURE_DOWNLOAD, SIGNATURE_QA_PURGE, SIGNATURE_READ, USER_READ, USER_SELF, USER_WRITE,
};
pub use source::with_source_ip;
pub use users::{ApiKey, Grant, Group, MAX_KEY_SCOPE, Profile, User, UserDetail};
pub use yara_qa::{
    MAX_PURGE_REASON, MAX_PURGE_VERSIONS, MAX_QA_DOWNLOAD_BYTES, MAX_QA_DOWNLOAD_FILES,
    MAX_QA_PAGE, QaDownload, QaMatch, QaMatchDetail, QaMatchPage, QaMatchSummary, QaPurge,
    QaPurged, QaRuleDetail, QaRuleFilter, QaRulePage, QaRuleSummary, QaRuleset, QaSort, QaStatus,
    QaStringSummary, QaVersion,
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
    /// A change that couldn't be encoded for its audit row, which fails the write.
    #[error("recording the audit row: {0}")]
    AuditEncoding(#[from] serde_json::Error),
    /// No actor: an unknown user, a wrong password or a disabled user at a login, or a credential that
    /// is wrong, revoked or expired. It says nothing more, on purpose, and an adapter shouldn't either.
    #[error("not authenticated")]
    NotAuthenticated,
    /// A session's request that another site's page could have made (`RequestParts::same_origin`).
    #[error("this request came from another site")]
    CrossSiteRequest,
    #[error("that username is taken")]
    UsernameTaken,
    #[error("that group name is taken")]
    GroupNameTaken,
    #[error("no user {0}")]
    NoUser(Uuid),
    #[error("a user exists already, so a first user needs forcing")]
    UsersExist,
    #[error("a user can't disable themselves: another user with user:write has to")]
    CantDisableYourself,
    #[error(
        "a password has to be at least {MIN_PASSWORD_CHARS} characters and at most {MAX_PASSWORD_BYTES} bytes"
    )]
    WeakPassword,
    #[error("an API key's name is 1 to 255 characters with no control characters")]
    InvalidKeyName,
    /// Hashing failed, or there was no randomness to do it with. It holds no password.
    #[error("hashing a credential: {0}")]
    Hashing(String),
    /// A request the service can't take as it is, such as a submission naming a mode that doesn't exist
    /// or a page that's too large. Nothing was written.
    #[error("{0}")]
    InvalidRequest(String),
    /// What a request names isn't there, or isn't what it says, such as a root that isn't an alert.
    #[error("{0}")]
    NotFound(String),
    /// A request for more than a limit allows at once, such as a download of too many files. Nothing was
    /// written.
    #[error("{0}")]
    TooLarge(String),
    /// A refusal that isn't about a permission the actor holds, such as changing another user's
    /// comment. Nothing was written.
    #[error("{0}")]
    Forbidden(String),
    #[error(transparent)]
    Bucket(#[from] BucketError),
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
            ServiceError::Bucket(BucketError::Db(e)) => e.is_retryable(),
            ServiceError::Bucket(_)
            | ServiceError::InvalidRequest(_)
            | ServiceError::NotFound(_)
            | ServiceError::TooLarge(_)
            | ServiceError::Forbidden(_)
            | ServiceError::PermissionDenied { .. }
            | ServiceError::InvalidPermission(_)
            | ServiceError::AuditEncoding(_)
            | ServiceError::NotAuthenticated
            | ServiceError::CrossSiteRequest
            | ServiceError::UsernameTaken
            | ServiceError::GroupNameTaken
            | ServiceError::NoUser(_)
            | ServiceError::UsersExist
            | ServiceError::CantDisableYourself
            | ServiceError::WeakPassword
            | ServiceError::InvalidKeyName
            | ServiceError::Hashing(_) => false,
        }
    }
}

/// A disposition's audit row, before and after: what it replaced and what it did to the analysis.
#[derive(Serialize)]
struct DispositionState {
    disposition: Option<String>,
    dispositioned_by: Option<Value>,
    analysis_mode: String,
}

impl Recorded for DispositionState {}

/// What's needed to read a disposition's audit row after its alert is deleted. ace3 records these
/// and the alert's type, tool, queue, company and owner, which ace4's roots don't have yet.
#[derive(Serialize)]
struct RootSnapshot {
    title: String,
    event_time: Option<DateTime<Utc>>,
    root_created_at: DateTime<Utc>,
}

impl Recorded for RootSnapshot {}

/// A permission row's audit: the row, and for a removed one who made it, since nothing else keeps that.
#[derive(Serialize)]
struct PermissionRecord<'a> {
    major: &'a str,
    minor: &'a str,
    effect: Effect,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_by: Option<Value>,
}

impl Recorded for PermissionRecord<'_> {}

/// The service layer over one database. The adapters hold one of these.
#[derive(Debug, Clone)]
pub struct Service {
    gate: Gate,
    orchestrator: Orchestrator,
    passwords: auth::Passwords,
}

impl Service {
    pub fn new(db: Db, orchestrator: Orchestrator) -> Self {
        Service {
            gate: Gate::new(db),
            orchestrator,
            passwords: auth::Passwords::new(),
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
    /// it learns nothing about the alert. A disposition is a name such as `FALSE_POSITIVE`: up to 64
    /// uppercase ASCII letters, digits and `_`, the shape of ace3's. Which names a site uses isn't
    /// checked yet: ace3 reads them from its configuration, which nothing here ports.
    pub async fn disposition(
        &self,
        actor: &Actor,
        root: Uuid,
        disposition: &str,
    ) -> Result<Dispositioned, ServiceError> {
        let shaped = disposition.len() <= 64
            && disposition.starts_with(|c: char| c.is_ascii_uppercase())
            && disposition
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !shaped {
            return Err(ServiceError::InvalidRequest(
                "a disposition is up to 64 uppercase ASCII letters, digits and _, starting with a letter"
                    .to_owned(),
            ));
        }
        self.gate
            .write(actor, "disposition", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    // Locks first, so `before` is what this write replaces. The title is capped here,
                    // not by the column: it's whatever the alert's sender wrote.
                    let found = sqlx::query!(
                        r#"SELECT disposition, dispositioned_by AS "dispositioned_by: Value",
                                  analysis_mode, event_time, created_at,
                                  left(description, $2) AS "title!"
                           FROM analysis.roots WHERE id = $1 FOR UPDATE"#,
                        root,
                        TITLE_LIMIT,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or(OrchestratorError::NoRoot(root))?;
                    let dispositioned = self.orchestrator.stop_for_disposition(tx, root).await?;
                    let mode = sqlx::query_scalar!(
                        "UPDATE analysis.roots
                         SET disposition = $2, dispositioned_at = now(), dispositioned_by = $3::jsonb
                         WHERE id = $1
                         RETURNING analysis_mode",
                        root,
                        disposition,
                        Json(actor) as _,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let change = Change::updated(
                        Target::root(root),
                        &DispositionState {
                            disposition: found.disposition,
                            dispositioned_by: found.dispositioned_by,
                            analysis_mode: found.analysis_mode,
                        },
                        &DispositionState {
                            disposition: Some(disposition.to_owned()),
                            dispositioned_by: Some(serde_json::to_value(actor)?),
                            analysis_mode: mode,
                        },
                    )?
                    .details(&RootSnapshot {
                        title: found.title,
                        event_time: found.event_time,
                        root_created_at: found.created_at,
                    })?;
                    Ok(Audited::changed(dispositioned, change))
                })
            })
            .await
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
        if permission::covered_by(pattern).next().is_none() {
            // ace3 warns about a likely typo and grants it anyway, since a site may know better
            tracing::warn!(%actor, %pattern, "a grant covers no permission ACE checks");
        }
        self.gate
            .write(actor, "grant", &USER_WRITE, &|tx| {
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
                    .await
                    .map_err(|error| {
                        let missing = error
                            .as_database_error()
                            .is_some_and(|error| error.is_foreign_key_violation());
                        if missing {
                            ServiceError::NotFound(format!("no {}", Target::holder(holder)))
                        } else {
                            error.into()
                        }
                    })?;
                    if added.rows_affected() == 0 {
                        return Ok(Audited::unchanged(false));
                    }
                    let change = Change::added(
                        Target::holder(holder),
                        &PermissionRecord {
                            major: pattern.major(),
                            minor: pattern.minor(),
                            effect,
                            created_by: None,
                        },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
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
        self.gate
            .write(actor, "revoke", &USER_WRITE, &|tx| {
                Box::pin(async move {
                    let removed = sqlx::query_scalar!(
                        r#"DELETE FROM service.permissions
                           WHERE user_id IS NOT DISTINCT FROM $1
                             AND group_id IS NOT DISTINCT FROM $2
                             AND api_key_id IS NOT DISTINCT FROM $3
                             AND component IS NOT DISTINCT FROM $4
                             AND major = $5::text AND minor = $6::text AND effect = $7
                           RETURNING created_by AS "created_by!: Value""#,
                        user,
                        group,
                        api_key,
                        component,
                        pattern.major(),
                        pattern.minor(),
                        effect as Effect,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(created_by) = removed else {
                        return Ok(Audited::unchanged(false));
                    };
                    let change = Change::removed(
                        Target::holder(holder),
                        &PermissionRecord {
                            major: pattern.major(),
                            minor: pattern.minor(),
                            effect,
                            created_by: Some(created_by),
                        },
                    )?;
                    Ok(Audited::changed(true, change))
                })
            })
            .await
    }
}
