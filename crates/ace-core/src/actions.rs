//! Actions (PLAN.md 7.9), as the queue holds them in `queue.actions`: remediations, remediation checks and
//! file collections, ace3's three queue services (#894) as one queue.
//!
//! ace3's `QueueService` scaffold runs each as a service of its own: a collector thread polls its table,
//! locks ready rows by uuid, and hands each to the worker threads of its handler, which write the row's
//! end and a history row. Here an action is a row leased through the lease API as a task is
//! (`ActionWorker::claim`), by a network pool that lists its handler as `@<kind>/<name>`
//! (`ace_sdk::actions`), and the pool renews its lease while the handler runs and ends it once
//! (`ActionWorker::end_in`). What a task has that an action hasn't is a root, an observable row and a module:
//! an action acts outside ACE on a type and a value, and a remediation outlives any alert. What an action has
//! that a task hasn't is ace3's status and result in its kind's words, its tries and their backoff from the
//! handler's spec, a deadline, and the alerts it's for (`queue.action_roots`). Its wakeups, its leases, its
//! reaper and its `run_after` are the queue's.
//!
//! The core decides everything from the handler's `ActionSpec` in its `ActionCatalog`, as ace3's collector
//! and worker do from their config: whether a try's end completes the action, when it's tried again,
//! and, before a pool gets it, whether its deadline passed (a check ends `EXPIRED`, a collection `FAILED`)
//! or another source already confirmed a check's target (`SUPERSEDED`, ace3's
//! `find_superseding_confirmation`). So the pool needs nothing but the handler.
//!
//! A file collection's file goes in the `alert_files` pool, held by the collection until the scheduler's
//! `file_collection_prune` lets it go after its retention (ace3's `ace file-collection prune`), and by
//! each alert the collection is for, as long as that alert keeps its files. ace3 records one alert per
//! collection, so a collection a second alert joined belonged only to the first (#1101); here each alert
//! that asks is a row of `queue.action_roots` (`request_collection`).
//!
//! Every write a person makes here goes through `ace_service`, which checks its permission and writes its
//! audit row in the transaction it gives these functions. The lease, the end and the reaper are the
//! engine's own writes, as a task's are.

use std::collections::BTreeMap;
use std::time::Duration;

use ace_results::Sha256;
use ace_sdk::actions::{
    ActionEnd, ActionKind, ActionSpec, CheckResult, CollectedFile, CollectorStatus, LeasedAction,
    ProbeOutcome, RemediationAction, RemediatorStatus, Retry,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::db::{Db, DbError, Isolation, Tx};

/// The most a message or an error on an action's row holds.
pub const MAX_MESSAGE_CHARS: usize = 4000;
/// The longest observable value an action takes.
pub const MAX_VALUE_CHARS: usize = 4096;
/// How long a collected file outlives its collection's end when no alert holds it: ace3's
/// `retention_days`, 7.
pub const COLLECTION_RETENTION: Duration = Duration::from_secs(7 * 86_400);
/// The most collections one prune lets go of.
pub const PRUNE_BATCH: i64 = 1000;
/// The hold a file collection keeps on its file.
pub const COLLECTION_HOLD: &str = "file_collection";

/// ace3's statuses.
pub const NEW: &str = "NEW";
pub const IN_PROGRESS: &str = "IN_PROGRESS";
pub const COMPLETED: &str = "COMPLETED";

#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    /// The worker no longer holds the action: its lease expired, or someone cancelled it.
    #[error("action {0} is no longer leased to this worker")]
    LeaseLost(i64),
    /// An end or a request that can't be taken as it is. Nothing was written.
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<sqlx::Error> for ActionError {
    fn from(error: sqlx::Error) -> Self {
        ActionError::Db(DbError::Sqlx(error))
    }
}

impl crate::db::Retryable for ActionError {
    fn is_retryable(&self) -> bool {
        matches!(self, ActionError::Db(e) if e.is_retryable())
    }
}

/// The handlers this binary knows, by kind and name: what the core decides an action's tries from, and what
/// the API names.
#[derive(Debug, Clone, Default)]
pub struct ActionCatalog {
    specs: BTreeMap<(ActionKind, &'static str), &'static ActionSpec>,
}

impl ActionCatalog {
    /// A catalog of `specs`, refusing one a spec's own rules refuse and two of one kind and name.
    pub fn new(specs: &[&'static ActionSpec]) -> Result<ActionCatalog, String> {
        let mut catalog = ActionCatalog::default();
        for spec in specs {
            if let Some(why) = spec.refusal() {
                return Err(why);
            }
            if catalog.specs.insert((spec.kind, spec.name), spec).is_some() {
                return Err(format!("{} is listed twice", spec.pool_entry()));
            }
        }
        Ok(catalog)
    }

    pub fn get(&self, kind: ActionKind, name: &str) -> Option<&'static ActionSpec> {
        self.specs
            .iter()
            .find(|((k, n), _)| *k == kind && *n == name)
            .map(|(_, spec)| *spec)
    }

    /// The handlers of `kind`, by name.
    pub fn of_kind(&self, kind: ActionKind) -> impl Iterator<Item = &'static ActionSpec> + '_ {
        self.specs
            .iter()
            .filter(move |((k, _), _)| *k == kind)
            .map(|(_, spec)| *spec)
    }

    pub fn iter(&self) -> impl Iterator<Item = &'static ActionSpec> + '_ {
        self.specs.values().copied()
    }

    /// The handler, or `Invalid` naming what this binary hasn't.
    pub fn require(
        &self,
        kind: ActionKind,
        name: &str,
    ) -> Result<&'static ActionSpec, ActionError> {
        self.get(kind, name).ok_or_else(|| {
            ActionError::Invalid(format!(
                "this server has no {} handler named {name:?}",
                kind.as_str()
            ))
        })
    }

    /// The handler's retries, or its kind's defaults for a handler this binary no longer has.
    fn retry(&self, kind: ActionKind, name: &str) -> Retry {
        match self.get(kind, name) {
            Some(spec) => spec.retry,
            None => match kind {
                ActionKind::Remediation => Retry::REMEDIATION,
                ActionKind::RemediationCheck => Retry::REMEDIATION_CHECK,
                ActionKind::FileCollection => Retry::FILE_COLLECTION,
            },
        }
    }
}

/// `text` with NUL as U+FFFD, cut to `MAX_MESSAGE_CHARS`.
pub fn bounded(text: &str) -> String {
    text.replace('\0', "\u{fffd}")
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .collect()
}

fn check_target(spec: &ActionSpec, observable_type: &str, value: &str) -> Result<(), ActionError> {
    if observable_type != spec.observable_type {
        return Err(ActionError::Invalid(format!(
            "{} acts on {} observables, not {observable_type}",
            spec.pool_entry(),
            spec.observable_type
        )));
    }
    if value.is_empty() || value.chars().count() > MAX_VALUE_CHARS || value.contains('\0') {
        return Err(ActionError::Invalid(format!(
            "a value is 1 to {MAX_VALUE_CHARS} characters with no NUL"
        )));
    }
    Ok(())
}

fn seconds(seconds: u32) -> f64 {
    f64::from(seconds)
}

fn delay_seconds(delay: Duration) -> f64 {
    delay.as_secs_f64()
}

fn limit(max_attempts: Option<u32>) -> Option<i32> {
    max_attempts.map(|m| i32::try_from(m).unwrap_or(i32::MAX))
}

/// A remediation to queue: ace3's `queue_remediation`.
#[derive(Debug, Clone)]
pub struct NewRemediation<'a> {
    pub handler: &'a str,
    pub observable_type: &'a str,
    pub observable_value: &'a str,
    pub action: RemediationAction,
    /// A restore's key: what the removal it undoes gave back.
    pub restore_key: Option<&'a str>,
    /// The actor that asked, as `service.actor` JSON.
    pub requested_by: &'a Value,
    pub user: Option<Uuid>,
}

/// Queues a remediation in `tx`, returning its id. Its pools wake at the commit.
pub async fn queue_remediation(
    tx: &mut Tx<'_>,
    catalog: &ActionCatalog,
    new: &NewRemediation<'_>,
) -> Result<i64, ActionError> {
    let spec = catalog.require(ActionKind::Remediation, new.handler)?;
    check_target(spec, new.observable_type, new.observable_value)?;
    Ok(sqlx::query_scalar!(
        "INSERT INTO queue.actions
             (kind, handler, observable_type, observable_value, action, restore_key, max_attempts,
              requested_by, user_id)
         VALUES ('remediation', $1, $2, $3, $4, $5, $6, $7::jsonb, $8)
         RETURNING id",
        spec.name,
        new.observable_type,
        new.observable_value,
        new.action.as_str(),
        new.restore_key,
        limit(spec.retry.max_attempts),
        new.requested_by,
        new.user,
    )
    .fetch_one(tx.conn())
    .await?)
}

/// A remediation check to queue, for one alert: ace3's `queue_external_check`.
#[derive(Debug, Clone)]
pub struct NewCheck<'a> {
    pub handler: &'a str,
    pub observable_type: &'a str,
    pub observable_value: &'a str,
    pub root: Uuid,
    /// What the module that asked knew, frozen for every try.
    pub context: Option<&'a Value>,
}

/// Queues a remediation check for an alert unless one for the same probe, target and alert is still
/// pending, which it returns instead, as ace3's callers check `get_pending_external_check_by_observable`
/// first. Returns the check's id and whether it's new.
pub async fn request_check(
    tx: &mut Tx<'_>,
    catalog: &ActionCatalog,
    new: &NewCheck<'_>,
) -> Result<(i64, bool), ActionError> {
    let spec = catalog.require(ActionKind::RemediationCheck, new.handler)?;
    check_target(spec, new.observable_type, new.observable_value)?;
    lock_target(tx, ActionKind::RemediationCheck, spec.name, new).await?;
    let pending = sqlx::query_scalar!(
        "SELECT a.id FROM queue.actions a
         JOIN queue.action_roots r ON r.action_id = a.id AND r.root_id = $4
         WHERE a.kind = 'remediation_check' AND a.handler = $1 AND a.observable_type = $2
           AND a.observable_value = $3 AND a.status <> 'COMPLETED'
         ORDER BY a.id DESC LIMIT 1",
        spec.name,
        new.observable_type,
        new.observable_value,
        new.root,
    )
    .fetch_optional(tx.conn())
    .await?;
    if let Some(id) = pending {
        return Ok((id, false));
    }
    let id = sqlx::query_scalar!(
        "INSERT INTO queue.actions
             (kind, handler, observable_type, observable_value, context, max_attempts, deadline_at)
         VALUES ('remediation_check', $1, $2, $3, $4, $5,
                 now() + make_interval(secs => $6))
         RETURNING id",
        spec.name,
        new.observable_type,
        new.observable_value,
        new.context,
        limit(spec.retry.max_attempts),
        spec.retry.deadline_seconds.map(seconds),
    )
    .fetch_one(tx.conn())
    .await?;
    attach(tx, id, new.root).await?;
    Ok((id, true))
}

/// A file collection to ask for.
#[derive(Debug, Clone)]
pub struct NewCollection<'a> {
    pub handler: &'a str,
    pub observable_type: &'a str,
    pub observable_value: &'a str,
    /// The alert that asks, or None for an analyst's or a script's request with no alert.
    pub root: Option<Uuid>,
    pub requested_by: Option<&'a Value>,
    pub user: Option<Uuid>,
}

/// What a collection request did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requested {
    /// A new collection.
    Queued(i64),
    /// A pending collection of the same file, which the alert now belongs to as well.
    Joined(i64),
    /// The alert's own collection of the same file, which already succeeded.
    Collected(i64),
}

impl Requested {
    pub fn id(self) -> i64 {
        match self {
            Requested::Queued(id) | Requested::Joined(id) | Requested::Collected(id) => id,
        }
    }
}

/// Asks for a file: joins a pending collection of the same file by the same collector, whoever asked
/// for it, so concurrent alerts share one collection and each holds its file (#1101), as ace3's
/// `get_pending_file_collection_by_observable` and `resolve_duplicate_pending_file_collection` meant to.
/// An alert whose own collection of it succeeded gets that one back, and one whose collection failed
/// asks again, as ace3's `endpoint_file_collection` does. A lock on the target makes two requests in
/// flight agree.
pub async fn request_collection(
    tx: &mut Tx<'_>,
    catalog: &ActionCatalog,
    new: &NewCollection<'_>,
) -> Result<Requested, ActionError> {
    let spec = catalog.require(ActionKind::FileCollection, new.handler)?;
    check_target(spec, new.observable_type, new.observable_value)?;
    lock_target(tx, ActionKind::FileCollection, spec.name, new).await?;
    let pending = sqlx::query_scalar!(
        "SELECT id FROM queue.actions
         WHERE kind = 'file_collection' AND handler = $1 AND observable_type = $2
           AND observable_value = $3 AND status <> 'COMPLETED'
         ORDER BY id LIMIT 1",
        spec.name,
        new.observable_type,
        new.observable_value,
    )
    .fetch_optional(tx.conn())
    .await?;
    if let Some(id) = pending {
        if let Some(root) = new.root {
            attach(tx, id, root).await?;
        }
        return Ok(Requested::Joined(id));
    }
    if let Some(root) = new.root {
        let collected = sqlx::query_scalar!(
            "SELECT a.id FROM queue.actions a
             JOIN queue.action_roots r ON r.action_id = a.id AND r.root_id = $4
             WHERE a.kind = 'file_collection' AND a.handler = $1 AND a.observable_type = $2
               AND a.observable_value = $3 AND a.status = 'COMPLETED' AND a.result = 'SUCCESS'
             ORDER BY a.id DESC LIMIT 1",
            spec.name,
            new.observable_type,
            new.observable_value,
            root,
        )
        .fetch_optional(tx.conn())
        .await?;
        if let Some(id) = collected {
            return Ok(Requested::Collected(id));
        }
    }
    let id = sqlx::query_scalar!(
        "INSERT INTO queue.actions
             (kind, handler, observable_type, observable_value, max_attempts, deadline_at,
              requested_by, user_id)
         VALUES ('file_collection', $1, $2, $3, $4, now() + make_interval(secs => $5), $6::jsonb, $7)
         RETURNING id",
        spec.name,
        new.observable_type,
        new.observable_value,
        limit(spec.retry.max_attempts),
        spec.retry.deadline_seconds.map(seconds),
        new.requested_by,
        new.user,
    )
    .fetch_one(tx.conn())
    .await?;
    if let Some(root) = new.root {
        attach(tx, id, root).await?;
    }
    Ok(Requested::Queued(id))
}

/// A file collection someone asks for through the API, for any number of alerts or none.
#[derive(Debug, Clone)]
pub struct CollectionRequest<'a> {
    pub handler: &'a str,
    pub observable_type: &'a str,
    pub observable_value: &'a str,
    /// The alerts it's for, each of which holds the file once it's collected.
    pub roots: &'a [Uuid],
    /// The actor that asked, as `service.actor` JSON.
    pub requested_by: &'a Value,
    pub user: Option<Uuid>,
}

impl Target for CollectionRequest<'_> {
    fn target(&self) -> (&str, &str) {
        (self.observable_type, self.observable_value)
    }
}

/// Asks for a file on someone's request: joins a pending collection of the same file by the same
/// collector, whoever asked for it, and makes it each root's, or queues a new one for them (#1101). It's
/// `Queued` or `Joined`, never `Collected`: someone asking again wants the file fetched again, as a site's
/// browser history request does, where a module asking for an alert's file takes the one it has. Returns
/// with it the roots a joined collection was for before, for the request's audit row.
pub async fn ask_for_collection(
    tx: &mut Tx<'_>,
    catalog: &ActionCatalog,
    new: &CollectionRequest<'_>,
) -> Result<(Requested, Vec<Uuid>), ActionError> {
    let spec = catalog.require(ActionKind::FileCollection, new.handler)?;
    check_target(spec, new.observable_type, new.observable_value)?;
    lock_target(tx, ActionKind::FileCollection, spec.name, new).await?;
    let pending = sqlx::query_scalar!(
        "SELECT id FROM queue.actions
         WHERE kind = 'file_collection' AND handler = $1 AND observable_type = $2
           AND observable_value = $3 AND status <> 'COMPLETED'
         ORDER BY id LIMIT 1",
        spec.name,
        new.observable_type,
        new.observable_value,
    )
    .fetch_optional(tx.conn())
    .await?;
    let (requested, before) = match pending {
        Some(id) => (Requested::Joined(id), roots_in(tx, id).await?),
        None => (
            Requested::Queued(
                sqlx::query_scalar!(
                    "INSERT INTO queue.actions
                     (kind, handler, observable_type, observable_value, max_attempts, deadline_at,
                      requested_by, user_id)
                 VALUES ('file_collection', $1, $2, $3, $4, now() + make_interval(secs => $5),
                         $6::jsonb, $7)
                 RETURNING id",
                    spec.name,
                    new.observable_type,
                    new.observable_value,
                    limit(spec.retry.max_attempts),
                    spec.retry.deadline_seconds.map(seconds),
                    new.requested_by,
                    new.user,
                )
                .fetch_one(tx.conn())
                .await?,
            ),
            Vec::new(),
        ),
    };
    for root in new.roots {
        attach(tx, requested.id(), *root).await?;
    }
    Ok((requested, before))
}

/// Something with a target, for `lock_target`.
trait Target {
    fn target(&self) -> (&str, &str);
}

impl Target for NewCheck<'_> {
    fn target(&self) -> (&str, &str) {
        (self.observable_type, self.observable_value)
    }
}

impl Target for NewCollection<'_> {
    fn target(&self) -> (&str, &str) {
        (self.observable_type, self.observable_value)
    }
}

/// Serializes requests for one handler's target until `tx` ends.
async fn lock_target(
    tx: &mut Tx<'_>,
    kind: ActionKind,
    handler: &str,
    new: &impl Target,
) -> Result<(), ActionError> {
    let (observable_type, value) = new.target();
    let key = format!("{kind}\u{1f}{handler}\u{1f}{observable_type}\u{1f}{value}");
    sqlx::query!(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 7909))",
        key
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Makes the action one of `root`'s. Attaching it again changes nothing.
async fn attach(tx: &mut Tx<'_>, action: i64, root: Uuid) -> Result<(), ActionError> {
    sqlx::query!(
        "INSERT INTO queue.action_roots (action_id, root_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
        action,
        root,
    )
    .execute(tx.conn())
    .await
    .map_err(|error| {
        let missing = error
            .as_database_error()
            .is_some_and(|error| error.is_foreign_key_violation());
        if missing {
            ActionError::Invalid(format!("no root {root}"))
        } else {
            error.into()
        }
    })?;
    Ok(())
}

/// The alerts an action is for, in the order they asked.
pub async fn roots_in(tx: &mut Tx<'_>, action: i64) -> Result<Vec<Uuid>, DbError> {
    Ok(sqlx::query_scalar!(
        "SELECT root_id FROM queue.action_roots WHERE action_id = $1 ORDER BY created_at, root_id",
        action,
    )
    .fetch_all(tx.conn())
    .await?)
}

/// One pool process's identity on the actions' queue.
#[derive(Debug, Clone)]
pub struct ActionWorker {
    db: Db,
    name: String,
    lease: Duration,
    catalog: ActionCatalog,
}

/// Why the core ended an action at its claim without giving it to the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Finalized {
    Expired,
    Superseded,
}

impl ActionWorker {
    pub fn new(db: Db, name: impl Into<String>, lease: Duration, catalog: ActionCatalog) -> Self {
        ActionWorker {
            db,
            name: name.into(),
            lease,
            catalog,
        }
    }

    pub fn lease(&self) -> Duration {
        self.lease
    }

    /// Claims the action of `handlers` that has waited longest, after ending, without a try, each one it
    /// finds past its deadline or superseded. None when there's none to claim.
    pub async fn claim(
        &self,
        handlers: &[(ActionKind, String)],
    ) -> Result<Option<LeasedAction>, ActionError> {
        let kinds: Vec<String> = handlers
            .iter()
            .map(|(k, _)| k.as_str().to_owned())
            .collect();
        let names: Vec<String> = handlers.iter().map(|(_, n)| n.clone()).collect();
        // each action ended without a try takes the claim round again; a pool's handlers bound how many
        loop {
            let (kinds, names) = (&kinds, &names);
            let claimed = self
                .db
                .transaction(Isolation::ReadCommitted, |tx| {
                    Box::pin(async move { self.claim_one(tx, kinds, names).await })
                })
                .await?;
            match claimed {
                Claim::None => return Ok(None),
                Claim::Leased(action) => return Ok(Some(*action)),
                Claim::Finalized(id, why) => {
                    tracing::info!(action = id, ?why, "ended an action without a try");
                }
            }
        }
    }

    async fn claim_one(
        &self,
        tx: &mut Tx<'_>,
        kinds: &[String],
        names: &[String],
    ) -> Result<Claim, ActionError> {
        let row = sqlx::query!(
            r#"SELECT a.id, a.kind::text AS "kind!", a.handler, a.observable_type, a.observable_value,
                      a.attempts, a.max_attempts, a.deadline_at, a.action, a.restore_key, a.context,
                      (a.deadline_at IS NOT NULL AND a.deadline_at <= now()) AS "expired!"
               FROM queue.actions a
               WHERE a.status <> 'COMPLETED' AND a.lease_owner IS NULL AND a.run_after <= now()
                 AND EXISTS (SELECT FROM unnest($1::text[], $2::text[]) h(k, n)
                             WHERE h.k = a.kind::text AND h.n = a.handler)
               ORDER BY a.run_after, a.id
               FOR UPDATE SKIP LOCKED
               LIMIT 1"#,
            kinds,
            names,
        )
        .fetch_optional(tx.conn())
        .await?;
        let Some(row) = row else {
            return Ok(Claim::None);
        };
        let kind = ActionKind::parse(&row.kind)
            .ok_or_else(|| DbError::Decode(format!("action {}: kind {}", row.id, row.kind)))?;
        if row.expired {
            expire(tx, row.id, kind).await?;
            return Ok(Claim::Finalized(row.id, Finalized::Expired));
        }
        if kind == ActionKind::RemediationCheck {
            let grace = self
                .catalog
                .get(kind, &row.handler)
                .map_or(43_200, |spec| spec.supersede_grace_seconds);
            if let Some(reason) = superseding_confirmation(
                tx,
                &row.observable_type,
                &row.observable_value,
                &row.handler,
                Duration::from_secs(u64::from(grace)),
            )
            .await?
            {
                finish(tx, row.id, CheckResult::Superseded.as_str(), &reason).await?;
                return Ok(Claim::Finalized(row.id, Finalized::Superseded));
            }
        }
        sqlx::query!(
            "UPDATE queue.actions
             SET lease_owner = $2, lease_expires_at = now() + make_interval(secs => $3)
             WHERE id = $1",
            row.id,
            self.name,
            self.lease.as_secs_f64(),
        )
        .execute(tx.conn())
        .await?;
        let roots = roots_in(tx, row.id).await?;
        Ok(Claim::Leased(Box::new(LeasedAction {
            id: row.id,
            kind,
            handler: row.handler,
            observable_type: row.observable_type,
            observable_value: row.observable_value,
            attempts: u32::try_from(row.attempts).unwrap_or_default(),
            max_attempts: row.max_attempts.and_then(|m| u32::try_from(m).ok()),
            deadline: row.deadline_at,
            action: row.action.as_deref().and_then(RemediationAction::parse),
            restore_key: row.restore_key,
            context: row.context,
            roots,
            lease_seconds: self.lease.as_secs_f64(),
        })))
    }

    /// Renews the lease on an action the worker holds. True when someone cancelled it meanwhile, so the
    /// pool should stop and send no end.
    pub async fn renew(&self, id: i64) -> Result<bool, ActionError> {
        let renewed = sqlx::query_scalar!(
            "UPDATE queue.actions SET lease_expires_at = now() + make_interval(secs => $3)
             WHERE id = $1 AND lease_owner = $2
             RETURNING id",
            id,
            self.name,
            self.lease.as_secs_f64(),
        )
        .fetch_optional(self.db.pool())
        .await?;
        if renewed.is_some() {
            return Ok(false);
        }
        let status = sqlx::query_scalar!("SELECT status FROM queue.actions WHERE id = $1", id)
            .fetch_optional(self.db.pool())
            .await?;
        match status.as_deref() {
            Some(COMPLETED) => Ok(true),
            _ => Err(ActionError::LeaseLost(id)),
        }
    }

    /// The kind of an action the worker holds, and the alerts it's for.
    pub async fn owned(&self, id: i64) -> Result<(ActionKind, Vec<Uuid>), ActionError> {
        let kind = sqlx::query_scalar!(
            r#"SELECT kind::text AS "kind!" FROM queue.actions WHERE id = $1 AND lease_owner = $2"#,
            id,
            self.name,
        )
        .fetch_optional(self.db.pool())
        .await?
        .ok_or(ActionError::LeaseLost(id))?;
        let kind = ActionKind::parse(&kind)
            .ok_or_else(|| DbError::Decode(format!("action {id}: kind {kind}")))?;
        let roots = sqlx::query_scalar!(
            "SELECT root_id FROM queue.action_roots WHERE action_id = $1 ORDER BY created_at, root_id",
            id,
        )
        .fetch_all(self.db.pool())
        .await?;
        Ok((kind, roots))
    }

    /// Ends a try of an action the worker holds, inside `tx`: records it, and either completes the action
    /// or sets when it's tried again, as ace3's workers decide. A collected file must already be in the
    /// bucket, held by the collection; the caller holds it for the alerts this returns.
    pub async fn end_in(
        &self,
        tx: &mut Tx<'_>,
        id: i64,
        end: &ActionEnd,
    ) -> Result<Vec<Uuid>, ActionError> {
        let row = sqlx::query!(
            r#"SELECT kind::text AS "kind!", handler, attempts, max_attempts
               FROM queue.actions WHERE id = $1 AND lease_owner = $2 FOR UPDATE"#,
            id,
            self.name,
        )
        .fetch_optional(tx.conn())
        .await?
        .ok_or(ActionError::LeaseLost(id))?;
        let kind = ActionKind::parse(&row.kind)
            .ok_or_else(|| DbError::Decode(format!("action {id}: kind {}", row.kind)))?;
        if end.kind() != kind {
            return Err(ActionError::Invalid(format!(
                "action {id} is a {kind}, and this is a {}'s end",
                end.kind()
            )));
        }
        let retry = self.catalog.retry(kind, &row.handler);
        let tried = u32::try_from(row.attempts)
            .unwrap_or_default()
            .saturating_add(1);
        let exhausted = row
            .max_attempts
            .is_some_and(|max| i64::from(tried) >= i64::from(max));
        let decided = decide(end, tried, exhausted, &retry)?;
        let message = decided.message.as_deref().map(bounded);
        let last_error = decided.last_error.as_deref().map(bounded);
        let (sha256, size, name) = match &decided.file {
            Some(file) => (
                Some(file.sha256.to_hex()),
                Some(i64::try_from(file.size).unwrap_or(i64::MAX)),
                Some(file.name.clone()),
            ),
            None => (None, None, None),
        };
        sqlx::query!(
            "UPDATE queue.actions
             SET status = $2, result = $3, result_message = $4,
                 attempts = attempts + 1, updated_at = now(),
                 run_after = now() + make_interval(secs => $5),
                 lease_owner = NULL, lease_expires_at = NULL,
                 restore_key = CASE WHEN kind = 'remediation' THEN $6 ELSE restore_key END,
                 events = coalesce($7, events), last_error = coalesce($8, last_error),
                 file_sha256 = coalesce($9, file_sha256), file_size = coalesce($10, file_size),
                 file_name = coalesce($11, file_name)
             WHERE id = $1",
            id,
            decided.status,
            decided.result.as_deref(),
            message.as_deref(),
            delay_seconds(decided.retry_in),
            decided.restore_key.as_deref(),
            decided.events,
            last_error.as_deref(),
            sha256,
            size,
            name,
        )
        .execute(tx.conn())
        .await?;
        sqlx::query!(
            "INSERT INTO queue.action_attempts (action_id, status, result, message)
             VALUES ($1, $2, $3, $4)",
            id,
            decided.status,
            decided.attempt_result,
            message.as_deref().unwrap_or_default(),
        )
        .execute(tx.conn())
        .await?;
        Ok(if decided.file.is_some() {
            roots_in(tx, id).await?
        } else {
            Vec::new()
        })
    }

    /// `end_in` in a transaction of its own, for an end with no file.
    pub async fn end(&self, id: i64, end: &ActionEnd) -> Result<(), ActionError> {
        self.db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move { self.end_in(tx, id, end).await.map(|_| ()) })
            })
            .await
    }
}

enum Claim {
    None,
    Leased(Box<LeasedAction>),
    Finalized(i64, Finalized),
}

/// What a try's end does to its action's row.
#[derive(Debug, PartialEq)]
struct Decided {
    status: &'static str,
    result: Option<String>,
    /// The attempt row's result, which a check still pending has too.
    attempt_result: String,
    message: Option<String>,
    retry_in: Duration,
    restore_key: Option<String>,
    events: Option<Value>,
    last_error: Option<String>,
    file: Option<CollectedFile>,
}

/// ace3's rules for a try's end: `RemediationWorker.remediate`, `persist_probe_outcome` and
/// `FileCollectionWorker.collect`. `tried` counts this try; `exhausted` says it was the last allowed.
fn decide(
    end: &ActionEnd,
    tried: u32,
    exhausted: bool,
    retry: &Retry,
) -> Result<Decided, ActionError> {
    let blank = |status: &'static str, result: &str| Decided {
        status,
        result: Some(result.to_owned()),
        attempt_result: result.to_owned(),
        message: None,
        retry_in: Duration::ZERO,
        restore_key: None,
        events: None,
        last_error: None,
        file: None,
    };
    Ok(match end {
        ActionEnd::Remediation { result } => {
            // ace3 retries a delayed remediation every delay_time_seconds, however often
            let status = if result.status.in_progress() {
                IN_PROGRESS
            } else {
                COMPLETED
            };
            Decided {
                message: result.message.clone(),
                retry_in: retry.delay(0),
                restore_key: result.restore_key.clone(),
                ..blank(status, result.status.as_str())
            }
        }
        ActionEnd::RemediationCheck { outcome } => match outcome {
            ProbeOutcome::FoundEvents { events, message } => {
                if events.len() > ace_sdk::actions::MAX_EVENTS {
                    return Err(ActionError::Invalid(format!(
                        "a confirmation records at most {} events",
                        ace_sdk::actions::MAX_EVENTS
                    )));
                }
                Decided {
                    message: message.clone(),
                    events: Some(serde_json::to_value(events).map_err(|e| {
                        ActionError::Invalid(format!("the events don't encode: {e}"))
                    })?),
                    ..blank(COMPLETED, CheckResult::Confirmed.as_str())
                }
            }
            ProbeOutcome::NotFound { message } => Decided {
                message: message.clone(),
                ..blank(COMPLETED, CheckResult::NotFound.as_str())
            },
            ProbeOutcome::Pending { .. } if exhausted => Decided {
                // ace3: we gave up waiting, the events never appeared
                message: Some(format!("retries exhausted after {tried} attempts")),
                attempt_result: "PENDING".to_owned(),
                ..blank(COMPLETED, CheckResult::Expired.as_str())
            },
            ProbeOutcome::Pending { message } => Decided {
                result: None,
                attempt_result: "PENDING".to_owned(),
                message: message.clone(),
                retry_in: retry.delay(tried),
                ..blank(NEW, "PENDING")
            },
            ProbeOutcome::PermanentError { error, message } => Decided {
                message: message.clone(),
                last_error: Some(error.clone()),
                ..blank(COMPLETED, CheckResult::Error.as_str())
            },
            ProbeOutcome::TransientError { error, message } if exhausted => Decided {
                message: message.clone(),
                last_error: Some(error.clone()),
                ..blank(COMPLETED, CheckResult::Error.as_str())
            },
            ProbeOutcome::TransientError { error, message } => Decided {
                result: None,
                message: message.clone(),
                last_error: Some(error.clone()),
                retry_in: retry.delay(tried),
                ..blank(NEW, CheckResult::Error.as_str())
            },
        },
        ActionEnd::FileCollection {
            status,
            message,
            file,
        } => {
            if file.is_some() && *status != CollectorStatus::Success {
                return Err(ActionError::Invalid(
                    "only a successful collection carries a file".to_owned(),
                ));
            }
            if let Some(file) = file
                && !is_file_name(&file.name)
            {
                return Err(ActionError::Invalid(format!(
                    "{:?} isn't a plain file name of at most 255 bytes",
                    file.name
                )));
            }
            let completes = status.is_final() || exhausted;
            Decided {
                message: message.clone(),
                retry_in: retry.delay(tried),
                file: file.clone(),
                ..blank(
                    if completes { COMPLETED } else { IN_PROGRESS },
                    status.as_str(),
                )
            }
        }
    })
}

/// A collected file's name: one plain name, at most 255 bytes.
pub fn is_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
}

/// Completes an action without a try, with `result` and `message` and an attempt row saying so.
async fn finish(tx: &mut Tx<'_>, id: i64, result: &str, message: &str) -> Result<(), ActionError> {
    let message = bounded(message);
    sqlx::query!(
        "UPDATE queue.actions
         SET status = 'COMPLETED', result = $2, result_message = $3, updated_at = now(),
             lease_owner = NULL, lease_expires_at = NULL
         WHERE id = $1",
        id,
        result,
        message,
    )
    .execute(tx.conn())
    .await?;
    sqlx::query!(
        "INSERT INTO queue.action_attempts (action_id, status, result, message)
         VALUES ($1, 'COMPLETED', $2, $3)",
        id,
        result,
        message,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Ends an action whose deadline passed: a check `EXPIRED`, as ace3's `finalize_expired`; a collection
/// `FAILED`, where ace3 leaves it pending and stops handing it out.
async fn expire(tx: &mut Tx<'_>, id: i64, kind: ActionKind) -> Result<(), ActionError> {
    match kind {
        ActionKind::RemediationCheck => {
            finish(tx, id, CheckResult::Expired.as_str(), "its deadline passed").await
        }
        ActionKind::FileCollection => {
            finish(
                tx,
                id,
                CollectorStatus::Failed.as_str(),
                "its collection time ran out",
            )
            .await
        }
        ActionKind::Remediation => {
            finish(
                tx,
                id,
                RemediatorStatus::Failed.as_str(),
                "its deadline passed",
            )
            .await
        }
    }
}

/// ace3's `find_superseding_confirmation`: why a check's target needs no more asking, if it doesn't. A
/// sibling probe's confirmation of the same target, for any alert, older than `grace`; or ACE's own latest
/// successful remediation of it, older than `grace`, when that was a removal (a restore after it puts the
/// target back).
async fn superseding_confirmation(
    tx: &mut Tx<'_>,
    observable_type: &str,
    value: &str,
    probe: &str,
    grace: Duration,
) -> Result<Option<String>, ActionError> {
    let sibling = sqlx::query!(
        "SELECT handler, updated_at FROM queue.actions
         WHERE kind = 'remediation_check' AND handler <> $3 AND observable_type = $1
           AND observable_value = $2 AND result = 'CONFIRMED'
           AND updated_at <= now() - make_interval(secs => $4)
         ORDER BY id DESC LIMIT 1",
        observable_type,
        value,
        probe,
        grace.as_secs_f64(),
    )
    .fetch_optional(tx.conn())
    .await?;
    if let Some(sibling) = sibling {
        return Ok(Some(probe_supersede_reason(
            &sibling.handler,
            sibling.updated_at,
        )));
    }
    let latest = sqlx::query!(
        "SELECT id, action, updated_at FROM queue.actions
         WHERE kind = 'remediation' AND observable_type = $1 AND observable_value = $2
           AND status = 'COMPLETED' AND result = 'SUCCESS'
           AND coalesce(updated_at, created_at) <= now() - make_interval(secs => $3)
         ORDER BY id DESC LIMIT 1",
        observable_type,
        value,
        grace.as_secs_f64(),
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(latest
        .filter(|latest| latest.action.as_deref() == Some("remove"))
        .map(|latest| ace_supersede_reason(latest.id, latest.updated_at)))
}

const PROBE_SUPERSEDE_PREFIX: &str = "probe ";
const PROBE_SUPERSEDE_INFIX: &str = " confirmed remediation at ";
const ACE_SUPERSEDE_PREFIX: &str = "ACE remediation id=";

fn time_text(time: Option<DateTime<Utc>>) -> String {
    time.map_or_else(|| "None".to_owned(), |t| t.to_rfc3339())
}

/// ace3's `probe_supersede_reason`, which a superseded check's message holds.
pub fn probe_supersede_reason(probe: &str, confirmed_at: Option<DateTime<Utc>>) -> String {
    format!(
        "{PROBE_SUPERSEDE_PREFIX}{probe}{PROBE_SUPERSEDE_INFIX}{}",
        time_text(confirmed_at)
    )
}

/// ace3's `ace_supersede_reason`.
pub fn ace_supersede_reason(remediation: i64, succeeded_at: Option<DateTime<Utc>>) -> String {
    format!(
        "{ACE_SUPERSEDE_PREFIX}{remediation} (remove) succeeded at {}",
        time_text(succeeded_at)
    )
}

/// ace3's `superseding_source_from_reason`: who confirmed a superseded check's target, the sibling probe's
/// name or `ACE`, from its message.
pub fn superseding_source(reason: Option<&str>) -> Option<String> {
    let reason = reason?;
    if reason.starts_with(ACE_SUPERSEDE_PREFIX) {
        return Some("ACE".to_owned());
    }
    let rest = reason.strip_prefix(PROBE_SUPERSEDE_PREFIX)?;
    let (probe, _) = rest.split_once(PROBE_SUPERSEDE_INFIX)?;
    (!probe.is_empty()).then(|| probe.to_owned())
}

/// Stops an action that hasn't completed: it completes `CANCELLED` and a pool trying it learns at its next
/// renewal. False when it's missing or completed. `message` is its attempt row's, as ace3's remediation
/// writes `cancelled by <name>`.
pub async fn cancel_in(tx: &mut Tx<'_>, id: i64, message: &str) -> Result<bool, DbError> {
    let cancelled = sqlx::query_scalar!(
        "UPDATE queue.actions
         SET status = 'COMPLETED', result = 'CANCELLED', updated_at = now(),
             lease_owner = NULL, lease_expires_at = NULL
         WHERE id = $1 AND status <> 'COMPLETED'
         RETURNING id",
        id,
    )
    .fetch_optional(tx.conn())
    .await?;
    if cancelled.is_none() {
        return Ok(false);
    }
    sqlx::query!(
        "INSERT INTO queue.action_attempts (action_id, status, result, message)
         VALUES ($1, 'COMPLETED', 'CANCELLED', $2)",
        id,
        bounded(message),
    )
    .execute(tx.conn())
    .await?;
    Ok(true)
}

/// Queues an action again. A remediation is queued as it was, only once it completed, as ace3's
/// `retry_remediation`; a file collection starts over with no tries counted whatever its state, as ace3's
/// `retry_file_collection`, and gets its time limit again. False when it's missing, or a remediation that
/// hasn't completed.
pub async fn retry_in(tx: &mut Tx<'_>, catalog: &ActionCatalog, id: i64) -> Result<bool, DbError> {
    let Some(row) = sqlx::query!(
        r#"SELECT kind::text AS "kind!", handler, status FROM queue.actions WHERE id = $1 FOR UPDATE"#,
        id,
    )
    .fetch_optional(tx.conn())
    .await?
    else {
        return Ok(false);
    };
    let kind = ActionKind::parse(&row.kind)
        .ok_or_else(|| DbError::Decode(format!("action {id}: kind {}", row.kind)))?;
    match kind {
        ActionKind::Remediation => {
            if row.status != COMPLETED {
                return Ok(false);
            }
            // ace3 clears update_time, and its history takes no row for a retry
            sqlx::query!(
                "UPDATE queue.actions
                 SET status = 'NEW', result = NULL, updated_at = NULL, run_after = now(),
                     lease_owner = NULL, lease_expires_at = NULL
                 WHERE id = $1",
                id,
            )
            .execute(tx.conn())
            .await?;
        }
        ActionKind::FileCollection | ActionKind::RemediationCheck => {
            let deadline = catalog.retry(kind, &row.handler).deadline_seconds;
            sqlx::query!(
                "UPDATE queue.actions
                 SET status = 'NEW', result = NULL, result_message = NULL, attempts = 0,
                     updated_at = now(), run_after = now(), lease_owner = NULL, lease_expires_at = NULL,
                     deadline_at = now() + make_interval(secs => $2)
                 WHERE id = $1",
                id,
                deadline.map(seconds),
            )
            .execute(tx.conn())
            .await?;
        }
    }
    Ok(true)
}

/// Deletes an action, its tries and which alerts it was for, and lets go of its own hold on a collected
/// file, which its alerts keep. Returns its kind and file, or None when it's missing.
pub async fn delete_in(
    tx: &mut Tx<'_>,
    id: i64,
) -> Result<Option<(ActionKind, Option<Sha256>)>, crate::bucket::BucketError> {
    let Some(row) = sqlx::query!(
        r#"DELETE FROM queue.actions WHERE id = $1
           RETURNING kind::text AS "kind!", file_sha256"#,
        id,
    )
    .fetch_optional(tx.conn())
    .await?
    else {
        return Ok(None);
    };
    let kind = ActionKind::parse(&row.kind)
        .ok_or_else(|| DbError::Decode(format!("action {id}: kind {}", row.kind)))?;
    let file = match row.file_sha256 {
        Some(hex) => Some(
            hex.parse::<Sha256>()
                .map_err(|e| DbError::Decode(format!("action {id}: {e}")))?,
        ),
        None => None,
    };
    if let Some(sha256) = &file {
        crate::bucket::release_in(tx, crate::bucket::ALERT_FILES, sha256, &collection_hold(id))
            .await?;
    }
    Ok(Some((kind, file)))
}

/// The hold a collection keeps on its file.
pub fn collection_hold(id: i64) -> crate::bucket::Hold {
    crate::bucket::Hold::new(COLLECTION_HOLD, id.to_string())
}

/// A collection whose file a prune let go of.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PrunedCollection {
    pub id: i64,
    pub sha256: String,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Lets go of the files of up to `PRUNE_BATCH` collections that completed more than `retention` ago, ace3's
/// `prune_unattached_files`: the rows stay, as the record of who collected what from which host, and only
/// the alerts that asked for a file keep it after this.
pub async fn prune_collections_in(
    tx: &mut Tx<'_>,
    retention: Duration,
) -> Result<Vec<PrunedCollection>, crate::bucket::BucketError> {
    let rows = sqlx::query!(
        r#"SELECT a.id, a.file_sha256 AS "file_sha256!", a.updated_at
           FROM queue.actions a
           JOIN store.holds h ON h.pool = 'alert_files' AND h.sha256 = a.file_sha256
                             AND h.holder_kind = 'file_collection' AND h.holder_id = a.id::text
           WHERE a.kind = 'file_collection' AND a.status = 'COMPLETED'
             AND a.updated_at < now() - make_interval(secs => $1)
           ORDER BY a.id
           LIMIT $2
           FOR UPDATE OF a"#,
        retention.as_secs_f64(),
        PRUNE_BATCH,
    )
    .fetch_all(tx.conn())
    .await?;
    let mut pruned = Vec::new();
    for row in rows {
        let sha256 = row
            .file_sha256
            .parse::<Sha256>()
            .map_err(|e| DbError::Decode(format!("action {}: {e}", row.id)))?;
        crate::bucket::release_in(
            tx,
            crate::bucket::ALERT_FILES,
            &sha256,
            &collection_hold(row.id),
        )
        .await?;
        pruned.push(PrunedCollection {
            id: row.id,
            sha256: row.file_sha256,
            completed_at: row.updated_at,
        });
    }
    Ok(pruned)
}

/// Takes back actions whose pool stopped renewing their lease, to be tried again now, as ace3's collectors
/// hand out a row whose lock timed out. The try that was running isn't counted. Returns how many.
pub async fn reap_actions(db: &Db) -> Result<u64, DbError> {
    let reaped = sqlx::query!(
        "UPDATE queue.actions
         SET lease_owner = NULL, lease_expires_at = NULL, run_after = now(),
             last_error = 'its pool stopped renewing its lease'
         WHERE lease_owner IS NOT NULL AND lease_expires_at < now()",
    )
    .execute(db.pool())
    .await?
    .rows_affected();
    if reaped > 0 {
        tracing::warn!(reaped, "took back actions whose pool stopped renewing them");
    }
    Ok(reaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_sdk::actions::{RemediationEvent, RemediatorResult};

    fn decided(end: &ActionEnd, tried: u32, exhausted: bool) -> Decided {
        decide(end, tried, exhausted, &Retry::FILE_COLLECTION).expect("decides")
    }

    #[test]
    fn a_remediation_runs_again_only_when_delayed() {
        let delayed = decided(
            &ActionEnd::Remediation {
                result: RemediatorResult::new(RemediatorStatus::Delayed, "later"),
            },
            3,
            false,
        );
        assert_eq!(
            (delayed.status, delayed.result.as_deref()),
            (IN_PROGRESS, Some("DELAYED"))
        );
        assert_eq!(delayed.retry_in, Duration::from_secs(60));
        let error = decided(
            &ActionEnd::Remediation {
                result: RemediatorResult::new(RemediatorStatus::Error, "boom"),
            },
            1,
            false,
        );
        assert_eq!(error.status, COMPLETED);
    }

    #[test]
    fn a_check_ends_as_ace3s_persist_probe_outcome_says() {
        let pending = ActionEnd::RemediationCheck {
            outcome: ProbeOutcome::Pending { message: None },
        };
        let first = decided(&pending, 1, false);
        assert_eq!((first.status, first.result), (NEW, None));
        assert_eq!(first.attempt_result, "PENDING");
        assert_eq!(first.retry_in, Duration::from_secs(120));
        let last = decided(&pending, 24, true);
        assert_eq!(
            (last.status, last.result.as_deref()),
            (COMPLETED, Some("EXPIRED"))
        );
        assert_eq!(
            last.message.as_deref(),
            Some("retries exhausted after 24 attempts")
        );
        let transient = ActionEnd::RemediationCheck {
            outcome: ProbeOutcome::TransientError {
                error: "503".to_owned(),
                message: None,
            },
        };
        assert_eq!(decided(&transient, 1, false).status, NEW);
        assert_eq!(
            decided(&transient, 2, true).result.as_deref(),
            Some("ERROR")
        );
        let found = ActionEnd::RemediationCheck {
            outcome: ProbeOutcome::FoundEvents {
                events: vec![RemediationEvent {
                    source: "Vendor".to_owned(),
                    event_type: "moved".to_owned(),
                    timestamp: Utc::now(),
                    description: "moved to junk".to_owned(),
                    event_time: None,
                    actor: None,
                    target: None,
                    folder: None,
                    portal_url: None,
                    metadata: serde_json::Map::new(),
                }],
                message: None,
            },
        };
        let confirmed = decided(&found, 1, false);
        assert_eq!(confirmed.result.as_deref(), Some("CONFIRMED"));
        assert!(confirmed.events.is_some());
    }

    #[test]
    fn a_collection_completes_when_final_or_out_of_tries() {
        let offline = ActionEnd::FileCollection {
            status: CollectorStatus::HostOffline,
            message: None,
            file: None,
        };
        let again = decided(&offline, 1, false);
        assert_eq!(
            (again.status, again.result.as_deref()),
            (IN_PROGRESS, Some("HOST_OFFLINE"))
        );
        assert_eq!(again.retry_in, Duration::from_secs(120));
        assert_eq!(decided(&offline, 10, true).status, COMPLETED);
        let file = CollectedFile {
            sha256: Sha256([1; 32]),
            size: 3,
            name: "../x".to_owned(),
        };
        let bad_name = ActionEnd::FileCollection {
            status: CollectorStatus::Success,
            message: None,
            file: Some(file.clone()),
        };
        assert!(decide(&bad_name, 1, false, &Retry::FILE_COLLECTION).is_err());
        let not_success = ActionEnd::FileCollection {
            status: CollectorStatus::Error,
            message: None,
            file: Some(CollectedFile {
                name: "x.bin".to_owned(),
                ..file
            }),
        };
        assert!(decide(&not_success, 1, false, &Retry::FILE_COLLECTION).is_err());
    }

    #[test]
    fn a_supersede_reason_names_its_source() {
        let now = Some(Utc::now());
        assert_eq!(
            superseding_source(Some(&probe_supersede_reason("mail_vendor", now))),
            Some("mail_vendor".to_owned())
        );
        assert_eq!(
            superseding_source(Some(&ace_supersede_reason(5, None))),
            Some("ACE".to_owned())
        );
        assert_eq!(superseding_source(Some("something else")), None);
        assert_eq!(superseding_source(None), None);
    }
}
