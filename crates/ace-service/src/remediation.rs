//! Remediations (PLAN.md 7.9): ace3's `aceapi_v2/remediation` service and `saq/remediation`'s helpers, for
//! the `remediation` router (5.6) and the GUI's remediations area and event page (5.11).
//!
//! A remediation is an action of `ace_core::actions`: a row of `queue.actions` that a network pool hosting
//! its remediator leases and tries until it completes. Here are the writes people make on them, each under
//! `remediation:write` with its audit row: queueing removals or restores of targets, and stopping,
//! retrying, restoring and deleting one. A remediation is attributed to a person, the user or a key's
//! owner, as ace3 attributes one to its `user_id`; a key with no owner is refused.
//!
//! A target is what a remediator acts on: the remediator, and an observable of the type it remediates. ace3
//! finds the targets of an observable through `ObservableRemediationInterface`s an integration registers per
//! type, and every one it ships, the test remediator's and Office 365's, makes one target per remediator of
//! the observable's type with its type and value. That is the rule here, from the remediators' specs, so an
//! alert's targets are its observables of those types, read from its rows, where ace3 loads each alert's
//! tree from disk.
//!
//! `remediation_coverage` is ace3's `saq/remediation/coverage.py`: for each alert, its `email_delivery`
//! targets, whether ACE's own latest remediation of each removed it, or a remediation check found another
//! system did, and the badge that sums them up, which the event page shows beside each alert. A target
//! whose delivery tag says the journal didn't deliver to that address (ace3's 1b4077d1 and 0b42ba1e:
//! forwarded, a distribution list, or not in the journal) and whose removal found nothing it explains
//! is shown with why and left out of the counts.

use std::collections::{BTreeMap, BTreeSet};

use ace_core::actions::{self as core_actions, NewRemediation};
use ace_core::db::Tx;
use ace_results::types::email::DeliveryReason;
use ace_sdk::actions::{ActionKind, RemediationAction, RemediationEvent};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::alerts::{SET_LIST_TIMEOUT, page_limit, timed_out};
use crate::filters::{FilterEntry, FilterScreen, Resolved, split};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{REMEDIATION_READ, REMEDIATION_WRITE};
use crate::{Actor, Service, ServiceError};

/// The most remediations or collections one page holds.
pub const MAX_ACTIONS_PAGE: u32 = 1000;
/// The most alerts one lookup of targets reads.
pub const MAX_TARGET_ALERTS: usize = 200;
/// The most targets one lookup returns, or one request queues.
pub const MAX_TARGETS: usize = 1000;
/// The most tries a remediation's or a collection's history returns.
pub const MAX_HISTORY: u32 = 1000;
/// The observable type whose targets coverage counts: one email delivered to one mailbox.
pub const COVERAGE_TYPE: &str = "email_delivery";
/// The most per-target lines a badge's tooltip holds, as ace3's `TOOLTIP_TARGET_LIMIT`.
pub const TOOLTIP_TARGET_LIMIT: usize = 25;
/// The source label of ACE's own remediations, as the remediation timeline labels them.
pub const ACE_SOURCE: &str = "ACE";

/// A remediation's state, in short.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionSummary {
    pub id: i64,
    /// A remediation's `remove` or `restore`; None for another kind of action.
    pub action: Option<String>,
    /// `NEW`, `IN_PROGRESS` or `COMPLETED`.
    pub status: String,
    pub result: Option<String>,
}

/// A remediator and the observable it acts on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetKey {
    pub remediator: String,
    pub observable_type: String,
    pub observable_value: String,
}

/// A target, with its remediator's display name and its latest remediation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationTarget {
    pub key: TargetKey,
    /// None when no remediator by that name is in this binary.
    pub display_name: Option<String>,
    /// The latest remediation of the target, which cancel and delete act on.
    pub current: Option<ActionSummary>,
}

/// One remediation, as its list shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Remediation {
    pub id: i64,
    pub remediator: String,
    pub display_name: Option<String>,
    pub observable_type: String,
    pub observable_value: String,
    pub action: String,
    pub status: String,
    pub result: Option<String>,
    pub result_message: Option<String>,
    /// The person it's attributed to, by their username now, or as they were named when they asked.
    pub analyst: Option<String>,
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// One page of remediations, newest first, the filters' total, and the cursor for the next.
#[derive(Debug, Clone, PartialEq)]
pub struct RemediationPage {
    pub remediations: Vec<Remediation>,
    pub total: i64,
    pub next: Option<i64>,
}

/// Which remediations to list: the remediations screen's filters.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionQuery {
    pub filters: Vec<FilterEntry>,
    /// Where a date filter's wall clock is.
    pub tz: Tz,
}

impl Default for ActionQuery {
    fn default() -> Self {
        ActionQuery {
            filters: Vec::new(),
            tz: Tz::UTC,
        }
    }
}

/// One try of an action, ace3's history row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionAttempt {
    pub status: String,
    pub result: String,
    pub message: String,
    /// What the remediator acted on when it wasn't the key, such as the mailbox owning an alias
    /// (ace3's `resolved_target`).
    pub resolved_target: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// What a queue of remediations records.
#[derive(Serialize)]
struct Queued<'a> {
    action: &'a str,
    remediations: Vec<QueuedTarget<'a>>,
}

#[derive(Serialize)]
struct QueuedTarget<'a> {
    id: i64,
    remediator: &'a str,
    observable_type: &'a str,
    observable_value: &'a str,
}

impl Recorded for Queued<'_> {}

/// A remediation's state, before and after a write, for its audit row.
#[derive(Serialize)]
pub(crate) struct ActionState {
    kind: String,
    handler: String,
    observable_type: String,
    observable_value: String,
    action: Option<String>,
    status: String,
    result: Option<String>,
}

impl Recorded for ActionState {}

/// The person a remediation is attributed to: the user, or the key's owner.
pub(crate) fn person(actor: &Actor) -> Result<Uuid, ServiceError> {
    match actor {
        Actor::User { id, .. } => Ok(id.0),
        Actor::ApiKey {
            owner: Some(owner), ..
        } => Ok(owner.0),
        Actor::ApiKey { owner: None, .. } | Actor::Internal { .. } => Err(ServiceError::Forbidden(
            "a remediation is an analyst's: ask as a user, or with a key a user owns".to_owned(),
        )),
    }
}

pub(crate) fn no_action(kind: ActionKind, id: i64) -> ServiceError {
    ServiceError::NotFound(format!("no {} {id}", kind.as_str().replace('_', " ")))
}

impl From<core_actions::ActionError> for ServiceError {
    fn from(error: core_actions::ActionError) -> Self {
        match error {
            core_actions::ActionError::Invalid(why) => ServiceError::InvalidRequest(why),
            core_actions::ActionError::LeaseLost(id) => {
                ServiceError::Conflict(format!("action {id} changed meanwhile"))
            }
            core_actions::ActionError::Db(e) => e.into(),
        }
    }
}

/// An action's state as its audit row records it, locked, or None when it isn't of `kind`.
pub(crate) async fn action_state(
    tx: &mut Tx<'_>,
    kind: ActionKind,
    id: i64,
) -> Result<Option<ActionState>, ServiceError> {
    let row = sqlx::query!(
        r#"SELECT kind::text AS "kind!", handler, observable_type, observable_value, action, status, result
           FROM queue.actions WHERE id = $1 FOR UPDATE"#,
        id,
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(row
        .filter(|row| row.kind == kind.as_str())
        .map(|row| ActionState {
            kind: row.kind,
            handler: row.handler,
            observable_type: row.observable_type,
            observable_value: row.observable_value,
            action: row.action,
            status: row.status,
            result: row.result,
        }))
}

pub(crate) async fn summary_in(tx: &mut Tx<'_>, id: i64) -> Result<ActionSummary, ServiceError> {
    let row = sqlx::query!(
        "SELECT id, action, status, result FROM queue.actions WHERE id = $1",
        id
    )
    .fetch_one(tx.conn())
    .await?;
    Ok(ActionSummary {
        id: row.id,
        action: row.action,
        status: row.status,
        result: row.result,
    })
}

/// An action's tries, newest first, up to `limit`.
pub(crate) async fn history_in(
    tx: &mut Tx<'_>,
    kind: ActionKind,
    id: i64,
    limit: u32,
) -> Result<Vec<ActionAttempt>, ServiceError> {
    if !(1..=MAX_HISTORY).contains(&limit) {
        return Err(ServiceError::InvalidRequest(format!(
            "a history holds 1 to {MAX_HISTORY} tries, not {limit}"
        )));
    }
    let known = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT FROM queue.actions WHERE id = $1 AND kind::text = $2) AS "known!""#,
        id,
        kind.as_str(),
    )
    .fetch_one(tx.conn())
    .await?;
    if !known {
        return Err(no_action(kind, id));
    }
    Ok(sqlx::query!(
        "SELECT status, result, message, resolved_target, created_at FROM queue.action_attempts
         WHERE action_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2",
        id,
        i64::from(limit),
    )
    .fetch_all(tx.conn())
    .await?
    .into_iter()
    .map(|row| ActionAttempt {
        status: row.status,
        result: row.result,
        message: row.message,
        resolved_target: row.resolved_target,
        created_at: row.created_at,
    })
    .collect())
}

/// The ids of an id filter, as numbers.
pub(crate) fn ids(values: Option<Vec<String>>) -> Option<Vec<i64>> {
    values.map(|values| values.iter().filter_map(|v| v.parse().ok()).collect())
}

/// The remediations screen's parameters, in the order its query takes them.
type Params = (
    [Option<Vec<i64>>; 2],
    [Option<Vec<String>>; 14],
    [Option<Vec<DateTime<Utc>>>; 4],
);

fn params(query: &ActionQuery) -> Result<Params, ServiceError> {
    let f = Resolved::new(
        FilterScreen::Remediations,
        &query.filters,
        Utc::now(),
        query.tz,
    )?;
    let ((c1, c2), (c3, c4)) = (
        split(f.windows("created", false)?),
        split(f.windows("created", true)?),
    );
    Ok((
        [ids(f.names("id", false)), ids(f.names("id", true))],
        [
            f.patterns("remediator", false, false),
            f.patterns("remediator", true, false),
            f.patterns("type", false, false),
            f.patterns("type", true, false),
            f.patterns("value", false, false),
            f.patterns("value", true, false),
            f.patterns("analyst", false, false),
            f.patterns("analyst", true, false),
            f.names("action", false),
            f.names("action", true),
            f.names("status", false),
            f.names("status", true),
            f.names("result", false),
            f.names("result", true),
        ],
        [c1, c2, c3, c4],
    ))
}

impl Service {
    /// The remediators' display names, by name.
    fn remediator_name(&self, name: &str) -> Option<String> {
        self.actions
            .get(ActionKind::Remediation, name)
            .map(|spec| spec.display_name.to_owned())
    }

    /// The remediation targets of the observables in `alerts`, each with its latest remediation, in
    /// remediator, type and value order: ace3's `lookup_targets`. An alert that isn't one is `NotFound`.
    pub async fn remediation_targets_of_alerts(
        &self,
        actor: &Actor,
        alerts: &[Uuid],
    ) -> Result<Vec<RemediationTarget>, ServiceError> {
        if alerts.is_empty() || alerts.len() > MAX_TARGET_ALERTS {
            return Err(ServiceError::InvalidRequest(format!(
                "a lookup reads 1 to {MAX_TARGET_ALERTS} alerts"
            )));
        }
        let types: Vec<String> = self
            .actions
            .of_kind(ActionKind::Remediation)
            .map(|spec| spec.observable_type.to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let (alerts, types) = (alerts, &types);
        self.gate
            .read(actor, "remediation_targets_of_alerts", &REMEDIATION_READ, &|tx| {
                Box::pin(async move {
                    let known: Vec<Uuid> = sqlx::query_scalar!(
                        "SELECT id FROM analysis.roots WHERE id = ANY($1) AND alerted_at IS NOT NULL",
                        alerts,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    if let Some(missing) = alerts.iter().find(|a| !known.contains(a)) {
                        return Err(crate::alerts::no_alert(*missing));
                    }
                    let observables = sqlx::query!(
                        "SELECT DISTINCT type, value FROM analysis.observables
                         WHERE root_id = ANY($1) AND type = ANY($2)
                         ORDER BY type, value LIMIT $3",
                        alerts,
                        types,
                        i64::try_from(MAX_TARGETS + 1).unwrap_or(i64::MAX),
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let pairs = observables
                        .into_iter()
                        .map(|row| (row.r#type, row.value))
                        .collect::<Vec<_>>();
                    self.targets_in(tx, &pairs).await
                })
            })
            .await
    }

    /// The remediation targets of these observables, as `remediation_targets_of_alerts`. A type this
    /// binary doesn't have, or a value its type refuses, is `InvalidRequest` naming each.
    pub async fn remediation_targets_of_observables(
        &self,
        actor: &Actor,
        observables: &[(String, String)],
    ) -> Result<Vec<RemediationTarget>, ServiceError> {
        if observables.is_empty() || observables.len() > MAX_TARGETS {
            return Err(ServiceError::InvalidRequest(format!(
                "a lookup takes 1 to {MAX_TARGETS} observables"
            )));
        }
        let mut pairs = BTreeSet::new();
        let mut invalid = Vec::new();
        for (kind, value) in observables {
            match crate::observables::normalized(kind, value) {
                Ok((kind, value)) => {
                    pairs.insert((kind.as_str().to_owned(), value));
                }
                Err(why) => invalid.push(format!("{kind} {value:?} ({why})")),
            }
        }
        if !invalid.is_empty() {
            return Err(ServiceError::InvalidRequest(format!(
                "invalid observables: {}",
                invalid.join(", ")
            )));
        }
        let pairs: Vec<(String, String)> = pairs.into_iter().collect();
        let pairs = &pairs;
        self.gate
            .read(
                actor,
                "remediation_targets_of_observables",
                &REMEDIATION_READ,
                &|tx| Box::pin(async move { self.targets_in(tx, pairs).await }),
            )
            .await
    }

    /// Each remediator's target for each (type, value), with its latest remediation, bounded.
    async fn targets_in(
        &self,
        tx: &mut Tx<'_>,
        pairs: &[(String, String)],
    ) -> Result<Vec<RemediationTarget>, ServiceError> {
        let mut keys: Vec<TargetKey> = Vec::new();
        for (kind, value) in pairs {
            for spec in self.actions.of_kind(ActionKind::Remediation) {
                if spec.observable_type == kind {
                    keys.push(TargetKey {
                        remediator: spec.name.to_owned(),
                        observable_type: kind.clone(),
                        observable_value: value.clone(),
                    });
                }
            }
        }
        keys.sort();
        keys.dedup();
        if keys.len() > MAX_TARGETS {
            return Err(ServiceError::TooLarge(format!(
                "these have more than {MAX_TARGETS} targets: look up fewer"
            )));
        }
        let mut targets = Vec::with_capacity(keys.len());
        for key in keys {
            let current = current_remediation(tx, &key).await?;
            targets.push(RemediationTarget {
                display_name: self.remediator_name(&key.remediator),
                key,
                current,
            });
        }
        Ok(targets)
    }

    /// Queues a removal or a restore of each target, after checking every one, and returns them in order:
    /// ace3's `queue_remediations`. A restore takes the restore key of the target's latest successful
    /// removal, as ace3's does. Each is attributed to the person asking. Audited as one write.
    pub async fn queue_remediations(
        &self,
        actor: &Actor,
        action: RemediationAction,
        targets: &[TargetKey],
    ) -> Result<Vec<ActionSummary>, ServiceError> {
        if targets.is_empty() || targets.len() > MAX_TARGETS {
            return Err(ServiceError::InvalidRequest(format!(
                "a request queues 1 to {MAX_TARGETS} remediations"
            )));
        }
        for target in targets {
            let spec = self
                .actions
                .require(ActionKind::Remediation, &target.remediator)?;
            if spec.observable_type != target.observable_type {
                return Err(ServiceError::InvalidRequest(format!(
                    "{} remediates {} observables, not {}",
                    spec.name, spec.observable_type, target.observable_type
                )));
            }
            crate::observables::normalized(&target.observable_type, &target.observable_value)
                .map_err(|why| {
                    ServiceError::InvalidRequest(format!(
                        "invalid {} value {:?}: {why}",
                        target.observable_type, target.observable_value
                    ))
                })?;
        }
        let requested_by = serde_json::to_value(actor)?;
        let requested_by = &requested_by;
        self.gate
            .write(actor, "queue_remediations", &REMEDIATION_WRITE, &|tx| {
                Box::pin(async move {
                    // after the permission, so an actor without it learns only that
                    let user = person(actor)?;
                    let mut ids = Vec::with_capacity(targets.len());
                    for target in targets {
                        let restore_key = match action {
                            RemediationAction::Restore => current_restore_key(tx, target).await?,
                            RemediationAction::Remove => None,
                        };
                        ids.push(
                            core_actions::queue_remediation(
                                tx,
                                &self.actions,
                                &NewRemediation {
                                    handler: &target.remediator,
                                    observable_type: &target.observable_type,
                                    observable_value: &target.observable_value,
                                    action,
                                    restore_key: restore_key.as_deref(),
                                    requested_by,
                                    user: Some(user),
                                },
                            )
                            .await?,
                        );
                    }
                    let mut queued = Vec::with_capacity(ids.len());
                    for id in &ids {
                        queued.push(summary_in(tx, *id).await?);
                    }
                    let change = Change::added(
                        Target::actions(&ids),
                        &Queued {
                            action: action.as_str(),
                            remediations: ids
                                .iter()
                                .zip(targets)
                                .map(|(id, t)| QueuedTarget {
                                    id: *id,
                                    remediator: &t.remediator,
                                    observable_type: &t.observable_type,
                                    observable_value: &t.observable_value,
                                })
                                .collect(),
                        },
                    )?;
                    Ok(Audited::changed(queued, change))
                })
            })
            .await
    }

    /// Stops a remediation that hasn't completed; it completes `CANCELLED`, and a pool trying it stops at
    /// its next renewal. One that has completed is a conflict: its result stands.
    pub async fn cancel_remediation(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<ActionSummary, ServiceError> {
        let name = match actor {
            Actor::User { name, .. } | Actor::ApiKey { name, .. } => name.clone(),
            Actor::Internal { id: component } => component.as_str().to_owned(),
        };
        let name = &name;
        self.gate
            .write(actor, "cancel_remediation", &REMEDIATION_WRITE, &|tx| {
                Box::pin(async move {
                    let before = action_state(tx, ActionKind::Remediation, id)
                        .await?
                        .ok_or_else(|| no_action(ActionKind::Remediation, id))?;
                    if !core_actions::cancel_in(tx, id, &format!("cancelled by {name}")).await? {
                        return Err(ServiceError::Conflict(format!(
                            "remediation {id} has already completed"
                        )));
                    }
                    let after = action_state(tx, ActionKind::Remediation, id)
                        .await?
                        .ok_or_else(|| no_action(ActionKind::Remediation, id))?;
                    let change = Change::updated(Target::action(id), &before, &after)?;
                    Ok(Audited::changed(summary_in(tx, id).await?, change))
                })
            })
            .await
    }

    /// Queues a completed remediation again, as it was. One that hasn't completed is a conflict.
    pub async fn retry_remediation(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<ActionSummary, ServiceError> {
        self.gate
            .write(actor, "retry_remediation", &REMEDIATION_WRITE, &|tx| {
                Box::pin(async move {
                    let before = action_state(tx, ActionKind::Remediation, id)
                        .await?
                        .ok_or_else(|| no_action(ActionKind::Remediation, id))?;
                    if !core_actions::retry_in(tx, &self.actions, id).await? {
                        return Err(ServiceError::Conflict(format!(
                            "remediation {id} has not completed"
                        )));
                    }
                    let after = action_state(tx, ActionKind::Remediation, id)
                        .await?
                        .ok_or_else(|| no_action(ActionKind::Remediation, id))?;
                    let change = Change::updated(Target::action(id), &before, &after)?;
                    Ok(Audited::changed(summary_in(tx, id).await?, change))
                })
            })
            .await
    }

    /// Queues a restore of what a successful removal removed, with the restore key that removal gave
    /// back, attributed to the person asking, and returns the restore. Anything but a removal that
    /// succeeded is a conflict.
    pub async fn restore_remediation(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<ActionSummary, ServiceError> {
        let requested_by = serde_json::to_value(actor)?;
        let requested_by = &requested_by;
        self.gate
            .write(actor, "restore_remediation", &REMEDIATION_WRITE, &|tx| {
                Box::pin(async move {
                    let user = person(actor)?;
                    let removal = sqlx::query!(
                        "SELECT handler, observable_type, observable_value, action, status, result,
                                restore_key
                         FROM queue.actions WHERE id = $1 AND kind = 'remediation' FOR UPDATE",
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| no_action(ActionKind::Remediation, id))?;
                    let succeeded = removal.action.as_deref() == Some("remove")
                        && removal.status == core_actions::COMPLETED
                        && removal.result.as_deref() == Some("SUCCESS");
                    if !succeeded {
                        return Err(ServiceError::Conflict(format!(
                            "remediation {id} is not a removal that succeeded"
                        )));
                    }
                    let restore = core_actions::queue_remediation(
                        tx,
                        &self.actions,
                        &NewRemediation {
                            handler: &removal.handler,
                            observable_type: &removal.observable_type,
                            observable_value: &removal.observable_value,
                            action: RemediationAction::Restore,
                            restore_key: removal.restore_key.as_deref(),
                            requested_by,
                            user: Some(user),
                        },
                    )
                    .await?;
                    let change = Change::added(
                        Target::action(restore),
                        &Queued {
                            action: RemediationAction::Restore.as_str(),
                            remediations: vec![QueuedTarget {
                                id: restore,
                                remediator: &removal.handler,
                                observable_type: &removal.observable_type,
                                observable_value: &removal.observable_value,
                            }],
                        },
                    )?
                    .details(&Restoring { removal: id })?;
                    Ok(Audited::changed(summary_in(tx, restore).await?, change))
                })
            })
            .await
    }

    /// Deletes a remediation's record and its history. Returns it as it was.
    pub async fn delete_remediation(
        &self,
        actor: &Actor,
        id: i64,
    ) -> Result<ActionSummary, ServiceError> {
        self.gate
            .write(actor, "delete_remediation", &REMEDIATION_WRITE, &|tx| {
                Box::pin(async move {
                    let before = action_state(tx, ActionKind::Remediation, id)
                        .await?
                        .ok_or_else(|| no_action(ActionKind::Remediation, id))?;
                    let summary = summary_in(tx, id).await?;
                    core_actions::delete_in(tx, id).await?;
                    let change = Change::removed(Target::action(id), &before)?;
                    Ok(Audited::changed(summary, change))
                })
            })
            .await
    }

    /// A remediation's tries, newest first, up to `limit`.
    pub async fn remediation_history(
        &self,
        actor: &Actor,
        id: i64,
        limit: u32,
    ) -> Result<Vec<ActionAttempt>, ServiceError> {
        self.gate
            .read(actor, "remediation_history", &REMEDIATION_READ, &|tx| {
                Box::pin(async move { history_in(tx, ActionKind::Remediation, id, limit).await })
            })
            .await
    }

    /// One remediation.
    pub async fn remediation(&self, actor: &Actor, id: i64) -> Result<Remediation, ServiceError> {
        let query = ActionQuery {
            filters: vec![FilterEntry::text("ID", false, &[&id.to_string()])],
            tz: Tz::UTC,
        };
        self.remediations(actor, &query, Some(1), None)
            .await?
            .remediations
            .pop()
            .ok_or_else(|| no_action(ActionKind::Remediation, id))
    }

    /// A page of remediations, newest first, of up to `limit` (100 when None, at most `MAX_ACTIONS_PAGE`),
    /// after the remediation `after` names, with the filters' total.
    pub async fn remediations(
        &self,
        actor: &Actor,
        query: &ActionQuery,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<RemediationPage, ServiceError> {
        let limit = page_limit(limit, MAX_ACTIONS_PAGE)?;
        let params = &params(query)?;
        let page = self
            .gate
            .read(actor, "remediations", &REMEDIATION_READ, &|tx| {
                Box::pin(async move {
                    let ([i1, i2], t, [c1, c2, c3, c4]) = params;
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    let rows = sqlx::query!(
                        r#"WITH matched AS (
                             SELECT a.id, a.handler, a.observable_type, a.observable_value,
                                    a.action AS "action!", a.status, a.result, a.result_message,
                                    a.attempts, a.created_at, a.updated_at,
                                    coalesce(u.username::text, a.requested_by ->> 'name') AS analyst
                             FROM queue.actions a LEFT JOIN service.users u ON u.id = a.user_id
                             WHERE a.kind = 'remediation'
                               AND ($3::bigint[] IS NULL OR a.id = ANY ($3))
                               AND ($4::bigint[] IS NULL OR NOT a.id = ANY ($4))
                               AND ($5::text[] IS NULL OR a.handler ILIKE ANY ($5))
                               AND ($6::text[] IS NULL OR NOT a.handler ILIKE ANY ($6))
                               AND ($7::text[] IS NULL OR a.observable_type ILIKE ANY ($7))
                               AND ($8::text[] IS NULL OR NOT a.observable_type ILIKE ANY ($8))
                               AND ($9::text[] IS NULL OR a.observable_value ILIKE ANY ($9))
                               AND ($10::text[] IS NULL OR NOT a.observable_value ILIKE ANY ($10))
                               AND ($11::text[] IS NULL
                                    OR coalesce(u.username::text, a.requested_by ->> 'name') ILIKE ANY ($11))
                               AND ($12::text[] IS NULL OR NOT coalesce(
                                    coalesce(u.username::text, a.requested_by ->> 'name') ILIKE ANY ($12), false))
                               AND ($13::text[] IS NULL OR a.action = ANY ($13))
                               AND ($14::text[] IS NULL OR NOT a.action = ANY ($14))
                               AND ($15::text[] IS NULL OR a.status = ANY ($15))
                               AND ($16::text[] IS NULL OR NOT a.status = ANY ($16))
                               AND ($17::text[] IS NULL OR a.result = ANY ($17))
                               AND ($18::text[] IS NULL OR NOT coalesce(a.result = ANY ($18), false))
                               AND ($19::timestamptz[] IS NULL OR EXISTS (
                                     SELECT FROM unnest($19::timestamptz[], $20::timestamptz[]) w(s, e)
                                     WHERE a.created_at BETWEEN w.s AND w.e))
                               AND ($21::timestamptz[] IS NULL OR NOT EXISTS (
                                     SELECT FROM unnest($21::timestamptz[], $22::timestamptz[]) w(s, e)
                                     WHERE a.created_at BETWEEN w.s AND w.e))
                           )
                           SELECT m.*, (SELECT count(*) FROM matched) AS "total!"
                           FROM matched m
                           WHERE $2::bigint IS NULL OR m.id < $2
                           ORDER BY m.id DESC
                           LIMIT $1"#,
                        limit + 1,
                        after,
                        i1.as_deref(),
                        i2.as_deref(),
                        t[0].as_deref(),
                        t[1].as_deref(),
                        t[2].as_deref(),
                        t[3].as_deref(),
                        t[4].as_deref(),
                        t[5].as_deref(),
                        t[6].as_deref(),
                        t[7].as_deref(),
                        t[8].as_deref(),
                        t[9].as_deref(),
                        t[10].as_deref(),
                        t[11].as_deref(),
                        t[12].as_deref(),
                        t[13].as_deref(),
                        c1.as_deref(),
                        c2.as_deref(),
                        c3.as_deref(),
                        c4.as_deref(),
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(timed_out)?;
                    let total = rows.first().map_or(0, |row| row.total);
                    let remediations: Vec<Remediation> = rows
                        .into_iter()
                        .map(|row| Remediation {
                                id: row.id,
                                display_name: None,
                                remediator: row.handler,
                                observable_type: row.observable_type,
                                observable_value: row.observable_value,
                                action: row.action,
                                status: row.status,
                                result: row.result,
                                result_message: row.result_message,
                                analyst: row.analyst,
                                attempts: row.attempts,
                                created_at: row.created_at,
                                updated_at: row.updated_at,
                        })
                        .collect();
                    Ok((remediations, total))
                })
            })
            .await?;
        let (mut remediations, total) = page;
        for remediation in &mut remediations {
            remediation.display_name = self.remediator_name(&remediation.remediator);
        }
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let more = remediations.len() > limit;
        remediations.truncate(limit);
        let next = if more {
            remediations.last().map(|r| r.id)
        } else {
            None
        };
        Ok(RemediationPage {
            remediations,
            total,
            next,
        })
    }

    /// Each alert's remediation coverage, ace3's `get_remediation_coverage`: every alert asked for has an
    /// entry, one with no `email_delivery` targets an empty one.
    pub async fn remediation_coverage(
        &self,
        actor: &Actor,
        alerts: &[Uuid],
    ) -> Result<BTreeMap<Uuid, Coverage>, ServiceError> {
        if alerts.len() > MAX_TARGET_ALERTS {
            return Err(ServiceError::InvalidRequest(format!(
                "coverage reads at most {MAX_TARGET_ALERTS} alerts"
            )));
        }
        self.gate
            .read(actor, "remediation_coverage", &REMEDIATION_READ, &|tx| {
                Box::pin(async move { coverage_in(tx, alerts).await })
            })
            .await
    }
}

#[derive(Serialize)]
struct Restoring {
    removal: i64,
}

impl Recorded for Restoring {}

/// The target's latest remediation, by any analyst.
async fn current_remediation(
    tx: &mut Tx<'_>,
    key: &TargetKey,
) -> Result<Option<ActionSummary>, ServiceError> {
    let row = sqlx::query!(
        "SELECT id, action, status, result FROM queue.actions
         WHERE kind = 'remediation' AND handler = $1 AND observable_type = $2 AND observable_value = $3
         ORDER BY id DESC LIMIT 1",
        key.remediator,
        key.observable_type,
        key.observable_value,
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(row.map(|row| ActionSummary {
        id: row.id,
        action: row.action,
        status: row.status,
        result: row.result,
    }))
}

/// The restore key of the target's latest successful removal, ace3's `get_current_restore_key`.
async fn current_restore_key(
    tx: &mut Tx<'_>,
    key: &TargetKey,
) -> Result<Option<String>, ServiceError> {
    Ok(sqlx::query_scalar!(
        "SELECT restore_key FROM queue.actions
         WHERE kind = 'remediation' AND handler = $1 AND observable_type = $2 AND observable_value = $3
           AND action = 'remove' AND result = 'SUCCESS'
         ORDER BY id DESC LIMIT 1",
        key.remediator,
        key.observable_type,
        key.observable_value,
    )
    .fetch_optional(tx.conn())
    .await?
    .flatten())
}

/// ace3's `CoverageState`: an alert's targets summed up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// No targets, or nothing attempted on any.
    None,
    /// Nothing confirmed yet; ACE is still removing one, or a probe still watching.
    Pending,
    /// Every attempt ended without confirming anything.
    Unremediated,
    /// Nothing remediated, but ACE looked and the message isn't in the mailbox.
    NotFound,
    Partial,
    Remediated,
    /// ACE's own attempt failed on at least one target.
    Failed,
}

/// One `email_delivery` target's state, ace3's `TargetCoverage`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TargetCoverage {
    /// The `email_delivery` value: `<message-id>|recipient`.
    pub target: String,
    /// What confirmed it was remediated: `ACE`, or the vendor events' sources.
    pub sources: BTreeSet<String>,
    pub failed: bool,
    pub pending: bool,
    /// ACE's own removal of it is still in flight.
    pub remediating: bool,
    pub not_found: bool,
    pub attempted: bool,
    /// Why the journal shows this address didn't receive its own copy, from the delivery tag the
    /// email module put on the observable (ace3's `undelivered`).
    pub undelivered: Option<DeliveryReason>,
    /// The journal explains ACE's finished, unsuccessful removal: there was nothing to remove at
    /// this address. Such a target is left out of the alert's counts (ace3's `not_delivered`).
    pub not_delivered: bool,
}

impl TargetCoverage {
    pub fn remediated(&self) -> bool {
        !self.sources.is_empty()
    }

    /// The recipient, from the value, or the value.
    pub fn recipient(&self) -> &str {
        match self.target.rsplit_once('|') {
            Some((_, recipient)) if !recipient.is_empty() => recipient,
            _ => &self.target,
        }
    }

    /// ace3's `status_display`.
    pub fn status_display(&self) -> String {
        if self.remediated() {
            self.sources.iter().cloned().collect::<Vec<_>>().join(", ")
        } else if let (true, Some(reason)) = (self.not_delivered, self.undelivered) {
            reason.describe_undelivered(&[])
        } else if self.failed {
            "failed".to_owned()
        } else if self.not_found {
            "not in mailbox".to_owned()
        } else if self.remediating {
            "remediating".to_owned()
        } else if self.pending {
            "watching".to_owned()
        } else if self.attempted {
            "not remediated".to_owned()
        } else {
            "not attempted".to_owned()
        }
    }
}

/// An alert's coverage, ace3's `RemediationCoverage`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Coverage {
    pub targets: Vec<TargetCoverage>,
}

impl Coverage {
    /// The targets the counts and the state cover: all but those the journal shows had nothing to
    /// remove (ace3's `counted`).
    pub fn counted(&self) -> impl Iterator<Item = &TargetCoverage> {
        self.targets.iter().filter(|t| !t.not_delivered)
    }

    pub fn total(&self) -> usize {
        self.counted().count()
    }

    pub fn remediated_count(&self) -> usize {
        self.counted().filter(|t| t.remediated()).count()
    }

    pub fn not_found_count(&self) -> usize {
        self.counted()
            .filter(|t| t.not_found && !t.remediated())
            .count()
    }

    /// Targets nothing is left to do for: remediated, or not in the mailbox.
    pub fn covered_count(&self) -> usize {
        self.counted()
            .filter(|t| t.remediated() || t.not_found)
            .count()
    }

    pub fn sources(&self) -> Vec<String> {
        self.targets
            .iter()
            .flat_map(|t| t.sources.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn state(&self) -> CoverageState {
        if self.total() == 0 || !self.counted().any(|t| t.attempted) {
            return CoverageState::None;
        }
        if self.counted().any(|t| t.failed && !t.remediated()) {
            return CoverageState::Failed;
        }
        let covered = self.covered_count();
        if covered > 0 && self.remediated_count() == 0 {
            return CoverageState::NotFound;
        }
        if covered == self.total() {
            return CoverageState::Remediated;
        }
        if covered > 0 {
            return CoverageState::Partial;
        }
        if self.counted().any(|t| t.pending) {
            return CoverageState::Pending;
        }
        CoverageState::Unremediated
    }

    /// Whether a list shows a badge for it.
    pub fn visible(&self) -> bool {
        self.state() != CoverageState::None
    }

    /// ace3's `status_label`: the state and the counts, such as `remediated 3/3`.
    pub fn status_label(&self) -> String {
        let state = self.state();
        if state == CoverageState::NotFound {
            return format!("not in mailbox {}/{}", self.not_found_count(), self.total());
        }
        let prefix = match state {
            CoverageState::Remediated | CoverageState::Partial => "remediated",
            CoverageState::Failed => "remediation failed",
            CoverageState::Pending if self.counted().any(|t| t.remediating) => "remediating",
            CoverageState::Pending => "watching",
            CoverageState::Unremediated => "not remediated",
            CoverageState::NotFound | CoverageState::None => "",
        };
        format!("{prefix} {}/{}", self.covered_count(), self.total())
    }

    /// ace3's `label`: the status, and who remediated, such as `remediated 3/3 · ACE, Vendor`.
    pub fn label(&self) -> String {
        let sources = self.sources();
        if sources.is_empty() {
            self.status_label()
        } else {
            format!("{} · {}", self.status_label(), sources.join(", "))
        }
    }

    /// ace3's `tooltip`: a line per target, at most `TOOLTIP_TARGET_LIMIT`.
    pub fn tooltip(&self) -> String {
        let mut lines: Vec<String> = self
            .targets
            .iter()
            .take(TOOLTIP_TARGET_LIMIT)
            .map(|t| format!("{}: {}", t.recipient(), t.status_display()))
            .collect();
        if self.targets.len() > TOOLTIP_TARGET_LIMIT {
            lines.push(format!(
                "... and {} more",
                self.targets.len() - TOOLTIP_TARGET_LIMIT
            ));
        }
        lines.join("\n")
    }
}

/// One of ACE's remediations of a coverage target, as coverage reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageRemediation {
    pub action: Option<String>,
    pub status: String,
    pub result: Option<String>,
}

/// A remediation check of one of an alert's coverage targets, as coverage reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageCheck {
    pub value: String,
    pub handler: String,
    pub status: String,
    pub result: Option<String>,
    pub result_message: Option<String>,
    pub events: Option<Value>,
}

async fn coverage_in(
    tx: &mut Tx<'_>,
    alerts: &[Uuid],
) -> Result<BTreeMap<Uuid, Coverage>, ServiceError> {
    let mut targets_by_alert: BTreeMap<Uuid, BTreeSet<String>> =
        alerts.iter().map(|a| (*a, BTreeSet::new())).collect();
    // the delivery tags are each alert's: the journal of this alert's email says where that address's
    // copy went
    let mut undelivered_by_alert: BTreeMap<Uuid, BTreeMap<String, DeliveryReason>> =
        BTreeMap::new();
    let observables = sqlx::query!(
        "SELECT root_id, value, tags FROM analysis.observables WHERE root_id = ANY($1) AND type = $2",
        alerts,
        COVERAGE_TYPE,
    )
    .fetch_all(tx.conn())
    .await?;
    for row in observables {
        if let Some(reason) = row.tags.iter().find_map(|tag| DeliveryReason::of_tag(tag)) {
            undelivered_by_alert
                .entry(row.root_id)
                .or_default()
                .insert(row.value.clone(), reason);
        }
        targets_by_alert
            .entry(row.root_id)
            .or_default()
            .insert(row.value);
    }
    let values: Vec<String> = targets_by_alert
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    // ACE's own remediations, by target: a message remediated through one alert is remediated in each
    let mut ace_rows: BTreeMap<String, Vec<CoverageRemediation>> = BTreeMap::new();
    for row in sqlx::query!(
        "SELECT observable_value, action, status, result FROM queue.actions
         WHERE kind = 'remediation' AND observable_type = $1 AND observable_value = ANY($2)
         ORDER BY id",
        COVERAGE_TYPE,
        &values,
    )
    .fetch_all(tx.conn())
    .await?
    {
        ace_rows
            .entry(row.observable_value)
            .or_default()
            .push(CoverageRemediation {
                action: row.action,
                status: row.status,
                result: row.result,
            });
    }
    // the checks, which are each an alert's
    let mut checks_by_alert: BTreeMap<Uuid, Vec<CoverageCheck>> = BTreeMap::new();
    for row in sqlx::query!(
        "SELECT r.root_id, a.observable_value, a.handler, a.status, a.result, a.result_message, a.events
         FROM queue.actions a JOIN queue.action_roots r ON r.action_id = a.id
         WHERE a.kind = 'remediation_check' AND a.observable_type = $1 AND r.root_id = ANY($2)
         ORDER BY a.id",
        COVERAGE_TYPE,
        alerts,
    )
    .fetch_all(tx.conn())
    .await?
    {
        checks_by_alert.entry(row.root_id).or_default().push(CoverageCheck {
            value: row.observable_value,
            handler: row.handler,
            status: row.status,
            result: row.result,
            result_message: row.result_message,
            events: row.events,
        });
    }
    Ok(alerts
        .iter()
        .map(|alert| {
            let empty = Vec::new();
            let checks = checks_by_alert.get(alert).unwrap_or(&empty);
            (
                *alert,
                assemble_coverage(
                    targets_by_alert.get(alert).cloned().unwrap_or_default(),
                    &ace_rows,
                    checks,
                    undelivered_by_alert.get(alert).cloned().unwrap_or_default(),
                ),
            )
        })
        .collect())
}

/// ace3's `assemble_coverage` for one alert: its `email_delivery` values, ACE's remediations of each target
/// oldest first, the alert's checks, and the journal's reason for each target its delivery tag names.
pub fn assemble_coverage(
    values: BTreeSet<String>,
    ace_rows: &BTreeMap<String, Vec<CoverageRemediation>>,
    checks: &[CoverageCheck],
    undelivered: BTreeMap<String, DeliveryReason>,
) -> Coverage {
    let mut targets: BTreeMap<String, TargetCoverage> = values
        .into_iter()
        .map(|value| {
            (
                value.clone(),
                TargetCoverage {
                    target: value,
                    ..TargetCoverage::default()
                },
            )
        })
        .collect();
    // a check of a target the alert has no row for still describes one of its emails
    for check in checks {
        let target = targets
            .entry(check.value.clone())
            .or_insert_with(|| TargetCoverage {
                target: check.value.clone(),
                ..TargetCoverage::default()
            });
        apply_check(target, check);
    }
    for (value, target) in &mut targets {
        let latest = ace_rows.get(value).and_then(|rows| rows.last());
        if let Some(latest) = latest {
            apply_ace_row(target, latest);
        }
        target.undelivered = undelivered.get(value).copied();
        if let Some(latest) = latest
            && !target.remediated()
            && !target.pending
            && latest.action.as_deref() == Some("remove")
            && journal_explains(target.undelivered, latest.result.as_deref())
        {
            target.not_delivered = true;
            target.failed = false;
        }
    }
    for check in checks {
        if check.result.as_deref() != Some("SUPERSEDED") {
            continue;
        }
        if let Some(target) = targets.get_mut(&check.value)
            && !target.remediated()
        {
            target.sources.insert(
                core_actions::superseding_source(check.result_message.as_deref())
                    .unwrap_or_else(|| "superseded".to_owned()),
            );
        }
    }
    Coverage {
        targets: targets.into_values().collect(),
    }
}

/// Whether the journal's account of an address explains ACE's finished removal there finding nothing
/// to remove (ace3's `journal_explains`): a distribution list holds no mail, so any unsuccessful result
/// is expected; a forwarded address explains `NOT_FOUND` and `FAILED` (not a mailbox) but not `ERROR`,
/// which says nothing about the address; and an address the journal doesn't name explains only
/// `NOT_FOUND`, since another journal report may name it.
pub fn journal_explains(reason: Option<DeliveryReason>, result: Option<&str>) -> bool {
    let Some(reason) = reason else {
        return false;
    };
    match result {
        Some("NOT_FOUND") => true,
        Some("FAILED") => reason != DeliveryReason::NotJournaled,
        Some("ERROR") => reason == DeliveryReason::Expanded,
        _ => false,
    }
}

fn apply_ace_row(target: &mut TargetCoverage, latest: &CoverageRemediation) {
    target.attempted = true;
    if latest.status != core_actions::COMPLETED {
        target.pending = true;
        target.remediating = latest.action.as_deref() == Some("remove");
        return;
    }
    if latest.action.as_deref() != Some("remove") {
        // a completed restore leaves the message in the mailbox, whatever came before it
        return;
    }
    match latest.result.as_deref() {
        Some("SUCCESS") => {
            target.sources.insert(ACE_SOURCE.to_owned());
        }
        Some("NOT_FOUND") => target.not_found = true,
        Some("FAILED" | "ERROR") => target.failed = true,
        _ => {}
    }
}

fn apply_check(target: &mut TargetCoverage, check: &CoverageCheck) {
    target.attempted = true;
    if check.status != core_actions::COMPLETED {
        target.pending = true;
        return;
    }
    if check.result.as_deref() == Some("CONFIRMED") {
        let sources: BTreeSet<String> = check
            .events
            .clone()
            .and_then(|events| serde_json::from_value::<Vec<RemediationEvent>>(events).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|event| event.source)
            .filter(|source| !source.is_empty())
            .collect();
        if sources.is_empty() {
            target.sources.insert(check.handler.clone());
        } else {
            target.sources.extend(sources);
        }
    }
}
