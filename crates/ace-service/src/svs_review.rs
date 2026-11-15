//! What a person does to a test run (PLAN.md 7.10 batch 7b): ace3's `saq/svs/review.py`, and the person's
//! half of `runs.py` (`cancel_by_person`, `end_by_person`, `close_by_person`, `close_reviewed_run_alerts`).
//! Take it, end it early, cancel it, close it, and review it, each under `svs:run_manage`.
//!
//! - **Ownership** works as ace3's does: a run someone else owns is changed only when the person confirmed
//!   taking it from them, by naming them, and then becomes theirs; a run whose owner's account is disabled
//!   or gone counts as nobody's. Reviewing a run also takes it when nobody owns it.
//! - **End**, **cancel** and **close** are the lifecycle's own (`svs_runs`). Ending a started run early
//!   makes it ended now, to be reviewed; closing discards the run: its alerts become SIMULATED and nothing
//!   is learned from it.
//! - **Review** signs the run's result off: an ended run becomes reviewed, and a reviewed run can be
//!   reviewed again, which replaces what was signed off. It needs the result to be current, every
//!   candidate decided (`svs_decisions`) and every context-only attribution kept or marked not a test
//!   (`svs_association`): [`ReviewBlockers`]. Then the run is reviewed with its reviewer, and its live
//!   result is copied to the reviewed columns of `svs.run_results`; its fully attributed open alerts
//!   nobody has taken become SIMULATED; and the detections of signatures ignored for the test get an FP
//!   verdict from the reviewer, unless someone already set one, so launcher noise isn't learned as a true
//!   positive.
//!
//! The bulk actions take up to [`MAX_BULK_RUNS`] runs and answer for each ([`BulkResult`]): done, left
//! alone for its owner, a conflict with why, or unknown. Each run is its own transaction, with the run's
//! row locked from the ownership check to the action's last write, so nobody takes a run between the two.
//!
//! What differs from ace3's:
//! - SIMULATED is a disposition only ACE sets: a person's close and a review close the run's alerts
//!   through `svs_association`'s `close_run_alerts_in`, as the component `svs`, where ace3 writes as its
//!   automation user. The run's `alerts_closed` event and the audit row name the person.
//! - One transaction holds a run's action. A take that was confirmed stands when the action then doesn't
//!   apply, as in ace3, where it is its own commit: the transaction commits the take alone.
//! - A review's sign-off, its closing of alerts and its verdicts are one transaction, the closing and the
//!   verdicts in a savepoint: a failure there leaves the sign-off, the alerts stay open and keep the run
//!   in Needs attention, and reviewing it again finishes the job, as in ace3. ace3 commits the sign-off
//!   first because its capture reads the run from another process; here both commit together.
//! - The confirmation names the owner by username, as ace3's API does, and counts only while that person
//!   still owns the run.
//! - An FP verdict is the reviewer's (`set_by`), written without the check an analyst's verdict gets, as
//!   ace3's `analyst=False`.
//! - Each write has an audit row; a bulk action has one per run it changed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use ace_core::db::{Retryable, Tx};
use ace_core::svs::RunState;
use ace_core::svs::runs::{CLOSE_REASON_CANCELED_BEFORE_START, whole_second};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::detection_verdicts::{BatchRules, Verdict};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SVS_RUN_MANAGE, SVS_RUN_READ};
use crate::svs_association::{AlertsClosed, svs_component};
use crate::svs_runs::{
    Loaded, Run, StateRecord, Values, add_event, close, end_in, find_run, log_transition,
    mark_stale, state_conflict, transition, unknown_run,
};
use crate::{Actor, Service, ServiceError};

/// The most runs one bulk action takes: ace3's `BulkRunRequest.run_ids`.
pub const MAX_BULK_RUNS: usize = 500;
/// The longest reason to end or close a run: ace3's `BulkRunRequest.reason`.
pub const MAX_RUN_REASON_CHARS: usize = 4096;
/// Why a run a person closed without saying why was closed: ace3's `CLOSE_REASON_BY_PERSON`.
pub const CLOSE_REASON_BY_PERSON: &str = "closed by hand";

/// What a bulk action did to each run it was given: ace3's `BulkResult`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BulkResult {
    /// The runs the action was applied to, in the order given.
    pub done: Vec<Uuid>,
    /// The runs left alone, each with the username of the person who owns it. Sent back as the
    /// confirmation, it takes them.
    pub left_alone: BTreeMap<Uuid, String>,
    /// The runs the action doesn't apply to, each with why: its state, or a missing reason.
    pub conflicts: BTreeMap<Uuid, String>,
    pub unknown: Vec<Uuid>,
}

/// What keeps a run from being reviewed: ace3's `review_blockers`. Empty when nothing does.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ReviewBlockers {
    /// Its result is being recomputed, or was never computed.
    pub stale: bool,
    /// The undecided signatures.
    pub candidates: Vec<String>,
    /// The alerts with context attributions neither kept nor marked not a test.
    pub context_alerts: Vec<Uuid>,
}

impl ReviewBlockers {
    pub fn is_empty(&self) -> bool {
        !self.stale && self.candidates.is_empty() && self.context_alerts.is_empty()
    }

    /// Why the run can't be reviewed, as ace3's `ReviewBlocked` says it.
    pub fn message(&self, run: Uuid) -> String {
        let mut reasons = Vec::new();
        if self.stale {
            reasons.push("its result is being recomputed".to_owned());
        }
        if !self.candidates.is_empty() {
            reasons.push(format!(
                "{} candidate signature(s) are undecided",
                self.candidates.len()
            ));
        }
        if !self.context_alerts.is_empty() {
            reasons.push(format!(
                "{} context-only alert(s) are neither kept nor marked not a test",
                self.context_alerts.len()
            ));
        }
        format!("run {run} can't be reviewed: {}", reasons.join("; "))
    }
}

/// A review that went through: ace3's `ReviewResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewed {
    pub run: Uuid,
    /// The run had been reviewed before; this sign-off replaces that one.
    pub re_review: bool,
    /// Signatures per result status, as signed off.
    pub counts: BTreeMap<String, i64>,
    /// Alerts that became SIMULATED.
    pub alerts_closed: usize,
    /// Detections of ignored signatures given an FP verdict.
    pub fp_verdicts: usize,
}

/// What a review came to. Only `Reviewed` signed anything off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewOutcome {
    Reviewed(Reviewed),
    /// Someone else owns the run, and taking it from them wasn't confirmed: their username.
    Owned {
        owner: String,
    },
    /// The run is neither ended nor reviewed.
    State(RunState),
    Blocked(ReviewBlockers),
}

/// The person an actor acts as: a user, or the user an API key belongs to, with the name the actor is
/// known by. Every action here records who took it, and a key that belongs to nobody is nobody.
fn person(actor: &Actor) -> Result<(Uuid, &str), ServiceError> {
    let user = crate::filters::queue_holder(actor).ok_or_else(|| {
        ServiceError::InvalidRequest(
            "this action records who took it: it requires a user's API key or session".to_owned(),
        )
    })?;
    let name = match actor {
        Actor::User { name, .. } | Actor::ApiKey { name, .. } => name.as_str(),
        Actor::Internal { id } => id.as_str(),
    };
    Ok((user, name))
}

/// A run's owner, as a claim reads it.
struct Owner {
    id: Uuid,
    name: String,
    enabled: bool,
    /// The caller named them as the person they agreed to take the run from.
    confirmed: bool,
}

/// The run's owner, with its row locked by the caller. A confirmation counts only while the person it
/// names still owns the run, so a run someone else took meanwhile is left alone rather than taken from
/// them unseen.
async fn owner_of(
    conn: &mut PgConnection,
    run: i64,
    confirmed: Option<&str>,
) -> Result<Option<Owner>, ServiceError> {
    Ok(sqlx::query!(
        r#"SELECT u.id, u.username::text AS "name!", u.enabled,
                  COALESCE(lower(u.username::text) = lower($2::text), false) AS "confirmed!"
           FROM svs.runs r JOIN service.users u ON u.id = r.owner_id
           WHERE r.id = $1"#,
        run,
        confirmed,
    )
    .fetch_optional(conn)
    .await?
    .map(|row| Owner {
        id: row.id,
        name: row.name,
        enabled: row.enabled,
        confirmed: row.confirmed,
    }))
}

/// A user's username, as an audit row names a run's owner; None for a user who is gone.
async fn username_of(conn: &mut PgConnection, user: Uuid) -> Result<Option<String>, ServiceError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT username::text AS "name!" FROM service.users WHERE id = $1"#,
        user
    )
    .fetch_optional(conn)
    .await?)
}

/// Whether a person may change a run: ace3's `check_alert_ownership`, for one run.
enum Claim {
    /// It's theirs.
    Mine,
    /// Nobody owns it.
    Free,
    /// Someone else owns it, and the person confirmed taking it, or its owner is disabled: the run
    /// becomes theirs, taken from this username.
    Take(String),
    /// Someone else owns it: their username.
    Refused(String),
}

fn claim(owner: Option<&Owner>, user: Uuid) -> Claim {
    match owner {
        None => Claim::Free,
        Some(owner) if owner.id == user => Claim::Mine,
        Some(owner) if !owner.enabled || owner.confirmed => Claim::Take(owner.name.clone()),
        Some(owner) => Claim::Refused(owner.name.clone()),
    }
}

/// Makes the person the run's owner, in the caller's transaction, and records it: ace3's `_take`.
async fn take(
    conn: &mut PgConnection,
    run: &Loaded,
    user: Uuid,
    actor: &Actor,
    from: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    sqlx::query!(
        "UPDATE svs.runs SET owner_id = $2 WHERE id = $1",
        run.id,
        user
    )
    .execute(&mut *conn)
    .await?;
    add_event(
        conn,
        run.id,
        "ownership_taken",
        actor,
        None,
        None,
        Some(json!({ "from": from })),
        now,
    )
    .await?;
    tracing::info!(
        svs_run = %run.run.uuid, svs_test = %run.run.test_guid, svs_marker = run.run.marker,
        actor = %actor, previous_owner = from,
        "svs run ownership taken"
    );
    Ok(())
}

/// A run's owner, as an audit row keeps its two sides.
#[derive(Serialize)]
struct OwnerRecord<'a> {
    owner: Option<&'a str>,
}

impl Recorded for OwnerRecord<'_> {}

/// What an action's audit row says of it.
#[derive(Serialize)]
struct ActionRecord<'a> {
    call: &'a str,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    /// The username the run was taken from, when the action took it.
    #[serde(skip_serializing_if = "Option::is_none")]
    taken_from: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alerts: Option<&'a AlertsClosed>,
}

impl Recorded for ActionRecord<'_> {}

/// What a review's audit row says of it.
#[derive(Serialize)]
struct ReviewRecord<'a> {
    call: &'static str,
    re_review: bool,
    counts: &'a BTreeMap<String, i64>,
    /// The username the run was taken from, or that nobody owned it and the review took it.
    #[serde(skip_serializing_if = "Option::is_none")]
    taken_from: Option<Option<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alerts: Option<&'a AlertsClosed>,
    /// The detections given an FP verdict.
    fp_verdicts: &'a [i64],
    /// Why the closing of its alerts failed, when it did: the sign-off stands.
    #[serde(skip_serializing_if = "Option::is_none")]
    closing_failed: Option<&'a str>,
}

impl Recorded for ReviewRecord<'_> {}

/// A bulk action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Take,
    Cancel,
    End,
    Close,
}

impl Action {
    fn call(self) -> &'static str {
        match self {
            Action::Take => "take",
            Action::Cancel => "cancel",
            Action::End => "end",
            Action::Close => "close",
        }
    }
}

/// What an action came to for one run.
enum Acted {
    Done,
    LeftAlone(String),
    Conflict(String),
    Unknown,
}

/// What an action logs once its transaction commits.
#[derive(Default)]
struct Moves {
    /// Each transition as (from, to, reason).
    transitions: Vec<(RunState, RunState, Option<String>)>,
    computed: Option<crate::svs_results::ComputedResult>,
}

fn checked_reason(reason: Option<&str>) -> Result<Option<&str>, ServiceError> {
    let reason = reason.map(str::trim).filter(|reason| !reason.is_empty());
    if reason.is_some_and(|reason| {
        reason.chars().count() > MAX_RUN_REASON_CHARS || reason.chars().any(|c| c == '\0')
    }) {
        return Err(ServiceError::InvalidRequest(format!(
            "a reason is at most {MAX_RUN_REASON_CHARS} characters, with no NUL"
        )));
    }
    Ok(reason)
}

/// The runs a bulk action was given, once each, in the order given.
fn checked_runs(runs: &[Uuid]) -> Result<Vec<Uuid>, ServiceError> {
    if runs.is_empty() || runs.len() > MAX_BULK_RUNS {
        return Err(ServiceError::InvalidRequest(format!(
            "a bulk action takes from 1 to {MAX_BULK_RUNS} runs"
        )));
    }
    let mut seen = BTreeSet::new();
    Ok(runs
        .iter()
        .copied()
        .filter(|run| seen.insert(*run))
        .collect())
}

impl BulkResult {
    fn record(&mut self, run: Uuid, acted: Acted) {
        match acted {
            Acted::Done => self.done.push(run),
            Acted::LeftAlone(owner) => {
                self.left_alone.insert(run, owner);
            }
            Acted::Conflict(why) => {
                self.conflicts.insert(run, why);
            }
            Acted::Unknown => self.unknown.push(run),
        }
    }
}

/// What keeps the run from being reviewed, and whether its result was never computed. A review locks the
/// run's result state (`lock`); the run page only reads it.
async fn blockers(
    conn: &mut PgConnection,
    run: i64,
    lock: bool,
) -> Result<(ReviewBlockers, bool), ServiceError> {
    let state = if lock {
        sqlx::query_scalar!(
            "SELECT stale FROM svs.run_result_state WHERE run_id = $1 FOR UPDATE",
            run
        )
        .fetch_optional(&mut *conn)
        .await?
    } else {
        sqlx::query_scalar!(
            "SELECT stale FROM svs.run_result_state WHERE run_id = $1",
            run
        )
        .fetch_optional(&mut *conn)
        .await?
    };
    let candidates = sqlx::query_scalar!(
        "SELECT signature_uuid FROM svs.run_results
         WHERE run_id = $1 AND status = 'candidate' ORDER BY signature_uuid",
        run,
    )
    .fetch_all(&mut *conn)
    .await?;
    let context_alerts = sqlx::query_scalar!(
        "SELECT DISTINCT root_id FROM svs.attributions
         WHERE run_id = $1 AND removed_at IS NULL AND confidence = 'context' AND kept_at IS NULL
         ORDER BY root_id",
        run,
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok((
        ReviewBlockers {
            stale: state.unwrap_or(true),
            candidates,
            context_alerts,
        },
        state.is_none(),
    ))
}

/// The run's attributed detections of signatures ignored for its test that nobody has given a verdict
/// yet, as (alert, detection): ace3's `ignored_detections`.
async fn ignored_detections(
    conn: &mut PgConnection,
    run: &Loaded,
) -> Result<Vec<(Uuid, i64)>, ServiceError> {
    Ok(sqlx::query!(
        "SELECT DISTINCT a.root_id, a.detection_id
         FROM svs.attributions a
         JOIN analysis.detections d ON d.id = a.detection_id
         WHERE a.run_id = $1 AND a.removed_at IS NULL
           AND d.signature_uuid IN (SELECT i.signature_uuid FROM svs.ignores i
                                    WHERE i.test_guid IS NULL OR i.test_guid = $2)
           AND NOT EXISTS (SELECT FROM analysis.detection_verdicts v WHERE v.detection_id = d.id)
         ORDER BY a.root_id, a.detection_id",
        run.id,
        run.run.test_guid,
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(|row| (row.root_id, row.detection_id))
    .collect())
}

/// What a review's closing did.
#[derive(Default)]
struct Closing {
    alerts: Option<AlertsClosed>,
    fp_verdicts: Vec<i64>,
}

impl Service {
    /// One run's bulk action, in the caller's transaction: the claim, then the action, with the run's row
    /// locked throughout. ace3's `_claim` and the action after it.
    #[allow(clippy::too_many_arguments)]
    async fn act_on_run_in(
        &self,
        tx: &mut Tx<'_>,
        actor: &Actor,
        action: Action,
        uuid: Uuid,
        reason: Option<&str>,
        confirmed: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Audited<(Acted, Moves)>, ServiceError> {
        // after the permission, which the gate checked: an actor without it learns nothing more
        let (user, _) = person(actor)?;
        let Some(loaded) = find_run(tx.conn(), uuid, true).await? else {
            return Ok(Audited::unchanged((Acted::Unknown, Moves::default())));
        };
        let owner = owner_of(tx.conn(), loaded.id, confirmed).await?;
        let owner_name = owner.as_ref().map(|owner| owner.name.as_str());
        let claimed = claim(owner.as_ref(), user);
        // who the run is taken from: Some(None) is from nobody, which only taking it does
        let taking: Option<Option<&str>> = match (&claimed, action) {
            (Claim::Refused(owner), _) => {
                return Ok(Audited::unchanged((
                    Acted::LeftAlone(owner.clone()),
                    Moves::default(),
                )));
            }
            (Claim::Take(from), _) => Some(Some(from.as_str())),
            (Claim::Free, Action::Take) => Some(None),
            (Claim::Free | Claim::Mine, _) => None,
        };
        let from = loaded.run.state;
        // why the action doesn't apply, before anything is written
        let refused = match action {
            Action::Take => None,
            Action::Cancel => (!matches!(from, RunState::Created | RunState::Started))
                .then(|| state_conflict(uuid, from, "cancel").to_string()),
            Action::End => {
                if from != RunState::Started {
                    Some(state_conflict(uuid, from, "end").to_string())
                } else if reason.is_none() {
                    Some(format!(
                        "run {uuid} is still observing: ending it early needs a reason"
                    ))
                } else {
                    None
                }
            }
            Action::Close => {
                if !matches!(from, RunState::Ended | RunState::Canceled | RunState::Error) {
                    Some(state_conflict(uuid, from, "close").to_string())
                } else if from == RunState::Ended && reason.is_none() {
                    Some(format!(
                        "run {uuid} ended and waits for a review: closing it instead needs a reason"
                    ))
                } else {
                    None
                }
            }
        };
        if let Some(from_owner) = taking {
            take(tx.conn(), &loaded, user, actor, from_owner, now).await?;
        }
        let username = username_of(tx.conn(), user).await?;
        let taken = || -> Result<Change, ServiceError> {
            Change::updated(
                Target::svs_run(uuid),
                &OwnerRecord { owner: owner_name },
                &OwnerRecord {
                    owner: username.as_deref(),
                },
            )
        };
        if let Some(why) = refused {
            // a confirmed take stands, as ace3 commits it before the action
            return Ok(match taking {
                Some(_) => Audited::changed(
                    (Acted::Conflict(why), Moves::default()),
                    taken()?.details(&ActionRecord {
                        call: action.call(),
                        outcome: "conflict",
                        reason: None,
                        taken_from: taking.flatten(),
                        alerts: None,
                    })?,
                ),
                None => Audited::unchanged((Acted::Conflict(why), Moves::default())),
            });
        }
        let mut moves = Moves::default();
        let mut alerts = None;
        let (to, outcome, recorded_reason) = match action {
            Action::Take => {
                return Ok(match taking {
                    Some(_) => Audited::changed((Acted::Done, moves), taken()?),
                    // already theirs
                    None => Audited::unchanged((Acted::Done, moves)),
                });
            }
            Action::Cancel => {
                let values = Values {
                    canceled_at: Some(now),
                    ..Values::default()
                };
                transition(
                    tx.conn(),
                    loaded.id,
                    from,
                    RunState::Canceled,
                    actor,
                    values,
                    None,
                    now,
                )
                .await?;
                moves.transitions.push((from, RunState::Canceled, None));
                if from == RunState::Created {
                    // a run canceled before it started has no windows, so it is closed at once
                    close(
                        tx.conn(),
                        loaded.id,
                        RunState::Canceled,
                        actor,
                        CLOSE_REASON_CANCELED_BEFORE_START,
                        now,
                    )
                    .await?;
                    moves.transitions.push((
                        RunState::Canceled,
                        RunState::Closed,
                        Some(CLOSE_REASON_CANCELED_BEFORE_START.to_owned()),
                    ));
                    alerts = self.close_alerts_after(tx, actor, uuid, None, now).await?;
                    (
                        RunState::Closed,
                        "canceled",
                        Some(CLOSE_REASON_CANCELED_BEFORE_START),
                    )
                } else {
                    (RunState::Canceled, "canceled", None)
                }
            }
            Action::End => {
                let reason = reason.unwrap_or_default();
                moves.computed = end_in(tx, actor, &loaded, reason, now).await?;
                moves
                    .transitions
                    .push((from, RunState::Ended, Some(reason.to_owned())));
                (RunState::Ended, "ended", Some(reason))
            }
            Action::Close => {
                let reason = reason.unwrap_or(CLOSE_REASON_BY_PERSON);
                close(tx.conn(), loaded.id, from, actor, reason, now).await?;
                moves
                    .transitions
                    .push((from, RunState::Closed, Some(reason.to_owned())));
                alerts = self.close_alerts_after(tx, actor, uuid, None, now).await?;
                (RunState::Closed, "closed", Some(reason))
            }
        };
        let change = Change::updated(
            Target::svs_run(uuid),
            &StateRecord { state: from },
            &StateRecord { state: to },
        )?
        .details(&ActionRecord {
            call: action.call(),
            outcome,
            reason: recorded_reason,
            taken_from: taking.flatten(),
            alerts: alerts.as_ref(),
        })?;
        Ok(Audited::changed((Acted::Done, moves), change))
    }

    /// Closes the alerts of a run a person just closed or reviewed, in a savepoint of their transaction:
    /// a failure never undoes the close or the sign-off, and the alerts stay for the timers' sweep (a
    /// closed run's) or the next review (a reviewed run's). ace3's `_after_close`.
    async fn close_alerts_after(
        &self,
        tx: &mut Tx<'_>,
        actor: &Actor,
        run: Uuid,
        reviewed: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<AlertsClosed>, ServiceError> {
        let closed = async {
            let mut inner = tx.savepoint().await?;
            let closed = self
                .close_run_alerts_in(
                    &mut inner,
                    &svs_component(),
                    actor,
                    run,
                    false,
                    reviewed,
                    now,
                )
                .await?;
            inner.commit().await?;
            Ok::<_, ServiceError>(closed)
        }
        .await;
        match closed {
            Ok(closed) => Ok(closed),
            Err(error) if error.is_retryable() => Err(error),
            Err(error) => {
                tracing::error!(svs_run = %run, "unable to close the alerts of an svs run: {error}");
                Ok(None)
            }
        }
    }

    fn log_moves(&self, run: &Loaded, actor: &Actor, moves: &Moves) {
        for (from, to, reason) in &moves.transitions {
            log_transition(&run.run, Some(*from), *to, actor, reason.as_deref());
        }
        if let Some(computed) = &moves.computed {
            crate::svs_results::log_computed(computed);
        }
    }

    /// Makes the person the owner of the runs, those owned by someone else only when `confirmed` names
    /// that owner for the run: ace3's `take_ownership`. It needs `svs:run_manage`, and an actor that is a
    /// person (`InvalidRequest` otherwise). Each run it takes is its own transaction, with the run's
    /// `ownership_taken` event and an audit row; a run already theirs is done and writes nothing.
    pub async fn take_svs_runs(
        &self,
        actor: &Actor,
        runs: &[Uuid],
        confirmed: &BTreeMap<Uuid, String>,
        now: DateTime<Utc>,
    ) -> Result<BulkResult, ServiceError> {
        let mut result = BulkResult::default();
        for uuid in checked_runs(runs)? {
            let confirmed = confirmed.get(&uuid).map(String::as_str);
            let (acted, _) = self
                .gate
                .write(actor, "take_svs_runs", &SVS_RUN_MANAGE, &|tx| {
                    Box::pin(async move {
                        self.act_on_run_in(tx, actor, Action::Take, uuid, None, confirmed, now)
                            .await
                    })
                })
                .await?;
            result.record(uuid, acted);
        }
        Ok(result)
    }

    /// Cancels the runs (created or started), as the launcher would: ace3's `cancel_runs`. A run canceled
    /// before it started is closed at once, and its alerts with it. A person's cancel is a transition, not
    /// a launcher's call. It needs `svs:run_manage` and a person, as [`Service::take_svs_runs`] does, and
    /// takes a run from a confirmed owner.
    pub async fn cancel_svs_runs(
        &self,
        actor: &Actor,
        runs: &[Uuid],
        confirmed: &BTreeMap<Uuid, String>,
        now: DateTime<Utc>,
    ) -> Result<BulkResult, ServiceError> {
        let mut result = BulkResult::default();
        for uuid in checked_runs(runs)? {
            let confirmed = confirmed.get(&uuid).map(String::as_str);
            let (acted, moves) = self
                .gate
                .write(actor, "cancel_svs_runs", &SVS_RUN_MANAGE, &|tx| {
                    Box::pin(async move {
                        self.act_on_run_in(tx, actor, Action::Cancel, uuid, None, confirmed, now)
                            .await
                    })
                })
                .await?;
            self.logged(actor, uuid, &moves).await;
            result.record(uuid, acted);
        }
        Ok(result)
    }

    /// Ends the runs (started) now, before their observation windows pass, for review: ace3's `end_runs`.
    /// It needs the reason, without which each run is a conflict. It needs `svs:run_manage` and a person,
    /// and takes a run from a confirmed owner.
    pub async fn end_svs_runs(
        &self,
        actor: &Actor,
        runs: &[Uuid],
        reason: Option<&str>,
        confirmed: &BTreeMap<Uuid, String>,
        now: DateTime<Utc>,
    ) -> Result<BulkResult, ServiceError> {
        let reason = checked_reason(reason)?;
        // to the second, as a start is: an alert of the second the run ended in isn't late
        let now = whole_second(now);
        let mut result = BulkResult::default();
        for uuid in checked_runs(runs)? {
            let confirmed = confirmed.get(&uuid).map(String::as_str);
            let (acted, moves) = self
                .gate
                .write(actor, "end_svs_runs", &SVS_RUN_MANAGE, &|tx| {
                    Box::pin(async move {
                        self.act_on_run_in(tx, actor, Action::End, uuid, reason, confirmed, now)
                            .await
                    })
                })
                .await?;
            self.logged(actor, uuid, &moves).await;
            result.record(uuid, acted);
        }
        Ok(result)
    }

    /// Closes the runs (ended, canceled or error): nothing is learned from them, and their alerts become
    /// SIMULATED. ace3's `close_runs`. An ended run needs the reason, since it waited for a review. It
    /// needs `svs:run_manage` and a person, and takes a run from a confirmed owner.
    pub async fn close_svs_runs(
        &self,
        actor: &Actor,
        runs: &[Uuid],
        reason: Option<&str>,
        confirmed: &BTreeMap<Uuid, String>,
        now: DateTime<Utc>,
    ) -> Result<BulkResult, ServiceError> {
        let reason = checked_reason(reason)?;
        let mut result = BulkResult::default();
        for uuid in checked_runs(runs)? {
            let confirmed = confirmed.get(&uuid).map(String::as_str);
            let (acted, moves) = self
                .gate
                .write(actor, "close_svs_runs", &SVS_RUN_MANAGE, &|tx| {
                    Box::pin(async move {
                        self.act_on_run_in(tx, actor, Action::Close, uuid, reason, confirmed, now)
                            .await
                    })
                })
                .await?;
            self.logged(actor, uuid, &moves).await;
            result.record(uuid, acted);
        }
        Ok(result)
    }

    /// Logs what an action moved, once it's committed.
    async fn logged(&self, actor: &Actor, uuid: Uuid, moves: &Moves) {
        if moves.transitions.is_empty() && moves.computed.is_none() {
            return;
        }
        let run = async {
            let mut conn = self.gate.db().pool().acquire().await?;
            find_run(&mut conn, uuid, false).await
        }
        .await;
        if let Ok(Some(run)) = run {
            self.log_moves(&run, actor, moves);
        }
    }

    /// Signs the run's result off (ended to reviewed, or reviewed again), then closes its alerts as
    /// SIMULATED and gives its ignored detections an FP verdict: ace3's `review` (the module's docs). It
    /// needs `svs:run_manage` and a person (`InvalidRequest` otherwise). A run that isn't there is
    /// `NotFound`. What stands in the way is an outcome, not an error: another person's ownership
    /// (`confirmed_from` names the owner the caller agreed to take it from), the run's state, or its
    /// blockers; none of those signs anything off, and only a confirmed take, or marking a result that
    /// was never computed stale so the timers compute it, is written.
    pub async fn review_svs_run(
        &self,
        actor: &Actor,
        uuid: Uuid,
        confirmed_from: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<ReviewOutcome, ServiceError> {
        // the run and the state the sign-off moved it from, for the records written once it committed;
        // a transaction tried again sets it again
        let signed_off: Mutex<Option<(Run, RunState)>> = Mutex::new(None);
        let signed_off = &signed_off;
        let outcome = self
            .gate
            .write(actor, "review_svs_run", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    // after the permission, which the gate checked
                    let (user, name) = person(actor)?;
                    let loaded = find_run(tx.conn(), uuid, true)
                        .await?
                        .ok_or_else(|| unknown_run(uuid))?;
                    let owner = owner_of(tx.conn(), loaded.id, confirmed_from).await?;
                    let owner_name = owner.as_ref().map(|owner| owner.name.clone());
                    let username = username_of(tx.conn(), user).await?;
                    // taking an unowned run happens with the sign-off, so a review that can't go
                    // through takes nothing; one taken from its owner is the person's either way
                    let taken_from = match claim(owner.as_ref(), user) {
                        Claim::Refused(owner) => {
                            return Ok(Audited::unchanged(ReviewOutcome::Owned { owner }));
                        }
                        Claim::Take(from) => {
                            take(tx.conn(), &loaded, user, actor, Some(&from), now).await?;
                            Some(from)
                        }
                        Claim::Mine | Claim::Free => None,
                    };
                    let taken = |outcome: ReviewOutcome, why: &'static str| {
                        Ok::<_, ServiceError>(match &taken_from {
                            Some(from) => Audited::changed(
                                outcome,
                                Change::updated(
                                    Target::svs_run(uuid),
                                    &OwnerRecord {
                                        owner: owner_name.as_deref(),
                                    },
                                    &OwnerRecord {
                                        owner: username.as_deref(),
                                    },
                                )?
                                .details(&ActionRecord {
                                    call: "review",
                                    outcome: why,
                                    reason: None,
                                    taken_from: Some(from),
                                    alerts: None,
                                })?,
                            ),
                            None => Audited::unchanged(outcome),
                        })
                    };
                    let from = loaded.run.state;
                    if !matches!(from, RunState::Ended | RunState::Reviewed) {
                        return taken(ReviewOutcome::State(from), "conflict");
                    }
                    let (found, never_computed) = blockers(tx.conn(), loaded.id, true).await?;
                    if !found.is_empty() {
                        if never_computed {
                            // so the timers compute it, and a review after that goes through
                            mark_stale(tx.conn(), &[loaded.id]).await?;
                            if taken_from.is_none() {
                                return Ok(Audited::changed(
                                    ReviewOutcome::Blocked(found),
                                    Change::noted(
                                        Target::svs_run(uuid),
                                        &ActionRecord {
                                            call: "review",
                                            outcome: "blocked: result marked stale",
                                            reason: None,
                                            taken_from: None,
                                            alerts: None,
                                        },
                                    )?,
                                ));
                            }
                        }
                        return taken(ReviewOutcome::Blocked(found), "blocked");
                    }

                    let unowned = owner.is_none();
                    let counts =
                        crate::svs_results::sign_off(tx.conn(), loaded.id, user, unowned, now)
                            .await?;
                    if unowned {
                        // reviewing a run takes it when nobody owns it
                        add_event(
                            tx.conn(),
                            loaded.id,
                            "ownership_taken",
                            actor,
                            None,
                            None,
                            Some(json!({ "from": null })),
                            now,
                        )
                        .await?;
                    }
                    let re_review = from == RunState::Reviewed;
                    add_event(
                        tx.conn(),
                        loaded.id,
                        "reviewed",
                        actor,
                        Some(from),
                        Some(RunState::Reviewed),
                        Some(json!({ "counts": counts, "re_review": re_review })),
                        now,
                    )
                    .await?;

                    // closing its alerts and the verdicts: a failure never undoes the sign-off
                    let closing = async {
                        let mut inner = tx.savepoint().await?;
                        let alerts = self
                            .close_run_alerts_in(
                                &mut inner,
                                &svs_component(),
                                actor,
                                uuid,
                                false,
                                Some(name),
                                now,
                            )
                            .await?;
                        let targets = ignored_detections(inner.conn(), &loaded).await?;
                        let written = self
                            .write_verdicts_as(
                                &mut inner,
                                actor,
                                false,
                                &targets,
                                Some(Verdict::Fp),
                                &BatchRules::default(),
                            )
                            .await?;
                        inner.commit().await?;
                        Ok::<_, ServiceError>(Closing {
                            alerts,
                            fp_verdicts: written.after.iter().map(|v| v.detection()).collect(),
                        })
                    }
                    .await;
                    let (closing, failed) = match closing {
                        Ok(closing) => (closing, None),
                        Err(error) if error.is_retryable() => return Err(error),
                        Err(error) => {
                            tracing::error!(
                                svs_run = %uuid,
                                "unable to close the alerts of a reviewed svs run: {error}"
                            );
                            (Closing::default(), Some(error.to_string()))
                        }
                    };
                    let reviewed = Reviewed {
                        run: uuid,
                        re_review,
                        counts,
                        alerts_closed: closing
                            .alerts
                            .as_ref()
                            .map_or(0, |alerts| alerts.alerts_closed.len()),
                        fp_verdicts: closing.fp_verdicts.len(),
                    };
                    let taken_from = match (&taken_from, unowned) {
                        (Some(from), _) => Some(Some(from.as_str())),
                        (None, true) => Some(None),
                        (None, false) => None,
                    };
                    let change = Change::updated(
                        Target::svs_run(uuid),
                        &StateRecord { state: from },
                        &StateRecord {
                            state: RunState::Reviewed,
                        },
                    )?
                    .details(&ReviewRecord {
                        call: "review",
                        re_review,
                        counts: &reviewed.counts,
                        taken_from,
                        alerts: closing.alerts.as_ref(),
                        fp_verdicts: &closing.fp_verdicts,
                        closing_failed: failed.as_deref(),
                    })?;
                    *signed_off.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some((loaded.run.clone(), from));
                    Ok(Audited::changed(ReviewOutcome::Reviewed(reviewed), change))
                })
            })
            .await?;
        let signed_off = signed_off
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let (ReviewOutcome::Reviewed(reviewed), Some((run, from))) = (&outcome, signed_off) {
            log_transition(&run, Some(from), RunState::Reviewed, actor, None);
            tracing::info!(
                svs_run = %uuid, svs_test = %run.test_guid, svs_marker = run.marker,
                actor = %actor, counts = %json!(reviewed.counts),
                re_review = reviewed.re_review, alerts_closed = reviewed.alerts_closed,
                fp_verdicts = reviewed.fp_verdicts,
                "svs run reviewed: {} alerts closed, {} ignored detections FP",
                reviewed.alerts_closed, reviewed.fp_verdicts
            );
        }
        Ok(outcome)
    }

    /// What a review of the run would be blocked by right now, for the run page: None for a run that is
    /// neither ended nor reviewed, which can't be reviewed at all. It needs `svs:run_read`; a run that
    /// isn't there is `NotFound`.
    pub async fn svs_review_blockers(
        &self,
        actor: &Actor,
        uuid: Uuid,
    ) -> Result<Option<ReviewBlockers>, ServiceError> {
        self.gate
            .read(actor, "svs_review_blockers", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let run = find_run(tx.conn(), uuid, false)
                        .await?
                        .ok_or_else(|| unknown_run(uuid))?;
                    if !matches!(run.run.state, RunState::Ended | RunState::Reviewed) {
                        return Ok(None);
                    }
                    Ok(Some(blockers(tx.conn(), run.id, false).await?.0))
                })
            })
            .await
    }
}
