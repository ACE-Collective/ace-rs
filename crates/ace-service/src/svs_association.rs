//! SVS's marker router, the closing of test alerts, and a person's changes to which alerts belong to a
//! test run (PLAN.md 7.10 batch 7a): ace3's `saq/svs/routing.py`, `association.py`, the closing half of
//! `runs.py` (`close_run_alerts`, `close_late_alerts`) and of `maintenance.py` (`close_alerts`).
//!
//! # The marker router
//!
//! [`MarkerRouter`] is one of 7.13's routers (`crate::routing::Router`), which `ace::app()` adds as
//! `svs_marker` at priority 100, ahead of the detection-queue router, so a YARA rule with a `queue` meta
//! that matched a dropped test file doesn't take the alert first. It sends an alert whose every detection
//! is attributed to a test run, or that belongs to a test host's maintenance window, to the test queue
//! (`ace_core::svs::SVS_QUEUE`), and sends one it put there back where it came from once that stops
//! holding. A queue a person set through SVS (the router name `svs_manual`) is never overridden: while
//! that is the alert's newest move the router holds it where it is, which also keeps a later router from
//! moving it.
//!
//! It never judges an event (#842). ace3's router evaluates the alert and writes its attributions at both
//! stages; here the core's SVS hook did both at the end of the pass (`ace_core::svs::attribution::judge`),
//! and the router reads `svs.attributions` and `svs.maintenance_alerts` in the routing's transaction, under
//! the root's lock. So ace3's gate has no place here: with nothing registered the hook writes nothing, an
//! alert has no rows, and the router's one query says so.
//!
//! # Closing
//!
//! `Service::run_svs_timers` gives SIMULATED to the alerts of a run it just closed, and to those attributed
//! to a closed run afterwards (the late-alert sweep), and IGNORE to the alerts of a maintenance window:
//! only an OPEN alert nobody has taken, which for a run is fully attributed, checked again under the
//! alert's lock, which disassociating takes too, so an alert disassociated while its run closes is never
//! frozen without a run. SIMULATED is a disposition only ACE sets: the write is `Service::disposition`'s
//! (`disposition_in`), made by the timers' component, in the timers' transaction with the run's
//! `alerts_closed` event. A person's close and a review (`svs_review`, batch 7b) close a run's alerts the
//! same way, as the component `svs`, with the person in the run's event and the audit row. A reviewed
//! run's alerts are its review's to close, never the sweep's.
//!
//! # Association
//!
//! `Service::change_svs_association` (`svs:run_manage`) associates an alert with a run by hand (every
//! detection attributed, as certain as a marker), disassociates it (the hook never attributes it to that
//! run again; **not a test** is the same for an alert the run holds by context alone), or keeps a context
//! attribution. `Service::release_alert_from_svs` (`alert:write`) is the alert's side: it disassociates
//! the alert from every run that holds it. An alert no longer fully attributed goes back to the queue SVS
//! took it from, and one already SIMULATED is given back OPEN, by the component `svs`, since an analyst
//! can't change a frozen alert. Every change appends to the run's event log, marks its result stale and a
//! reviewed run changed since review, and has an audit row.
//!
//! # What differs from ace3
//!
//! - One transaction holds a change: the runs' rows locked in id order, then the alert's, as the hook
//!   locks them, then the attribution rows, the events, the reopen and the move. ace3 commits the
//!   attributions and then moves the alert.
//! - An alert's owner is a user (`analysis.roots.owner_id`). ACE's components own nothing, so a SIMULATED
//!   alert has no owner to give up when it's reopened, where ace3's automation user owned it.
//! - ace3 adds a comment to an alert it closes or reopens; ace4's alerts have no comments, so a closing's
//!   text is in the timers' audit row, and a reopening is in the association's (`reopened`).
//! - A detection is its row's id, not a content hash.
//! - The test queue isn't a setting (`ace_core::svs::SVS_QUEUE`).

use std::collections::BTreeSet;

use ace_core::db::Tx;
use ace_core::svs::attribution;
use ace_core::svs::{AttributionConfidence, MARKER_MISMATCH_SIGNATURE, RunState, SvsStatus};
pub use ace_core::svs::{MANUAL_ROUTER, MARKER_ROUTER, MARKER_ROUTER_PRIORITY, SVS_QUEUE};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::types::Json;
use uuid::Uuid;

use crate::actor::{Actor, Component, UserId};
use crate::alerts::no_alert;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::observables::OPEN;
use crate::permission::{ALERT_WRITE, SVS_RUN_MANAGE};
use crate::routing::{
    Alert, Decision, Queue, RouteFuture, Router, Stage, acting_user, last_queue_change, move_alert,
};
use crate::svs::statuses;
use crate::svs_runs::{Loaded, add_event, locked_run, mark_stale};
use crate::{Service, ServiceError};

/// The disposition of a closed test alert, which only ACE sets.
pub const SIMULATED: &str = "SIMULATED";
/// The disposition of a maintenance window's alert.
pub const IGNORE: &str = "IGNORE";
/// The most alerts one closing takes: ace3's `CLOSE_ALERTS_BATCH`.
pub const CLOSE_ALERTS_BATCH: i64 = 500;
/// The longest reason a person gives: `analysis.queue_changes.reason`'s room, less what's added to it.
pub const MAX_ASSOCIATION_REASON_CHARS: usize = 512;
/// Why an attribution marked not a test was removed: ace3's `REASON_NOT_A_TEST`.
pub const REASON_NOT_A_TEST: &str = "not a test";

/// The component that reopens or closes an alert for a person, and that the hook's rows name.
pub(crate) fn svs_component() -> Actor {
    Actor::Internal {
        id: Component::new(attribution::ROUTER_ACTOR).expect("a valid component name"),
    }
}

fn svs_queue() -> Queue {
    Queue::new(SVS_QUEUE).expect("a valid queue name")
}

//
// the marker router
//

/// SVS's marker router: the module's docs. ace3's `MarkerRouter`.
#[derive(Debug, Clone, Copy, Default)]
pub struct MarkerRouter;

/// What the router reads of an alert.
struct Routing {
    full: bool,
    any: bool,
    mismatch: bool,
    owner_id: Option<Uuid>,
    run: Option<Uuid>,
}

impl MarkerRouter {
    async fn decide(
        alert: &Alert,
        stage: Stage,
        tx: &mut Tx<'_>,
    ) -> Result<Option<Decision>, String> {
        let read = sqlx::query_as!(
            Routing,
            r#"SELECT svs.fully_attributed(o.id) AS "full!",
                      EXISTS (SELECT FROM svs.attributions a
                              WHERE a.root_id = o.id AND a.removed_at IS NULL) AS "any!",
                      EXISTS (SELECT FROM analysis.detections d
                              WHERE d.root_id = o.id AND d.signature_uuid = $2) AS "mismatch!",
                      o.owner_id,
                      (SELECT r.uuid FROM svs.attributions a JOIN svs.runs r ON r.id = a.run_id
                       WHERE a.root_id = o.id AND a.removed_at IS NULL
                       ORDER BY r.id LIMIT 1) AS run
               FROM analysis.roots o WHERE o.id = $1"#,
            alert.root,
            MARKER_MISMATCH_SIGNATURE,
        )
        .fetch_optional(tx.conn())
        .await
        .map_err(|e| e.to_string())?;
        let Some(read) = read else {
            return Ok(None);
        };
        let maintenance = sqlx::query!(
            "SELECT w.uuid, w.host FROM svs.maintenance_alerts m
             JOIN svs.maintenance_windows w ON w.id = m.window_id
             WHERE m.root_id = $1 AND m.removed_at IS NULL
             ORDER BY m.id DESC LIMIT 1",
            alert.root,
        )
        .fetch_optional(tx.conn())
        .await
        .map_err(|e| e.to_string())?;

        let last = alert.last_change.as_ref();
        let routed_here = alert.queue == SVS_QUEUE
            && last.is_some_and(|change| {
                change.router.as_deref() == Some(MARKER_ROUTER) && change.to_queue == SVS_QUEUE
            });
        let (decision, mut outcome) =
            if last.is_some_and(|change| change.router.as_deref() == Some(MANUAL_ROUTER)) {
                (
                    Some(Decision::new(
                        alert.queue.clone(),
                        "queue set by hand in SVS",
                    )?),
                    "held (manual)".to_owned(),
                )
            } else if read.full {
                let run = read.run.map(|run| run.to_string()).unwrap_or_default();
                (
                    Some(Decision::new(
                        SVS_QUEUE,
                        format!("every detection is attributed to SVS test run {run}"),
                    )?),
                    "routed".to_owned(),
                )
            } else if let Some(window) = &maintenance {
                (
                    Some(Decision::new(
                        SVS_QUEUE,
                        format!(
                            "in SVS maintenance window {} on test host {}",
                            window.uuid, window.host
                        ),
                    )?),
                    "maintenance".to_owned(),
                )
            } else if let Some(change) = last.filter(|_| routed_here) {
                (
                    Some(Decision::new(
                        change.from_queue.clone(),
                        "no longer attributed to an SVS test run",
                    )?),
                    "moved back".to_owned(),
                )
            } else if read.any {
                (None, "partial".to_owned())
            } else if read.mismatch {
                (None, "mismatch".to_owned())
            } else {
                // nothing in this alert has to do with a run
                return Ok(None);
            };
        if let Some(decision) = &decision
            && decision.queue.as_str() != alert.queue
        {
            if read.owner_id.is_some() {
                outcome = "not moved because owned".to_owned();
            } else if !alert.is_open() {
                outcome = "not moved because closed".to_owned();
            }
        }
        tracing::info!(
            alert_uuid = %alert.root,
            stage = stage.as_str(),
            decision = outcome,
            queue = decision.as_ref().map(|d| d.queue.as_str()),
            svs_run = read.run.map(|run| run.to_string()),
            svs_maintenance = maintenance.as_ref().map(|w| w.uuid.to_string()),
            "svs router decision on an alert"
        );
        Ok(decision)
    }
}

impl Router for MarkerRouter {
    fn route<'a>(&'a self, alert: &'a Alert, stage: Stage, tx: &'a mut Tx<'_>) -> RouteFuture<'a> {
        Box::pin(MarkerRouter::decide(alert, stage, tx))
    }
}

//
// a person's changes
//

/// A person's change to a run's hold on an alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Association {
    /// Attribute every detection of the alert to the run.
    Associate { reason: Option<String> },
    /// Remove the alert's attributions to the run. `not_a_test` applies only to an alert the run holds by
    /// context alone.
    Disassociate {
        reason: Option<String>,
        not_a_test: bool,
    },
    /// Confirm the alert's context attributions to the run: it is the run's.
    Keep,
}

impl Association {
    fn name(&self) -> &'static str {
        match self {
            Association::Associate { .. } => "associate",
            Association::Disassociate {
                not_a_test: true, ..
            } => "not_a_test",
            Association::Disassociate { .. } => "disassociate",
            Association::Keep => "keep",
        }
    }
}

/// What a change left: ace3's `AssociationResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssociationResult {
    pub alert: Uuid,
    /// The alert's SVS status after the change, None when it has none.
    pub svs_status: Option<SvsStatus>,
    pub queue: String,
    /// The alert moved to another queue.
    pub moved: bool,
    /// The alert was SIMULATED and is OPEN again.
    pub reopened: bool,
}

/// What releasing an alert left: ace3's `AlertDisassociationResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AlertRelease {
    pub alert: Uuid,
    /// The runs the alert was disassociated from, oldest first.
    pub runs: Vec<Uuid>,
    pub svs_status: Option<SvsStatus>,
    pub queue: String,
    pub moved: bool,
    pub reopened: bool,
}

/// The alert's row, locked.
struct AlertRow {
    queue: String,
    disposition: Option<String>,
}

async fn lock_alert(tx: &mut Tx<'_>, alert: Uuid) -> Result<AlertRow, ServiceError> {
    sqlx::query!(
        r#"SELECT queue AS "queue!: String", disposition, alerted_at
           FROM analysis.roots WHERE id = $1 FOR UPDATE"#,
        alert,
    )
    .fetch_optional(tx.conn())
    .await?
    .filter(|row| row.alerted_at.is_some())
    .map(|row| AlertRow {
        queue: row.queue,
        disposition: row.disposition,
    })
    .ok_or_else(|| no_alert(alert))
}

async fn status_of(tx: &mut Tx<'_>, alert: Uuid) -> Result<Option<SvsStatus>, ServiceError> {
    Ok(statuses(tx.conn(), &[alert])
        .await?
        .remove(&alert)
        .map(|status| status.status))
}

fn is_test(status: Option<SvsStatus>) -> bool {
    matches!(status, Some(SvsStatus::Test | SvsStatus::TestContext))
}

fn checked_reason(reason: Option<&str>) -> Result<Option<String>, ServiceError> {
    let reason = reason.map(str::trim).filter(|reason| !reason.is_empty());
    if reason.is_some_and(|reason| {
        reason.chars().count() > MAX_ASSOCIATION_REASON_CHARS || reason.chars().any(|c| c == '\0')
    }) {
        return Err(ServiceError::InvalidRequest(format!(
            "a reason is at most {MAX_ASSOCIATION_REASON_CHARS} characters, with no NUL"
        )));
    }
    Ok(reason.map(str::to_owned))
}

/// What every change to a run's attributions does to the run: a reviewed run is changed since review,
/// and its result is stale. ace3's `_changed`.
async fn changed(tx: &mut Tx<'_>, run: i64) -> Result<(), ServiceError> {
    sqlx::query!(
        "UPDATE svs.runs SET changed_since_review = true
         WHERE id = $1 AND state = 'reviewed' AND NOT changed_since_review",
        run,
    )
    .execute(tx.conn())
    .await?;
    mark_stale(tx.conn(), &[run]).await
}

/// The alert's state for an audit row.
#[derive(Serialize)]
struct AlertState {
    svs_status: Option<SvsStatus>,
    queue: String,
    disposition: Option<String>,
}

impl Recorded for AlertState {}

#[derive(Serialize)]
struct AssociationRecord<'a> {
    action: &'a str,
    runs: &'a [Uuid],
    reason: Option<&'a str>,
    moved: bool,
    reopened: bool,
}

impl Recorded for AssociationRecord<'_> {}

/// What one disassociation did.
struct Released {
    moved: bool,
    reopened: bool,
}

impl Service {
    /// Attributes every detection of the alert to the run, by hand, in the caller's transaction, with the
    /// run's and the alert's rows locked. Returns whether the alert is late for the run.
    async fn associate_in(
        &self,
        tx: &mut Tx<'_>,
        actor: &Actor,
        run: &Loaded,
        alert: Uuid,
        reason: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<(), ServiceError> {
        if run.run.state == RunState::Created {
            return Err(ServiceError::Conflict(format!(
                "run {} never started, so no alert can be its",
                run.run.uuid
            )));
        }
        // judged as the hook judges it: the event's own time, or when it became an alert
        let event = attribution::root_event(tx.conn(), alert)
            .await?
            .ok_or_else(|| no_alert(alert))?;
        let (event_time, source) = (event.time, event.source);
        // a run canceled or timed out before it started has no observation window to be late for
        let late = run
            .run
            .observation_ends_at
            .is_some_and(|ends| event_time > ends);
        let detections: Vec<i64> = sqlx::query_scalar!(
            "INSERT INTO svs.attributions
                 (run_id, root_id, detection_id, confidence, late, event_time, event_time_source,
                  source, scan_point, actor, created_at)
             SELECT $1, $2, d.id, 'marker', $3, $4, $5, 'manual', NULL, $6::jsonb, $7
             FROM analysis.detections d WHERE d.root_id = $2 ORDER BY d.id
             ON CONFLICT ON CONSTRAINT attributions_are_unique DO UPDATE
             SET confidence = 'marker', late = EXCLUDED.late, event_time = EXCLUDED.event_time,
                 event_time_source = EXCLUDED.event_time_source, source = 'manual', scan_point = NULL,
                 actor = EXCLUDED.actor, removed_at = NULL, removed_by = NULL, removal_reason = NULL
             RETURNING detection_id",
            run.id,
            alert,
            late,
            event_time,
            source.as_str(),
            Json(actor) as _,
            now,
        )
        .fetch_all(tx.conn())
        .await?;
        if detections.is_empty() {
            return Err(ServiceError::InvalidRequest(format!(
                "alert {alert} has no detections to attribute"
            )));
        }
        let mut detections = detections;
        detections.sort_unstable();
        add_event(
            tx.conn(),
            run.id,
            "associated",
            actor,
            None,
            None,
            Some(json!({
                "alert_uuid": alert, "detections": detections, "late": late, "reason": reason,
            })),
            now,
        )
        .await?;
        changed(tx, run.id).await?;
        tracing::info!(
            svs_run = %run.run.uuid, alert_uuid = %alert, actor = %actor, late, reason,
            "svs alert associated with a run"
        );
        Ok(())
    }

    /// Removes the alert's attributions to the run, by hand, and gives the alert back when it's no longer
    /// fully attributed: OPEN if it was SIMULATED, and in the queue SVS took it from. In the caller's
    /// transaction, with the run's and the alert's rows locked.
    #[allow(clippy::too_many_arguments)]
    async fn disassociate_in(
        &self,
        tx: &mut Tx<'_>,
        actor: &Actor,
        run: &Loaded,
        alert: Uuid,
        reason: Option<&str>,
        not_a_test: bool,
        now: DateTime<Utc>,
    ) -> Result<Released, ServiceError> {
        let rows = sqlx::query!(
            r#"SELECT id, detection_id, confidence AS "confidence: AttributionConfidence"
               FROM svs.attributions
               WHERE run_id = $1 AND root_id = $2 AND removed_at IS NULL ORDER BY detection_id"#,
            run.id,
            alert,
        )
        .fetch_all(tx.conn())
        .await?;
        if rows.is_empty() {
            return Err(ServiceError::Conflict(format!(
                "alert {alert} is not attributed to run {}",
                run.run.uuid
            )));
        }
        if not_a_test
            && rows
                .iter()
                .any(|row| row.confidence != AttributionConfidence::Context)
        {
            return Err(ServiceError::Conflict(format!(
                "alert {alert} is attributed to run {} by more than context: disassociate it instead",
                run.run.uuid
            )));
        }
        let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
        let detections: Vec<i64> = rows.iter().map(|row| row.detection_id).collect();
        sqlx::query!(
            "UPDATE svs.attributions
             SET removed_at = $2, removed_by = $3::jsonb, removal_reason = $4
             WHERE id = ANY ($1)",
            &ids,
            now,
            Json(actor) as _,
            if not_a_test {
                Some(REASON_NOT_A_TEST)
            } else {
                reason
            },
        )
        .execute(tx.conn())
        .await?;
        add_event(
            tx.conn(),
            run.id,
            "disassociated",
            actor,
            None,
            None,
            Some(json!({
                "alert_uuid": alert, "detections": detections, "reason": reason,
                "not_a_test": not_a_test,
            })),
            now,
        )
        .await?;
        changed(tx, run.id).await?;
        tracing::info!(
            svs_run = %run.run.uuid, alert_uuid = %alert, actor = %actor, reason, not_a_test,
            "svs alert disassociated from a run"
        );

        let status = status_of(tx, alert).await?;
        if is_test(status) {
            // still fully attributed, to another run: it stays a test alert
            return Ok(Released {
                moved: false,
                reopened: false,
            });
        }
        let disposition = sqlx::query_scalar!(
            "SELECT disposition FROM analysis.roots WHERE id = $1",
            alert
        )
        .fetch_one(tx.conn())
        .await?;
        let mut reopened = false;
        if disposition.as_deref() == Some(SIMULATED) {
            // an analyst can't change a frozen alert, so ACE's component writes it; the association's
            // audit row names the person and says the alert was reopened
            self.disposition_in(tx, alert, OPEN, &svs_component(), None)
                .await?;
            reopened = true;
        }
        let moved = match previous_queue(tx, alert).await? {
            Some(previous) => move_alert(
                tx,
                alert,
                &previous,
                &format!("disassociated from SVS test run {}", run.run.uuid),
                Some(MANUAL_ROUTER),
                actor,
                acting_user(actor),
            )
            .await?
            .is_some(),
            None => false,
        };
        Ok(Released { moved, reopened })
    }

    /// A person's change to a run's hold on an alert: the module's docs. It needs `svs:run_manage`. A run
    /// or an alert that isn't there is `NotFound`; a change that doesn't apply to them as they are
    /// (associating with a run that never started, disassociating an alert the run doesn't hold, not a
    /// test on more than context, nothing to keep) is `Conflict`; an alert with no detections, or a reason
    /// over `MAX_ASSOCIATION_REASON_CHARS`, `InvalidRequest`. None of those writes anything.
    pub async fn change_svs_association(
        &self,
        actor: &Actor,
        run: Uuid,
        alert: Uuid,
        change: &Association,
        now: DateTime<Utc>,
    ) -> Result<AssociationResult, ServiceError> {
        let reason = match change {
            Association::Associate { reason } | Association::Disassociate { reason, .. } => {
                checked_reason(reason.as_deref())?
            }
            Association::Keep => None,
        };
        let reason = reason.as_deref();
        self.gate
            .write(actor, "change_svs_association", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let loaded = locked_run(tx.conn(), run).await?;
                    let row = lock_alert(tx, alert).await?;
                    let before = AlertState {
                        svs_status: status_of(tx, alert).await?,
                        queue: row.queue.clone(),
                        disposition: row.disposition.clone(),
                    };
                    let mut moved = false;
                    let mut reopened = false;
                    match change {
                        Association::Associate { .. } => {
                            self.associate_in(tx, actor, &loaded, alert, reason, now)
                                .await?;
                            if is_test(status_of(tx, alert).await?) {
                                moved = move_alert(
                                    tx,
                                    alert,
                                    &svs_queue(),
                                    &format!(
                                        "associated with SVS test run {} by hand",
                                        loaded.run.uuid
                                    ),
                                    Some(MANUAL_ROUTER),
                                    actor,
                                    acting_user(actor),
                                )
                                .await?
                                .is_some();
                            }
                        }
                        Association::Disassociate { not_a_test, .. } => {
                            let released = self
                                .disassociate_in(
                                    tx,
                                    actor,
                                    &loaded,
                                    alert,
                                    reason,
                                    *not_a_test,
                                    now,
                                )
                                .await?;
                            moved = released.moved;
                            reopened = released.reopened;
                        }
                        Association::Keep => {
                            let kept = sqlx::query!(
                                "UPDATE svs.attributions SET kept_at = $3, kept_by = $4::jsonb
                                 WHERE run_id = $1 AND root_id = $2 AND removed_at IS NULL
                                   AND confidence = 'context'",
                                loaded.id,
                                alert,
                                now,
                                Json(actor) as _,
                            )
                            .execute(tx.conn())
                            .await?
                            .rows_affected();
                            if kept == 0 {
                                return Err(ServiceError::Conflict(format!(
                                    "alert {alert} has no context attribution to run {} to keep",
                                    loaded.run.uuid
                                )));
                            }
                            add_event(
                                tx.conn(),
                                loaded.id,
                                "context_kept",
                                actor,
                                None,
                                None,
                                Some(json!({ "alert_uuid": alert })),
                                now,
                            )
                            .await?;
                            tracing::info!(
                                svs_run = %loaded.run.uuid, alert_uuid = %alert, actor = %actor,
                                "svs context attribution kept"
                            );
                        }
                    }
                    let after = lock_alert(tx, alert).await?;
                    let result = AssociationResult {
                        alert,
                        svs_status: status_of(tx, alert).await?,
                        queue: after.queue.clone(),
                        moved,
                        reopened,
                    };
                    let audit = Change::updated(
                        Target::root(alert),
                        &before,
                        &AlertState {
                            svs_status: result.svs_status,
                            queue: after.queue,
                            disposition: after.disposition,
                        },
                    )?
                    .details(&AssociationRecord {
                        action: change.name(),
                        runs: &[loaded.run.uuid],
                        reason,
                        moved,
                        reopened,
                    })?;
                    Ok(Audited::changed(result, audit))
                })
            })
            .await
    }

    /// Disassociates the alert from every run that holds it, oldest run first, so it's given back to
    /// analysts: ace3's `disassociate_alert`. `not_a_test` applies only to a `test?` alert, which its runs
    /// hold by context alone. It needs `alert:write`. An alert that isn't there is `NotFound`; one nothing
    /// holds, or `not_a_test` on an alert a marker or a person attributed, `Conflict`.
    pub async fn release_alert_from_svs(
        &self,
        actor: &Actor,
        alert: Uuid,
        reason: Option<&str>,
        not_a_test: bool,
        now: DateTime<Utc>,
    ) -> Result<AlertRelease, ServiceError> {
        let reason = checked_reason(reason)?;
        let reason = reason.as_deref();
        self.gate
            .write(actor, "release_alert_from_svs", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    // the runs first, in id order, as the hook locks them, then the alert
                    let runs = sqlx::query!(
                        "SELECT r.id, r.uuid FROM svs.runs r
                         WHERE EXISTS (SELECT FROM svs.attributions a
                                       WHERE a.run_id = r.id AND a.root_id = $1
                                         AND a.removed_at IS NULL)
                         ORDER BY r.id FOR UPDATE OF r",
                        alert,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let row = lock_alert(tx, alert).await?;
                    let nothing = || {
                        ServiceError::Conflict(format!(
                            "alert {alert} is not attributed to any test run"
                        ))
                    };
                    if runs.is_empty() {
                        return Err(nothing());
                    }
                    let before = AlertState {
                        svs_status: status_of(tx, alert).await?,
                        queue: row.queue.clone(),
                        disposition: row.disposition.clone(),
                    };
                    if not_a_test && before.svs_status != Some(SvsStatus::TestContext) {
                        return Err(ServiceError::Conflict(format!(
                            "alert {alert} is not test? (attributed by context only): disassociate it instead"
                        )));
                    }
                    let mut done = Vec::new();
                    let mut moved = false;
                    let mut reopened = false;
                    for run in runs {
                        let loaded = locked_run(tx.conn(), run.uuid).await?;
                        match self
                            .disassociate_in(tx, actor, &loaded, alert, reason, not_a_test, now)
                            .await
                        {
                            Ok(released) => {
                                done.push(run.uuid);
                                moved |= released.moved;
                                reopened |= released.reopened;
                            }
                            // a change that committed while this waited for the locks released it first
                            Err(ServiceError::Conflict(why)) => {
                                tracing::info!(
                                    svs_run = %run.uuid, alert_uuid = %alert,
                                    "svs alert was no longer held by a run: {why}"
                                );
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    if done.is_empty() {
                        return Err(nothing());
                    }
                    let after = lock_alert(tx, alert).await?;
                    let result = AlertRelease {
                        alert,
                        runs: done,
                        svs_status: status_of(tx, alert).await?,
                        queue: after.queue.clone(),
                        moved,
                        reopened,
                    };
                    let audit = Change::updated(
                        Target::root(alert),
                        &before,
                        &AlertState {
                            svs_status: result.svs_status,
                            queue: after.queue,
                            disposition: after.disposition,
                        },
                    )?
                    .details(&AssociationRecord {
                        action: if not_a_test {
                            "not_a_test"
                        } else {
                            "disassociate"
                        },
                        runs: &result.runs,
                        reason,
                        moved,
                        reopened,
                    })?;
                    Ok(Audited::changed(result, audit))
                })
            })
            .await
    }

    /// Makes `owner` the alert's owner, or nobody with None: ace3's `change_alert_owner`, without its
    /// confirmation to take an alert from someone. It needs `alert:write`. Returns who owned it before. An
    /// alert that isn't there is `NotFound`, and so is a user who isn't; an alert already theirs writes
    /// nothing.
    pub async fn set_alert_owner(
        &self,
        actor: &Actor,
        alert: Uuid,
        owner: Option<UserId>,
    ) -> Result<Option<UserId>, ServiceError> {
        self.gate
            .write(actor, "set_alert_owner", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let row = sqlx::query!(
                        "SELECT owner_id, alerted_at FROM analysis.roots WHERE id = $1 FOR UPDATE",
                        alert,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .filter(|row| row.alerted_at.is_some())
                    .ok_or_else(|| no_alert(alert))?;
                    let before = row.owner_id.map(UserId);
                    if before == owner {
                        return Ok(Audited::unchanged(before));
                    }
                    if let Some(owner) = owner {
                        let known = sqlx::query_scalar!(
                            r#"SELECT EXISTS (SELECT FROM service.users WHERE id = $1) AS "known!""#,
                            owner.0,
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        if !known {
                            return Err(ServiceError::NoUser(owner.0));
                        }
                    }
                    sqlx::query!(
                        "UPDATE analysis.roots
                         SET owner_id = $2, owned_at = CASE WHEN $2::uuid IS NULL THEN NULL ELSE now() END
                         WHERE id = $1",
                        alert,
                        owner.map(|owner| owner.0),
                    )
                    .execute(tx.conn())
                    .await?;
                    let change = Change::updated(
                        Target::root(alert),
                        &OwnerRecord {
                            owner: before.map(|owner| owner.0),
                        },
                        &OwnerRecord {
                            owner: owner.map(|owner| owner.0),
                        },
                    )?;
                    Ok(Audited::changed(before, change))
                })
            })
            .await
    }
}

#[derive(Serialize)]
struct OwnerRecord {
    owner: Option<Uuid>,
}

impl Recorded for OwnerRecord {}

/// The queue the alert came from when SVS put it in the test queue: the alert's newest move, when that
/// was into the test queue by the marker router or a person through SVS, and the alert is still there.
/// ace3's `_previous_queue`.
async fn previous_queue(tx: &mut Tx<'_>, alert: Uuid) -> Result<Option<Queue>, ServiceError> {
    let Some(change) = last_queue_change(tx, alert).await? else {
        return Ok(None);
    };
    let by_svs = matches!(
        change.router.as_deref(),
        Some(MARKER_ROUTER | MANUAL_ROUTER)
    );
    if change.to_queue != SVS_QUEUE || !by_svs {
        return Ok(None);
    }
    Queue::new(change.from_queue)
        .map(Some)
        .map_err(ServiceError::InvalidRequest)
}

//
// closing
//

/// What closing a run's alerts did, for the timers' audit row.
#[derive(Serialize)]
pub(crate) struct AlertsClosed {
    pub(crate) alerts_closed: Vec<Uuid>,
    pub(crate) left_alone: Vec<Uuid>,
    pub(crate) disposition: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) late: Option<bool>,
    pub(crate) comment: String,
}

impl Recorded for AlertsClosed {}

/// The closed runs that have an alert the sweep can close: fully attributed, open and nobody's. ace3's
/// `close_late_alerts`' choice, by run, oldest first, so an alert of two closed runs closes with the older.
pub(crate) async fn runs_with_late_alerts(
    tx: &mut Tx<'_>,
    limit: i64,
) -> Result<Vec<Uuid>, ServiceError> {
    Ok(sqlx::query_scalar!(
        "SELECT r.uuid FROM svs.runs r
         WHERE r.state = 'closed' AND r.id IN (
             SELECT a.run_id FROM analysis.roots o
             JOIN svs.attributions a ON a.root_id = o.id AND a.removed_at IS NULL
             WHERE o.alerted_at IS NOT NULL AND (o.disposition IS NULL OR o.disposition = 'OPEN')
               AND o.owner_id IS NULL AND svs.fully_attributed(o.id))
         ORDER BY r.id LIMIT $1",
        limit,
    )
    .fetch_all(tx.conn())
    .await?)
}

/// The maintenance windows with a record that stands: ace3's `close_alerts`' choice, by window.
pub(crate) async fn windows_with_standing_alerts(
    tx: &mut Tx<'_>,
    limit: i64,
) -> Result<Vec<i64>, ServiceError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT DISTINCT window_id AS "window_id!" FROM svs.maintenance_alerts
           WHERE removed_at IS NULL AND closed_at IS NULL ORDER BY 1 LIMIT $1"#,
        limit,
    )
    .fetch_all(tx.conn())
    .await?)
}

impl Service {
    /// Gives SIMULATED to the run's alerts: those fully attributed, open and not taken by an analyst,
    /// judged again under each alert's lock. In the caller's transaction, with the run's `alerts_closed`
    /// event. ace3's `close_run_alerts`, with `late` the sweep's part for one run, and with `reviewed`
    /// its `close_reviewed_run_alerts`. `by` is the component the alerts' rows name, since SIMULATED is a
    /// disposition only ACE sets, and `who` is who the event names: the timers for both, or `svs` and the
    /// person who closed or reviewed the run. Nothing is learned from the alerts of a run that isn't
    /// reviewed: they have no verdicts and no capture. None when there was nothing to close.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn close_run_alerts_in(
        &self,
        tx: &mut Tx<'_>,
        by: &Actor,
        who: &Actor,
        run: Uuid,
        late: bool,
        reviewed: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<AlertsClosed>, ServiceError> {
        let loaded = locked_run(tx.conn(), run).await?;
        // chosen and locked in id order; a disposition, a take or a disassociation that commits while
        // this waits for a lock is seen by the check after it
        let chosen = sqlx::query_scalar!(
            "SELECT o.id FROM analysis.roots o
             WHERE o.alerted_at IS NOT NULL AND (o.disposition IS NULL OR o.disposition = 'OPEN')
               AND o.owner_id IS NULL
               AND EXISTS (SELECT FROM svs.attributions a
                           WHERE a.run_id = $1 AND a.root_id = o.id AND a.removed_at IS NULL)
               AND svs.fully_attributed(o.id)
             ORDER BY o.id LIMIT $2 FOR UPDATE OF o",
            loaded.id,
            CLOSE_ALERTS_BATCH,
        )
        .fetch_all(tx.conn())
        .await?;
        if chosen.is_empty() {
            return Ok(None);
        }
        let still: BTreeSet<Uuid> = sqlx::query_scalar!(
            "SELECT o.id FROM analysis.roots o
             WHERE o.id = ANY ($2) AND (o.disposition IS NULL OR o.disposition = 'OPEN')
               AND o.owner_id IS NULL
               AND EXISTS (SELECT FROM svs.attributions a
                           WHERE a.run_id = $1 AND a.root_id = o.id AND a.removed_at IS NULL)
               AND svs.fully_attributed(o.id)",
            loaded.id,
            &chosen,
        )
        .fetch_all(tx.conn())
        .await?
        .into_iter()
        .collect();
        let comment = match reviewed {
            Some(reviewer) => format!("reviewed with SVS test run {run} by {reviewer}"),
            None => format!("closed with SVS test run {run}"),
        };
        let mut closed = Vec::new();
        let mut left_alone = Vec::new();
        for alert in chosen {
            if !still.contains(&alert) {
                left_alone.push(alert);
                continue;
            }
            self.disposition_in(tx, alert, SIMULATED, by, Some(&comment))
                .await?;
            closed.push(alert);
        }
        if !closed.is_empty() {
            add_event(
                tx.conn(),
                loaded.id,
                "alerts_closed",
                who,
                None,
                None,
                Some(json!({
                    "alerts": closed, "disposition": SIMULATED, "late": late,
                    "reviewed": reviewed.is_some(),
                })),
                now,
            )
            .await?;
        }
        tracing::info!(
            svs_run = %run, alert_uuids = ?closed, left_alone = ?left_alone, late, actor = %who,
            "svs run: {} {}alerts closed as {SIMULATED}, {} left alone",
            closed.len(),
            if late { "late " } else { "" },
            left_alone.len()
        );
        if closed.is_empty() {
            return Ok(None);
        }
        Ok(Some(AlertsClosed {
            alerts_closed: closed,
            left_alone,
            disposition: SIMULATED,
            late: Some(late),
            comment,
        }))
    }

    /// Closes, as IGNORE, the open alerts nobody has taken that the hook recorded for the maintenance
    /// window. One an analyst took, dispositioned or associated with a run meanwhile is left alone.
    /// Either way its record is closed, so it isn't looked at again. ace3's `_close_window_alerts`. In the
    /// caller's transaction, as `by`. Returns the window's uuid with what it did, or None when no record
    /// stands.
    pub(crate) async fn close_maintenance_alerts_in(
        &self,
        tx: &mut Tx<'_>,
        by: &Actor,
        window: i64,
        now: DateTime<Utc>,
    ) -> Result<Option<(Uuid, AlertsClosed)>, ServiceError> {
        let Some(found) = sqlx::query!(
            "SELECT uuid, host, reason FROM svs.maintenance_windows WHERE id = $1",
            window,
        )
        .fetch_optional(tx.conn())
        .await?
        else {
            return Ok(None);
        };
        let standing = sqlx::query_scalar!(
            "SELECT root_id FROM svs.maintenance_alerts
             WHERE window_id = $1 AND removed_at IS NULL AND closed_at IS NULL
             ORDER BY root_id LIMIT $2",
            window,
            CLOSE_ALERTS_BATCH,
        )
        .fetch_all(tx.conn())
        .await?;
        if standing.is_empty() {
            return Ok(None);
        }
        sqlx::query!(
            "SELECT id FROM analysis.roots WHERE id = ANY ($1) ORDER BY id FOR UPDATE",
            &standing,
        )
        .fetch_all(tx.conn())
        .await?;
        // under the alerts' locks, which the hook and an association take too: the record still stands,
        // and no person associated the alert with a run
        let eligible: BTreeSet<Uuid> = sqlx::query_scalar!(
            "SELECT o.id FROM analysis.roots o
             WHERE o.id = ANY ($2) AND (o.disposition IS NULL OR o.disposition = 'OPEN')
               AND o.owner_id IS NULL
               AND EXISTS (SELECT FROM svs.maintenance_alerts m
                           WHERE m.window_id = $1 AND m.root_id = o.id
                             AND m.removed_at IS NULL AND m.closed_at IS NULL)
               AND NOT EXISTS (SELECT FROM svs.attributions a
                               WHERE a.root_id = o.id AND a.removed_at IS NULL)",
            window,
            &standing,
        )
        .fetch_all(tx.conn())
        .await?
        .into_iter()
        .collect();
        let comment = format!(
            "closed: SVS maintenance window {} on test host {}: {}",
            found.uuid, found.host, found.reason
        );
        let mut closed = Vec::new();
        let mut left_alone = Vec::new();
        for alert in &standing {
            if !eligible.contains(alert) {
                left_alone.push(*alert);
                continue;
            }
            self.disposition_in(tx, *alert, IGNORE, by, Some(&comment))
                .await?;
            closed.push(*alert);
            tracing::info!(
                svs_maintenance = %found.uuid, host = found.host, alert_uuid = %alert,
                "svs maintenance window: alert closed as {IGNORE}"
            );
        }
        // a record the hook removed meanwhile stays open to it
        sqlx::query!(
            "UPDATE svs.maintenance_alerts SET closed_at = $3
             WHERE window_id = $1 AND root_id = ANY ($2) AND removed_at IS NULL AND closed_at IS NULL",
            window,
            &standing,
            now,
        )
        .execute(tx.conn())
        .await?;
        if !left_alone.is_empty() {
            tracing::info!(
                svs_maintenance = %found.uuid, host = found.host, alert_uuids = ?left_alone,
                "svs maintenance window: {} alerts left alone (taken, dispositioned or associated with a run by an analyst, or no longer judged maintenance)",
                left_alone.len()
            );
        }
        Ok(Some((
            found.uuid,
            AlertsClosed {
                alerts_closed: closed,
                left_alone,
                disposition: IGNORE,
                late: None,
                comment,
            },
        )))
    }
}
