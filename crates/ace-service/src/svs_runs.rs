//! SVS test runs (PLAN.md 7.10 batch 5, part 5a): ace3's `saq/svs/runs.py`, `refusals.py` and
//! `maintenance.py`. The model is `ace_core::svs::runs`.
//!
//! **A run's life.** A launcher registers a run for one catalog test against one or more test hosts
//! ([`Service::register_svs_run`]), gets its marker, starts it, may report how the test executed and when its
//! cleanup began, and may cancel it, each under `svs:run_register`. [`Service::validate_svs_run`] decides a
//! registration as registering would and only reads. [`Service::run_svs_timers`] moves runs on by time,
//! under `svs:run_timers`, which only the scheduler's `svs_run_timers` holds: a run never started goes to
//! error and is closed, a started run ends when its observation window passes, and a canceled or failed run
//! is closed when its attribution window passes. A person ends a started run early with
//! [`Service::end_svs_run`], under `svs:run_manage`; taking, reviewing, canceling and closing a run by hand
//! are `svs_review`'s (batch 7b). The timers also close alerts: SIMULATED for those of a run they close and those
//! attributed to a closed run afterwards, IGNORE for a maintenance window's (`svs_association`, batch 7a).
//!
//! Every change of state is one transaction that locks the run's row, checks the state it found and
//! appends the transition to the run's event log, so a timer that fires twice, or a launcher's call racing
//! a timer, changes the run once. A launcher's call that doesn't apply is recorded in the event log too,
//! and answered with `Conflict`.
//!
//! **One run per test host.** A run holds its hosts from registration until its claim ends, and a
//! maintenance window holds its host until it ends ([`HostHolder`]). Registration, start and opening a
//! window lock the hosts' rows in id order and then look for holders, so two of them on one host are
//! decided one at a time.
//!
//! **Refusals.** A registration against a host that isn't a test host, or as a user the host doesn't
//! list, is `Forbidden` and makes an alert in the default queue with the built-in
//! `REGISTRATION_REFUSED_SIGNATURE` detection, one per caller, host and hour (`svs.registration_refusals`).
//!
//! **Maintenance windows.** A launcher opens a window on a test host before it stages something there and
//! ends it afterwards; the timers expire one it never ends, and removing the host ends its window.
//!
//! What differs from ace3's:
//! - The windows' lengths come from the hunts the hunter recorded (`ace_core::svs::windows`' docs), read in
//!   the registration's own transaction.
//! - A refusal's row and its alert are written in the registration's transaction, the alert in a savepoint:
//!   if the alert can't be made the row stays without one and the call is refused all the same, as in ace3,
//!   but a row is never committed before its alert, so a crash between the two can't leave an hour with a
//!   row and no alert. The alert's detection is on the refused host's observable, since a root has no
//!   detections of its own here. The caller is keyed by its identity (`api_key:<id>`), which a rename
//!   doesn't change, where ace3 keys on the name.
//! - Each write has an audit row, where ace3 logs a launcher's calls and audits only the maintenance
//!   windows. The timers act as `scheduler:svs_run_timers`, which a transition's event names, where ace3's
//!   says `svs`.
//! - `extra` is measured as compact JSON, where ace3 measures Python's spaced form, so the same limit
//!   admits slightly more.
//! - The alerts of a run the timers close, and of a maintenance window, are closed by the timers' own
//!   steps after the close commits (`svs_association`, batch 7a), and a person's close and a review close
//!   theirs in the same transaction (`svs_review`, batch 7b).
//! - Registering a run and opening a maintenance window take the lock that orders them against a pass
//!   that is ending on a closed attribution gate (`ace_core::svs::attribution`'s *The gate*).
//! - A run's result is computed as it ends (`svs_results`): by the timers in a transaction of its own
//!   after the end's, and by a person's end in a savepoint of the end's transaction, so in both a
//!   computation that fails leaves the end, and the run stale for the timers' next pass. Each pass of the
//!   timers also recomputes the stale results of ended and reviewed runs.

use std::collections::BTreeSet;

use ace_core::submit::{Origin, Submission};
use ace_core::svs::REGISTRATION_REFUSED_SIGNATURE;
use ace_core::svs::RunState;
use ace_core::svs::hosts::{
    MatchedHost, TargetMatch, match_target, normalize_username, repr, split_hostname,
};
use ace_core::svs::markers::new_marker;
use ace_core::svs::runs::{
    self, CALL_CANCEL, CALL_CLEANUP, CALL_EXECUTED, CALL_START, CLOSE_REASON_ATTRIBUTION_ENDED,
    CLOSE_REASON_CANCELED_BEFORE_START, CLOSE_REASON_START_TIMEOUT, HOLDER_MAINTENANCE, HostHolder,
    HostPlatform, OUTCOME_HOST_BUSY, ObservationSource, Registration, RunsConfig, TIMER_BATCH,
    TargetSpec, host_busy_message, whole_second,
};
use ace_core::svs::signatures::FAMILY_BUILTIN;
use ace_core::svs::windows::{
    attribution_window, hunt_latencies, observation_window, recorded_hunts,
};
use ace_results::{Detection, NewObservable, ObservableKind};
use chrono::{DateTime, DurationRound, TimeDelta, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::PgConnection;
use sqlx::types::Json;
use uuid::Uuid;

use crate::alerts::RecordedActor;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SVS_RUN_MANAGE, SVS_RUN_READ, SVS_RUN_REGISTER, SVS_RUN_TIMERS};
use crate::{Actor, Service, ServiceError};

/// The alert type and tool of a refusal's alert: ace3's `ALERT_TYPE` and `TOOL`.
pub const REFUSAL_ALERT_TYPE: &str = "svs - registration refused";
pub const REFUSAL_TOOL: &str = "svs";
/// Refusal rows are only needed for the hour they collapse; the run timers remove older ones.
const REFUSAL_RETENTION: TimeDelta = TimeDelta::days(1);
/// The most events of a run one read gives.
pub const MAX_RUN_EVENTS_PAGE: i64 = 1000;
/// The most maintenance windows one read gives.
pub const MAX_MAINTENANCE_PAGE: i64 = 1000;

/// A host and user a run targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunTarget {
    /// As the launcher sent them.
    pub hostname: String,
    pub username: Option<String>,
    /// Normalized: the short name, the fully qualified one, and the bare user name, lower case.
    pub host: String,
    pub fqdn: Option<String>,
    pub user: Option<String>,
}

/// A test run, as it's stored, without what its test printed (`RunDetail`).
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    pub uuid: Uuid,
    pub test_guid: Uuid,
    pub platform: String,
    pub test_content_hash: String,
    pub catalog_commit: String,
    pub state: RunState,
    pub marker: String,
    pub launcher: String,
    pub batch_id: Option<String>,
    pub extra: Value,
    pub registered_by: Option<RecordedActor>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub executed_at: Option<DateTime<Utc>>,
    pub cleanup_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub launcher_error: Option<String>,
    pub ended_at: Option<DateTime<Utc>>,
    pub end_reason: Option<String>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub close_reason: Option<String>,
    pub error_reason: Option<String>,
    pub observation_seconds: i32,
    pub attribution_seconds: i32,
    pub observation_ends_at: Option<DateTime<Utc>>,
    pub attribution_ends_at: Option<DateTime<Utc>>,
    pub holds_host: bool,
    /// What its registration warned of: `ace_core::svs::runs::no_hunts_warning`.
    pub warnings: Vec<String>,
    pub updated_at: DateTime<Utc>,
    pub targets: Vec<RunTarget>,
}

/// A run with what its test printed, as the launcher reported it.
#[derive(Debug, Clone, PartialEq)]
pub struct RunDetail {
    pub run: Run,
    pub launcher_output: Option<String>,
}

/// One row of a run's event log.
#[derive(Debug, Clone, PartialEq)]
pub struct RunEvent {
    pub id: i64,
    /// `ace_core::svs::RunEventKind`, in snake case.
    pub kind: String,
    pub from_state: Option<RunState>,
    pub to_state: Option<RunState>,
    pub actor: Option<RecordedActor>,
    pub details: Option<Value>,
    pub created_at: DateTime<Utc>,
}

/// What registering would decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationDecision {
    Accepted,
    Refused,
    Invalid,
    HostBusy,
}

/// A target of a registration, judged as registering would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTarget {
    pub hostname: String,
    pub username: Option<String>,
    /// The target is a test host and a user it lists.
    pub accepted: bool,
    /// Why it would be refused.
    pub reason: Option<String>,
    /// The test host it names, by its short name, and that host's platform.
    pub test_host: Option<String>,
    pub platform: Option<String>,
    /// What holds that test host.
    pub held_by: Vec<HostHolder>,
}

/// What registering a body would decide, decided without changing anything: ace3's `RunValidation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunValidation {
    pub decision: RegistrationDecision,
    /// Why the registration is invalid.
    pub message: Option<String>,
    /// Every target; empty when the registration is invalid before its targets are judged.
    pub targets: Vec<ValidatedTarget>,
    /// When accepted: the run's platform, its windows and where its observation window comes from.
    pub platform: Option<String>,
    pub observation_seconds: Option<i64>,
    pub observation_source: Option<ObservationSource>,
    pub attribution_seconds: Option<i64>,
    pub holds_host: Option<bool>,
    /// What registering would warn of: `ace_core::svs::runs::no_hunts_warning`.
    pub warnings: Vec<String>,
}

/// What one pass of the timers did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TimerResult {
    /// Runs never started: created to error to closed.
    pub timed_out: u64,
    /// Started runs whose observation window passed.
    pub ended: u64,
    /// Canceled and failed runs whose attribution window passed.
    pub closed: u64,
    /// Maintenance windows whose time passed.
    pub expired_windows: u64,
    /// Alerts given SIMULATED with the run the timers just closed.
    pub alerts_closed: u64,
    /// Alerts given SIMULATED that were attributed to a run after it closed: the late-alert sweep.
    pub late_alerts_closed: u64,
    /// Alerts of maintenance windows given IGNORE.
    pub maintenance_alerts_closed: u64,
    /// Stale results of ended and reviewed runs computed again.
    pub results_computed: u64,
    pub pruned_refusals: u64,
    /// Moves that failed; each is logged, and the next pass tries it again.
    pub failed: u64,
    /// Why the first of them failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_error: Option<String>,
}

/// A maintenance window on a test host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceWindow {
    pub id: i64,
    pub uuid: Uuid,
    /// The test host's id; None once the host is removed.
    pub test_host_id: Option<i64>,
    pub host: String,
    pub fqdn: Option<String>,
    pub reason: String,
    pub opened_by: Option<RecordedActor>,
    pub opened_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub ended_by: Option<RecordedActor>,
    /// `ended` or `expired`.
    pub end_reason: Option<String>,
    pub updated_at: DateTime<Utc>,
}

pub(crate) fn unknown_run(uuid: Uuid) -> ServiceError {
    ServiceError::NotFound(format!("run {uuid} not found"))
}

pub(crate) fn state_conflict(uuid: Uuid, state: RunState, call: &str) -> ServiceError {
    ServiceError::Conflict(format!("run {uuid} is {state}; {call} does not apply"))
}

pub(crate) fn decode<T>(what: &str, value: Option<T>) -> Result<T, ServiceError> {
    value.ok_or_else(|| ServiceError::from(ace_core::DbError::Decode(format!("a stored {what}"))))
}

fn state_of(text: &str) -> Result<RunState, ServiceError> {
    decode("run state", RunState::parse(text))
}

/// The name an actor is known by, for a refusal's alert: ace3's `Caller.name`.
fn caller_name(actor: &Actor) -> String {
    match actor {
        Actor::User { name, .. } | Actor::ApiKey { name, .. } => name.clone(),
        Actor::Internal { id } => id.as_str().to_owned(),
    }
}

struct RunRow {
    id: i64,
    uuid: Uuid,
    test_guid: Uuid,
    platform: String,
    test_content_hash: String,
    catalog_commit: String,
    state: String,
    marker: String,
    launcher: String,
    batch_id: Option<String>,
    extra: Value,
    registered_by: Option<Value>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    executed_at: Option<DateTime<Utc>>,
    cleanup_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    launcher_error: Option<String>,
    ended_at: Option<DateTime<Utc>>,
    end_reason: Option<String>,
    canceled_at: Option<DateTime<Utc>>,
    closed_at: Option<DateTime<Utc>>,
    close_reason: Option<String>,
    error_reason: Option<String>,
    observation_seconds: i32,
    attribution_seconds: i32,
    observation_ends_at: Option<DateTime<Utc>>,
    attribution_ends_at: Option<DateTime<Utc>>,
    holds_host: bool,
    warnings: Vec<String>,
    updated_at: DateTime<Utc>,
}

/// A run and its row's id, which the writes need.
pub(crate) struct Loaded {
    pub(crate) id: i64,
    pub(crate) run: Run,
}

/// The run, with its row locked when `lock`, or None when there's none.
pub(crate) async fn find_run(
    conn: &mut PgConnection,
    uuid: Uuid,
    lock: bool,
) -> Result<Option<Loaded>, ServiceError> {
    if lock {
        sqlx::query_scalar!("SELECT id FROM svs.runs WHERE uuid = $1 FOR UPDATE", uuid)
            .fetch_optional(&mut *conn)
            .await?;
    }
    let Some(row) = sqlx::query_as!(
        RunRow,
        r#"SELECT id, uuid, test_guid, platform, test_content_hash, catalog_commit,
                  state::text AS "state!", marker, launcher, batch_id, extra,
                  registered_by AS "registered_by: Value", created_at, started_at, executed_at,
                  cleanup_at, exit_code, launcher_error, ended_at, end_reason, canceled_at, closed_at,
                  close_reason, error_reason, observation_seconds, attribution_seconds,
                  observation_ends_at, attribution_ends_at, holds_host, warnings, updated_at
           FROM svs.runs WHERE uuid = $1"#,
        uuid,
    )
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let targets = sqlx::query_as!(
        RunTarget,
        r#"SELECT hostname, username, host, fqdn, "user" FROM svs.run_targets
           WHERE run_id = $1 ORDER BY id"#,
        row.id,
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(Some(Loaded {
        id: row.id,
        run: Run {
            uuid: row.uuid,
            test_guid: row.test_guid,
            platform: row.platform,
            test_content_hash: row.test_content_hash,
            catalog_commit: row.catalog_commit,
            state: state_of(&row.state)?,
            marker: row.marker,
            launcher: row.launcher,
            batch_id: row.batch_id,
            extra: row.extra,
            registered_by: RecordedActor::from_row(row.registered_by)?,
            created_at: row.created_at,
            started_at: row.started_at,
            executed_at: row.executed_at,
            cleanup_at: row.cleanup_at,
            exit_code: row.exit_code,
            launcher_error: row.launcher_error,
            ended_at: row.ended_at,
            end_reason: row.end_reason,
            canceled_at: row.canceled_at,
            closed_at: row.closed_at,
            close_reason: row.close_reason,
            error_reason: row.error_reason,
            observation_seconds: row.observation_seconds,
            attribution_seconds: row.attribution_seconds,
            observation_ends_at: row.observation_ends_at,
            attribution_ends_at: row.attribution_ends_at,
            holds_host: row.holds_host,
            warnings: row.warnings,
            updated_at: row.updated_at,
            targets,
        },
    }))
}

pub(crate) async fn locked_run(
    conn: &mut PgConnection,
    uuid: Uuid,
) -> Result<Loaded, ServiceError> {
    find_run(conn, uuid, true)
        .await?
        .ok_or_else(|| unknown_run(uuid))
}

/// Appends a row to a run's event log.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn add_event(
    conn: &mut PgConnection,
    run: i64,
    kind: &str,
    actor: &Actor,
    from: Option<RunState>,
    to: Option<RunState>,
    details: Option<Value>,
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    sqlx::query!(
        "INSERT INTO svs.run_events (run_id, kind, from_state, to_state, actor, details, created_at)
         VALUES ($1, $2, $3::text::svs.run_state, $4::text::svs.run_state, $5::jsonb, $6, $7)",
        run,
        kind,
        from.map(RunState::as_str),
        to.map(RunState::as_str),
        Json(actor) as _,
        details,
        now,
    )
    .execute(conn)
    .await?;
    Ok(())
}

/// Records a launcher's call in the run's event log.
async fn launcher_call(
    conn: &mut PgConnection,
    run: i64,
    actor: &Actor,
    call: &str,
    outcome: &str,
    payload: Value,
    now: DateTime<Utc>,
) -> Result<(), ServiceError> {
    let details = json!({"call": call, "outcome": outcome, "payload": payload});
    add_event(
        conn,
        run,
        "launcher_call",
        actor,
        None,
        None,
        Some(details),
        now,
    )
    .await
}

/// What a transition sets besides the state; None leaves a column as it is.
#[derive(Default)]
pub(crate) struct Values<'a> {
    pub(crate) started_at: Option<DateTime<Utc>>,
    pub(crate) observation_ends_at: Option<DateTime<Utc>>,
    pub(crate) attribution_ends_at: Option<DateTime<Utc>>,
    pub(crate) executed_at: Option<DateTime<Utc>>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) launcher_error: Option<&'a str>,
    pub(crate) launcher_output: Option<&'a str>,
    pub(crate) error_reason: Option<&'a str>,
    pub(crate) canceled_at: Option<DateTime<Utc>>,
    pub(crate) closed_at: Option<DateTime<Utc>>,
    pub(crate) close_reason: Option<&'a str>,
    pub(crate) ended_at: Option<DateTime<Utc>>,
    pub(crate) end_reason: Option<&'a str>,
}

/// Moves the run from `from` to `to`, with `values`, and appends the transition to its event log: ace3's
/// `_transition`. False, changing nothing, when the run isn't in `from`. `from` and `to` may be the same,
/// for a call that only records values, which writes no transition event.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn transition(
    conn: &mut PgConnection,
    run: i64,
    from: RunState,
    to: RunState,
    actor: &Actor,
    values: Values<'_>,
    reason: Option<&str>,
    now: DateTime<Utc>,
) -> Result<bool, ServiceError> {
    let moved = sqlx::query!(
        "UPDATE svs.runs SET
             state = $3::text::svs.run_state,
             started_at = COALESCE($4, started_at),
             observation_ends_at = COALESCE($5, observation_ends_at),
             attribution_ends_at = COALESCE($6, attribution_ends_at),
             executed_at = COALESCE($7, executed_at),
             exit_code = COALESCE($8, exit_code),
             launcher_error = COALESCE($9, launcher_error),
             launcher_output = COALESCE($10, launcher_output),
             error_reason = COALESCE($11, error_reason),
             canceled_at = COALESCE($12, canceled_at),
             closed_at = COALESCE($13, closed_at),
             close_reason = COALESCE($14, close_reason),
             ended_at = COALESCE($15, ended_at),
             end_reason = COALESCE($16, end_reason)
         WHERE id = $1 AND state = $2::text::svs.run_state",
        run,
        from.as_str(),
        to.as_str(),
        values.started_at,
        values.observation_ends_at,
        values.attribution_ends_at,
        values.executed_at,
        values.exit_code,
        values.launcher_error,
        values.launcher_output,
        values.error_reason,
        values.canceled_at,
        values.closed_at,
        values.close_reason,
        values.ended_at,
        values.end_reason,
    )
    .execute(&mut *conn)
    .await?
    .rows_affected()
        == 1;
    if moved && from != to {
        let details = reason.map(|reason| json!({ "reason": reason }));
        add_event(
            conn,
            run,
            "transition",
            actor,
            Some(from),
            Some(to),
            details,
            now,
        )
        .await?;
    }
    Ok(moved)
}

/// Closes the run: ace3's `_close`.
pub(crate) async fn close(
    conn: &mut PgConnection,
    run: i64,
    from: RunState,
    actor: &Actor,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<bool, ServiceError> {
    let values = Values {
        closed_at: Some(now),
        close_reason: Some(reason),
        ..Values::default()
    };
    transition(
        conn,
        run,
        from,
        RunState::Closed,
        actor,
        values,
        Some(reason),
        now,
    )
    .await
}

/// A person's end of a started run, in the caller's transaction, with the run's row locked and found
/// started, and a reason given: its observation window ends now, and its result is computed in a
/// savepoint, so a computation that fails leaves the end and the run stale, for the timers to compute.
/// `Service::end_svs_run`'s and the bulk end's (`svs_review`) write.
pub(crate) async fn end_in(
    tx: &mut ace_core::db::Tx<'_>,
    actor: &Actor,
    loaded: &Loaded,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<Option<crate::svs_results::ComputedResult>, ServiceError> {
    let uuid = loaded.run.uuid;
    // the timers may not have ended a run whose window already passed: that end stands
    let window = decode("window", loaded.run.observation_ends_at)?;
    let values = Values {
        ended_at: Some(now),
        observation_ends_at: Some(now.min(window)),
        end_reason: Some(reason),
        ..Values::default()
    };
    transition(
        tx.conn(),
        loaded.id,
        RunState::Started,
        RunState::Ended,
        actor,
        values,
        Some(reason),
        now,
    )
    .await?;
    mark_stale(tx.conn(), &[loaded.id]).await?;
    let computed = async {
        let mut inner = tx.savepoint().await?;
        let computed = crate::svs_results::compute(inner.conn(), loaded.id, actor, now).await?;
        inner.commit().await?;
        Ok::<_, ServiceError>(computed)
    }
    .await;
    match computed {
        Ok(computed) => Ok(computed),
        Err(error) => {
            use ace_core::db::Retryable;
            if error.is_retryable() {
                return Err(error);
            }
            tracing::error!(
                svs_run = %uuid,
                "unable to compute the result of an svs run as it ended: {error}"
            );
            Ok(None)
        }
    }
}

/// Marks the runs' live results stale, in run id order: ace3's `mark_runs_stale` for given runs, which
/// the core's SVS hook shares (`ace_core::svs::attribution::mark_runs_stale`).
pub(crate) async fn mark_stale(conn: &mut PgConnection, runs: &[i64]) -> Result<(), ServiceError> {
    Ok(ace_core::svs::attribution::mark_runs_stale(conn, runs).await?)
}

/// Locks the test hosts' rows, in id order, so registrations, starts and maintenance windows on a host are
/// decided one at a time: ace3's `lock_hosts`. The transaction is READ COMMITTED, so `host_holders` after
/// this sees every run another registration committed while it held them.
async fn lock_hosts(conn: &mut PgConnection, hosts: &[i64]) -> Result<(), ServiceError> {
    let hosts: Vec<i64> = hosts
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !hosts.is_empty() {
        let locked = sqlx::query_scalar!(
            "SELECT id FROM svs.test_hosts WHERE id = ANY ($1) ORDER BY id FOR UPDATE",
            &hosts,
        )
        .fetch_all(conn)
        .await?;
        // a host removed since it was matched: the caller's decision was made of a host that's gone
        if locked.len() != hosts.len() {
            return Err(ServiceError::Conflict(
                "a test host was removed while this was decided; try again".to_owned(),
            ));
        }
    }
    Ok(())
}

/// The runs and maintenance windows holding any of the test hosts (short names) at `now`, other than run
/// `except`: a run not started yet holds its hosts until it starts, times out or is canceled; a started
/// run, in any state, until its claim ends (its observation window, or its attribution window when its
/// test holds the host); a maintenance window until it ends. Claims judge by time, as attribution does, so
/// a run closed early still holds its hosts until its claim ends. ace3's `host_holders`.
pub(crate) async fn host_holders(
    conn: &mut PgConnection,
    hosts: &[String],
    now: DateTime<Utc>,
    except: Option<i64>,
) -> Result<Vec<HostHolder>, ServiceError> {
    let hosts: Vec<String> = hosts
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if hosts.is_empty() {
        return Ok(Vec::new());
    }
    let mut holders: Vec<HostHolder> = sqlx::query!(
        r#"SELECT DISTINCT t.host, r.uuid, r.state::text AS "state!",
                  CASE WHEN r.started_at IS NULL THEN NULL
                       WHEN r.holds_host THEN r.attribution_ends_at
                       ELSE r.observation_ends_at END AS until
           FROM svs.run_targets t
           JOIN svs.runs r ON r.id = t.run_id
           WHERE t.host = ANY ($1)
             AND (r.state = 'created'
                  OR (r.started_at IS NOT NULL AND r.attribution_ends_at >= $2
                      AND CASE WHEN r.holds_host THEN r.attribution_ends_at
                               ELSE r.observation_ends_at END >= $2))
             AND ($3::bigint IS NULL OR r.id <> $3)
           ORDER BY t.host, r.uuid"#,
        &hosts,
        now,
        except,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| HostHolder {
        host: row.host,
        run: Some(row.uuid),
        state: row.state,
        until: row.until,
        maintenance: None,
    })
    .collect();
    let windows = sqlx::query!(
        "SELECT host, uuid, ends_at FROM svs.maintenance_windows
         WHERE host = ANY ($1) AND ended_at IS NULL AND ends_at >= $2
         ORDER BY host, id",
        &hosts,
        now,
    )
    .fetch_all(&mut *conn)
    .await?;
    holders.extend(windows.into_iter().map(|row| HostHolder {
        host: row.host,
        run: None,
        state: HOLDER_MAINTENANCE.to_owned(),
        until: Some(row.ends_at),
        maintenance: Some(row.uuid),
    }));
    Ok(holders)
}

struct TestRow {
    guid: Uuid,
    platforms: Vec<String>,
    content_hash: String,
    commit: String,
}

/// What registering would decide: ace3's `RegistrationDecision`.
#[derive(Default)]
struct Decided {
    test: Option<TestRow>,
    /// Every target with how it matched the test hosts; empty when the registration is invalid before its
    /// targets are judged.
    matches: Vec<(TargetSpec, TargetMatch)>,
    invalid: Option<String>,
    platform: Option<String>,
    busy: Vec<HostHolder>,
    observation: Option<TimeDelta>,
    source: Option<ObservationSource>,
    attribution: Option<TimeDelta>,
    holds_host: bool,
    /// What the answer warns of.
    warnings: Vec<String>,
}

impl Decided {
    fn refused(&self) -> Vec<(&TargetSpec, &str)> {
        self.matches
            .iter()
            .filter(|(_, matched)| !matched.matched())
            .map(|(target, matched)| (target, matched.reason.as_deref().unwrap_or_default()))
            .collect()
    }

    fn hosts(&self) -> Vec<&MatchedHost> {
        self.matches
            .iter()
            .filter_map(|(_, matched)| matched.host.as_ref())
            .collect()
    }
}

/// Checks what doesn't depend on the test hosts: ace3's `_validate`. An error is why the registration
/// can't be accepted as sent.
async fn check_registration(
    conn: &mut PgConnection,
    config: &RunsConfig,
    registration: &Registration,
) -> Result<Result<TestRow, String>, ServiceError> {
    let asked = &registration.test_guid;
    let guid = Uuid::parse_str(asked.trim()).ok();
    let test = match guid {
        Some(guid) => {
            sqlx::query!(
                "SELECT guid, platforms, content_hash, commit, removed_at
                 FROM svs.catalog_tests WHERE guid = $1",
                guid,
            )
            .fetch_optional(&mut *conn)
            .await?
        }
        None => None,
    };
    let Some(test) = test else {
        return Ok(Err(format!("test {asked} is not in the catalog")));
    };
    if let Some(removed_at) = test.removed_at {
        return Ok(Err(format!(
            "test {asked} was removed from the catalog at {}",
            removed_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )));
    }
    if registration.targets.is_empty() {
        return Ok(Err("a run needs at least one target".to_owned()));
    }
    if registration.targets.len() > config.max_targets {
        return Ok(Err(format!(
            "a run may have at most {} targets",
            config.max_targets
        )));
    }
    if !registration.extra.is_object() {
        return Ok(Err("extra must be a JSON object".to_owned()));
    }
    if registration.extra.to_string().len() > config.max_extra_bytes {
        return Ok(Err(format!(
            "extra is larger than {} bytes",
            config.max_extra_bytes
        )));
    }
    for target in &registration.targets {
        let checked = split_hostname(&target.hostname).and_then(|_| match &target.username {
            Some(username) => normalize_username(username).map(|_| ()),
            None => Ok(()),
        });
        if let Err(error) = checked {
            return Ok(Err(error.0));
        }
    }
    Ok(Ok(TestRow {
        guid: test.guid,
        platforms: test.platforms,
        content_hash: test.content_hash,
        commit: test.commit,
    }))
}

/// The test's expected signatures on the platform that no ignore applies to: ace3's
/// `expected_signatures`.
async fn expected_signatures(
    conn: &mut PgConnection,
    test: Uuid,
    platform: &str,
) -> Result<BTreeSet<String>, ServiceError> {
    Ok(sqlx::query_scalar!(
        "SELECT e.signature_uuid FROM svs.expectations e
         WHERE e.test_guid = $1 AND e.platform = $2 AND e.state = 'expected'
           AND NOT EXISTS (SELECT FROM svs.ignores i
                           WHERE i.signature_uuid = e.signature_uuid
                             AND (i.test_guid IS NULL OR i.test_guid = e.test_guid))",
        test,
        platform,
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .collect())
}

/// The observation window of a run of the test on the platform registered now, and where it comes from:
/// the test's settings, else the latency of its expected signatures on the platform, else the slowest
/// enabled hunt. ace3's `observation_for_test`. The last says whether the window was computed with no
/// hunt recorded at all, which makes it the floor (`runs::no_hunts_warning`).
async fn observation_for_test(
    conn: &mut PgConnection,
    config: &RunsConfig,
    test: Uuid,
    platform: &str,
) -> Result<(TimeDelta, ObservationSource, bool), ServiceError> {
    let minutes = sqlx::query_scalar!(
        "SELECT observation_minutes FROM svs.test_settings WHERE test_guid = $1",
        test,
    )
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    if let Some(minutes) = minutes.filter(|minutes| *minutes > 0) {
        return Ok((
            TimeDelta::minutes(i64::from(minutes)),
            ObservationSource::Override,
            false,
        ));
    }
    let expected = expected_signatures(conn, test, platform).await?;
    let hunts = recorded_hunts(conn).await?;
    let no_hunts = hunts.is_empty();
    let latencies = hunt_latencies(&hunts);
    if expected.is_empty() {
        return Ok((
            observation_window(&latencies, None, &config.windows),
            ObservationSource::AllHunts,
            no_hunts,
        ));
    }
    Ok((
        observation_window(&latencies, Some(&expected), &config.windows),
        ObservationSource::Expected,
        no_hunts,
    ))
}

/// Decides a registration, in ace3's `decide`'s order. With `lock` it locks the matched hosts' rows before
/// it looks for what holds them, as registering does; a dry run only reads.
async fn decide(
    conn: &mut PgConnection,
    config: &RunsConfig,
    registration: &Registration,
    now: DateTime<Utc>,
    lock: bool,
) -> Result<Decided, ServiceError> {
    let test = match check_registration(conn, config, registration).await? {
        Ok(test) => test,
        Err(invalid) => {
            return Ok(Decided {
                invalid: Some(invalid),
                ..Decided::default()
            });
        }
    };
    let mut decided = Decided::default();
    for target in &registration.targets {
        let matched = match_target(conn, &target.hostname, target.username.as_deref()).await?;
        decided.matches.push((target.clone(), matched));
    }
    if !decided.refused().is_empty() {
        decided.test = Some(test);
        return Ok(decided);
    }
    let platform = {
        let hosts: Vec<HostPlatform<'_>> = decided
            .hosts()
            .into_iter()
            .map(|host| HostPlatform {
                hostname: &host.hostname,
                platform: host.platform.as_deref(),
            })
            .collect();
        runs::run_platform(test.guid, &test.platforms, &hosts)
    };
    let platform = match platform {
        Ok(platform) => platform,
        Err(invalid) => {
            decided.invalid = Some(invalid);
            decided.test = Some(test);
            return Ok(decided);
        }
    };
    if lock {
        let ids: Vec<i64> = decided.hosts().iter().map(|host| host.id).collect();
        lock_hosts(conn, &ids).await?;
    }
    let names: Vec<String> = decided
        .hosts()
        .iter()
        .map(|host| host.hostname.clone())
        .collect();
    decided.busy = host_holders(conn, &names, now, None).await?;
    decided.platform = Some(platform.clone());
    if decided.busy.is_empty() {
        let (observation, source, no_hunts) =
            observation_for_test(conn, config, test.guid, &platform).await?;
        if no_hunts {
            decided
                .warnings
                .push(runs::no_hunts_warning(config.windows.floor));
        }
        decided.observation = Some(observation);
        decided.source = Some(source);
        decided.attribution = Some(attribution_window(observation, &config.windows));
        decided.holds_host = sqlx::query_scalar!(
            "SELECT holds_host FROM svs.test_settings WHERE test_guid = $1",
            test.guid,
        )
        .fetch_optional(&mut *conn)
        .await?
        .unwrap_or(false);
    }
    decided.test = Some(test);
    Ok(decided)
}

/// The refused host as the caller named it, normalized: its fully qualified name when it has one. Not the
/// short name a test host matches on: a production host that shares a test host's short name in another
/// domain is another host, and gets its own alert. ace3's `_host_key`.
fn host_key(hostname: &str) -> String {
    let key = match split_hostname(hostname) {
        Ok((short, fqdn)) => fqdn.unwrap_or(short),
        Err(_) => hostname.trim().to_lowercase(),
    };
    key.chars().take(255).collect()
}

/// What a refusal says of the call it refused.
struct RefusedCall<'a> {
    launcher: Option<&'a str>,
    test_guid: Option<Uuid>,
    /// The request, as the alert keeps it.
    payload: Value,
}

/// One refused target, as the write's audit row keeps it.
#[derive(Debug, Clone, Serialize)]
struct RefusedTarget {
    host: String,
    reason: String,
    /// The alert this refusal made; None when the caller's refusals of the host already alerted this hour,
    /// or when the alert couldn't be made.
    alert: Option<Uuid>,
}

#[derive(Serialize)]
struct RefusalRecord<'a> {
    launcher: Option<&'a str>,
    test_guid: Option<Uuid>,
    refused: &'a [RefusedTarget],
}

impl Recorded for RefusalRecord<'_> {}

/// The submission of a refusal's alert: ace3's `_create_alert`.
fn refusal_alert(
    actor: &Actor,
    hostname: &str,
    username: Option<&str>,
    reason: &str,
    call: &RefusedCall<'_>,
    now: DateTime<Utc>,
) -> (Submission, Origin) {
    let caller = caller_name(actor);
    let address = crate::source::source_ip();
    let mut detection = Detection::new(format!("SVS test run registration refused: {reason}"));
    detection.signature_uuid = Some(REGISTRATION_REFUSED_SIGNATURE.to_owned());
    detection.signature_family = Some(FAMILY_BUILTIN.to_owned());
    let mut host = NewObservable::new(ObservableKind::Hostname, hostname.trim());
    host.detections.push(detection);
    let mut observables = vec![host];
    if let Some(username) = username.map(str::trim).filter(|name| !name.is_empty()) {
        let user = normalize_username(username).unwrap_or_else(|_| username.to_owned());
        observables.push(NewObservable::new(ObservableKind::User, user));
    }
    observables.push(NewObservable::new(ObservableKind::User, caller.clone()));
    if let Some(std::net::IpAddr::V4(ip)) = address {
        observables.push(NewObservable::new(ObservableKind::Ipv4, ip.to_string()));
    }
    let key = match actor {
        Actor::ApiKey { id, .. } => Some(id.0),
        Actor::User { .. } | Actor::Internal { .. } => None,
    };
    let submission = Submission {
        description: format!("SVS test run registration refused: {caller} targeted {hostname}"),
        analysis_mode: Some("correlation".to_owned()),
        event_time: Some(now),
        observables: Vec::new(),
        file_yara_meta: std::collections::BTreeMap::new(),
    };
    let origin = Origin {
        event_time_from_query: false,
        observables,
        details: Some(json!({
            "alert_type": REFUSAL_ALERT_TYPE,
            "tool": REFUSAL_TOOL,
            "details": {
                "reason": reason,
                "caller": caller,
                "caller_identity": actor.to_string(),
                "caller_key_id": key,
                "caller_address": address.map(|ip| ip.to_string()),
                "launcher": call.launcher,
                "test_guid": call.test_guid,
                "request": call.payload,
            },
        })),
        queue: None,
    };
    (submission, origin)
}

/// Records a refused target and, for the first refusal of (caller, host) in this hour, makes the alert:
/// ace3's `refuse`. A failure to make the alert is logged and undone alone: the target is refused either
/// way.
#[allow(clippy::too_many_arguments)]
async fn refuse(
    tx: &mut ace_core::db::Tx<'_>,
    service: &Service,
    actor: &Actor,
    hostname: &str,
    username: Option<&str>,
    reason: &str,
    call: &RefusedCall<'_>,
    now: DateTime<Utc>,
) -> Result<RefusedTarget, ServiceError> {
    let hour = now
        .duration_trunc(TimeDelta::hours(1))
        .map_err(|e| ServiceError::InvalidRequest(format!("a time that has no hour: {e}")))?;
    let host = host_key(hostname);
    let caller: String = actor.to_string().chars().take(256).collect();
    let row = sqlx::query!(
        r#"INSERT INTO svs.registration_refusals AS r (caller, host, hour, first_at, last_at)
           VALUES ($1, $2, $3, $4, $4)
           ON CONFLICT ON CONSTRAINT registration_refusals_collapse
           DO UPDATE SET count = r.count + 1, last_at = $4
           RETURNING r.id, (r.count = 1) AS "first!""#,
        caller,
        host,
        hour,
        now,
    )
    .fetch_one(tx.conn())
    .await?;
    let mut alert = None;
    if row.first {
        let made = async {
            let bucket = service.bucket().ok_or_else(|| {
                ServiceError::Unconfigured("the service has no bucket to submit with".to_owned())
            })?;
            let (submission, origin) = refusal_alert(actor, hostname, username, reason, call, now);
            let svs = Actor::Internal {
                id: crate::Component::new(runs::SVS_COMPONENT)
                    .map_err(|e| ServiceError::InvalidRequest(e.to_string()))?,
            };
            let mut inner = tx.savepoint().await?;
            let (submitted, _) = crate::submit::submit_in(
                &mut inner,
                service,
                bucket,
                &svs,
                &submission,
                &origin,
                &[],
            )
            .await?;
            inner.commit().await?;
            Ok::<Uuid, ServiceError>(submitted.uuid)
        }
        .await;
        match made {
            Ok(root) => {
                sqlx::query!(
                    "UPDATE svs.registration_refusals SET root_id = $2 WHERE id = $1",
                    row.id,
                    root,
                )
                .execute(tx.conn())
                .await?;
                alert = Some(root);
            }
            Err(error) => {
                use ace_core::db::Retryable;
                if error.is_retryable() {
                    return Err(error);
                }
                tracing::error!(
                    caller,
                    host,
                    "unable to create the alert for a refused svs run registration: {error}"
                );
            }
        }
    }
    tracing::warn!(
        caller,
        host,
        username,
        reason,
        launcher = call.launcher,
        svs_test = ?call.test_guid,
        alerted = alert.is_some(),
        alert_uuid = ?alert,
        "svs run registration refused"
    );
    Ok(RefusedTarget {
        host,
        reason: reason.to_owned(),
        alert,
    })
}

/// What a write's audit row keeps of a run.
#[derive(Serialize)]
struct RunRecord<'a> {
    test_guid: Uuid,
    platform: &'a str,
    state: RunState,
    launcher: &'a str,
    batch_id: Option<&'a str>,
    targets: Vec<&'a str>,
    observation_seconds: i32,
    attribution_seconds: i32,
    holds_host: bool,
}

impl Recorded for RunRecord<'_> {}

impl<'a> RunRecord<'a> {
    fn of(run: &'a Run) -> Self {
        RunRecord {
            test_guid: run.test_guid,
            platform: &run.platform,
            state: run.state,
            launcher: &run.launcher,
            batch_id: run.batch_id.as_deref(),
            targets: run.targets.iter().map(|t| t.host.as_str()).collect(),
            observation_seconds: run.observation_seconds,
            attribution_seconds: run.attribution_seconds,
            holds_host: run.holds_host,
        }
    }
}

/// A run's state, as a transition's audit row keeps its two sides.
#[derive(Serialize)]
pub(crate) struct StateRecord {
    pub(crate) state: RunState,
}

impl Recorded for StateRecord {}

/// What a transition's or a call's audit row says of it.
#[derive(Serialize)]
struct CallRecord<'a> {
    call: &'a str,
    outcome: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

impl Recorded for CallRecord<'_> {}

fn moved_change(
    uuid: Uuid,
    from: RunState,
    to: RunState,
    call: &str,
    outcome: &str,
    reason: Option<&str>,
) -> Result<Change, ServiceError> {
    Change::updated(
        Target::svs_run(uuid),
        &StateRecord { state: from },
        &StateRecord { state: to },
    )?
    .details(&CallRecord {
        call,
        outcome,
        reason,
    })
}

fn noted_change(uuid: Uuid, call: &str, outcome: &str) -> Result<Change, ServiceError> {
    Change::noted(
        Target::svs_run(uuid),
        &CallRecord {
            call,
            outcome,
            reason: None,
        },
    )
}

/// What a launcher's call came to, once its transaction commits.
enum Called {
    Done(Box<Run>),
    /// The call doesn't apply to the run's state; it's in the event log.
    Conflict(RunState),
    /// Another run or a maintenance window holds one of its hosts; it's in the event log.
    Busy(Vec<HostHolder>),
}

impl Called {
    fn into_run(self, uuid: Uuid, call: &str) -> Result<Run, ServiceError> {
        match self {
            Called::Done(run) => Ok(*run),
            Called::Conflict(state) => Err(state_conflict(uuid, state, call)),
            Called::Busy(holders) => Err(ServiceError::Conflict(host_busy_message(&holders))),
        }
    }
}

/// Records a call that doesn't apply to the run's state: ace3's `_conflict`.
async fn conflict(
    conn: &mut PgConnection,
    loaded: &Loaded,
    actor: &Actor,
    call: &str,
    payload: Value,
    now: DateTime<Utc>,
) -> Result<Audited<Called>, ServiceError> {
    launcher_call(conn, loaded.id, actor, call, "conflict", payload, now).await?;
    tracing::info!(
        svs_run = %loaded.run.uuid,
        svs_test = %loaded.run.test_guid,
        svs_marker = loaded.run.marker,
        launcher = loaded.run.launcher,
        call,
        outcome = "conflict",
        state = %loaded.run.state,
        caller = %actor,
        "svs launcher call"
    );
    Ok(Audited::changed(
        Called::Conflict(loaded.run.state),
        noted_change(loaded.run.uuid, call, "conflict")?,
    ))
}

pub(crate) async fn reloaded(conn: &mut PgConnection, uuid: Uuid) -> Result<Run, ServiceError> {
    Ok(find_run(conn, uuid, false)
        .await?
        .ok_or_else(|| unknown_run(uuid))?
        .run)
}

pub(crate) fn log_transition(
    run: &Run,
    from: Option<RunState>,
    to: RunState,
    actor: &Actor,
    reason: Option<&str>,
) {
    tracing::info!(
        svs_run = %run.uuid,
        svs_test = %run.test_guid,
        svs_marker = run.marker,
        from_state = from.map(RunState::as_str),
        to_state = to.as_str(),
        actor = %actor,
        reason,
        "svs run transition"
    );
}

fn log_call(run: &Run, call: &str, outcome: &str, actor: &Actor) {
    tracing::info!(
        svs_run = %run.uuid,
        svs_test = %run.test_guid,
        svs_marker = run.marker,
        launcher = run.launcher,
        call,
        outcome,
        caller = %actor,
        "svs launcher call"
    );
}

/// What one step of the timers moves.
#[derive(Debug, Clone, Copy)]
enum Step {
    TimeOut(Uuid),
    End(Uuid),
    Close(Uuid),
    Expire(i64),
    /// The alerts of a closed run: just closed, or `late`, found by the sweep.
    CloseAlerts {
        run: Uuid,
        late: bool,
    },
    /// The alerts the hook recorded for a maintenance window.
    CloseMaintenance(i64),
    PruneRefusals,
}

#[derive(Serialize)]
struct PrunedRecord {
    refusals: u64,
    before: DateTime<Utc>,
}

impl Recorded for PrunedRecord {}

struct WindowRow {
    id: i64,
    uuid: Uuid,
    test_host_id: Option<i64>,
    host: String,
    fqdn: Option<String>,
    reason: String,
    opened_by: Value,
    opened_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    ended_by: Option<Value>,
    end_reason: Option<String>,
    updated_at: DateTime<Utc>,
}

impl WindowRow {
    fn into_window(self) -> Result<MaintenanceWindow, ServiceError> {
        Ok(MaintenanceWindow {
            id: self.id,
            uuid: self.uuid,
            test_host_id: self.test_host_id,
            host: self.host,
            fqdn: self.fqdn,
            reason: self.reason,
            opened_by: RecordedActor::from_row(Some(self.opened_by))?,
            opened_at: self.opened_at,
            ends_at: self.ends_at,
            ended_at: self.ended_at,
            ended_by: RecordedActor::from_row(self.ended_by)?,
            end_reason: self.end_reason,
            updated_at: self.updated_at,
        })
    }
}

async fn window(conn: &mut PgConnection, id: i64) -> Result<MaintenanceWindow, ServiceError> {
    sqlx::query_as!(
        WindowRow,
        r#"SELECT id, uuid, test_host_id, host, fqdn, reason, opened_by AS "opened_by!: Value",
                  opened_at, ends_at, ended_at, ended_by AS "ended_by: Value", end_reason, updated_at
           FROM svs.maintenance_windows WHERE id = $1"#,
        id,
    )
    .fetch_one(conn)
    .await?
    .into_window()
}

/// What a maintenance window's audit row keeps: ace3's AUDIT line's fields.
#[derive(Serialize)]
struct WindowRecord<'a> {
    host: &'a str,
    reason: &'a str,
    opened_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    end_reason: Option<&'a str>,
}

impl Recorded for WindowRecord<'_> {}

impl<'a> WindowRecord<'a> {
    fn of(window: &'a MaintenanceWindow) -> Self {
        WindowRecord {
            host: &window.host,
            reason: &window.reason,
            opened_at: window.opened_at,
            ends_at: window.ends_at,
            ended_at: window.ended_at,
            end_reason: window.end_reason.as_deref(),
        }
    }
}

/// Ends the test host's open windows now, in the caller's transaction, which holds the host's row lock:
/// ace3's `ending_host_windows`, for `delete_test_host`. A window outliving its host would go on claiming
/// the alerts of a host nobody tests, and nothing could end it. The uuids of the windows it ended.
pub(crate) async fn end_host_windows(
    conn: &mut PgConnection,
    host: i64,
    actor: &Actor,
    now: DateTime<Utc>,
) -> Result<Vec<Uuid>, ServiceError> {
    Ok(sqlx::query_scalar!(
        "UPDATE svs.maintenance_windows
         SET ended_at = $3, ended_by = $2::jsonb, end_reason = 'ended'
         WHERE test_host_id = $1 AND ended_at IS NULL AND ends_at >= $4
         RETURNING uuid",
        host,
        Json(actor) as _,
        whole_second(now),
        now,
    )
    .fetch_all(conn)
    .await?)
}

/// A test host a maintenance call names, or why it names none.
enum Resolved {
    Host(MatchedHost),
    /// A name that isn't a test host's: refused, with why.
    Refused(String),
}

/// The test host `host_ref` names: its id, or its short or fully qualified name. ace3's `_resolve`. A host
/// that lists its users matches without one: a window is on the host, not a user. An unknown id is
/// `NotFound`.
async fn resolve(conn: &mut PgConnection, host_ref: &str) -> Result<Resolved, ServiceError> {
    let host_ref = host_ref.trim();
    if !host_ref.is_empty() && host_ref.bytes().all(|b| b.is_ascii_digit()) {
        let not_found = || ServiceError::NotFound(format!("test host {host_ref} not found"));
        let id: i64 = host_ref.parse().map_err(|_| not_found())?;
        return sqlx::query_as!(
            MatchedHost,
            "SELECT id, hostname, fqdn, usernames, platform FROM svs.test_hosts WHERE id = $1",
            id,
        )
        .fetch_optional(conn)
        .await?
        .map(Resolved::Host)
        .ok_or_else(not_found);
    }
    let matched = match_target(conn, host_ref, None).await?;
    Ok(match matched.host {
        Some(host) => Resolved::Host(host),
        None => Resolved::Refused(matched.reason.unwrap_or_default()),
    })
}

/// What a maintenance call came to, once its transaction commits.
enum Maintained {
    Window(Box<MaintenanceWindow>),
    /// The host isn't a test host; the refusal is recorded.
    Refused(String),
}

impl Maintained {
    fn into_window(self) -> Result<MaintenanceWindow, ServiceError> {
        match self {
            Maintained::Window(window) => Ok(*window),
            Maintained::Refused(reason) => Err(ServiceError::Forbidden(reason)),
        }
    }
}

impl Service {
    /// The service with the overlay's `svs.runs` (PLAN.md 7.10 batch 5).
    pub fn with_runs(mut self, config: RunsConfig) -> Self {
        self.runs = std::sync::Arc::new(config);
        self
    }

    /// The runs' settings.
    pub fn runs_config(&self) -> std::sync::Arc<RunsConfig> {
        self.runs.clone()
    }

    /// What registering would decide, with no run, event, refusal or alert: ace3's `validate`, a launcher's
    /// dry run. It needs `svs:run_register`.
    pub async fn validate_svs_run(
        &self,
        actor: &Actor,
        registration: &Registration,
        now: DateTime<Utc>,
    ) -> Result<RunValidation, ServiceError> {
        let config = &self.runs;
        let decided = self
            .gate
            .read(actor, "validate_svs_run", &SVS_RUN_REGISTER, &|tx| {
                Box::pin(async move { decide(tx.conn(), config, registration, now, false).await })
            })
            .await?;
        let refused = !decided.refused().is_empty();
        let decision = if decided.invalid.is_some() {
            RegistrationDecision::Invalid
        } else if refused {
            RegistrationDecision::Refused
        } else if !decided.busy.is_empty() {
            RegistrationDecision::HostBusy
        } else {
            RegistrationDecision::Accepted
        };
        tracing::info!(
            call = "validate",
            outcome = ?decision,
            launcher = registration.launcher,
            svs_test = registration.test_guid,
            caller = %actor,
            "svs launcher call"
        );
        let targets = decided
            .matches
            .iter()
            .map(|(target, matched)| {
                let host = matched.host.as_ref();
                ValidatedTarget {
                    hostname: target.hostname.clone(),
                    username: target.username.clone(),
                    accepted: matched.matched(),
                    reason: matched.reason.clone(),
                    test_host: host.map(|host| host.hostname.clone()),
                    platform: host.and_then(|host| host.platform.clone()),
                    held_by: decided
                        .busy
                        .iter()
                        .filter(|holder| host.is_some_and(|host| host.hostname == holder.host))
                        .cloned()
                        .collect(),
                }
            })
            .collect();
        let accepted = decision == RegistrationDecision::Accepted;
        Ok(RunValidation {
            decision,
            message: decided.invalid.clone(),
            targets,
            platform: decided.platform.clone().filter(|_| accepted),
            observation_seconds: decided.observation.map(|span| span.num_seconds()),
            observation_source: decided.source,
            attribution_seconds: decided.attribution.map(|span| span.num_seconds()),
            holds_host: accepted.then_some(decided.holds_host),
            warnings: if accepted {
                decided.warnings.clone()
            } else {
                Vec::new()
            },
        })
    }

    /// Registers a run in state created and gives it, with its marker: ace3's `register`. It needs
    /// `svs:run_register`. A registration that can't be accepted as sent is `InvalidRequest`, saying why,
    /// and writes nothing. A target that isn't a test host, or not a user its host lists, is `Forbidden`
    /// with each reason, after each refused target is recorded and, once an hour per caller and host,
    /// alerted. A host another run or a maintenance window holds is `Conflict`, which writes nothing.
    pub async fn register_svs_run(
        &self,
        actor: &Actor,
        registration: &Registration,
        now: DateTime<Utc>,
    ) -> Result<Run, ServiceError> {
        let config = &self.runs;
        let registered: Result<Run, Vec<String>> = self
            .gate
            .write(actor, "register_svs_run", &SVS_RUN_REGISTER, &|tx| {
                Box::pin(async move {
                    let decided = decide(tx.conn(), config, registration, now, true).await?;
                    if let Some(invalid) = decided.invalid {
                        return Err(ServiceError::InvalidRequest(invalid));
                    }
                    let test = decode("catalog test", decided.test.as_ref())?;
                    let launcher = registration.launcher.as_str();
                    let refusals: Vec<(TargetSpec, String)> = decided
                        .refused()
                        .into_iter()
                        .map(|(target, reason)| (target.clone(), reason.to_owned()))
                        .collect();
                    if !refusals.is_empty() {
                        let call = RefusedCall {
                            launcher: Some(launcher),
                            test_guid: Some(test.guid),
                            payload: registration.payload(),
                        };
                        let mut refused = Vec::new();
                        for (target, reason) in &refusals {
                            refused.push(
                                refuse(
                                    tx,
                                    self,
                                    actor,
                                    &target.hostname,
                                    target.username.as_deref(),
                                    reason,
                                    &call,
                                    now,
                                )
                                .await?,
                            );
                        }
                        let change = Change::added(
                            Target::svs_refusal(&actor.to_string()),
                            &RefusalRecord {
                                launcher: Some(launcher),
                                test_guid: Some(test.guid),
                                refused: &refused,
                            },
                        )?;
                        let reasons = refusals.into_iter().map(|(_, reason)| reason).collect();
                        return Ok(Audited::changed(Err(reasons), change));
                    }
                    if !decided.busy.is_empty() {
                        tracing::info!(
                            call = "register",
                            outcome = OUTCOME_HOST_BUSY,
                            launcher,
                            svs_test = %test.guid,
                            caller = %actor,
                            "svs launcher call"
                        );
                        return Err(ServiceError::Conflict(host_busy_message(&decided.busy)));
                    }
                    let platform = decode("platform", decided.platform.as_deref())?;
                    let observation = decode("window", decided.observation)?;
                    let attribution = decode("window", decided.attribution)?;
                    let source = decode("window", decided.source)?;
                    let seconds = |span: TimeDelta| {
                        i32::try_from(span.num_seconds()).map_err(|_| {
                            ServiceError::InvalidRequest("a window too long to store".to_owned())
                        })
                    };
                    let uuid = Uuid::new_v4();
                    // a registered run opens SVS's gate: no pass ends on a closed gate while this
                    // commits (`ace_core::svs::attribution`'s *The gate*)
                    ace_core::svs::attribution::lock_gate_to_open(tx.conn()).await?;
                    let id = sqlx::query_scalar!(
                        "INSERT INTO svs.runs
                             (uuid, test_guid, platform, test_content_hash, catalog_commit, state,
                              marker, launcher, batch_id, extra, registered_by, created_at,
                              observation_seconds, attribution_seconds, holds_host, warnings)
                         VALUES ($1, $2, $3, $4, $5, 'created', $6, $7, $8, $9, $10::jsonb, $11, $12,
                                 $13, $14, $15)
                         RETURNING id",
                        uuid,
                        test.guid,
                        platform,
                        test.content_hash,
                        test.commit,
                        new_marker(),
                        launcher,
                        registration.batch_id,
                        registration.extra,
                        Json(actor) as _,
                        now,
                        seconds(observation)?,
                        seconds(attribution)?,
                        decided.holds_host,
                        &decided.warnings,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    for warning in &decided.warnings {
                        tracing::warn!(svs_run = %uuid, svs_test = %test.guid, "svs registration: {warning}");
                    }
                    let mut seen = BTreeSet::new();
                    for (target, matched) in &decided.matches {
                        let (host, fqdn) = split_hostname(&target.hostname)
                            .map_err(|e| ServiceError::InvalidRequest(e.0))?;
                        let user = target
                            .username
                            .as_deref()
                            .map(normalize_username)
                            .transpose()
                            .map_err(|e| ServiceError::InvalidRequest(e.0))?;
                        if !seen.insert((host.clone(), fqdn.clone(), user.clone())) {
                            continue;
                        }
                        let test_host = decode("test host", matched.host.as_ref())?;
                        sqlx::query!(
                            r#"INSERT INTO svs.run_targets
                                   (run_id, hostname, username, host, fqdn, "user", test_host_id)
                               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
                            id,
                            target.hostname.trim(),
                            target
                                .username
                                .as_deref()
                                .map(str::trim)
                                .filter(|name| !name.is_empty()),
                            host,
                            fqdn.or_else(|| test_host.fqdn.clone()),
                            user,
                            test_host.id,
                        )
                        .execute(tx.conn())
                        .await?;
                    }
                    let mut details = registration.payload();
                    if let Some(details) = details.as_object_mut() {
                        details.insert("platform".to_owned(), json!(platform));
                        details.insert("observation_source".to_owned(), json!(source));
                        details.insert("holds_host".to_owned(), json!(decided.holds_host));
                        if !decided.warnings.is_empty() {
                            details.insert("warnings".to_owned(), json!(decided.warnings));
                        }
                    }
                    add_event(
                        tx.conn(),
                        id,
                        "registered",
                        actor,
                        None,
                        Some(RunState::Created),
                        Some(details),
                        now,
                    )
                    .await?;
                    let run = reloaded(tx.conn(), uuid).await?;
                    let change = Change::added(Target::svs_run(uuid), &RunRecord::of(&run))?;
                    Ok(Audited::changed(Ok(run), change))
                })
            })
            .await?;
        match registered {
            Ok(run) => {
                log_transition(&run, None, run.state, actor, None);
                // the run's platform is decided at registration, so its record says it
                tracing::info!(
                    svs_run = %run.uuid,
                    svs_test = %run.test_guid,
                    svs_marker = run.marker,
                    launcher = run.launcher,
                    call = "register",
                    outcome = "created",
                    platform = run.platform,
                    caller = %actor,
                    "svs launcher call"
                );
                Ok(run)
            }
            Err(reasons) => {
                // each refused target has its own record; this is the call's
                tracing::warn!(
                    launcher = registration.launcher,
                    svs_test = registration.test_guid,
                    call = "register",
                    outcome = "refused",
                    caller = %actor,
                    "svs launcher call"
                );
                Err(ServiceError::Forbidden(format!(
                    "registration refused: {}",
                    reasons.join("; ")
                )))
            }
        }
    }

    /// Created to started; the windows start now, at the whole second: ace3's `start`. It needs
    /// `svs:run_register`. A run that isn't there is `NotFound`; one in any other state, or one of whose
    /// hosts another run or a maintenance window holds, is `Conflict`, recorded in its event log.
    pub async fn start_svs_run(
        &self,
        actor: &Actor,
        uuid: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Run, ServiceError> {
        let now = whole_second(now);
        let called = self
            .gate
            .write(actor, "start_svs_run", &SVS_RUN_REGISTER, &|tx| {
                Box::pin(async move {
                    let loaded = locked_run(tx.conn(), uuid).await?;
                    if loaded.run.state != RunState::Created {
                        return conflict(tx.conn(), &loaded, actor, CALL_START, json!({}), now)
                            .await;
                    }
                    let hosts: Vec<i64> = sqlx::query_scalar!(
                        r#"SELECT test_host_id AS "id!" FROM svs.run_targets
                           WHERE run_id = $1 AND test_host_id IS NOT NULL"#,
                        loaded.id,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    lock_hosts(tx.conn(), &hosts).await?;
                    let names: Vec<String> =
                        loaded.run.targets.iter().map(|t| t.host.clone()).collect();
                    let busy = host_holders(tx.conn(), &names, now, Some(loaded.id)).await?;
                    if !busy.is_empty() {
                        let holding: Vec<Uuid> = busy.iter().filter_map(|h| h.run).collect();
                        launcher_call(
                            tx.conn(),
                            loaded.id,
                            actor,
                            CALL_START,
                            OUTCOME_HOST_BUSY,
                            json!({ "holding_runs": holding }),
                            now,
                        )
                        .await?;
                        log_call(&loaded.run, CALL_START, OUTCOME_HOST_BUSY, actor);
                        return Ok(Audited::changed(
                            Called::Busy(busy),
                            noted_change(uuid, CALL_START, OUTCOME_HOST_BUSY)?,
                        ));
                    }
                    let values = Values {
                        started_at: Some(now),
                        observation_ends_at: Some(
                            now + TimeDelta::seconds(i64::from(loaded.run.observation_seconds)),
                        ),
                        attribution_ends_at: Some(
                            now + TimeDelta::seconds(i64::from(loaded.run.attribution_seconds)),
                        ),
                        ..Values::default()
                    };
                    transition(
                        tx.conn(),
                        loaded.id,
                        RunState::Created,
                        RunState::Started,
                        actor,
                        values,
                        None,
                        now,
                    )
                    .await?;
                    launcher_call(
                        tx.conn(),
                        loaded.id,
                        actor,
                        CALL_START,
                        "started",
                        json!({}),
                        now,
                    )
                    .await?;
                    let run = reloaded(tx.conn(), uuid).await?;
                    let change = moved_change(
                        uuid,
                        RunState::Created,
                        RunState::Started,
                        CALL_START,
                        "started",
                        None,
                    )?;
                    Ok(Audited::changed(Called::Done(Box::new(run)), change))
                })
            })
            .await?;
        let run = called.into_run(uuid, CALL_START)?;
        log_transition(&run, Some(RunState::Created), run.state, actor, None);
        log_call(&run, CALL_START, "started", actor);
        Ok(run)
    }

    /// Records how the test executed on a started run, and what it printed, kept as
    /// `ace_core::svs::runs::truncate_output` keeps it: ace3's `executed`. A non-zero exit code or an error
    /// is a launcher-reported failure, which moves the run to error. It needs `svs:run_register`. A run
    /// that isn't there is `NotFound`; one that isn't started is `Conflict`, recorded in its event log.
    pub async fn svs_run_executed(
        &self,
        actor: &Actor,
        uuid: Uuid,
        exit_code: i32,
        error: Option<&str>,
        output: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Run, ServiceError> {
        let mut payload = json!({"exit_code": exit_code, "error": error});
        // the output itself is on the run, not repeated in its event log
        let kept = output.map(runs::truncate_output);
        if let (Some((_, size, truncated)), Some(payload)) = (&kept, payload.as_object_mut()) {
            payload.insert("output_bytes".to_owned(), json!(size));
            payload.insert("output_truncated".to_owned(), json!(truncated));
        }
        let (payload, kept) = (&payload, &kept);
        let failed = runs::failed(exit_code, error);
        let reason = failed.then(|| runs::failure_reason(exit_code, error));
        let reason = reason.as_deref();
        let outcome = if failed { "error" } else { "recorded" };
        let called = self
            .gate
            .write(actor, "svs_run_executed", &SVS_RUN_REGISTER, &|tx| {
                Box::pin(async move {
                    let loaded = locked_run(tx.conn(), uuid).await?;
                    if loaded.run.state != RunState::Started {
                        return conflict(
                            tx.conn(),
                            &loaded,
                            actor,
                            CALL_EXECUTED,
                            payload.clone(),
                            now,
                        )
                        .await;
                    }
                    let values = Values {
                        executed_at: Some(now),
                        exit_code: Some(exit_code),
                        launcher_error: error,
                        launcher_output: kept.as_ref().map(|(output, _, _)| output.as_str()),
                        error_reason: reason,
                        ..Values::default()
                    };
                    let to = if failed {
                        RunState::Error
                    } else {
                        RunState::Started
                    };
                    transition(
                        tx.conn(),
                        loaded.id,
                        RunState::Started,
                        to,
                        actor,
                        values,
                        reason,
                        now,
                    )
                    .await?;
                    launcher_call(
                        tx.conn(),
                        loaded.id,
                        actor,
                        CALL_EXECUTED,
                        outcome,
                        payload.clone(),
                        now,
                    )
                    .await?;
                    let run = reloaded(tx.conn(), uuid).await?;
                    let change = if failed {
                        moved_change(
                            uuid,
                            RunState::Started,
                            RunState::Error,
                            CALL_EXECUTED,
                            outcome,
                            reason,
                        )?
                    } else {
                        noted_change(uuid, CALL_EXECUTED, outcome)?
                    };
                    Ok(Audited::changed(Called::Done(Box::new(run)), change))
                })
            })
            .await?;
        let run = called.into_run(uuid, CALL_EXECUTED)?;
        if failed {
            log_transition(&run, Some(RunState::Started), run.state, actor, reason);
        }
        tracing::info!(
            svs_run = %run.uuid,
            svs_test = %run.test_guid,
            svs_marker = run.marker,
            launcher = run.launcher,
            call = CALL_EXECUTED,
            outcome,
            exit_code,
            output_bytes = kept.as_ref().map(|(_, size, _)| *size),
            output_truncated = kept.as_ref().map(|(_, _, truncated)| *truncated),
            caller = %actor,
            "svs launcher call"
        );
        Ok(run)
    }

    /// Records, once, that the test's cleanup begins now, at the whole second, on a started run: what
    /// fires at or after it is the cleanup's. ace3's `cleanup`. It needs `svs:run_register`. A run that
    /// isn't there is `NotFound`; one that isn't started, or whose cleanup already began, is `Conflict`,
    /// recorded in its event log.
    pub async fn svs_run_cleanup(
        &self,
        actor: &Actor,
        uuid: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Run, ServiceError> {
        let now = whole_second(now);
        let called = self
            .gate
            .write(actor, "svs_run_cleanup", &SVS_RUN_REGISTER, &|tx| {
                Box::pin(async move {
                    let loaded = locked_run(tx.conn(), uuid).await?;
                    if loaded.run.state != RunState::Started || loaded.run.cleanup_at.is_some() {
                        let payload = match loaded.run.cleanup_at {
                            Some(at) => json!({ "cleanup_at": at }),
                            None => json!({}),
                        };
                        return conflict(tx.conn(), &loaded, actor, CALL_CLEANUP, payload, now)
                            .await;
                    }
                    sqlx::query!(
                        "UPDATE svs.runs SET cleanup_at = $2 WHERE id = $1",
                        loaded.id,
                        now,
                    )
                    .execute(tx.conn())
                    .await?;
                    launcher_call(
                        tx.conn(),
                        loaded.id,
                        actor,
                        CALL_CLEANUP,
                        "recorded",
                        json!({ "cleanup_at": now }),
                        now,
                    )
                    .await?;
                    let run = reloaded(tx.conn(), uuid).await?;
                    let change = noted_change(uuid, CALL_CLEANUP, "recorded")?;
                    Ok(Audited::changed(Called::Done(Box::new(run)), change))
                })
            })
            .await?;
        let run = called.into_run(uuid, CALL_CLEANUP)?;
        log_call(&run, CALL_CLEANUP, "recorded", actor);
        Ok(run)
    }

    /// The launcher's cancel: created or started to canceled. ace3's `cancel`. A canceled run keeps
    /// attributing until its attribution window ends, because the test may have run anyway; one canceled
    /// before it started has no windows, so it is closed at once. It needs `svs:run_register`. A run that
    /// isn't there is `NotFound`; one in any other state is `Conflict`, recorded in its event log.
    pub async fn cancel_svs_run(
        &self,
        actor: &Actor,
        uuid: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Run, ServiceError> {
        let called = self
            .gate
            .write(actor, "cancel_svs_run", &SVS_RUN_REGISTER, &|tx| {
                Box::pin(async move {
                    let loaded = locked_run(tx.conn(), uuid).await?;
                    let from = loaded.run.state;
                    if !matches!(from, RunState::Created | RunState::Started) {
                        return conflict(tx.conn(), &loaded, actor, CALL_CANCEL, json!({}), now)
                            .await;
                    }
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
                    let mut to = RunState::Canceled;
                    if from == RunState::Created {
                        close(
                            tx.conn(),
                            loaded.id,
                            RunState::Canceled,
                            actor,
                            CLOSE_REASON_CANCELED_BEFORE_START,
                            now,
                        )
                        .await?;
                        to = RunState::Closed;
                    }
                    launcher_call(
                        tx.conn(),
                        loaded.id,
                        actor,
                        CALL_CANCEL,
                        "canceled",
                        json!({}),
                        now,
                    )
                    .await?;
                    let run = reloaded(tx.conn(), uuid).await?;
                    let reason =
                        (to == RunState::Closed).then_some(CLOSE_REASON_CANCELED_BEFORE_START);
                    let change = moved_change(uuid, from, to, CALL_CANCEL, "canceled", reason)?;
                    Ok(Audited::changed(Called::Done(Box::new(run)), change))
                })
            })
            .await?;
        let run = called.into_run(uuid, CALL_CANCEL)?;
        let from = if run.started_at.is_some() {
            RunState::Started
        } else {
            RunState::Created
        };
        log_transition(&run, Some(from), RunState::Canceled, actor, None);
        if run.state == RunState::Closed {
            log_transition(
                &run,
                Some(RunState::Canceled),
                RunState::Closed,
                actor,
                run.close_reason.as_deref(),
            );
        }
        log_call(&run, CALL_CANCEL, "canceled", actor);
        Ok(run)
    }

    /// A person ends a started run now, at the whole second, rather than waiting out its observation
    /// window, because they know nothing more will fire: started to ended, as the timers would. ace3's
    /// `end_by_person`. Its observation window ends now, which ends its claim on its hosts unless its test
    /// holds them; its attribution window is left as it was, so an alert that fires anyway is still the
    /// run's, as late. It needs `svs:run_manage`, and a reason, since a signature that hadn't had time to
    /// fire is missing from its result. A run that isn't there is `NotFound`, one that isn't started
    /// `Conflict`, and no reason `InvalidRequest`; none of those writes anything.
    pub async fn end_svs_run(
        &self,
        actor: &Actor,
        uuid: Uuid,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<Run, ServiceError> {
        let now = whole_second(now);
        let reason = reason.trim();
        let run = self
            .gate
            .write(actor, "end_svs_run", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let loaded = locked_run(tx.conn(), uuid).await?;
                    if loaded.run.state != RunState::Started {
                        return Err(state_conflict(uuid, loaded.run.state, "end"));
                    }
                    if reason.is_empty() {
                        return Err(ServiceError::InvalidRequest(format!(
                            "run {uuid} is still observing: ending it early needs a reason"
                        )));
                    }
                    let computed = end_in(tx, actor, &loaded, reason, now).await?;
                    let run = reloaded(tx.conn(), uuid).await?;
                    let change = moved_change(
                        uuid,
                        RunState::Started,
                        RunState::Ended,
                        "end",
                        "ended",
                        Some(reason),
                    )?;
                    Ok(Audited::changed((run, computed), change))
                })
            })
            .await?;
        let (run, computed) = run;
        log_transition(
            &run,
            Some(RunState::Started),
            run.state,
            actor,
            Some(reason),
        );
        if let Some(computed) = &computed {
            crate::svs_results::log_computed(computed);
        }
        Ok(run)
    }

    /// Moves every run whose start timeout or window has passed, closes the alerts of the runs it closes
    /// and of runs closed before their alerts arrived as SIMULATED, expires the maintenance windows whose
    /// time has passed and closes their alerts as IGNORE (`svs_association`), and removes the refusals past
    /// their day: ace3's `run_timers` and its maintenance half's. It needs `svs:run_timers`. Each move is its own transaction, on the state
    /// it finds under the row's lock, so a pass that runs twice changes nothing, and one that fails is
    /// logged and counted while the others go on.
    pub async fn run_svs_timers(
        &self,
        actor: &Actor,
        now: DateTime<Utc>,
    ) -> Result<TimerResult, ServiceError> {
        let timeout = self.runs.start_timeout;
        let minutes = self.runs.start_timeout_minutes;
        let mut steps: std::collections::VecDeque<Step> = self
            .gate
            .read(actor, "run_svs_timers", &SVS_RUN_TIMERS, &|tx| {
                Box::pin(async move {
                    let mut steps = std::collections::VecDeque::new();
                    let timed_out = sqlx::query_scalar!(
                        "SELECT uuid FROM svs.runs WHERE state = 'created' AND created_at <= $1
                         ORDER BY id LIMIT $2",
                        now - timeout,
                        TIMER_BATCH,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    steps.extend(timed_out.into_iter().map(Step::TimeOut));
                    let ended = sqlx::query_scalar!(
                        "SELECT uuid FROM svs.runs
                         WHERE state = 'started' AND observation_ends_at <= $1
                         ORDER BY id LIMIT $2",
                        now,
                        TIMER_BATCH,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    steps.extend(ended.into_iter().map(Step::End));
                    let closed = sqlx::query_scalar!(
                        "SELECT uuid FROM svs.runs
                         WHERE state IN ('canceled', 'error')
                           AND (attribution_ends_at IS NULL OR attribution_ends_at <= $1)
                         ORDER BY id LIMIT $2",
                        now,
                        TIMER_BATCH,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    steps.extend(closed.into_iter().map(Step::Close));
                    let expired = sqlx::query_scalar!(
                        "SELECT id FROM svs.maintenance_windows
                         WHERE ended_at IS NULL AND ends_at < $1 ORDER BY id LIMIT $2",
                        now,
                        TIMER_BATCH,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    steps.extend(expired.into_iter().map(Step::Expire));
                    // the sweep: alerts attributed to a run after it closed, or that its close
                    // couldn't reach; the runs this pass closes get theirs as each closes
                    let late =
                        crate::svs_association::runs_with_late_alerts(tx, TIMER_BATCH).await?;
                    steps.extend(
                        late.into_iter()
                            .map(|run| Step::CloseAlerts { run, late: true }),
                    );
                    let windows =
                        crate::svs_association::windows_with_standing_alerts(tx, TIMER_BATCH)
                            .await?;
                    steps.extend(windows.into_iter().map(Step::CloseMaintenance));
                    Ok(steps)
                })
            })
            .await?;
        steps.push_back(Step::PruneRefusals);
        let mut result = TimerResult::default();
        while let Some(step) = steps.pop_front() {
            let step = &step;
            let moved = self
                .gate
                .write(actor, "run_svs_timers", &SVS_RUN_TIMERS, &|tx| {
                    Box::pin(async move {
                        let conn = tx.conn();
                        match *step {
                            Step::TimeOut(uuid) => {
                                let loaded = locked_run(conn, uuid).await?;
                                let reason = runs::start_timeout_reason(minutes);
                                let values = Values {
                                    error_reason: Some(&reason),
                                    ..Values::default()
                                };
                                if !transition(
                                    conn,
                                    loaded.id,
                                    RunState::Created,
                                    RunState::Error,
                                    actor,
                                    values,
                                    Some(&reason),
                                    now,
                                )
                                .await?
                                {
                                    return Ok(Audited::unchanged(0));
                                }
                                close(
                                    conn,
                                    loaded.id,
                                    RunState::Error,
                                    actor,
                                    CLOSE_REASON_START_TIMEOUT,
                                    now,
                                )
                                .await?;
                                log_transition(
                                    &loaded.run,
                                    Some(RunState::Created),
                                    RunState::Error,
                                    actor,
                                    Some(&reason),
                                );
                                log_transition(
                                    &loaded.run,
                                    Some(RunState::Error),
                                    RunState::Closed,
                                    actor,
                                    Some(CLOSE_REASON_START_TIMEOUT),
                                );
                                let change = moved_change(
                                    uuid,
                                    RunState::Created,
                                    RunState::Closed,
                                    "timer",
                                    "timed out",
                                    Some(CLOSE_REASON_START_TIMEOUT),
                                )?;
                                Ok(Audited::changed(1, change))
                            }
                            Step::End(uuid) => {
                                let loaded = locked_run(conn, uuid).await?;
                                let values = Values {
                                    ended_at: Some(now),
                                    ..Values::default()
                                };
                                if !transition(
                                    conn,
                                    loaded.id,
                                    RunState::Started,
                                    RunState::Ended,
                                    actor,
                                    values,
                                    None,
                                    now,
                                )
                                .await?
                                {
                                    return Ok(Audited::unchanged(0));
                                }
                                mark_stale(conn, &[loaded.id]).await?;
                                log_transition(
                                    &loaded.run,
                                    Some(RunState::Started),
                                    RunState::Ended,
                                    actor,
                                    None,
                                );
                                let change = moved_change(
                                    uuid,
                                    RunState::Started,
                                    RunState::Ended,
                                    "timer",
                                    "ended",
                                    None,
                                )?;
                                Ok(Audited::changed(1, change))
                            }
                            Step::Close(uuid) => {
                                let loaded = locked_run(conn, uuid).await?;
                                let from = loaded.run.state;
                                if !matches!(from, RunState::Canceled | RunState::Error)
                                    || !close(
                                        conn,
                                        loaded.id,
                                        from,
                                        actor,
                                        CLOSE_REASON_ATTRIBUTION_ENDED,
                                        now,
                                    )
                                    .await?
                                {
                                    return Ok(Audited::unchanged(0));
                                }
                                log_transition(
                                    &loaded.run,
                                    Some(from),
                                    RunState::Closed,
                                    actor,
                                    Some(CLOSE_REASON_ATTRIBUTION_ENDED),
                                );
                                let change = moved_change(
                                    uuid,
                                    from,
                                    RunState::Closed,
                                    "timer",
                                    "closed",
                                    Some(CLOSE_REASON_ATTRIBUTION_ENDED),
                                )?;
                                Ok(Audited::changed(1, change))
                            }
                            Step::Expire(id) => {
                                // conditional: a call ending it meanwhile wins
                                let expired = sqlx::query_scalar!(
                                    "UPDATE svs.maintenance_windows
                                     SET ended_at = ends_at, ended_by = $2::jsonb, end_reason = 'expired'
                                     WHERE id = $1 AND ended_at IS NULL
                                     RETURNING id",
                                    id,
                                    Json(actor) as _,
                                )
                                .fetch_optional(&mut *conn)
                                .await?;
                                if expired.is_none() {
                                    return Ok(Audited::unchanged(0));
                                }
                                let after = window(conn, id).await?;
                                let mut before = after.clone();
                                before.ended_at = None;
                                before.end_reason = None;
                                let change = Change::updated(
                                    Target::svs_maintenance_window(after.uuid),
                                    &WindowRecord::of(&before),
                                    &WindowRecord::of(&after),
                                )?;
                                Ok(Audited::changed(1, change))
                            }
                            Step::CloseAlerts { run, late } => {
                                match self
                                    .close_run_alerts_in(tx, actor, actor, run, late, None, now)
                                    .await? {
                                    None => Ok(Audited::unchanged(0)),
                                    Some(closed) => {
                                        let count = closed.alerts_closed.len() as u64;
                                        let change = Change::noted(Target::svs_run(run), &closed)?;
                                        Ok(Audited::changed(count, change))
                                    }
                                }
                            }
                            Step::CloseMaintenance(window) => {
                                match self
                                    .close_maintenance_alerts_in(tx, actor, window, now)
                                    .await?
                                {
                                    None => Ok(Audited::unchanged(0)),
                                    Some((uuid, closed)) => {
                                        let count = closed.alerts_closed.len() as u64;
                                        let change = Change::noted(
                                            Target::svs_maintenance_window(uuid),
                                            &closed,
                                        )?;
                                        Ok(Audited::changed(count, change))
                                    }
                                }
                            }
                            Step::PruneRefusals => {
                                let before = now - REFUSAL_RETENTION;
                                let pruned = sqlx::query!(
                                    "DELETE FROM svs.registration_refusals WHERE hour < $1",
                                    before,
                                )
                                .execute(&mut *conn)
                                .await?
                                .rows_affected();
                                if pruned == 0 {
                                    return Ok(Audited::unchanged(0));
                                }
                                let change = Change::removed(
                                    Target::expired_svs_refusals(),
                                    &PrunedRecord {
                                        refusals: pruned,
                                        before,
                                    },
                                )?;
                                Ok(Audited::changed(pruned, change))
                            }
                        }
                    })
                })
                .await;
            match (moved, step) {
                (Ok(count), Step::TimeOut(run)) => {
                    result.timed_out += count;
                    if count > 0 {
                        steps.push_front(Step::CloseAlerts {
                            run: *run,
                            late: false,
                        });
                    }
                }
                (Ok(count), Step::End(uuid)) => {
                    result.ended += count;
                    // the result, as the run ends: a computation that fails leaves the end, and the
                    // run stale for a later pass
                    if count > 0
                        && let Err(error) = self.compute_svs_result(actor, *uuid, now).await
                    {
                        tracing::error!(
                            svs_run = %uuid,
                            "unable to compute the result of an svs run as it ended: {error}"
                        );
                    }
                }
                // a failure to close its alerts never undoes the close: the sweep closes them on a
                // later pass
                (Ok(count), Step::Close(run)) => {
                    result.closed += count;
                    if count > 0 {
                        steps.push_front(Step::CloseAlerts {
                            run: *run,
                            late: false,
                        });
                    }
                }
                (Ok(count), Step::CloseAlerts { late: false, .. }) => result.alerts_closed += count,
                (Ok(count), Step::CloseAlerts { late: true, .. }) => {
                    result.late_alerts_closed += count;
                }
                (Ok(count), Step::CloseMaintenance(_)) => {
                    result.maintenance_alerts_closed += count;
                }
                (Ok(count), Step::Expire(_)) => result.expired_windows += count,
                (Ok(count), Step::PruneRefusals) => result.pruned_refusals += count,
                (Err(error), step) => {
                    tracing::error!(?step, "an svs timer step failed: {error}");
                    result.failed += 1;
                    result.first_error.get_or_insert_with(|| error.to_string());
                }
            }
        }
        match self.recompute_stale_svs_results(actor, now, None).await {
            Ok(computed) => result.results_computed = computed,
            Err(error) => {
                tracing::error!("the svs timers couldn't recompute the stale results: {error}");
                result.failed += 1;
                result.first_error.get_or_insert_with(|| error.to_string());
            }
        }
        Ok(result)
    }

    /// One run, with what its test printed. It needs `svs:run_read`; a run that isn't there is `NotFound`.
    pub async fn svs_run(&self, actor: &Actor, uuid: Uuid) -> Result<RunDetail, ServiceError> {
        self.gate
            .read(actor, "svs_run", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let run = reloaded(tx.conn(), uuid).await?;
                    let launcher_output = sqlx::query_scalar!(
                        "SELECT launcher_output FROM svs.runs WHERE uuid = $1",
                        uuid,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    Ok(RunDetail {
                        run,
                        launcher_output,
                    })
                })
            })
            .await
    }

    /// A run's event log, oldest first: those after the event `after`, at most `limit`
    /// ([`MAX_RUN_EVENTS_PAGE`] when None or more). It needs `svs:run_read`; a run that isn't there is
    /// `NotFound`.
    pub async fn svs_run_events(
        &self,
        actor: &Actor,
        uuid: Uuid,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Vec<RunEvent>, ServiceError> {
        let limit = limit
            .unwrap_or(MAX_RUN_EVENTS_PAGE)
            .clamp(1, MAX_RUN_EVENTS_PAGE);
        self.gate
            .read(actor, "svs_run_events", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let run =
                        sqlx::query_scalar!("SELECT id FROM svs.runs WHERE uuid = $1", uuid)
                            .fetch_optional(tx.conn())
                            .await?
                            .ok_or_else(|| unknown_run(uuid))?;
                    sqlx::query!(
                        r#"SELECT id, kind, from_state::text AS from_state, to_state::text AS to_state,
                                  actor AS "actor!: Value", details, created_at
                           FROM svs.run_events
                           WHERE run_id = $1 AND id > $2 ORDER BY id LIMIT $3"#,
                        run,
                        after.unwrap_or(0),
                        limit,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| {
                        Ok(RunEvent {
                            id: row.id,
                            kind: row.kind,
                            from_state: row.from_state.as_deref().map(state_of).transpose()?,
                            to_state: row.to_state.as_deref().map(state_of).transpose()?,
                            actor: RecordedActor::from_row(Some(row.actor))?,
                            details: row.details,
                            created_at: row.created_at,
                        })
                    })
                    .collect()
                })
            })
            .await
    }

    /// Opens a maintenance window on a test host for `minutes`, up to the overlay's
    /// `svs.runs.max_maintenance_minutes`, from now at the whole second: ace3's `open_window`. `host_ref`
    /// is the host's id, or its short or fully qualified name. It needs `svs:run_register`. No reason, or
    /// minutes out of range, is `InvalidRequest`; an unknown id `NotFound`; a name that isn't a test
    /// host's `Forbidden`, recorded and alerted as a refused registration is; a host a run or another
    /// window holds `Conflict`.
    pub async fn open_svs_maintenance(
        &self,
        actor: &Actor,
        host_ref: &str,
        minutes: i64,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<MaintenanceWindow, ServiceError> {
        let now = whole_second(now);
        let reason = reason.trim();
        let cap = i64::from(self.runs.max_maintenance_minutes);
        self.gate
            .write(actor, "open_svs_maintenance", &SVS_RUN_REGISTER, &|tx| {
                Box::pin(async move {
                    // after the permission, so an actor without it learns nothing of the settings
                    if reason.is_empty() {
                        return Err(ServiceError::InvalidRequest(
                            "a maintenance window needs a reason".to_owned(),
                        ));
                    }
                    if !(1..=cap).contains(&minutes) {
                        return Err(ServiceError::InvalidRequest(format!(
                            "minutes must be from 1 to {cap} (svs.runs.max_maintenance_minutes)"
                        )));
                    }
                    let host = match resolve(tx.conn(), host_ref).await? {
                        Resolved::Host(host) => host,
                        Resolved::Refused(why) => {
                            let call = RefusedCall {
                                launcher: None,
                                test_guid: None,
                                payload: json!({"maintenance": {
                                    "host": host_ref, "minutes": minutes, "reason": reason,
                                }}),
                            };
                            let refused = refuse(
                                tx,
                                self,
                                actor,
                                host_ref,
                                None,
                                &format!("maintenance window refused: {why}"),
                                &call,
                                now,
                            )
                            .await?;
                            let change = Change::added(
                                Target::svs_refusal(&actor.to_string()),
                                &RefusalRecord {
                                    launcher: None,
                                    test_guid: None,
                                    refused: &[refused],
                                },
                            )?;
                            return Ok(Audited::changed(Maintained::Refused(why), change));
                        }
                    };
                    lock_hosts(tx.conn(), &[host.id]).await?;
                    let busy =
                        host_holders(tx.conn(), std::slice::from_ref(&host.hostname), now, None)
                            .await?;
                    if !busy.is_empty() {
                        tracing::info!(
                            host = host.hostname,
                            caller = %actor,
                            "svs maintenance window refused: the host is held"
                        );
                        return Err(ServiceError::Conflict(host_busy_message(&busy)));
                    }
                    let uuid = Uuid::new_v4();
                    // an open window opens SVS's gate, as a registered run does
                    ace_core::svs::attribution::lock_gate_to_open(tx.conn()).await?;
                    let id = sqlx::query_scalar!(
                        "INSERT INTO svs.maintenance_windows
                             (uuid, test_host_id, host, fqdn, reason, opened_by, opened_at, ends_at)
                         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
                         RETURNING id",
                        uuid,
                        host.id,
                        host.hostname,
                        host.fqdn,
                        reason,
                        Json(actor) as _,
                        now,
                        now + TimeDelta::minutes(minutes),
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let opened = window(tx.conn(), id).await?;
                    let change = Change::added(
                        Target::svs_maintenance_window(uuid),
                        &WindowRecord::of(&opened),
                    )?;
                    Ok(Audited::changed(
                        Maintained::Window(Box::new(opened)),
                        change,
                    ))
                })
            })
            .await?
            .into_window()
    }

    /// Ends the test host's open maintenance window now, stored at the whole second: ace3's `end_window`.
    /// It needs `svs:run_register`. An unknown id, or a host with no open window, is `NotFound`; a name
    /// that isn't a test host's is `Forbidden`, recorded and alerted.
    pub async fn end_svs_maintenance(
        &self,
        actor: &Actor,
        host_ref: &str,
        now: DateTime<Utc>,
    ) -> Result<MaintenanceWindow, ServiceError> {
        self.gate
            .write(actor, "end_svs_maintenance", &SVS_RUN_REGISTER, &|tx| {
                Box::pin(async move {
                    let host = match resolve(tx.conn(), host_ref).await? {
                        Resolved::Host(host) => host,
                        Resolved::Refused(why) => {
                            let call = RefusedCall {
                                launcher: None,
                                test_guid: None,
                                payload: json!({"maintenance": {"host": host_ref}}),
                            };
                            let refused = refuse(
                                tx,
                                self,
                                actor,
                                host_ref,
                                None,
                                &format!("maintenance window end refused: {why}"),
                                &call,
                                now,
                            )
                            .await?;
                            let change = Change::added(
                                Target::svs_refusal(&actor.to_string()),
                                &RefusalRecord {
                                    launcher: None,
                                    test_guid: None,
                                    refused: &[refused],
                                },
                            )?;
                            return Ok(Audited::changed(Maintained::Refused(why), change));
                        }
                    };
                    let open = sqlx::query_scalar!(
                        "SELECT id FROM svs.maintenance_windows
                         WHERE host = $1 AND ended_at IS NULL AND ends_at >= $2
                         ORDER BY id LIMIT 1 FOR UPDATE",
                        host.hostname,
                        now,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(id) = open else {
                        return Err(ServiceError::NotFound(format!(
                            "test host {} has no open maintenance window",
                            host.hostname
                        )));
                    };
                    let before = window(tx.conn(), id).await?;
                    sqlx::query!(
                        "UPDATE svs.maintenance_windows
                         SET ended_at = $2, ended_by = $3::jsonb, end_reason = 'ended'
                         WHERE id = $1",
                        id,
                        whole_second(now),
                        Json(actor) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                    let after = window(tx.conn(), id).await?;
                    let change = Change::updated(
                        Target::svs_maintenance_window(after.uuid),
                        &WindowRecord::of(&before),
                        &WindowRecord::of(&after),
                    )?;
                    Ok(Audited::changed(
                        Maintained::Window(Box::new(after)),
                        change,
                    ))
                })
            })
            .await?
            .into_window()
    }

    /// The test host's maintenance windows, latest first: those with an id below `before`, at most `limit`
    /// ([`MAX_MAINTENANCE_PAGE`] at most). ace3's `list_windows`. It needs `svs:run_read`. An unknown id,
    /// or a name that isn't a host name, is `NotFound`: reading never alerts. A name that is one and no
    /// test host's has no windows.
    pub async fn svs_maintenance_windows(
        &self,
        actor: &Actor,
        host_ref: &str,
        limit: i64,
        before: Option<i64>,
    ) -> Result<Vec<MaintenanceWindow>, ServiceError> {
        let limit = limit.clamp(1, MAX_MAINTENANCE_PAGE);
        let host_ref = host_ref.trim();
        self.gate
            .read(actor, "svs_maintenance_windows", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let hostname =
                        if !host_ref.is_empty() && host_ref.bytes().all(|b| b.is_ascii_digit()) {
                            match resolve(tx.conn(), host_ref).await? {
                                Resolved::Host(host) => host.hostname,
                                Resolved::Refused(why) => return Err(ServiceError::NotFound(why)),
                            }
                        } else {
                            split_hostname(host_ref)
                                .map_err(|_| {
                                    ServiceError::NotFound(format!(
                                        "{} is not a host name",
                                        repr(host_ref)
                                    ))
                                })?
                                .0
                        };
                    sqlx::query_as!(
                        WindowRow,
                        r#"SELECT id, uuid, test_host_id, host, fqdn, reason,
                                  opened_by AS "opened_by!: Value", opened_at, ends_at, ended_at,
                                  ended_by AS "ended_by: Value", end_reason, updated_at
                           FROM svs.maintenance_windows
                           WHERE host = $1 AND ($2::bigint IS NULL OR id < $2)
                           ORDER BY id DESC LIMIT $3"#,
                        hostname,
                        before,
                        limit,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(WindowRow::into_window)
                    .collect()
                })
            })
            .await
    }
}

/// What ending a removed host's windows adds to the removal's audit row.
#[derive(Serialize)]
pub(crate) struct EndedMaintenance {
    pub(crate) ended_maintenance: Vec<Uuid>,
}

impl Recorded for EndedMaintenance {}
