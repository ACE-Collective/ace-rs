//! Reading SVS test runs, and a run's comments (PLAN.md 7.10 batch 5, part 5b): the reads of ace3's
//! `aceapi_v2/svs/runs` router, over `ace_service`'s `svs_run_reads`. Everything here reads with
//! `svs:run_read`; a comment's writes need `svs:run_manage`.
//!
//! From ace3: a page is its rows under their own name and `next`, where ace3's is `{data, next_cursor}`; a
//! refused parameter is 400 where ace3 answers 422; an export is one operation, `.../export/{format}`
//! with `csv` or `ndjson`, at ace3's two URLs; who did something is an actor (`kind`, `id`, `name`), where
//! ace3 gives a name.
//!
//! Batch 6 brought the attributions, which the core's SVS hook writes (`ace_core::svs::attribution`):
//! ace3's `GET /attributions` and `/{run_id}/attributions`, each with its export, are
//! `GET /api/svs/v1/runs/attributions` and `/runs/{run_id}/attributions`. A row names its alert (`alert`,
//! ace3's `alert_uuid`) and its detection by the detection's id (`detection`, ace3's content hash). A
//! run's alerts (`/{run_id}/alerts`) are `svs_review`'s, with the run's review (batch 7b).

use ace_service::filters::{FilterScreen, decode};
use ace_service::{
    HistoryRun, MAX_RUN_COMMENT_CHARS, MAX_RUNS_PAGE, RunAttribution, RunBatch, RunComment,
    RunEvent, RunEventRow, RunHistory, RunQuery, RunResult, RunRow, RunSummary, SuppressionShare,
    SvsFeed,
};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::params::Params;
use crate::svs_runs::RunTargetBody;

/// An export's format, from its path.
pub(crate) fn format_of(text: &str) -> Result<Format, ApiError> {
    match text {
        "csv" => Ok(Format::Csv),
        "ndjson" => Ok(Format::Ndjson),
        other => Err(ApiError::bad_request(format!(
            "an export is csv or ndjson, not {other:?}"
        ))),
    }
}

pub(crate) fn cell(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

pub(crate) fn uuid_of(text: &str) -> Result<Uuid, ApiError> {
    text.parse()
        .map_err(|_| ApiError::bad_request(format!("{text:?} isn't a run's uuid")))
}

/// What the runs screen adds to a run: its test's name, who owns and reviewed it, whether it needs
/// attention, and its result's and alerts' summary.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunSeenBody {
    /// From the catalog.
    test_name: Option<String>,
    /// The test's ATT&CK technique, from the catalog.
    technique: Option<String>,
    technique_name: Option<String>,
    /// The owner's username.
    owner: Option<String>,
    /// Who reviewed it, by username.
    reviewer: Option<String>,
    reviewed_at: Option<DateTime<Utc>>,
    /// A late alert or a manual association came after the review.
    changed_since_review: bool,
    /// The run is in the Needs attention view: ended and not reviewed, failed, changed since it was
    /// reviewed, or reviewed or closed with an alert still open.
    needs_attention: bool,
    /// Expected signatures that fired.
    result_hit: i64,
    /// The expected signatures the result judged: hit, missing or possibly suppressed.
    result_expected: i64,
    /// Expected signatures that didn't fire, possibly suppressed ones included.
    result_missing: i64,
    result_possibly_suppressed: i64,
    /// Signatures that fired and nobody has decided about.
    result_candidate: i64,
    result_rejected: i64,
    result_ignored: i64,
    /// Signatures that fired only during the test's cleanup.
    result_cleanup: i64,
    /// The result is about to be recomputed.
    result_stale: bool,
    /// `result_hit` as signed off at the run's latest review; 0 until it is reviewed.
    reviewed_hit: i64,
    reviewed_expected: i64,
    reviewed_missing: i64,
    reviewed_possibly_suppressed: i64,
    /// The alerts attributed to the run; of those, attributed by a marker, by context alone, and late.
    alerts: i64,
    marker_alerts: i64,
    context_alerts: i64,
    late_alerts: i64,
}

impl RunSeenBody {
    fn of(row: &RunRow) -> Self {
        let s: &RunSummary = &row.summary;
        RunSeenBody {
            test_name: row.test_name.clone(),
            technique: row.technique.clone(),
            technique_name: row.technique_name.clone(),
            owner: row.owner.clone(),
            reviewer: row.reviewer.clone(),
            reviewed_at: row.reviewed_at,
            changed_since_review: row.changed_since_review,
            needs_attention: row.needs_attention,
            result_hit: s.hit,
            result_expected: s.expected(),
            result_missing: s.all_missing(),
            result_possibly_suppressed: s.possibly_suppressed,
            result_candidate: s.candidate,
            result_rejected: s.rejected,
            result_ignored: s.ignored,
            result_cleanup: s.cleanup,
            result_stale: s.result_stale,
            reviewed_hit: s.reviewed_hit,
            reviewed_expected: s.reviewed_expected(),
            reviewed_missing: s.reviewed_all_missing(),
            reviewed_possibly_suppressed: s.reviewed_possibly_suppressed,
            alerts: s.alerts,
            marker_alerts: s.marker_alerts,
            context_alerts: s.context_alerts,
            late_alerts: s.late_alerts,
        }
    }
}

/// What a run's detail adds to what its launcher sees: what the runs screen shows of it, and its search
/// in the site's log tooling.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunDetailSeenBody {
    #[serde(flatten)]
    seen: RunSeenBody,
    /// The run's search in the site's log tooling, from `svs.log_search_url`; null when that isn't set.
    log_search_url: Option<String>,
}

impl RunDetailSeenBody {
    pub(crate) fn of(row: &RunRow, log_search_url: Option<String>) -> Self {
        RunDetailSeenBody {
            seen: RunSeenBody::of(row),
            log_search_url,
        }
    }
}

/// A run as the runs screen lists it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunRowBody {
    /// The run's uuid.
    run_id: Uuid,
    /// `created`, `started`, `ended`, `reviewed`, `canceled`, `error` or `closed`.
    state: String,
    /// The catalog test (`/api/svs/v1/tests/{guid}`).
    test_guid: Uuid,
    /// The platform the run is on, an ATT&CK platform slug.
    platform: String,
    /// The run's marker.
    marker: String,
    targets: Vec<RunTargetBody>,
    launcher: String,
    batch_id: Option<String>,
    /// When the run was registered.
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    /// When the launcher reported how the test executed.
    executed_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    /// When the launcher said the test's cleanup began: detections after it are the cleanup's.
    cleanup_at: Option<DateTime<Utc>>,
    ended_at: Option<DateTime<Utc>>,
    /// Why a person ended it before its observation window passed; null when the window passed.
    end_reason: Option<String>,
    canceled_at: Option<DateTime<Utc>>,
    closed_at: Option<DateTime<Utc>>,
    observation_ends_at: Option<DateTime<Utc>>,
    attribution_ends_at: Option<DateTime<Utc>>,
    error_reason: Option<String>,
    close_reason: Option<String>,
    #[serde(flatten)]
    seen: RunSeenBody,
    /// When the row last changed: the `changed_since` key. A change to its result or alerts doesn't change
    /// it: pull `/api/svs/v1/runs/results`.
    updated_at: DateTime<Utc>,
}

impl From<RunRow> for RunRowBody {
    fn from(row: RunRow) -> Self {
        let seen = RunSeenBody::of(&row);
        let run = row.run;
        RunRowBody {
            run_id: run.uuid,
            state: run.state.as_str().to_owned(),
            test_guid: run.test_guid,
            platform: run.platform,
            marker: run.marker,
            targets: run.targets.into_iter().map(Into::into).collect(),
            launcher: run.launcher,
            batch_id: run.batch_id,
            created_at: run.created_at,
            started_at: run.started_at,
            executed_at: run.executed_at,
            exit_code: run.exit_code,
            cleanup_at: run.cleanup_at,
            ended_at: run.ended_at,
            end_reason: run.end_reason,
            canceled_at: run.canceled_at,
            closed_at: run.closed_at,
            observation_ends_at: run.observation_ends_at,
            attribution_ends_at: run.attribution_ends_at,
            error_reason: run.error_reason,
            close_reason: run.close_reason,
            seen,
            updated_at: run.updated_at,
        }
    }
}

impl ExportRow for RunRowBody {
    const HEADER: &'static [&'static str] = &[
        "run_id",
        "state",
        "test_guid",
        "test_name",
        "technique",
        "technique_name",
        "platform",
        "marker",
        "targets",
        "launcher",
        "batch_id",
        "created_at",
        "started_at",
        "executed_at",
        "exit_code",
        "cleanup_at",
        "ended_at",
        "end_reason",
        "canceled_at",
        "closed_at",
        "observation_ends_at",
        "attribution_ends_at",
        "error_reason",
        "close_reason",
        "owner",
        "reviewer",
        "reviewed_at",
        "changed_since_review",
        "needs_attention",
        "result_hit",
        "result_expected",
        "result_missing",
        "result_possibly_suppressed",
        "result_candidate",
        "result_rejected",
        "result_ignored",
        "result_cleanup",
        "result_stale",
        "reviewed_hit",
        "reviewed_expected",
        "reviewed_missing",
        "reviewed_possibly_suppressed",
        "alerts",
        "marker_alerts",
        "context_alerts",
        "late_alerts",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        let s = &self.seen;
        // targets joined as host or host/user with ",", as ace3's CSV writes them
        let targets = self
            .targets
            .iter()
            .map(|target| match &target.username {
                Some(username) => format!("{}/{username}", target.hostname),
                None => target.hostname.clone(),
            })
            .collect::<Vec<_>>()
            .join(",");
        vec![
            self.run_id.to_string(),
            self.state.clone(),
            self.test_guid.to_string(),
            cell(&s.test_name),
            cell(&s.technique),
            cell(&s.technique_name),
            self.platform.clone(),
            self.marker.clone(),
            targets,
            self.launcher.clone(),
            cell(&self.batch_id),
            time_cell(Some(self.created_at)),
            time_cell(self.started_at),
            time_cell(self.executed_at),
            self.exit_code
                .map(|code| code.to_string())
                .unwrap_or_default(),
            time_cell(self.cleanup_at),
            time_cell(self.ended_at),
            cell(&self.end_reason),
            time_cell(self.canceled_at),
            time_cell(self.closed_at),
            time_cell(self.observation_ends_at),
            time_cell(self.attribution_ends_at),
            cell(&self.error_reason),
            cell(&self.close_reason),
            cell(&s.owner),
            cell(&s.reviewer),
            time_cell(s.reviewed_at),
            s.changed_since_review.to_string(),
            s.needs_attention.to_string(),
            s.result_hit.to_string(),
            s.result_expected.to_string(),
            s.result_missing.to_string(),
            s.result_possibly_suppressed.to_string(),
            s.result_candidate.to_string(),
            s.result_rejected.to_string(),
            s.result_ignored.to_string(),
            s.result_cleanup.to_string(),
            s.result_stale.to_string(),
            s.reviewed_hit.to_string(),
            s.reviewed_expected.to_string(),
            s.reviewed_missing.to_string(),
            s.reviewed_possibly_suppressed.to_string(),
            s.alerts.to_string(),
            s.marker_alerts.to_string(),
            s.context_alerts.to_string(),
            s.late_alerts.to_string(),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of runs.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunPageBody {
    runs: Vec<RunRowBody>,
    /// Pass it as `cursor`, with the same filters and `changed_since`, for the next page; null on the
    /// last.
    next: Option<String>,
}

/// How many runs the filters match.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunCountBody {
    count: i64,
}

/// One `batch_id` over the runs the filters match: only those runs are counted.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunBatchBody {
    batch_id: String,
    runs: i64,
    /// The runs per state, every state named.
    #[schema(value_type = Object)]
    states: Value,
    /// The runs in the Needs attention view.
    needs_attention: i64,
    /// When its first run was registered.
    first_created_at: DateTime<Utc>,
    /// When its latest run was registered; the batches are newest first by it.
    last_created_at: DateTime<Utc>,
    /// Summed over the runs: expected signatures that fired, that the results judged, that didn't fire
    /// (possibly suppressed ones included), and undecided ones that fired.
    result_hit: i64,
    result_expected: i64,
    result_missing: i64,
    result_candidate: i64,
    #[serde(skip)]
    counts: Vec<i64>,
}

impl From<RunBatch> for RunBatchBody {
    fn from(batch: RunBatch) -> Self {
        RunBatchBody {
            states: Value::Object(
                batch
                    .states
                    .iter()
                    .map(|(state, count)| (state.as_str().to_owned(), Value::from(*count)))
                    .collect(),
            ),
            counts: batch.states.iter().map(|(_, count)| *count).collect(),
            batch_id: batch.batch_id,
            runs: batch.runs,
            needs_attention: batch.needs_attention,
            first_created_at: batch.first_created_at,
            last_created_at: batch.last_created_at,
            result_hit: batch.result_hit,
            result_expected: batch.result_expected,
            result_missing: batch.result_missing,
            result_candidate: batch.result_candidate,
        }
    }
}

impl ExportRow for RunBatchBody {
    // the CSV spreads a batch's states over one column each, as ace3's does
    const HEADER: &'static [&'static str] = &[
        "batch_id",
        "runs",
        "state_created",
        "state_started",
        "state_ended",
        "state_reviewed",
        "state_canceled",
        "state_error",
        "state_closed",
        "needs_attention",
        "first_created_at",
        "last_created_at",
        "result_hit",
        "result_expected",
        "result_missing",
        "result_candidate",
    ];

    fn cells(&self) -> Vec<String> {
        let mut cells = vec![self.batch_id.clone(), self.runs.to_string()];
        cells.extend(self.counts.iter().map(i64::to_string));
        cells.extend([
            self.needs_attention.to_string(),
            time_cell(Some(self.first_created_at)),
            time_cell(Some(self.last_created_at)),
            self.result_hit.to_string(),
            self.result_expected.to_string(),
            self.result_missing.to_string(),
            self.result_candidate.to_string(),
        ]);
        cells
    }
}

/// A page of batches.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunBatchPageBody {
    batches: Vec<RunBatchBody>,
    /// Pass it as `cursor`, with the same filters, for the next page; null on the last.
    next: Option<String>,
}

/// One row of a run's event log, as the feed over every run's has it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunFeedEventBody {
    /// The event's id; a run's events are in id order.
    id: i64,
    /// The run's uuid.
    run_id: Uuid,
    /// What happened: `registered`, `transition`, `launcher_call`, `result_computed`,
    /// `candidate_decision` and the kinds later parts write.
    kind: String,
    from_state: Option<String>,
    to_state: Option<String>,
    actor: Option<ActorBody>,
    /// What the event carries; its shape depends on `kind`.
    #[schema(value_type = Option<Object>)]
    details: Option<Value>,
    created_at: DateTime<Utc>,
    /// The feed's `changed_since` key; null in a run's own log, which is in id order.
    updated_at: Option<DateTime<Utc>>,
}

impl From<RunEventRow> for RunFeedEventBody {
    fn from(event: RunEventRow) -> Self {
        RunFeedEventBody {
            id: event.id,
            run_id: event.run,
            kind: event.kind,
            from_state: event.from_state.map(|state| state.as_str().to_owned()),
            to_state: event.to_state.map(|state| state.as_str().to_owned()),
            actor: event.actor.map(ActorBody::from),
            details: event.details,
            created_at: event.created_at,
            updated_at: Some(event.updated_at),
        }
    }
}

impl RunFeedEventBody {
    fn of_run(run: Uuid, event: RunEvent) -> Self {
        RunFeedEventBody {
            id: event.id,
            run_id: run,
            kind: event.kind,
            from_state: event.from_state.map(|state| state.as_str().to_owned()),
            to_state: event.to_state.map(|state| state.as_str().to_owned()),
            actor: event.actor.map(ActorBody::from),
            details: event.details,
            created_at: event.created_at,
            updated_at: None,
        }
    }
}

impl ExportRow for RunFeedEventBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "run_id",
        "kind",
        "from_state",
        "to_state",
        "actor",
        "details",
        "created_at",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.run_id.to_string(),
            self.kind.clone(),
            cell(&self.from_state),
            cell(&self.to_state),
            self.actor
                .as_ref()
                .map(ActorBody::shown)
                .unwrap_or_default(),
            // details as a JSON string, as ace3's CSV writes them
            self.details
                .as_ref()
                .map(Value::to_string)
                .unwrap_or_default(),
            time_cell(Some(self.created_at)),
            time_cell(self.updated_at),
        ]
    }
}

/// A page of the event feed.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunFeedEventPageBody {
    events: Vec<RunFeedEventBody>,
    /// Pass it as `cursor`, with the same filters and `changed_since`, for the next page; null on the
    /// last.
    next: Option<String>,
}

/// One signature of a run's result.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunResultBody {
    /// The row's id.
    id: i64,
    /// The run's uuid.
    run_id: Uuid,
    signature_uuid: String,
    /// `yara`, `hunt`, `builtin` and so on.
    signature_family: Option<String>,
    signature_name: Option<String>,
    /// `hit`, `missing`, `possibly_suppressed`, `candidate`, `rejected`, `ignored` or `cleanup`; null once
    /// the signature left the live result and the row holds only the reviewed result.
    status: Option<String>,
    /// The run's attributed alerts that carry the signature.
    alert_count: i32,
    /// Every attribution of it is late.
    late_only: bool,
    /// Every attribution of it is by context alone.
    context_only: bool,
    /// Some attribution of it was judged by a fallback event time: a hunt's query time, when its producer
    /// made the alert, or the alert's insert time.
    fallback_time: bool,
    /// The rule's own content hash when the result was computed.
    content_hash: Option<String>,
    /// possibly_suppressed: the hunt's latest alert within its suppression period; null when the hunter
    /// recorded that it dropped the run's match.
    suppressing_alert: Option<Uuid>,
    /// The status as signed off; null until the run is reviewed.
    reviewed_status: Option<String>,
    reviewed_alert_count: Option<i32>,
    reviewed_late_only: Option<bool>,
    reviewed_content_hash: Option<String>,
    /// The feed's `changed_since` key.
    updated_at: DateTime<Utc>,
}

impl From<RunResult> for RunResultBody {
    fn from(row: RunResult) -> Self {
        RunResultBody {
            id: row.id,
            run_id: row.run,
            signature_uuid: row.signature_uuid,
            signature_family: row.signature_family,
            signature_name: row.signature_name,
            status: row.status,
            alert_count: row.alert_count,
            late_only: row.late_only,
            context_only: row.context_only,
            fallback_time: row.fallback_time,
            content_hash: row.content_hash,
            suppressing_alert: row.suppressing_alert,
            reviewed_status: row.reviewed_status,
            reviewed_alert_count: row.reviewed_alert_count,
            reviewed_late_only: row.reviewed_late_only,
            reviewed_content_hash: row.reviewed_content_hash,
            updated_at: row.updated_at,
        }
    }
}

impl ExportRow for RunResultBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "run_id",
        "signature_uuid",
        "signature_family",
        "signature_name",
        "status",
        "alert_count",
        "late_only",
        "context_only",
        "fallback_time",
        "content_hash",
        "suppressing_alert",
        "reviewed_status",
        "reviewed_alert_count",
        "reviewed_late_only",
        "reviewed_content_hash",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.run_id.to_string(),
            self.signature_uuid.clone(),
            cell(&self.signature_family),
            cell(&self.signature_name),
            cell(&self.status),
            self.alert_count.to_string(),
            self.late_only.to_string(),
            self.context_only.to_string(),
            self.fallback_time.to_string(),
            cell(&self.content_hash),
            self.suppressing_alert
                .map(|alert| alert.to_string())
                .unwrap_or_default(),
            cell(&self.reviewed_status),
            self.reviewed_alert_count
                .map(|count| count.to_string())
                .unwrap_or_default(),
            self.reviewed_late_only
                .map(|late| late.to_string())
                .unwrap_or_default(),
            cell(&self.reviewed_content_hash),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of the result feed.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunResultFeedPageBody {
    results: Vec<RunResultBody>,
    /// Pass it as `cursor`, with the same filters and `changed_since`, for the next page; null on the
    /// last.
    next: Option<String>,
}

/// A page of one run's result.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunResultPageBody {
    results: Vec<RunResultBody>,
    /// Pass it as `after` for the next page; null on the last.
    next: Option<i64>,
    /// Something changed since the result was computed, and the timers recompute it shortly.
    stale: bool,
    /// When it was last computed.
    computed_at: Option<DateTime<Utc>>,
}

/// One detection of an alert attributed to a run, removed ones included.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunAttributionBody {
    /// The row's id; a run's attributions are in id order.
    id: i64,
    /// The run's uuid.
    run_id: Uuid,
    /// The alert's uuid.
    alert: Uuid,
    /// The detection's id, as the alert's detections list it.
    detection: i64,
    signature_uuid: Option<String>,
    /// `yara`, `hunt`, `builtin` and so on.
    signature_family: Option<String>,
    /// `marker` or `context`; a person's association is `marker`.
    confidence: String,
    /// The alert's event came after the run's observation window.
    late: bool,
    /// The alert's event time it was judged by.
    event_time: Option<DateTime<Utc>>,
    /// Its event time is at or after the run's `cleanup_at`: the test's cleanup caused it, so it is left
    /// out of the run's candidates and expectations.
    cleanup: bool,
    /// Where `event_time` came from: `event` (the event's own), `query_time` (a hunt couldn't extract
    /// it), `now` (nothing gave the alert a time, so its producer used the time it made it) or
    /// `insert_time` (the alert has none).
    event_time_source: Option<String>,
    /// `event_time` is a fallback, which may have put the alert in the wrong window.
    fallback_time: bool,
    /// `router` (the core's SVS hook) or `manual` (a person associated the alert).
    source: String,
    /// Where the agreeing marker was found: `observable`, `detection`, `root_details`, `analysis` or
    /// `file_contents`; null for context or manual.
    scan_point: Option<String>,
    /// Who attributed it: the component `svs` for the hook, else the person.
    actor: Option<ActorBody>,
    created_at: DateTime<Utc>,
    /// When it stopped holding; null while it holds.
    removed_at: Option<DateTime<Utc>>,
    /// The component `svs` when the hook found it no longer applies, else the person who disassociated it.
    removed_by: Option<ActorBody>,
    removal_reason: Option<String>,
    /// When a person kept this context attribution.
    kept_at: Option<DateTime<Utc>>,
    kept_by: Option<ActorBody>,
    /// The feed's `changed_since` key.
    updated_at: DateTime<Utc>,
}

impl From<RunAttribution> for RunAttributionBody {
    fn from(row: RunAttribution) -> Self {
        RunAttributionBody {
            id: row.id,
            run_id: row.run,
            alert: row.alert,
            detection: row.detection,
            signature_uuid: row.signature_uuid,
            signature_family: row.signature_family,
            confidence: row.confidence.as_str().to_owned(),
            late: row.late,
            event_time: row.event_time,
            cleanup: row.cleanup,
            event_time_source: row.event_time_source,
            fallback_time: row.fallback_time,
            source: row.source,
            scan_point: row.scan_point,
            actor: row.actor.map(ActorBody::from),
            created_at: row.created_at,
            removed_at: row.removed_at,
            removed_by: row.removed_by.map(ActorBody::from),
            removal_reason: row.removal_reason,
            kept_at: row.kept_at,
            kept_by: row.kept_by.map(ActorBody::from),
            updated_at: row.updated_at,
        }
    }
}

impl ExportRow for RunAttributionBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "run_id",
        "alert",
        "detection",
        "signature_uuid",
        "signature_family",
        "confidence",
        "late",
        "event_time",
        "cleanup",
        "event_time_source",
        "fallback_time",
        "source",
        "scan_point",
        "actor",
        "created_at",
        "removed_at",
        "removed_by",
        "removal_reason",
        "kept_at",
        "kept_by",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        let shown =
            |actor: &Option<ActorBody>| actor.as_ref().map(ActorBody::shown).unwrap_or_default();
        vec![
            self.id.to_string(),
            self.run_id.to_string(),
            self.alert.to_string(),
            self.detection.to_string(),
            cell(&self.signature_uuid),
            cell(&self.signature_family),
            self.confidence.clone(),
            self.late.to_string(),
            time_cell(self.event_time),
            self.cleanup.to_string(),
            cell(&self.event_time_source),
            self.fallback_time.to_string(),
            self.source.clone(),
            cell(&self.scan_point),
            shown(&self.actor),
            time_cell(Some(self.created_at)),
            time_cell(self.removed_at),
            shown(&self.removed_by),
            cell(&self.removal_reason),
            time_cell(self.kept_at),
            shown(&self.kept_by),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of the attribution feed.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunAttributionFeedPageBody {
    attributions: Vec<RunAttributionBody>,
    /// Pass it as `cursor`, with the same filters and `changed_since`, for the next page; null on the
    /// last.
    next: Option<String>,
}

/// A page of one run's attributions.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunAttributionPageBody {
    attributions: Vec<RunAttributionBody>,
    /// Pass it as `after` for the next page; null on the last.
    next: Option<i64>,
}

/// An earlier run of a run's history.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HistoryRunBody {
    run_id: Uuid,
    state: String,
    created_at: DateTime<Utc>,
    reviewed_at: Option<DateTime<Utc>>,
}

impl From<HistoryRun> for HistoryRunBody {
    fn from(run: HistoryRun) -> Self {
        HistoryRunBody {
            run_id: run.run,
            state: run.state.as_str().to_owned(),
            created_at: run.created_at,
            reviewed_at: run.reviewed_at,
        }
    }
}

/// How one signature of a run's result did in the earlier runs.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SignatureHistoryBody {
    signature_uuid: String,
    /// Its status in each of the runs, in their order: as reviewed for a reviewed run, else live; null
    /// when it isn't in that run's result.
    statuses: Vec<Option<String>>,
}

/// How the signatures of a run's result did in the test's earlier runs.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunHistoryBody {
    /// The test's ended and reviewed runs on this run's platform registered before this one, newest
    /// first.
    runs: Vec<HistoryRunBody>,
    /// One per signature of this run's result, in its order.
    signatures: Vec<SignatureHistoryBody>,
}

impl From<RunHistory> for RunHistoryBody {
    fn from(history: RunHistory) -> Self {
        RunHistoryBody {
            runs: history.runs.into_iter().map(Into::into).collect(),
            signatures: history
                .signatures
                .into_iter()
                .map(|signature| SignatureHistoryBody {
                    signature_uuid: signature.signature_uuid,
                    statuses: signature.statuses,
                })
                .collect(),
        }
    }
}

/// How many of the expected signatures missing from reviewed runs were possibly suppressed: the trigger to
/// revisit keeping the hunter from suppressing test targets. Read from every run's result as signed off.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SuppressionShareBody {
    /// Expected signatures missing from the signed-off results, possibly suppressed ones included.
    missing: i64,
    /// Of those, the possibly suppressed.
    possibly_suppressed: i64,
    /// `possibly_suppressed / missing`; null while nothing is missing.
    share: Option<f64>,
    /// The runs with a signed-off result.
    reviewed_runs: i64,
    /// When the first run was reviewed.
    first_reviewed_at: Option<DateTime<Utc>>,
    /// 50 runs are reviewed, or 90 days passed since the first review.
    trigger_reached: bool,
    /// The trigger is reached and more than 10% of the missing signatures were possibly suppressed:
    /// preventing suppression is worth reconsidering.
    reconsider: bool,
}

impl From<SuppressionShare> for SuppressionShareBody {
    fn from(share: SuppressionShare) -> Self {
        SuppressionShareBody {
            share: share.share(),
            reconsider: share.reconsider(),
            missing: share.missing,
            possibly_suppressed: share.possibly_suppressed,
            reviewed_runs: share.reviewed_runs,
            first_reviewed_at: share.first_reviewed_at,
            trigger_reached: share.trigger_reached,
        }
    }
}

/// A comment's text.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunCommentRequest {
    /// 1 to 16384 characters.
    comment: String,
}

/// A person's comment on a run.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RunCommentBody {
    id: i64,
    run_id: Uuid,
    /// Its author's username.
    user: Option<String>,
    comment: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<RunComment> for RunCommentBody {
    fn from(comment: RunComment) -> Self {
        RunCommentBody {
            id: comment.id,
            run_id: comment.run,
            user: comment.user,
            comment: comment.comment,
            created_at: comment.created_at,
            updated_at: comment.updated_at,
        }
    }
}

/// The runs' list's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct RunsQuery {
    /// A filter in the share-link encoding (`[!]slug:v1,v2`) with the runs screen's slugs:
    /// needs_attention, state, test, test_name, technique (T1059 also finds its sub-techniques), target,
    /// platform, launcher, batch, created, started, ended, reviewed, owner, reviewer, reason,
    /// changed_since_review, has_open_alerts, has_missing, has_possibly_suppressed, has_candidates,
    /// has_late, has_context_only. Repeat it for more; filters are ANDed, the values of one ORed.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only what was written or changed at or after this time; the pages are then in (updated_at, id)
    /// order, and hold nothing changed in the last few seconds.
    changed_since: Option<String>,
    /// The timezone relative date filters (`-7d`) resolve in; UTC when left out.
    tz: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// The filters of a count, a batch listing or an export: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct RunsFilterQuery {
    /// A filter, as the runs' list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only what was written or changed at or after this time, where the listing takes it.
    changed_since: Option<String>,
    /// The timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
}

/// One run's page of results, or its history.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct RunResultsQuery {
    /// The `next` of the page before.
    after: Option<i64>,
    /// At most this many, 1 to 1000; 100 when left out.
    limit: Option<i64>,
}

#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct RunHistoryQuery {
    /// How many earlier runs, 1 to 50; 10 when left out.
    runs: Option<u32>,
}

fn run_query(params: &Params) -> Result<RunQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::SvsRuns, &params.all("f"), true)?;
    Ok(RunQuery {
        filters,
        changed_since: params.time("changed_since")?,
        tz: params.tz()?,
    })
}

fn limit_of(params: &Params) -> Result<Option<u32>, ApiError> {
    params.parsed("limit", "a number from 1 to 1000")
}

pub(crate) fn after_limit(params: &Params) -> Result<(Option<i64>, i64), ApiError> {
    let after = params.parsed::<i64>("after", "a number")?;
    let most = i64::from(MAX_RUNS_PAGE);
    let limit = params.parsed::<i64>("limit", "a number")?.unwrap_or(100);
    if !(1..=most).contains(&limit) {
        return Err(ApiError::bad_request(format!(
            "limit is from 1 to {most}, not {limit}"
        )));
    }
    Ok((after, limit))
}

/// The runs the filters match, newest first, a page at a time; with `changed_since`, in (updated_at, id)
/// order. Follow `next` with the same filters and `changed_since` until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs",
    tag = "svs",
    params(RunsQuery),
    responses(
        (status = 200, description = "A page of runs", body = RunPageBody),
        (status = 400, description = "A filter, time, timezone, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<RunPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = run_query(&params)?;
    let page = web
        .service
        .svs_runs(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(RunPageBody {
        runs: page.runs.into_iter().map(Into::into).collect(),
        next: page.next_cursor,
    }))
}

/// Every run the list's filters match, in its order, as CSV (targets joined as host or host/user with
/// `,`) or NDJSON (one run as the list gives it on each line). A failure part-way ends a CSV there and an
/// NDJSON with an `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), RunsFilterQuery),
    responses(
        (status = 200, description = "The runs, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, filter, time or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More runs than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = run_query(&Params::of(raw)?)?;
    let total = service
        .svs_feed_count(&actor, &SvsFeed::Runs(&query), max)
        .await?;
    let first = service
        .svs_runs(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.runs.into_iter().map(RunRowBody::from).collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-runs",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_runs(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.runs.into_iter().map(RunRowBody::from).collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// How many runs the filters match: `f=needs_attention:true` is the count on the GUI's SVS entry.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/count",
    tag = "svs",
    params(RunsFilterQuery),
    responses(
        (status = 200, description = "The count", body = RunCountBody),
        (status = 400, description = "A filter or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn count(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<RunCountBody>, ApiError> {
    let query = run_query(&Params::of(raw)?)?;
    Ok(Json(RunCountBody {
        count: web.service.svs_run_count(&actor, &query).await?,
    }))
}

/// How many of the expected signatures missing from reviewed runs were possibly suppressed, and whether
/// the trigger to revisit keeping the hunter from suppressing test targets is reached.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/suppression-share",
    tag = "svs",
    responses(
        (status = 200, description = "The share", body = SuppressionShareBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn suppression_share(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<SuppressionShareBody>, ApiError> {
    Ok(Json(
        web.service
            .svs_suppression_share(&actor, Utc::now())
            .await?
            .into(),
    ))
}

/// One row per `batch_id` over the runs the filters match, summing only those runs: their states, how
/// many need attention, and their results. The batch with the latest run comes first; runs without a
/// `batch_id` are left out. Follow `next`, with the same filters, until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/batches",
    tag = "svs",
    params(RunsQuery),
    responses(
        (status = 200, description = "A page of batches", body = RunBatchPageBody),
        (status = 400, description = "A filter, timezone, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn batches(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<RunBatchPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = run_query(&params)?;
    let page = web
        .service
        .svs_run_batches(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(RunBatchPageBody {
        batches: page.batches.into_iter().map(Into::into).collect(),
        next: page.next_cursor,
    }))
}

/// Every batch, as CSV (one `state_<state>` column per state) or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/batches/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), RunsFilterQuery),
    responses(
        (status = 200, description = "The batches, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, filter or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More batches than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_batches(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = run_query(&Params::of(raw)?)?;
    let total = service
        .svs_feed_count(&actor, &SvsFeed::Batches(&query), max)
        .await?;
    let first = service
        .svs_run_batches(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.batches.into_iter().map(RunBatchBody::from).collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-run-batches",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_run_batches(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.batches.into_iter().map(RunBatchBody::from).collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// The events of every run the filters match, in (updated_at, id) order: the runs' change feed. An event
/// shows up a few seconds after it's written, so a pull resumed from its last `updated_at` never misses
/// one, and may repeat one.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/events",
    tag = "svs",
    params(RunsQuery),
    responses(
        (status = 200, description = "A page of events", body = RunFeedEventPageBody),
        (status = 400, description = "A filter, time, timezone, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn event_feed(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<RunFeedEventPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = run_query(&params)?;
    let page = web
        .service
        .svs_run_event_feed(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(RunFeedEventPageBody {
        events: page.events.into_iter().map(Into::into).collect(),
        next: page.next_cursor,
    }))
}

/// The event feed, as CSV (details as a JSON string) or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/events/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), RunsFilterQuery),
    responses(
        (status = 200, description = "The events, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, filter, time or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More events than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_event_feed(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = run_query(&Params::of(raw)?)?;
    let total = service
        .svs_feed_count(&actor, &SvsFeed::Events(&query), max)
        .await?;
    let first = service
        .svs_run_event_feed(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first
            .events
            .into_iter()
            .map(RunFeedEventBody::from)
            .collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-run-events",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_run_event_feed(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.events
                        .into_iter()
                        .map(RunFeedEventBody::from)
                        .collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// The result rows of every run the filters match, in (updated_at, id) order: what reports pull. A row
/// shows up a few seconds after it's written, so a pull resumed from its last `updated_at` never misses
/// one, and may repeat one.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/results",
    tag = "svs",
    params(RunsQuery),
    responses(
        (status = 200, description = "A page of result rows", body = RunResultFeedPageBody),
        (status = 400, description = "A filter, time, timezone, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn result_feed(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<RunResultFeedPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = run_query(&params)?;
    let page = web
        .service
        .svs_run_result_feed(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(RunResultFeedPageBody {
        results: page.results.into_iter().map(Into::into).collect(),
        next: page.next_cursor,
    }))
}

/// The result feed, as CSV or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/results/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), RunsFilterQuery),
    responses(
        (status = 200, description = "The result rows, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, filter, time or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More result rows than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_result_feed(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = run_query(&Params::of(raw)?)?;
    let total = service
        .svs_feed_count(&actor, &SvsFeed::Results(&query), max)
        .await?;
    let first = service
        .svs_run_result_feed(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.results.into_iter().map(RunResultBody::from).collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-run-results",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_run_result_feed(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.results.into_iter().map(RunResultBody::from).collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// The attributions of every run the filters match, removed ones included, in (updated_at, id) order: one
/// row per (run, alert, detection), written by the core's SVS hook at the end of an alert's pass or by a
/// person. A row shows up a few seconds after it's written, removed or kept, so a pull resumed from its
/// last `updated_at` never misses one, and may repeat one.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/attributions",
    tag = "svs",
    params(RunsQuery),
    responses(
        (status = 200, description = "A page of attributions", body = RunAttributionFeedPageBody),
        (status = 400, description = "A filter, time, timezone, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn attribution_feed(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<RunAttributionFeedPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = run_query(&params)?;
    let page = web
        .service
        .svs_attribution_feed(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(RunAttributionFeedPageBody {
        attributions: page.attributions.into_iter().map(Into::into).collect(),
        next: page.next_cursor,
    }))
}

/// The attribution feed, as CSV or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/attributions/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), RunsFilterQuery),
    responses(
        (status = 200, description = "The attributions, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, filter, time or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More attributions than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_attribution_feed(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = run_query(&Params::of(raw)?)?;
    let total = service
        .svs_feed_count(&actor, &SvsFeed::Attributions(&query), max)
        .await?;
    let first = service
        .svs_attribution_feed(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first
            .attributions
            .into_iter()
            .map(RunAttributionBody::from)
            .collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-attributions",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_attribution_feed(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.attributions
                        .into_iter()
                        .map(RunAttributionBody::from)
                        .collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// A run's attributions, one row per (alert, detection) in id order, removed ones included.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/attributions",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid"), RunResultsQuery),
    responses(
        (status = 200, description = "A page of the run's attributions", body = RunAttributionPageBody),
        (status = 400, description = "An id that isn't a uuid, or a parameter that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
    )
)]
pub(crate) async fn run_attributions(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<RunAttributionPageBody>, ApiError> {
    let Path(run) = path?;
    let uuid = uuid_of(&run)?;
    let (after, limit) = after_limit(&Params::of(raw)?)?;
    let rows = web
        .service
        .svs_run_attributions(&actor, uuid, after, Some(limit))
        .await?;
    let next = (rows.len() as i64 == limit)
        .then(|| rows.last().map(|row| row.id))
        .flatten();
    Ok(Json(RunAttributionPageBody {
        attributions: rows.into_iter().map(Into::into).collect(),
        next,
    }))
}

/// A run's attributions, as CSV or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/attributions/export/{format}",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("format" = String, Path, description = "`csv` or `ndjson`"),
    ),
    responses(
        (status = 200, description = "The attributions, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "An id that isn't a uuid, or a format that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 413, description = "More attributions than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_run_attributions(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((run, format)) = path?;
    let (uuid, format) = (uuid_of(&run)?, format_of(&format)?);
    let (service, max) = (web.service, web.config.max_export_rows);
    let total = service
        .svs_feed_count(&actor, &SvsFeed::RunAttributions(uuid), max)
        .await?;
    let page = i64::from(EXPORT_PAGE);
    let rows = move |rows: Vec<RunAttribution>| {
        let next = (rows.len() as i64 == page)
            .then(|| rows.last().map(|row| row.id))
            .flatten();
        (
            rows.into_iter()
                .map(RunAttributionBody::from)
                .collect::<Vec<_>>(),
            next,
        )
    };
    let first = rows(
        service
            .svs_run_attributions(&actor, uuid, None, Some(page))
            .await?,
    );
    export::respond(
        format,
        &format!("svs-run-{uuid}-attributions"),
        max,
        total,
        first,
        move |after: i64| {
            let (service, actor) = (service.clone(), actor.clone());
            async move {
                Ok(rows(
                    service
                        .svs_run_attributions(&actor, uuid, Some(after), Some(page))
                        .await?,
                ))
            }
        },
    )
}

/// A run's event log, oldest first, as CSV (details as a JSON string) or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/events/export/{format}",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("format" = String, Path, description = "`csv` or `ndjson`"),
    ),
    responses(
        (status = 200, description = "The events, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "An id that isn't a uuid, or a format that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 413, description = "More events than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_run_events(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((run, format)) = path?;
    let (uuid, format) = (uuid_of(&run)?, format_of(&format)?);
    let (service, max) = (web.service, web.config.max_export_rows);
    let total = service
        .svs_feed_count(&actor, &SvsFeed::RunEvents(uuid), max)
        .await?;
    let page = i64::from(EXPORT_PAGE);
    let events = move |events: Vec<RunEvent>| {
        let next = (events.len() as i64 == page)
            .then(|| events.last().map(|event| event.id))
            .flatten();
        (
            events
                .into_iter()
                .map(|event| RunFeedEventBody::of_run(uuid, event))
                .collect::<Vec<_>>(),
            next,
        )
    };
    let first = events(
        service
            .svs_run_events(&actor, uuid, None, Some(page))
            .await?,
    );
    export::respond(
        format,
        &format!("svs-run-{uuid}-events"),
        max,
        total,
        first,
        move |after: i64| {
            let (service, actor) = (service.clone(), actor.clone());
            async move {
                Ok(events(
                    service
                        .svs_run_events(&actor, uuid, Some(after), Some(page))
                        .await?,
                ))
            }
        },
    )
}

/// A run's result, one row per signature. `stale` says it is about to be recomputed.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/results",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid"), RunResultsQuery),
    responses(
        (status = 200, description = "A page of the run's result", body = RunResultPageBody),
        (status = 400, description = "An id that isn't a uuid, or a parameter that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
    )
)]
pub(crate) async fn run_results(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<RunResultPageBody>, ApiError> {
    let Path(run) = path?;
    let uuid = uuid_of(&run)?;
    let (after, limit) = after_limit(&Params::of(raw)?)?;
    let result = web
        .service
        .svs_run_results(&actor, uuid, after, Some(limit))
        .await?;
    let next = (result.results.len() as i64 == limit)
        .then(|| result.results.last().map(|row| row.id))
        .flatten();
    Ok(Json(RunResultPageBody {
        results: result.results.into_iter().map(Into::into).collect(),
        next,
        stale: result.stale,
        computed_at: result.computed_at,
    }))
}

/// A run's result, as CSV or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/results/export/{format}",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("format" = String, Path, description = "`csv` or `ndjson`"),
    ),
    responses(
        (status = 200, description = "The result rows, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "An id that isn't a uuid, or a format that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 413, description = "More result rows than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_run_results(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((run, format)) = path?;
    let (uuid, format) = (uuid_of(&run)?, format_of(&format)?);
    let (service, max) = (web.service, web.config.max_export_rows);
    let total = service
        .svs_feed_count(&actor, &SvsFeed::RunResults(uuid), max)
        .await?;
    let page = i64::from(EXPORT_PAGE);
    let rows = move |rows: Vec<RunResult>| {
        let next = (rows.len() as i64 == page)
            .then(|| rows.last().map(|row| row.id))
            .flatten();
        (
            rows.into_iter()
                .map(RunResultBody::from)
                .collect::<Vec<_>>(),
            next,
        )
    };
    let first = rows(
        service
            .svs_run_results(&actor, uuid, None, Some(page))
            .await?
            .results,
    );
    export::respond(
        format,
        &format!("svs-run-{uuid}-results"),
        max,
        total,
        first,
        move |after: i64| {
            let (service, actor) = (service.clone(), actor.clone());
            async move {
                Ok(rows(
                    service
                        .svs_run_results(&actor, uuid, Some(after), Some(page))
                        .await?
                        .results,
                ))
            }
        },
    )
}

/// How each signature of the run's result did in the test's ended and reviewed runs on the run's platform
/// registered before it, latest first.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/history",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid"), RunHistoryQuery),
    responses(
        (status = 200, description = "The history", body = RunHistoryBody),
        (status = 400, description = "An id that isn't a uuid, or a number of runs out of range", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
    )
)]
pub(crate) async fn history(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<RunHistoryBody>, ApiError> {
    let Path(run) = path?;
    let uuid = uuid_of(&run)?;
    let runs = Params::of(raw)?.parsed::<u32>("runs", "a number from 1 to 50")?;
    Ok(Json(
        web.service
            .svs_run_history(&actor, uuid, runs)
            .await?
            .into(),
    ))
}

/// The run's comments, oldest first.
#[utoipa::path(
    get,
    path = "/api/svs/v1/runs/{run_id}/comments",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid")),
    responses(
        (status = 200, description = "The comments", body = Vec<RunCommentBody>),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
    )
)]
pub(crate) async fn comments(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<Vec<RunCommentBody>>, ApiError> {
    let Path(run) = path?;
    let comments = web.service.svs_run_comments(&actor, uuid_of(&run)?).await?;
    Ok(Json(comments.into_iter().map(Into::into).collect()))
}

fn comment_of(body: Result<Json<RunCommentRequest>, JsonRejection>) -> Result<String, ApiError> {
    let Json(body) = body?;
    if body.comment.is_empty() || body.comment.chars().count() > MAX_RUN_COMMENT_CHARS {
        return Err(ApiError::bad_request(format!(
            "a comment is 1 to {MAX_RUN_COMMENT_CHARS} characters"
        )));
    }
    Ok(body.comment)
}

/// Adds a comment to a run.
#[utoipa::path(
    post,
    path = "/api/svs/v1/runs/{run_id}/comments",
    tag = "svs",
    params(("run_id" = String, Path, description = "The run's uuid")),
    request_body = RunCommentRequest,
    responses(
        (status = 201, description = "The comment", body = RunCommentBody),
        (status = 400, description = "An id that isn't a uuid, a body that isn't one, a comment that is empty or too long, or a key that belongs to no user", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No run with that id", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn add_comment(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<RunCommentRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<RunCommentBody>), ApiError> {
    let Path(run) = path?;
    let uuid = uuid_of(&run)?;
    let comment = comment_of(body)?;
    let added = web
        .service
        .add_svs_run_comment(&actor, uuid, &comment, Utc::now())
        .await?;
    Ok((StatusCode::CREATED, Json(added.into())))
}

fn comment_path(
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<(Uuid, i64), ApiError> {
    let Path((run, id)) = path?;
    let id = id
        .parse()
        .map_err(|_| ApiError::bad_request(format!("{id:?} isn't a comment's id")))?;
    Ok((uuid_of(&run)?, id))
}

/// Changes a comment; only its author can.
#[utoipa::path(
    patch,
    path = "/api/svs/v1/runs/{run_id}/comments/{id}",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("id" = i64, Path, description = "The comment's id"),
    ),
    request_body = RunCommentRequest,
    responses(
        (status = 200, description = "The comment", body = RunCommentBody),
        (status = 400, description = "An id that isn't one, a body that isn't one, or a comment that is empty or too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage, or isn't the comment's author", body = ErrorBody),
        (status = 404, description = "No run with that id, or no such comment on it", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn update_comment(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Result<Json<RunCommentRequest>, JsonRejection>,
) -> Result<Json<RunCommentBody>, ApiError> {
    let (uuid, id) = comment_path(path)?;
    let comment = comment_of(body)?;
    let changed = web
        .service
        .update_svs_run_comment(&actor, uuid, id, &comment)
        .await?;
    Ok(Json(changed.into()))
}

/// Deletes a comment; only its author can.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/runs/{run_id}/comments/{id}",
    tag = "svs",
    params(
        ("run_id" = String, Path, description = "The run's uuid"),
        ("id" = i64, Path, description = "The comment's id"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage, or isn't the comment's author", body = ErrorBody),
        (status = 404, description = "No run with that id, or no such comment on it", body = ErrorBody),
    )
)]
pub(crate) async fn delete_comment(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let (uuid, id) = comment_path(path)?;
    web.service.delete_svs_run_comment(&actor, uuid, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
