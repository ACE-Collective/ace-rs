//! Reading SVS test runs (PLAN.md 7.10 batch 5, part 5b): ace3's `saq/svs/run_filters.py`,
//! `run_summary.py` and `run_comments.py`, and the reads of `aceapi_v2/svs/runs/service.py`.
//!
//! **The runs screen.** The runs, newest first, with ace3's runs screen's filters
//! (`FilterScreen::SvsRuns`); with `changed_since`, in (updated_at, id) order, which is what a client
//! pulls. The count, the batches (one row per `batch_id` over the runs the filters match), and the feeds
//! of every matching run's events and result rows take the same filters. The filters are one SQL
//! condition, `svs.run_matches` (migration 0054), which this module resolves a filter list for, and what
//! needs attention is one too, `svs.run_needs_attention`: ended and not reviewed, failed, changed since it
//! was reviewed, or reviewed or closed with an alert still open.
//!
//! **A run's page.** Its row with its result's and alerts' summary, its result a row per signature, how
//! each of those signatures did in the test's earlier runs on the same platform, and its comments.
//! Anyone who manages runs adds a comment; only its author changes or deletes it.
//!
//! Everything here reads with `svs:run_read`; a comment's writes need `svs:run_manage`, and are audited.
//!
//! What differs from ace3's:
//! - A changed-since page and a feed hold a row back for a few seconds after it changed
//!   (`Service::with_feed_settle`), as ace3's do.
//! - A batch id compares without case, as in ace3, whose column's collation does it: the Batch filter
//!   and the batches both fold it, and a batch is shown by the first of its spellings.
//! - A comment's author is the user, or the user an API key belongs to; a key that belongs to nobody
//!   can't comment, as in ace3.
//! - A run's alerts and its review's blockers come with batch 7b, which reviews them. The
//!   summary's alert counts read `svs.attributions`.
//!
//! **The attributions** (batch 6). A run's attributions, a row per (alert, detection) in id order, and
//! the feed of every matching run's in (updated_at, id) order, settled rows only, removed ones included
//! in both: what the core's SVS hook wrote at the end of each alert's pass
//! (`ace_core::svs::attribution`), and what a person changes (batch 7). A row names its detection by the
//! detection's id, where ace3's names a content hash, and reads the detection's signature from the
//! detection rather than a copy.

use std::collections::{BTreeMap, BTreeSet};

use ace_core::svs::hosts::split_hostname;
use ace_core::svs::{AttributionConfidence, RunState};
use chrono::{DateTime, TimeDelta, Utc};
use chrono_tz::Tz;
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::alerts::{RecordedActor, page_limit};
use crate::filters::{FilterEntry, FilterScreen, RUN_STATES, Resolved};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SVS_RUN_MANAGE, SVS_RUN_READ};
use crate::svs_decisions::FeedCursor;
use crate::svs_runs::{Run, RunTarget};
use crate::{Actor, Service, ServiceError};

/// The most runs, batches, events or result rows one page holds.
pub const MAX_RUNS_PAGE: u32 = 1000;
/// The most earlier runs a run's history compares with: ace3's `RUN_HISTORY_MAX_RUNS`.
pub const MAX_RUN_HISTORY: u32 = 50;
/// A comment is text a person types, not a document: ace3's `MAX_COMMENT_LENGTH`.
pub const MAX_RUN_COMMENT_CHARS: usize = 16384;

/// The revisit trigger of the possibly-suppressed share: this many reviewed runs, or this long since the
/// first review. ace3's `SUPPRESSION_REVIEW_RUNS` and `SUPPRESSION_REVIEW_PERIOD`.
pub const SUPPRESSION_REVIEW_RUNS: i64 = 50;
pub const SUPPRESSION_REVIEW_DAYS: i64 = 90;
/// Above this share of missing results that are possibly suppressed, suppression is worth preventing.
pub const SUPPRESSION_SHARE_THRESHOLD: f64 = 0.10;

/// Which runs to list.
#[derive(Debug, Clone)]
pub struct RunQuery {
    pub filters: Vec<FilterEntry>,
    /// Only what was written or changed at or after this: runs for the list, events and result rows for
    /// the feeds.
    pub changed_since: Option<DateTime<Utc>>,
    /// The timezone relative date filters resolve in.
    pub tz: Tz,
}

impl Default for RunQuery {
    fn default() -> Self {
        RunQuery {
            filters: Vec::new(),
            changed_since: None,
            tz: Tz::UTC,
        }
    }
}

/// What the runs screen shows of a run's result and alerts: ace3's `RunSummary`. Read per page; nothing
/// here is stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RunSummary {
    /// Signatures per live result status.
    pub hit: i64,
    pub missing: i64,
    pub possibly_suppressed: i64,
    pub candidate: i64,
    pub rejected: i64,
    pub ignored: i64,
    pub cleanup: i64,
    /// Something changed since the result was computed; the timers recompute it shortly.
    pub result_stale: bool,
    /// The expected signatures per status as signed off at the run's latest review.
    pub reviewed_hit: i64,
    pub reviewed_missing: i64,
    pub reviewed_possibly_suppressed: i64,
    /// The alerts attributed to the run: by a marker (at least one of its attributions is), by context
    /// alone, and late (at least one of its attributions is).
    pub alerts: i64,
    pub marker_alerts: i64,
    pub context_alerts: i64,
    pub late_alerts: i64,
}

impl RunSummary {
    /// The expected signatures the result judged: hit, missing or possibly suppressed.
    pub fn expected(&self) -> i64 {
        self.hit + self.missing + self.possibly_suppressed
    }

    /// `expected`, as signed off.
    pub fn reviewed_expected(&self) -> i64 {
        self.reviewed_hit + self.reviewed_missing + self.reviewed_possibly_suppressed
    }

    /// Expected signatures that didn't fire, possibly suppressed ones included: ace3's `result_missing`.
    pub fn all_missing(&self) -> i64 {
        self.missing + self.possibly_suppressed
    }

    /// `all_missing`, as signed off.
    pub fn reviewed_all_missing(&self) -> i64 {
        self.reviewed_missing + self.reviewed_possibly_suppressed
    }

    fn count(&mut self, status: &str, count: i64, reviewed: bool) {
        let field = match (status, reviewed) {
            ("hit", false) => &mut self.hit,
            ("missing", false) => &mut self.missing,
            ("possibly_suppressed", false) => &mut self.possibly_suppressed,
            ("candidate", false) => &mut self.candidate,
            ("rejected", false) => &mut self.rejected,
            ("ignored", false) => &mut self.ignored,
            ("cleanup", false) => &mut self.cleanup,
            ("hit", true) => &mut self.reviewed_hit,
            ("missing", true) => &mut self.reviewed_missing,
            ("possibly_suppressed", true) => &mut self.reviewed_possibly_suppressed,
            _ => return,
        };
        *field += count;
    }
}

/// A run as the runs screen lists it: ace3's `RunRow`.
#[derive(Debug, Clone, PartialEq)]
pub struct RunRow {
    pub run: Run,
    /// From the catalog; None for a test that left it before its row was kept.
    pub test_name: Option<String>,
    pub technique: Option<String>,
    pub technique_name: Option<String>,
    /// The owner's and the reviewer's usernames.
    pub owner: Option<String>,
    pub reviewer: Option<String>,
    pub reviewed_at: Option<DateTime<Utc>>,
    /// A late alert or a manual association came after the review.
    pub changed_since_review: bool,
    /// The run is in the Needs attention view.
    pub needs_attention: bool,
    pub summary: RunSummary,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunPage {
    pub runs: Vec<RunRow>,
    pub next_cursor: Option<String>,
}

/// One `batch_id` over the runs the filters match: only those runs are counted. ace3's `RunBatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunBatch {
    pub batch_id: String,
    pub runs: i64,
    /// The runs per state, every state named, in ace3's order.
    pub states: Vec<(RunState, i64)>,
    pub needs_attention: i64,
    pub first_created_at: DateTime<Utc>,
    /// When its latest run was registered; the batches are newest first by it.
    pub last_created_at: DateTime<Utc>,
    /// Summed over the runs: expected signatures that fired, that the results judged, that didn't fire
    /// (possibly suppressed ones included), and undecided ones that fired.
    pub result_hit: i64,
    pub result_expected: i64,
    pub result_missing: i64,
    pub result_candidate: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunBatchPage {
    pub batches: Vec<RunBatch>,
    pub next_cursor: Option<String>,
}

/// One row of a run's event log, in the feed over every run's.
#[derive(Debug, Clone, PartialEq)]
pub struct RunEventRow {
    pub id: i64,
    pub run: Uuid,
    pub kind: String,
    pub from_state: Option<RunState>,
    pub to_state: Option<RunState>,
    pub actor: Option<RecordedActor>,
    pub details: Option<Value>,
    pub created_at: DateTime<Utc>,
    /// The feed's `changed_since` key.
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunEventFeedPage {
    pub events: Vec<RunEventRow>,
    pub next_cursor: Option<String>,
}

/// One signature of a run's result: ace3's `RunResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    pub id: i64,
    pub run: Uuid,
    pub signature_uuid: String,
    pub signature_family: Option<String>,
    pub signature_name: Option<String>,
    /// `hit`, `missing`, `possibly_suppressed`, `candidate`, `rejected`, `ignored` or `cleanup`; None
    /// once the signature left the live result and the row holds only the reviewed result.
    pub status: Option<String>,
    pub alert_count: i32,
    pub late_only: bool,
    pub context_only: bool,
    pub fallback_time: bool,
    pub content_hash: Option<String>,
    /// possibly suppressed: the hunt's latest alert within its suppression period; None when the hunter
    /// recorded that it dropped the run's match.
    pub suppressing_alert: Option<Uuid>,
    pub reviewed_status: Option<String>,
    pub reviewed_alert_count: Option<i32>,
    pub reviewed_late_only: Option<bool>,
    pub reviewed_content_hash: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResultPage {
    pub results: Vec<RunResult>,
    pub next_cursor: Option<String>,
}

/// One run's result rows, and whether the result is about to be recomputed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResults {
    pub results: Vec<RunResult>,
    /// Something changed since the result was computed. A run whose result was never computed or
    /// marked isn't stale: it has none yet.
    pub stale: bool,
    pub computed_at: Option<DateTime<Utc>>,
}

/// One detection of an alert attributed to a run, removed ones included: ace3's `Attribution`. The
/// core's SVS hook writes the `router` rows (`ace_core::svs::attribution`, PLAN.md 7.10 batch 6) and a
/// person's association the `manual` ones (batch 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunAttribution {
    pub id: i64,
    pub run: Uuid,
    /// The alert: the root the detection is on.
    pub alert: Uuid,
    /// The detection, `analysis.detections.id`, where ace3 names its content hash.
    pub detection: i64,
    pub signature_uuid: Option<String>,
    pub signature_family: Option<String>,
    /// `marker` or `context`; a person's association is `marker`.
    pub confidence: AttributionConfidence,
    /// The alert's event came after the run's observation window.
    pub late: bool,
    /// The event time it was judged by.
    pub event_time: Option<DateTime<Utc>>,
    /// Its event time is at or after the run's `cleanup_at`: the test's cleanup caused it.
    pub cleanup: bool,
    /// `event`, `query_time`, `now` or `insert_time`.
    pub event_time_source: Option<String>,
    /// The event time is a fallback, which may have put the alert in the wrong window.
    pub fallback_time: bool,
    /// `router` or `manual`.
    pub source: String,
    /// Where the agreeing marker was found; None for context or manual.
    pub scan_point: Option<String>,
    pub actor: Option<RecordedActor>,
    pub created_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
    pub removed_by: Option<RecordedActor>,
    pub removal_reason: Option<String>,
    pub kept_at: Option<DateTime<Utc>>,
    pub kept_by: Option<RecordedActor>,
    /// The feed's `changed_since` key.
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunAttributionPage {
    pub attributions: Vec<RunAttribution>,
    pub next_cursor: Option<String>,
}

struct AttributionRowDb {
    id: i64,
    run: Uuid,
    root_id: Uuid,
    detection_id: i64,
    signature_uuid: Option<String>,
    signature_family: Option<String>,
    confidence: String,
    late: bool,
    event_time: Option<DateTime<Utc>>,
    cleanup: bool,
    event_time_source: Option<String>,
    source: String,
    scan_point: Option<String>,
    actor: Value,
    created_at: DateTime<Utc>,
    removed_at: Option<DateTime<Utc>>,
    removed_by: Option<Value>,
    removal_reason: Option<String>,
    kept_at: Option<DateTime<Utc>>,
    kept_by: Option<Value>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<AttributionRowDb> for RunAttribution {
    type Error = ServiceError;

    fn try_from(row: AttributionRowDb) -> Result<Self, ServiceError> {
        let fallback_time = row.event_time_source.as_deref().is_some_and(|source| {
            ace_core::svs::results::FALLBACK_EVENT_TIME_SOURCES.contains(&source)
        });
        Ok(RunAttribution {
            id: row.id,
            run: row.run,
            alert: row.root_id,
            detection: row.detection_id,
            signature_uuid: row.signature_uuid,
            signature_family: row.signature_family,
            confidence: decode(
                "an attribution's confidence",
                AttributionConfidence::parse(&row.confidence),
            )?,
            late: row.late,
            event_time: row.event_time,
            cleanup: row.cleanup,
            event_time_source: row.event_time_source,
            fallback_time,
            source: row.source,
            scan_point: row.scan_point,
            actor: RecordedActor::from_row(Some(row.actor))?,
            created_at: row.created_at,
            removed_at: row.removed_at,
            removed_by: RecordedActor::from_row(row.removed_by)?,
            removal_reason: row.removal_reason,
            kept_at: row.kept_at,
            kept_by: RecordedActor::from_row(row.kept_by)?,
            updated_at: row.updated_at,
        })
    }
}

/// One detection of an alert a run holds or held, and its attribution to the run: ace3's
/// `RunAlertDetection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunAlertDetection {
    /// `analysis.detections.id`.
    pub detection: i64,
    pub description: String,
    pub signature_uuid: Option<String>,
    pub signature_family: Option<String>,
    /// Its attribution to this run, removed or not; None when it never had one.
    pub attribution: Option<RunAttribution>,
}

/// An alert attributed to a run, now or before: ace3's `RunAlert`.
#[derive(Debug, Clone, PartialEq)]
pub struct RunAlert {
    /// The alert as the alert list shows it, with its SVS status over every run.
    pub alert: crate::alerts::AlertSummary,
    /// The first attribution of it to the run, which orders the run's alerts and pages them.
    pub first_attribution: i64,
    /// Some attribution of it to the run holds.
    pub holds: bool,
    /// Of those that hold: marker when any is (a person's association is marker), else context.
    pub confidence: Option<AttributionConfidence>,
    /// An attribution that holds is late.
    pub late: bool,
    /// Every attribution that holds is the test's cleanup's.
    pub cleanup: bool,
    /// An attribution that holds was judged by a fallback event time.
    pub fallback_time: bool,
    /// An attribution that holds was made by a person.
    pub manual: bool,
    /// A person kept its context attributions.
    pub kept: bool,
    /// It has a context attribution that holds and nobody kept: a review waits for keep or not a test.
    pub undecided_context: bool,
    /// Every detection of the alert, in the order they were made.
    pub detections: Vec<RunAlertDetection>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunAlertPage {
    pub alerts: Vec<RunAlert>,
    /// The `after` of the next page; None on the last.
    pub next: Option<i64>,
}

/// An earlier run of a run's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRun {
    pub run: Uuid,
    pub state: RunState,
    pub created_at: DateTime<Utc>,
    pub reviewed_at: Option<DateTime<Utc>>,
}

/// How one signature of a run's result did in the earlier runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureHistory {
    pub signature_uuid: String,
    /// Its status in each of the runs, in their order: as reviewed for a reviewed run, else live; None
    /// when it isn't in that run's result.
    pub statuses: Vec<Option<String>>,
}

/// How the signatures of a run's result did in the test's earlier runs: ace3's `RunHistory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunHistory {
    /// The test's ended and reviewed runs on this run's platform registered before this one, newest
    /// first.
    pub runs: Vec<HistoryRun>,
    /// One per signature of this run's result, in its order.
    pub signatures: Vec<SignatureHistory>,
}

/// A person's comment on a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunComment {
    pub id: i64,
    pub run: Uuid,
    /// Its author's username; None once that user is gone.
    pub user: Option<String>,
    pub comment: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// How many of the expected signatures missing from reviewed runs were possibly suppressed: the trigger to
/// revisit keeping the hunter from suppressing test targets. ace3's `SuppressionShare`.
#[derive(Debug, Clone, PartialEq)]
pub struct SuppressionShare {
    /// The expected signatures missing from the signed-off results, possibly suppressed ones included.
    pub missing: i64,
    pub possibly_suppressed: i64,
    /// The runs with a signed-off result, and when the first one was signed off.
    pub reviewed_runs: i64,
    pub first_reviewed_at: Option<DateTime<Utc>>,
    pub trigger_reached: bool,
}

impl SuppressionShare {
    /// `possibly_suppressed / missing`; None while nothing is missing.
    pub fn share(&self) -> Option<f64> {
        (self.missing > 0).then(|| self.possibly_suppressed as f64 / self.missing as f64)
    }

    /// The trigger is reached and the share is above the threshold.
    pub fn reconsider(&self) -> bool {
        self.trigger_reached
            && self
                .share()
                .is_some_and(|share| share > SUPPRESSION_SHARE_THRESHOLD)
    }
}

/// What a listing an export reads holds, for its count.
pub enum SvsFeed<'a> {
    Runs(&'a RunQuery),
    Batches(&'a RunQuery),
    Events(&'a RunQuery),
    Results(&'a RunQuery),
    Attributions(&'a RunQuery),
    /// One run's event log, result and attributions.
    RunEvents(Uuid),
    RunResults(Uuid),
    RunAttributions(Uuid),
    /// The alerts one run holds or held.
    RunAlerts(Uuid),
    Expectations(&'a crate::svs_decisions::ExpectationQuery),
    Ignores(&'a crate::svs_decisions::IgnoreQuery),
    TestHosts(Option<DateTime<Utc>>),
}

fn unknown_run(uuid: Uuid) -> ServiceError {
    ServiceError::NotFound(format!("run {uuid} not found"))
}

fn decode<T>(what: &str, value: Option<T>) -> Result<T, ServiceError> {
    value.ok_or_else(|| ServiceError::from(ace_core::DbError::Decode(format!("a stored {what}"))))
}

fn state_of(text: &str) -> Result<RunState, ServiceError> {
    decode("run state", RunState::parse(text))
}

/// A flag filter and its inverse as one wanted value, and whether together they match nothing: ace3's
/// `_flag`, under which a filter holding both values filters nothing, and so its inverse matches nothing.
fn flag(f: &Resolved, slug: &'static str) -> (Option<bool>, bool) {
    let side = |inverted: bool| -> Option<Option<bool>> {
        let values: BTreeSet<String> = f.names(slug, inverted)?.into_iter().collect();
        Some(match values.len() {
            1 => Some(values.contains("true")),
            _ => None,
        })
    };
    let mut want = side(false).flatten();
    let mut nothing = false;
    match side(true) {
        None => {}
        // the inverse of a filter that filters nothing
        Some(None) => nothing = true,
        Some(Some(value)) => {
            if want.is_some_and(|wanted| wanted == value) {
                nothing = true;
            }
            want = Some(!value);
        }
    }
    (want, nothing)
}

/// The runs screen's filters as `svs.run_matches` reads them (migration 0054): ace3's
/// `run_filter_conditions`.
fn run_filter(query: &RunQuery, now: DateTime<Utc>) -> Result<Value, ServiceError> {
    let f = Resolved::new(FilterScreen::SvsRuns, &query.filters, now, query.tz)?;
    let mut doc = Map::new();
    let mut nothing = false;
    let key = |slug: &str, inverted: bool| {
        if inverted {
            format!("not_{slug}")
        } else {
            slug.to_owned()
        }
    };
    for inverted in [false, true] {
        for slug in [
            "state",
            "test",
            "technique",
            "platform",
            "owner",
            "reviewer",
        ] {
            if let Some(values) = f.names(slug, inverted) {
                doc.insert(key(slug, inverted), json!(values));
            }
        }
        if let Some(values) = f.names("batch", inverted) {
            let values: Vec<String> = values.iter().map(|v| v.to_lowercase()).collect();
            doc.insert(key("batch", inverted), json!(values));
        }
        for slug in ["test_name", "launcher", "reason"] {
            if let Some(patterns) = f.patterns(slug, inverted, false) {
                doc.insert(key(slug, inverted), json!(patterns));
            }
        }
        // a target is a host's short name, as a run's target is matched; a value that isn't a host
        // name matches no run
        if let Some(values) = f.names("target", inverted) {
            let hosts: Vec<String> = values
                .iter()
                .filter_map(|value| split_hostname(value).ok())
                .map(|(host, _)| host)
                .collect();
            if !hosts.is_empty() {
                doc.insert(key("target", inverted), json!(hosts));
            } else if !inverted {
                nothing = true;
            }
        }
        for slug in ["created", "started", "ended", "reviewed"] {
            if let Some((starts, ends)) = f.windows(slug, inverted)? {
                let windows: Vec<Value> = starts
                    .iter()
                    .zip(&ends)
                    .map(|(start, end)| json!([start, end]))
                    .collect();
                doc.insert(key(slug, inverted), json!(windows));
            }
        }
    }
    for slug in [
        "needs_attention",
        "changed_since_review",
        "has_open_alerts",
        "has_missing",
        "has_possibly_suppressed",
        "has_candidates",
        "has_late",
        "has_context_only",
    ] {
        let (want, none) = flag(&f, slug);
        nothing |= none;
        if let Some(want) = want {
            doc.insert(slug.to_owned(), json!(want));
        }
    }
    if nothing {
        doc.insert("nothing".to_owned(), json!(true));
    }
    Ok(Value::Object(doc))
}

struct ListRow {
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
    reviewed_at: Option<DateTime<Utc>>,
    changed_since_review: bool,
    test_name: Option<String>,
    technique: Option<String>,
    technique_name: Option<String>,
    owner: Option<String>,
    reviewer: Option<String>,
    needs_attention: bool,
}

/// Where a page of runs left off: by (created_at, id) newest first, or (updated_at, id) for a
/// changed-since pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RunCursor {
    /// `created` or `updated_at`.
    o: String,
    at: DateTime<Utc>,
    id: i64,
}

fn encode<T: Serialize>(cursor: &T) -> String {
    hex::encode(serde_json::to_vec(cursor).unwrap_or_default())
}

fn decode_cursor<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ServiceError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| ServiceError::InvalidRequest(format!("{text:?} isn't a cursor")))
}

fn run_cursor(text: &str, changed: bool) -> Result<RunCursor, ServiceError> {
    let cursor: RunCursor = decode_cursor(text)?;
    let order = if changed { "updated_at" } else { "created" };
    if cursor.o != order {
        return Err(ServiceError::InvalidRequest(format!(
            "this cursor pages a listing ordered by {}, not {order}: pass the same changed_since (or \
             none) as the request that returned it",
            cursor.o
        )));
    }
    Ok(cursor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchCursor {
    at: DateTime<Utc>,
    batch: String,
}

/// The matching runs, a page of them, or one of them (`only`), with their catalog test, owner and
/// reviewer.
#[allow(clippy::too_many_arguments)]
async fn list(
    conn: &mut PgConnection,
    filter: &Value,
    changed_since: Option<DateTime<Utc>>,
    settle: f64,
    only: Option<Uuid>,
    after: Option<&RunCursor>,
    limit: i64,
) -> Result<Vec<ListRow>, sqlx::Error> {
    let changed = changed_since.is_some();
    sqlx::query_as!(
        ListRow,
        r#"SELECT r.id, r.uuid, r.test_guid, r.platform, r.test_content_hash, r.catalog_commit,
                  r.state::text AS "state!", r.marker, r.launcher, r.batch_id, r.extra,
                  r.registered_by AS "registered_by: Value", r.created_at, r.started_at, r.executed_at,
                  r.cleanup_at, r.exit_code, r.launcher_error, r.ended_at, r.end_reason, r.canceled_at,
                  r.closed_at, r.close_reason, r.error_reason, r.observation_seconds,
                  r.attribution_seconds, r.observation_ends_at, r.attribution_ends_at, r.holds_host,
                  r.warnings, r.updated_at, r.reviewed_at, r.changed_since_review,
                  c.name AS "test_name?", c.technique AS "technique?",
                  c.technique_name AS "technique_name?",
                  o.username::text AS "owner?", v.username::text AS "reviewer?",
                  svs.run_needs_attention(r) AS "needs_attention!"
           FROM svs.runs r
           LEFT JOIN svs.catalog_tests c ON c.guid = r.test_guid
           LEFT JOIN service.users o ON o.id = r.owner_id
           LEFT JOIN service.users v ON v.id = r.reviewer_id
           WHERE svs.run_matches(r, $1)
             AND ($2::timestamptz IS NULL
                  OR (r.updated_at >= $2 AND r.updated_at < now() - make_interval(secs => $3)))
             AND ($4::uuid IS NULL OR r.uuid = $4)
             AND ($5::bigint IS NULL
                  OR CASE WHEN $7 THEN (r.updated_at, r.id) > ($6::timestamptz, $5)
                          ELSE (r.created_at, r.id) < ($6::timestamptz, $5) END)
           ORDER BY CASE WHEN $7 THEN r.updated_at END ASC,
                    CASE WHEN $7 THEN r.id END ASC,
                    CASE WHEN NOT $7 THEN r.created_at END DESC,
                    CASE WHEN NOT $7 THEN r.id END DESC
           LIMIT $8"#,
        filter,
        changed_since,
        settle,
        only,
        after.map(|c| c.id),
        after.map(|c| c.at),
        changed,
        limit,
    )
    .fetch_all(conn)
    .await
}

/// The summary of each run, by its row's id; a run with no result and no alerts gets the empty one.
/// ace3's `run_summaries`: any number of runs in a fixed number of queries.
async fn summaries(
    conn: &mut PgConnection,
    runs: &[i64],
) -> Result<BTreeMap<i64, RunSummary>, ServiceError> {
    let mut by: BTreeMap<i64, RunSummary> = runs
        .iter()
        .map(|run| (*run, RunSummary::default()))
        .collect();
    if runs.is_empty() {
        return Ok(by);
    }
    for row in sqlx::query!(
        r#"SELECT run_id, status AS "status!", count(*) AS "count!" FROM svs.run_results
           WHERE run_id = ANY ($1) AND status IS NOT NULL GROUP BY run_id, status"#,
        runs,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        if let Some(summary) = by.get_mut(&row.run_id) {
            summary.count(&row.status, row.count, false);
        }
    }
    for row in sqlx::query!(
        r#"SELECT run_id, reviewed_status AS "status!", count(*) AS "count!" FROM svs.run_results
           WHERE run_id = ANY ($1) AND reviewed_status IN ('hit', 'missing', 'possibly_suppressed')
           GROUP BY run_id, reviewed_status"#,
        runs,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        if let Some(summary) = by.get_mut(&row.run_id) {
            summary.count(&row.status, row.count, true);
        }
    }
    for run in sqlx::query_scalar!(
        "SELECT run_id FROM svs.run_result_state WHERE run_id = ANY ($1) AND stale",
        runs,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        if let Some(summary) = by.get_mut(&run) {
            summary.result_stale = true;
        }
    }
    for row in sqlx::query!(
        r#"SELECT run_id, count(*) AS "alerts!",
                  count(*) FILTER (WHERE marker) AS "marker!",
                  count(*) FILTER (WHERE late) AS "late!"
           FROM (SELECT run_id, bool_or(confidence = 'marker') AS marker, bool_or(late) AS late
                 FROM svs.attributions
                 WHERE run_id = ANY ($1) AND removed_at IS NULL
                 GROUP BY run_id, root_id) alerts
           GROUP BY run_id"#,
        runs,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        if let Some(summary) = by.get_mut(&row.run_id) {
            summary.alerts = row.alerts;
            summary.marker_alerts = row.marker;
            summary.context_alerts = row.alerts - row.marker;
            summary.late_alerts = row.late;
        }
    }
    Ok(by)
}

/// The rows as the screen shows them: each with its targets and its summary, read for the whole page.
async fn run_rows(
    conn: &mut PgConnection,
    rows: Vec<ListRow>,
) -> Result<Vec<RunRow>, ServiceError> {
    let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
    let mut summaries = summaries(conn, &ids).await?;
    let mut targets: BTreeMap<i64, Vec<RunTarget>> = BTreeMap::new();
    for target in sqlx::query!(
        r#"SELECT run_id, hostname, username, host, fqdn, "user" FROM svs.run_targets
           WHERE run_id = ANY ($1) ORDER BY id"#,
        &ids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        targets.entry(target.run_id).or_default().push(RunTarget {
            hostname: target.hostname,
            username: target.username,
            host: target.host,
            fqdn: target.fqdn,
            user: target.user,
        });
    }
    rows.into_iter()
        .map(|row| {
            Ok(RunRow {
                test_name: row.test_name,
                technique: row.technique,
                technique_name: row.technique_name,
                owner: row.owner,
                reviewer: row.reviewer,
                reviewed_at: row.reviewed_at,
                changed_since_review: row.changed_since_review,
                needs_attention: row.needs_attention,
                summary: summaries.remove(&row.id).unwrap_or_default(),
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
                    targets: targets.remove(&row.id).unwrap_or_default(),
                },
            })
        })
        .collect()
}

struct ResultRowDb {
    id: i64,
    run: Uuid,
    signature_uuid: String,
    signature_family: Option<String>,
    signature_name: Option<String>,
    status: Option<String>,
    alert_count: i32,
    late_only: bool,
    context_only: bool,
    fallback_time: bool,
    content_hash: Option<String>,
    suppressing_root_id: Option<Uuid>,
    reviewed_status: Option<String>,
    reviewed_alert_count: Option<i32>,
    reviewed_late_only: Option<bool>,
    reviewed_content_hash: Option<String>,
    updated_at: DateTime<Utc>,
}

impl From<ResultRowDb> for RunResult {
    fn from(row: ResultRowDb) -> Self {
        RunResult {
            id: row.id,
            run: row.run,
            signature_uuid: row.signature_uuid,
            signature_family: row.signature_family,
            signature_name: row.signature_name,
            status: row.status,
            alert_count: row.alert_count,
            late_only: row.late_only,
            context_only: row.context_only,
            fallback_time: row.fallback_time,
            content_hash: row.content_hash,
            suppressing_alert: row.suppressing_root_id,
            reviewed_status: row.reviewed_status,
            reviewed_alert_count: row.reviewed_alert_count,
            reviewed_late_only: row.reviewed_late_only,
            reviewed_content_hash: row.reviewed_content_hash,
            updated_at: row.updated_at,
        }
    }
}

async fn run_id(conn: &mut PgConnection, uuid: Uuid) -> Result<i64, ServiceError> {
    sqlx::query_scalar!("SELECT id FROM svs.runs WHERE uuid = $1", uuid)
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| unknown_run(uuid))
}

/// A comment as it's stored: line endings as one character, no white space around it, not empty and not
/// longer than a comment may be. ace3's `_text`.
fn comment_text(comment: &str) -> Result<String, ServiceError> {
    let comment = comment.replace("\r\n", "\n");
    let comment = comment.trim();
    if comment.is_empty() {
        return Err(ServiceError::InvalidRequest(
            "a comment can't be empty".to_owned(),
        ));
    }
    if comment.chars().count() > MAX_RUN_COMMENT_CHARS {
        return Err(ServiceError::InvalidRequest(format!(
            "a comment is at most {MAX_RUN_COMMENT_CHARS} characters"
        )));
    }
    Ok(comment.to_owned())
}

/// The user a comment is by: the user, or the user an API key belongs to. Every comment records who
/// wrote it, and a key that belongs to nobody is nobody.
fn author(actor: &Actor) -> Result<Uuid, ServiceError> {
    crate::filters::queue_holder(actor).ok_or_else(|| {
        ServiceError::InvalidRequest(
            "this action records who took it: it requires a user's API key or session".to_owned(),
        )
    })
}

async fn comment_row(conn: &mut PgConnection, id: i64) -> Result<RunComment, ServiceError> {
    Ok(sqlx::query_as!(
        RunComment,
        r#"SELECT c.id, r.uuid AS run, u.username::text AS "user?", c.comment, c.created_at,
                  c.updated_at
           FROM svs.run_comments c
           JOIN svs.runs r ON r.id = c.run_id
           LEFT JOIN service.users u ON u.id = c.user_id
           WHERE c.id = $1"#,
        id,
    )
    .fetch_one(conn)
    .await?)
}

/// The run's comment `id`, locked, once `actor` is its author: ace3's `_own_comment`.
async fn own_comment(
    conn: &mut PgConnection,
    run: Uuid,
    id: i64,
    user: Uuid,
) -> Result<RunComment, ServiceError> {
    let run_row = run_id(conn, run).await?;
    let by = sqlx::query_scalar!(
        "SELECT user_id FROM svs.run_comments WHERE id = $1 AND run_id = $2 FOR UPDATE",
        id,
        run_row,
    )
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| ServiceError::NotFound(format!("comment {id} not found on run {run}")))?;
    if by != Some(user) {
        return Err(ServiceError::Forbidden(
            "only its author changes or deletes a comment".to_owned(),
        ));
    }
    comment_row(conn, id).await
}

/// What a comment's audit row keeps: its size, not its text, which stays in its own row.
#[derive(Serialize)]
struct CommentRecord {
    run: Uuid,
    chars: usize,
}

impl Recorded for CommentRecord {}

impl CommentRecord {
    fn of(comment: &RunComment) -> Self {
        CommentRecord {
            run: comment.run,
            chars: comment.comment.chars().count(),
        }
    }
}

impl Service {
    /// The run's search in the site's log tooling, from the overlay's `svs.log_search_url`; None when the
    /// site set none. ace3's `log_search_url`.
    pub fn svs_run_log_search_url(&self, run: &Run, now: DateTime<Utc>) -> Option<String> {
        use ace_core::svs::log_search::{RunSearch, RunTimes};
        let template = self.log_search()?;
        Some(template.url(
            &RunSearch {
                run_uuid: &run.uuid.to_string(),
                marker: &run.marker,
                test_guid: &run.test_guid.to_string(),
                times: RunTimes {
                    created_at: run.created_at,
                    started_at: run.started_at,
                    attribution_ends_at: run.attribution_ends_at,
                    canceled_at: run.canceled_at,
                    closed_at: run.closed_at,
                },
            },
            now,
        ))
    }

    /// A page of the runs the filters match, newest first, or with `changed_since` in (updated_at, id)
    /// order of settled runs, after where `cursor` left off: ace3's `fetch_page`. It needs
    /// `svs:run_read`. A filter, limit or cursor that can't be used is `InvalidRequest`.
    pub async fn svs_runs(
        &self,
        actor: &Actor,
        query: &RunQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<RunPage, ServiceError> {
        let limit = page_limit(limit, MAX_RUNS_PAGE)?;
        let changed = query.changed_since.is_some();
        let after = &cursor
            .map(|cursor| run_cursor(cursor, changed))
            .transpose()?;
        let filter = &run_filter(query, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_runs", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = list(
                        tx.conn(),
                        filter,
                        changed_since,
                        settle,
                        None,
                        after.as_ref(),
                        limit + 1,
                    )
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last().map(|last| {
                            encode(&RunCursor {
                                o: if changed { "updated_at" } else { "created" }.to_owned(),
                                at: if changed {
                                    last.updated_at
                                } else {
                                    last.created_at
                                },
                                id: last.id,
                            })
                        })
                    } else {
                        None
                    };
                    Ok(RunPage {
                        runs: run_rows(tx.conn(), rows).await?,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// One run as the runs screen shows it, with its result's and alerts' summary. It needs
    /// `svs:run_read`; a run that isn't there is `NotFound`.
    pub async fn svs_run_row(&self, actor: &Actor, uuid: Uuid) -> Result<RunRow, ServiceError> {
        self.gate
            .read(actor, "svs_run_row", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let rows = list(tx.conn(), &json!({}), None, 0.0, Some(uuid), None, 1).await?;
                    run_rows(tx.conn(), rows)
                        .await?
                        .pop()
                        .ok_or_else(|| unknown_run(uuid))
                })
            })
            .await
    }

    /// How many runs the filters match: ace3's `count_runs`. `needs_attention:true` is the count on the
    /// GUI's SVS entry. It needs `svs:run_read`.
    pub async fn svs_run_count(
        &self,
        actor: &Actor,
        query: &RunQuery,
    ) -> Result<i64, ServiceError> {
        let filter = &run_filter(query, Utc::now())?;
        self.gate
            .read(actor, "svs_run_count", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar!(
                        r#"SELECT count(*) AS "count!" FROM svs.runs r WHERE svs.run_matches(r, $1)"#,
                        filter,
                    )
                    .fetch_one(tx.conn())
                    .await?)
                })
            })
            .await
    }

    /// A page of batches: one row per `batch_id` over the runs the filters match, summing only those
    /// runs, the batch with the latest run first; runs without a `batch_id` are left out. ace3's
    /// `fetch_batch_page`. It needs `svs:run_read`.
    pub async fn svs_run_batches(
        &self,
        actor: &Actor,
        query: &RunQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<RunBatchPage, ServiceError> {
        let limit = page_limit(limit, MAX_RUNS_PAGE)?;
        let after = &cursor.map(decode_cursor::<BatchCursor>).transpose()?;
        let filter = &run_filter(query, Utc::now())?;
        self.gate
            .read(actor, "svs_run_batches", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = sqlx::query!(
                        r#"SELECT lower(r.batch_id) AS "key!", min(r.batch_id) AS "batch_id!",
                                  count(*) AS "runs!", min(r.created_at) AS "first!",
                                  max(r.created_at) AS "last!",
                                  count(*) FILTER (WHERE svs.run_needs_attention(r)) AS "attention!",
                                  count(*) FILTER (WHERE r.state = 'created') AS "created!",
                                  count(*) FILTER (WHERE r.state = 'started') AS "started!",
                                  count(*) FILTER (WHERE r.state = 'ended') AS "ended!",
                                  count(*) FILTER (WHERE r.state = 'reviewed') AS "reviewed!",
                                  count(*) FILTER (WHERE r.state = 'canceled') AS "canceled!",
                                  count(*) FILTER (WHERE r.state = 'error') AS "error!",
                                  count(*) FILTER (WHERE r.state = 'closed') AS "closed!"
                           FROM svs.runs r
                           WHERE r.batch_id IS NOT NULL AND svs.run_matches(r, $1)
                           GROUP BY lower(r.batch_id)
                           HAVING $2::timestamptz IS NULL
                               OR (max(r.created_at), lower(r.batch_id) COLLATE "C")
                                  < ($2::timestamptz, $3::text COLLATE "C")
                           ORDER BY max(r.created_at) DESC, lower(r.batch_id) COLLATE "C" DESC
                           LIMIT $4"#,
                        filter,
                        after.as_ref().map(|c| c.at),
                        after.as_ref().map(|c| c.batch.as_str()),
                        limit + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last().map(|last| {
                            encode(&BatchCursor {
                                at: last.last,
                                batch: last.key.clone(),
                            })
                        })
                    } else {
                        None
                    };
                    // the live results of each batch's matching runs, summed
                    let keys: Vec<String> = rows.iter().map(|row| row.key.clone()).collect();
                    let mut results: BTreeMap<String, RunSummary> = BTreeMap::new();
                    for row in sqlx::query!(
                        r#"SELECT lower(r.batch_id) AS "key!", x.status AS "status!",
                                  count(*) AS "count!"
                           FROM svs.runs r
                           JOIN svs.run_results x ON x.run_id = r.id
                           WHERE lower(r.batch_id) = ANY ($1) AND x.status IS NOT NULL
                             AND svs.run_matches(r, $2)
                           GROUP BY 1, 2"#,
                        &keys,
                        filter,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        results
                            .entry(row.key)
                            .or_default()
                            .count(&row.status, row.count, false);
                    }
                    let batches = rows
                        .into_iter()
                        .map(|row| {
                            let summary = results.remove(&row.key).unwrap_or_default();
                            let counts = [
                                row.created,
                                row.started,
                                row.ended,
                                row.reviewed,
                                row.canceled,
                                row.error,
                                row.closed,
                            ];
                            Ok(RunBatch {
                                batch_id: row.batch_id,
                                runs: row.runs,
                                states: RUN_STATES
                                    .iter()
                                    .zip(counts)
                                    .map(|(state, count)| Ok((state_of(state)?, count)))
                                    .collect::<Result<_, ServiceError>>()?,
                                needs_attention: row.attention,
                                first_created_at: row.first,
                                last_created_at: row.last,
                                result_hit: summary.hit,
                                result_expected: summary.expected(),
                                result_missing: summary.all_missing(),
                                result_candidate: summary.candidate,
                            })
                        })
                        .collect::<Result<_, ServiceError>>()?;
                    Ok(RunBatchPage {
                        batches,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// A page of the events of every run the filters match, in (updated_at, id) order, settled rows
    /// only: the runs' change feed. ace3's `fetch_event_feed_page`. An event shows up a few seconds
    /// after it's written, so a pull resumed from its last `updated_at` never misses one, and may repeat
    /// one. It needs `svs:run_read`.
    pub async fn svs_run_event_feed(
        &self,
        actor: &Actor,
        query: &RunQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<RunEventFeedPage, ServiceError> {
        let limit = page_limit(limit, MAX_RUNS_PAGE)?;
        let after = &cursor
            .map(|cursor| FeedCursor::decode(cursor, true))
            .transpose()?;
        let filter = &run_filter(query, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_run_event_feed", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = sqlx::query!(
                        r#"SELECT e.id, r.uuid AS run, e.kind, e.from_state::text AS from_state,
                                  e.to_state::text AS to_state, e.actor AS "actor!: Value", e.details,
                                  e.created_at, e.updated_at
                           FROM svs.run_events e
                           JOIN svs.runs r ON r.id = e.run_id
                           WHERE svs.run_matches(r, $1)
                             AND ($2::timestamptz IS NULL OR e.updated_at >= $2)
                             AND e.updated_at < now() - make_interval(secs => $3)
                             AND ($4::bigint IS NULL
                                  OR (e.updated_at, e.id) > ($5::timestamptz, $4))
                           ORDER BY e.updated_at, e.id
                           LIMIT $6"#,
                        filter,
                        changed_since,
                        settle,
                        after.as_ref().map(|c| c.id),
                        after.as_ref().and_then(|c| c.at),
                        limit + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last()
                            .map(|last| FeedCursor::encode(true, last.updated_at, last.id))
                    } else {
                        None
                    };
                    let events = rows
                        .into_iter()
                        .map(|row| {
                            Ok(RunEventRow {
                                id: row.id,
                                run: row.run,
                                kind: row.kind,
                                from_state: row
                                    .from_state
                                    .as_deref()
                                    .map(state_of)
                                    .transpose()?,
                                to_state: row.to_state.as_deref().map(state_of).transpose()?,
                                actor: RecordedActor::from_row(Some(row.actor))?,
                                details: row.details,
                                created_at: row.created_at,
                                updated_at: row.updated_at,
                            })
                        })
                        .collect::<Result<_, ServiceError>>()?;
                    Ok(RunEventFeedPage {
                        events,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// A page of the result rows of every run the filters match, in (updated_at, id) order, settled
    /// rows only: what reports pull. ace3's `fetch_result_feed_page`. It needs `svs:run_read`.
    pub async fn svs_run_result_feed(
        &self,
        actor: &Actor,
        query: &RunQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<RunResultPage, ServiceError> {
        let limit = page_limit(limit, MAX_RUNS_PAGE)?;
        let after = &cursor
            .map(|cursor| FeedCursor::decode(cursor, true))
            .transpose()?;
        let filter = &run_filter(query, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_run_result_feed", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = sqlx::query_as!(
                        ResultRowDb,
                        r#"SELECT x.id, r.uuid AS run, x.signature_uuid, x.signature_family,
                                  x.signature_name, x.status, x.alert_count, x.late_only,
                                  x.context_only, x.fallback_time, x.content_hash,
                                  x.suppressing_root_id, x.reviewed_status, x.reviewed_alert_count,
                                  x.reviewed_late_only, x.reviewed_content_hash, x.updated_at
                           FROM svs.run_results x
                           JOIN svs.runs r ON r.id = x.run_id
                           WHERE svs.run_matches(r, $1)
                             AND ($2::timestamptz IS NULL OR x.updated_at >= $2)
                             AND x.updated_at < now() - make_interval(secs => $3)
                             AND ($4::bigint IS NULL
                                  OR (x.updated_at, x.id) > ($5::timestamptz, $4))
                           ORDER BY x.updated_at, x.id
                           LIMIT $6"#,
                        filter,
                        changed_since,
                        settle,
                        after.as_ref().map(|c| c.id),
                        after.as_ref().and_then(|c| c.at),
                        limit + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last()
                            .map(|last| FeedCursor::encode(true, last.updated_at, last.id))
                    } else {
                        None
                    };
                    Ok(RunResultPage {
                        results: rows.into_iter().map(RunResult::from).collect(),
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// A page of the attributions of every run the filters match, removed ones included, in
    /// (updated_at, id) order, settled rows only: ace3's `fetch_attribution_feed_page`. A row shows up a
    /// few seconds after it's written, removed or kept, so a pull resumed from its last `updated_at`
    /// never misses one, and may repeat one. It needs `svs:run_read`.
    pub async fn svs_attribution_feed(
        &self,
        actor: &Actor,
        query: &RunQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<RunAttributionPage, ServiceError> {
        let limit = page_limit(limit, MAX_RUNS_PAGE)?;
        let after = &cursor
            .map(|cursor| FeedCursor::decode(cursor, true))
            .transpose()?;
        let filter = &run_filter(query, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_attribution_feed", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = sqlx::query_as!(
                        AttributionRowDb,
                        r#"SELECT a.id, r.uuid AS run, a.root_id, a.detection_id, d.signature_uuid,
                                  d.signature_family, a.confidence::text AS "confidence!", a.late,
                                  a.event_time,
                                  (r.cleanup_at IS NOT NULL AND a.event_time IS NOT NULL
                                   AND a.event_time >= r.cleanup_at) AS "cleanup!",
                                  a.event_time_source, a.source, a.scan_point,
                                  a.actor AS "actor!: Value", a.created_at, a.removed_at,
                                  a.removed_by AS "removed_by: Value", a.removal_reason, a.kept_at,
                                  a.kept_by AS "kept_by: Value", a.updated_at
                           FROM svs.attributions a
                           JOIN svs.runs r ON r.id = a.run_id
                           JOIN analysis.detections d ON d.id = a.detection_id
                           WHERE svs.run_matches(r, $1)
                             AND ($2::timestamptz IS NULL OR a.updated_at >= $2)
                             AND a.updated_at < now() - make_interval(secs => $3)
                             AND ($4::bigint IS NULL
                                  OR (a.updated_at, a.id) > ($5::timestamptz, $4))
                           ORDER BY a.updated_at, a.id
                           LIMIT $6"#,
                        filter,
                        changed_since,
                        settle,
                        after.as_ref().map(|c| c.id),
                        after.as_ref().and_then(|c| c.at),
                        limit + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last()
                            .map(|last| FeedCursor::encode(true, last.updated_at, last.id))
                    } else {
                        None
                    };
                    Ok(RunAttributionPage {
                        attributions: rows
                            .into_iter()
                            .map(RunAttribution::try_from)
                            .collect::<Result<_, _>>()?,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// A run's attributions, one row per (alert, detection) in id order, removed ones included: those
    /// after the row `after`, at most `limit` (`MAX_RUNS_PAGE` when None or more). ace3's
    /// `fetch_run_attributions_page`. It needs `svs:run_read`; a run that isn't there is `NotFound`.
    pub async fn svs_run_attributions(
        &self,
        actor: &Actor,
        uuid: Uuid,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Vec<RunAttribution>, ServiceError> {
        let max = i64::from(MAX_RUNS_PAGE);
        let limit = limit.unwrap_or(max).clamp(1, max);
        self.gate
            .read(actor, "svs_run_attributions", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let run = run_id(tx.conn(), uuid).await?;
                    let rows = sqlx::query_as!(
                        AttributionRowDb,
                        r#"SELECT a.id, $2::uuid AS "run!", a.root_id, a.detection_id,
                                  d.signature_uuid, d.signature_family,
                                  a.confidence::text AS "confidence!", a.late, a.event_time,
                                  (r.cleanup_at IS NOT NULL AND a.event_time IS NOT NULL
                                   AND a.event_time >= r.cleanup_at) AS "cleanup!",
                                  a.event_time_source, a.source, a.scan_point,
                                  a.actor AS "actor!: Value", a.created_at, a.removed_at,
                                  a.removed_by AS "removed_by: Value", a.removal_reason, a.kept_at,
                                  a.kept_by AS "kept_by: Value", a.updated_at
                           FROM svs.attributions a
                           JOIN svs.runs r ON r.id = a.run_id
                           JOIN analysis.detections d ON d.id = a.detection_id
                           WHERE a.run_id = $1 AND a.id > $3
                           ORDER BY a.id LIMIT $4"#,
                        run,
                        uuid,
                        after.unwrap_or(0),
                        limit,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    rows.into_iter().map(RunAttribution::try_from).collect()
                })
            })
            .await
    }

    /// The alerts a run holds or held, in the order they were first attributed to it, each with every
    /// detection it has and that detection's attribution to the run: those first attributed after the
    /// attribution `after` (a page's `next`), at most `limit` (`MAX_RUNS_PAGE` when None or more). ace3's
    /// `fetch_run_alerts_page`. It needs `svs:run_read`; a run that isn't there is `NotFound`. An
    /// attribution goes with its alert (`svs.attributions.root_id`), so ace3's alert that is gone has no
    /// row here.
    pub async fn svs_run_alerts(
        &self,
        actor: &Actor,
        uuid: Uuid,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<RunAlertPage, ServiceError> {
        let max = i64::from(MAX_RUNS_PAGE);
        let limit = limit.unwrap_or(max).clamp(1, max);
        self.gate
            .read(actor, "svs_run_alerts", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let run = run_id(tx.conn(), uuid).await?;
                    let mut keys = sqlx::query!(
                        r#"SELECT root_id, min(id) AS "first!" FROM svs.attributions
                           WHERE run_id = $1 GROUP BY root_id
                           HAVING min(id) > $2 ORDER BY min(id) LIMIT $3"#,
                        run,
                        after.unwrap_or(0),
                        limit + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let more = keys.len() as i64 > limit;
                    keys.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                    let next = keys.last().filter(|_| more).map(|key| key.first);
                    let roots: Vec<Uuid> = keys.iter().map(|key| key.root_id).collect();
                    if roots.is_empty() {
                        return Ok(RunAlertPage {
                            alerts: Vec::new(),
                            next,
                        });
                    }
                    let mut attributions: BTreeMap<Uuid, BTreeMap<i64, RunAttribution>> =
                        BTreeMap::new();
                    for row in sqlx::query_as!(
                        AttributionRowDb,
                        r#"SELECT a.id, $2::uuid AS "run!", a.root_id, a.detection_id,
                                  d.signature_uuid, d.signature_family,
                                  a.confidence::text AS "confidence!", a.late, a.event_time,
                                  (r.cleanup_at IS NOT NULL AND a.event_time IS NOT NULL
                                   AND a.event_time >= r.cleanup_at) AS "cleanup!",
                                  a.event_time_source, a.source, a.scan_point,
                                  a.actor AS "actor!: Value", a.created_at, a.removed_at,
                                  a.removed_by AS "removed_by: Value", a.removal_reason, a.kept_at,
                                  a.kept_by AS "kept_by: Value", a.updated_at
                           FROM svs.attributions a
                           JOIN svs.runs r ON r.id = a.run_id
                           JOIN analysis.detections d ON d.id = a.detection_id
                           WHERE a.run_id = $1 AND a.root_id = ANY ($3)
                           ORDER BY a.id"#,
                        run,
                        uuid,
                        &roots,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        let attribution = RunAttribution::try_from(row)?;
                        attributions
                            .entry(attribution.alert)
                            .or_default()
                            .insert(attribution.detection, attribution);
                    }
                    let mut detections: BTreeMap<Uuid, Vec<RunAlertDetection>> = BTreeMap::new();
                    for row in sqlx::query!(
                        "SELECT id, root_id, description, signature_uuid, signature_family
                         FROM analysis.detections WHERE root_id = ANY ($1) ORDER BY id",
                        &roots,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        let attribution = attributions
                            .get_mut(&row.root_id)
                            .and_then(|by| by.remove(&row.id));
                        detections
                            .entry(row.root_id)
                            .or_default()
                            .push(RunAlertDetection {
                                detection: row.id,
                                description: row.description,
                                signature_uuid: row.signature_uuid,
                                signature_family: row.signature_family,
                                attribution,
                            });
                    }
                    let mut summaries = crate::alerts::summaries_in(tx.conn(), &roots).await?;
                    let mut alerts = Vec::with_capacity(keys.len());
                    for key in keys {
                        let Some(alert) = summaries.remove(&key.root_id) else {
                            continue;
                        };
                        let detections = detections.remove(&key.root_id).unwrap_or_default();
                        let holding: Vec<&RunAttribution> = detections
                            .iter()
                            .filter_map(|d| d.attribution.as_ref())
                            .filter(|a| a.removed_at.is_none())
                            .collect();
                        let context: Vec<&&RunAttribution> = holding
                            .iter()
                            .filter(|a| a.confidence == AttributionConfidence::Context)
                            .collect();
                        let all_context = context.len() == holding.len();
                        let confidence = (!holding.is_empty()).then_some(if all_context {
                            AttributionConfidence::Context
                        } else {
                            AttributionConfidence::Marker
                        });
                        alerts.push(RunAlert {
                            alert,
                            first_attribution: key.first,
                            holds: !holding.is_empty(),
                            confidence,
                            late: holding.iter().any(|a| a.late),
                            cleanup: !holding.is_empty() && holding.iter().all(|a| a.cleanup),
                            fallback_time: holding.iter().any(|a| a.fallback_time),
                            manual: holding.iter().any(|a| a.source == "manual"),
                            kept: context.iter().any(|a| a.kept_at.is_some()),
                            undecided_context: context.iter().any(|a| a.kept_at.is_none()),
                            detections,
                        });
                    }
                    Ok(RunAlertPage { alerts, next })
                })
            })
            .await
    }

    /// A run's result, one row per signature in id order: those after the row `after`, at most `limit`
    /// (`MAX_RUNS_PAGE` when None or more), with whether the result is about to be recomputed. ace3's
    /// `fetch_run_results_page`. It needs `svs:run_read`; a run that isn't there is `NotFound`.
    pub async fn svs_run_results(
        &self,
        actor: &Actor,
        uuid: Uuid,
        after: Option<i64>,
        limit: Option<i64>,
    ) -> Result<RunResults, ServiceError> {
        let max = i64::from(MAX_RUNS_PAGE);
        let limit = limit.unwrap_or(max).clamp(1, max);
        self.gate
            .read(actor, "svs_run_results", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let state = sqlx::query!(
                        r#"SELECT r.id, s.stale AS "stale?", s.computed_at
                           FROM svs.runs r
                           LEFT JOIN svs.run_result_state s ON s.run_id = r.id
                           WHERE r.uuid = $1"#,
                        uuid,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| unknown_run(uuid))?;
                    let rows = sqlx::query_as!(
                        ResultRowDb,
                        r#"SELECT x.id, $2::uuid AS "run!", x.signature_uuid, x.signature_family,
                                  x.signature_name, x.status, x.alert_count, x.late_only,
                                  x.context_only, x.fallback_time, x.content_hash,
                                  x.suppressing_root_id, x.reviewed_status, x.reviewed_alert_count,
                                  x.reviewed_late_only, x.reviewed_content_hash, x.updated_at
                           FROM svs.run_results x
                           WHERE x.run_id = $1 AND x.id > $3
                           ORDER BY x.id LIMIT $4"#,
                        state.id,
                        uuid,
                        after.unwrap_or(0),
                        limit,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    Ok(RunResults {
                        results: rows.into_iter().map(RunResult::from).collect(),
                        stale: state.stale.unwrap_or(false),
                        computed_at: state.computed_at,
                    })
                })
            })
            .await
    }

    /// How each signature of the run's result did in the test's ended and reviewed runs on the run's
    /// platform (the only runs it is compared with) registered before it, the latest `runs` of them (10
    /// when None, at most `MAX_RUN_HISTORY`): ace3's `run_history`. It needs `svs:run_read`; a run that
    /// isn't there is `NotFound`, and a number of runs out of range `InvalidRequest`.
    pub async fn svs_run_history(
        &self,
        actor: &Actor,
        uuid: Uuid,
        runs: Option<u32>,
    ) -> Result<RunHistory, ServiceError> {
        let max = match runs {
            None => 10,
            Some(runs) if (1..=MAX_RUN_HISTORY).contains(&runs) => i64::from(runs),
            Some(runs) => {
                return Err(ServiceError::InvalidRequest(format!(
                    "a history holds 1 to {MAX_RUN_HISTORY} earlier runs, not {runs}"
                )));
            }
        };
        self.gate
            .read(actor, "svs_run_history", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let run = sqlx::query!(
                        "SELECT id, test_guid, platform, created_at FROM svs.runs WHERE uuid = $1",
                        uuid,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| unknown_run(uuid))?;
                    let signatures = sqlx::query_scalar!(
                        "SELECT signature_uuid FROM svs.run_results WHERE run_id = $1 ORDER BY id",
                        run.id,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let earlier = sqlx::query!(
                        r#"SELECT id, uuid, state::text AS "state!", created_at, reviewed_at
                           FROM svs.runs
                           WHERE test_guid = $1 AND platform = $2 AND state IN ('ended', 'reviewed')
                             AND (created_at, id) < ($3, $4)
                           ORDER BY created_at DESC, id DESC
                           LIMIT $5"#,
                        run.test_guid,
                        run.platform,
                        run.created_at,
                        run.id,
                        max,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let mut statuses: BTreeMap<(i64, String), Option<String>> = BTreeMap::new();
                    if !earlier.is_empty() && !signatures.is_empty() {
                        let ids: Vec<i64> = earlier.iter().map(|row| row.id).collect();
                        let reviewed: BTreeSet<i64> = earlier
                            .iter()
                            .filter(|row| row.state == "reviewed")
                            .map(|row| row.id)
                            .collect();
                        for row in sqlx::query!(
                            "SELECT run_id, signature_uuid, status, reviewed_status
                             FROM svs.run_results
                             WHERE run_id = ANY ($1) AND signature_uuid = ANY ($2)",
                            &ids,
                            &signatures,
                        )
                        .fetch_all(tx.conn())
                        .await?
                        {
                            let status = if reviewed.contains(&row.run_id) {
                                row.reviewed_status
                            } else {
                                row.status
                            };
                            statuses.insert((row.run_id, row.signature_uuid), status);
                        }
                    }
                    let signatures = signatures
                        .into_iter()
                        .map(|signature| SignatureHistory {
                            statuses: earlier
                                .iter()
                                .map(|row| {
                                    statuses
                                        .get(&(row.id, signature.clone()))
                                        .cloned()
                                        .flatten()
                                })
                                .collect(),
                            signature_uuid: signature,
                        })
                        .collect();
                    let runs = earlier
                        .into_iter()
                        .map(|row| {
                            Ok(HistoryRun {
                                run: row.uuid,
                                state: state_of(&row.state)?,
                                created_at: row.created_at,
                                reviewed_at: row.reviewed_at,
                            })
                        })
                        .collect::<Result<_, ServiceError>>()?;
                    Ok(RunHistory { runs, signatures })
                })
            })
            .await
    }

    /// How many of the expected signatures missing from reviewed runs were possibly suppressed, over
    /// every run's result as signed off, and whether the revisit trigger is reached: ace3's
    /// `suppression_share`. It needs `svs:run_read`.
    pub async fn svs_suppression_share(
        &self,
        actor: &Actor,
        now: DateTime<Utc>,
    ) -> Result<SuppressionShare, ServiceError> {
        self.gate
            .read(actor, "svs_suppression_share", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let missing = sqlx::query!(
                        r#"SELECT count(*) AS "missing!",
                                  count(*) FILTER (WHERE reviewed_status = 'possibly_suppressed')
                                      AS "suppressed!"
                           FROM svs.run_results
                           WHERE reviewed_status IN ('missing', 'possibly_suppressed')"#,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let reviewed_runs = sqlx::query_scalar!(
                        r#"SELECT count(*) AS "count!" FROM svs.runs WHERE reviewed_at IS NOT NULL"#,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    // a review again moves reviewed_at, so the first sign-off is the event log's
                    let first_reviewed_at = sqlx::query_scalar!(
                        "SELECT min(created_at) FROM svs.run_events WHERE kind = 'reviewed'",
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let trigger_reached = reviewed_runs >= SUPPRESSION_REVIEW_RUNS
                        || first_reviewed_at.is_some_and(|first| {
                            now - first >= TimeDelta::days(SUPPRESSION_REVIEW_DAYS)
                        });
                    Ok(SuppressionShare {
                        missing: missing.missing,
                        possibly_suppressed: missing.suppressed,
                        reviewed_runs,
                        first_reviewed_at,
                        trigger_reached,
                    })
                })
            })
            .await
    }

    /// How many rows a listing an export reads holds, counting up to `max` + 1, for the export to refuse
    /// one too large before it starts. It needs `svs:run_read`; a run that isn't there is `NotFound`.
    pub async fn svs_feed_count(
        &self,
        actor: &Actor,
        feed: &SvsFeed<'_>,
        max: i64,
    ) -> Result<i64, ServiceError> {
        let now = Utc::now();
        let filter = &match feed {
            SvsFeed::Runs(query)
            | SvsFeed::Batches(query)
            | SvsFeed::Events(query)
            | SvsFeed::Results(query)
            | SvsFeed::Attributions(query) => run_filter(query, now)?,
            _ => json!({}),
        };
        let settle = self.feed_settle_seconds();
        let cap = max.saturating_add(1);
        self.gate
            .read(actor, "svs_feed_count", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    Ok(match feed {
                        SvsFeed::Runs(query) => {
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                   SELECT FROM svs.runs r
                                   WHERE svs.run_matches(r, $1)
                                     AND ($2::timestamptz IS NULL
                                          OR (r.updated_at >= $2
                                              AND r.updated_at < now() - make_interval(secs => $3)))
                                   LIMIT $4) x"#,
                                filter,
                                query.changed_since,
                                settle,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::Batches(_) => {
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                   SELECT FROM svs.runs r
                                   WHERE r.batch_id IS NOT NULL AND svs.run_matches(r, $1)
                                   GROUP BY lower(r.batch_id)
                                   LIMIT $2) x"#,
                                filter,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::Events(query) => {
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                   SELECT FROM svs.run_events e
                                   JOIN svs.runs r ON r.id = e.run_id
                                   WHERE svs.run_matches(r, $1)
                                     AND ($2::timestamptz IS NULL OR e.updated_at >= $2)
                                     AND e.updated_at < now() - make_interval(secs => $3)
                                   LIMIT $4) x"#,
                                filter,
                                query.changed_since,
                                settle,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::Results(query) => {
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                   SELECT FROM svs.run_results x
                                   JOIN svs.runs r ON r.id = x.run_id
                                   WHERE svs.run_matches(r, $1)
                                     AND ($2::timestamptz IS NULL OR x.updated_at >= $2)
                                     AND x.updated_at < now() - make_interval(secs => $3)
                                   LIMIT $4) x"#,
                                filter,
                                query.changed_since,
                                settle,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::Attributions(query) => {
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                   SELECT FROM svs.attributions a
                                   JOIN svs.runs r ON r.id = a.run_id
                                   WHERE svs.run_matches(r, $1)
                                     AND ($2::timestamptz IS NULL OR a.updated_at >= $2)
                                     AND a.updated_at < now() - make_interval(secs => $3)
                                   LIMIT $4) x"#,
                                filter,
                                query.changed_since,
                                settle,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::RunAttributions(uuid) => {
                            let run = run_id(conn, *uuid).await?;
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                       SELECT FROM svs.attributions WHERE run_id = $1 LIMIT $2) x"#,
                                run,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::RunAlerts(uuid) => {
                            let run = run_id(conn, *uuid).await?;
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                       SELECT DISTINCT root_id FROM svs.attributions
                                       WHERE run_id = $1 LIMIT $2) x"#,
                                run,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::RunEvents(uuid) => {
                            let run = run_id(conn, *uuid).await?;
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                       SELECT FROM svs.run_events WHERE run_id = $1 LIMIT $2) x"#,
                                run,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::RunResults(uuid) => {
                            let run = run_id(conn, *uuid).await?;
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                       SELECT FROM svs.run_results WHERE run_id = $1 LIMIT $2) x"#,
                                run,
                                cap,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                        SvsFeed::Expectations(query) => {
                            crate::svs_decisions::expectation_count(conn, query, settle, cap)
                                .await?
                        }
                        SvsFeed::Ignores(query) => {
                            crate::svs_decisions::ignore_count(conn, query, settle, cap).await?
                        }
                        SvsFeed::TestHosts(changed_since) => {
                            sqlx::query_scalar!(
                                r#"SELECT count(*) AS "n!" FROM (
                                   SELECT FROM svs.test_hosts
                                   WHERE $1::timestamptz IS NULL
                                      OR (updated_at >= $1
                                          AND updated_at < now() - make_interval(secs => $3))
                                   LIMIT $2) x"#,
                                *changed_since,
                                cap,
                                settle,
                            )
                            .fetch_one(conn)
                            .await?
                        }
                    })
                })
            })
            .await
    }

    /// The run's comments, oldest first: ace3's `list_comments`. It needs `svs:run_read`; a run that
    /// isn't there is `NotFound`.
    pub async fn svs_run_comments(
        &self,
        actor: &Actor,
        uuid: Uuid,
    ) -> Result<Vec<RunComment>, ServiceError> {
        self.gate
            .read(actor, "svs_run_comments", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let run = run_id(tx.conn(), uuid).await?;
                    Ok(sqlx::query_as!(
                        RunComment,
                        r#"SELECT c.id, $2::uuid AS "run!", u.username::text AS "user?", c.comment,
                                  c.created_at, c.updated_at
                           FROM svs.run_comments c
                           LEFT JOIN service.users u ON u.id = c.user_id
                           WHERE c.run_id = $1 ORDER BY c.id"#,
                        run,
                        uuid,
                    )
                    .fetch_all(tx.conn())
                    .await?)
                })
            })
            .await
    }

    /// Adds a comment to a run: ace3's `add_comment`. It needs `svs:run_manage`, and a user to be by. A
    /// run that isn't there is `NotFound`; a comment that is empty or too long, or an actor that is
    /// nobody's, `InvalidRequest`.
    pub async fn add_svs_run_comment(
        &self,
        actor: &Actor,
        uuid: Uuid,
        comment: &str,
        now: DateTime<Utc>,
    ) -> Result<RunComment, ServiceError> {
        self.gate
            .write(actor, "add_svs_run_comment", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let user = author(actor)?;
                    let run = run_id(tx.conn(), uuid).await?;
                    let text = comment_text(comment)?;
                    let id = sqlx::query_scalar!(
                        "INSERT INTO svs.run_comments (run_id, user_id, comment, created_at)
                         VALUES ($1, $2, $3, $4) RETURNING id",
                        run,
                        user,
                        text,
                        now,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let added = comment_row(tx.conn(), id).await?;
                    let change =
                        Change::added(Target::svs_run_comment(id), &CommentRecord::of(&added))?;
                    Ok(Audited::changed(added, change))
                })
            })
            .await
    }

    /// Changes a comment; only its author can: ace3's `update_comment`. It needs `svs:run_manage`. A run
    /// or a comment that isn't there is `NotFound`, another's comment `Forbidden`, and text that can't be
    /// kept `InvalidRequest`. A change to nothing writes nothing.
    pub async fn update_svs_run_comment(
        &self,
        actor: &Actor,
        uuid: Uuid,
        id: i64,
        comment: &str,
    ) -> Result<RunComment, ServiceError> {
        self.gate
            .write(actor, "update_svs_run_comment", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let user = author(actor)?;
                    let before = own_comment(tx.conn(), uuid, id, user).await?;
                    let text = comment_text(comment)?;
                    if before.comment == text {
                        return Ok(Audited::unchanged(before));
                    }
                    sqlx::query!(
                        "UPDATE svs.run_comments SET comment = $2 WHERE id = $1",
                        id,
                        text,
                    )
                    .execute(tx.conn())
                    .await?;
                    let after = comment_row(tx.conn(), id).await?;
                    let change = Change::updated(
                        Target::svs_run_comment(id),
                        &CommentRecord::of(&before),
                        &CommentRecord::of(&after),
                    )?;
                    Ok(Audited::changed(after, change))
                })
            })
            .await
    }

    /// Deletes a comment; only its author can: ace3's `delete_comment`. It needs `svs:run_manage`. A run
    /// or a comment that isn't there is `NotFound`, and another's comment `Forbidden`.
    pub async fn delete_svs_run_comment(
        &self,
        actor: &Actor,
        uuid: Uuid,
        id: i64,
    ) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "delete_svs_run_comment", &SVS_RUN_MANAGE, &|tx| {
                Box::pin(async move {
                    let user = author(actor)?;
                    let before = own_comment(tx.conn(), uuid, id, user).await?;
                    sqlx::query!("DELETE FROM svs.run_comments WHERE id = $1", id)
                        .execute(tx.conn())
                        .await?;
                    let change =
                        Change::removed(Target::svs_run_comment(id), &CommentRecord::of(&before))?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }
}
