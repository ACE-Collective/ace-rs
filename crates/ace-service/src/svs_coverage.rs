//! SVS's ATT&CK coverage (PLAN.md 7.10 batch 8): the refresh, the snapshots and the reads of ace3's
//! `saq/svs/coverage.py`, `coverage_lock.py`, `coverage_filters.py` and `aceapi_v2/svs/coverage/service.py`,
//! over `ace_core::svs::coverage`, which computes.
//!
//! **The refresh** ([`Service::refresh_svs_coverage`]) needs `svs:coverage_refresh`, which the scheduler's
//! `svs_coverage_refresh` (every two minutes, ace3's `svs.coverage.refresh_interval_seconds`) and
//! `svs_coverage_snapshot` hold; `ace svs coverage refresh` acts as the first. In one transaction it locks
//! the one row of `svs.coverage_state`, reads the catalog tests that aren't removed or excluded (batch 10)
//! and judges them
//! (`svs_test_state`), reads the signatures' `mitre:` tags, refreshes the worklist (`svs_worklist`), computes
//! every row, and writes only the rows that changed, so a row's `updated_at` moves only on a real change. A
//! row the computation no longer produces is retired, never deleted. A refresh that changed a row writes
//! one audit row with its counts and the first of its state changes; one that changed nothing writes none,
//! so the audit log doesn't grow every two minutes. A failure changes no row; it's recorded on
//! `svs.coverage_state` by [`Service::record_svs_coverage_error`], audited once, and returned.
//!
//! **The lock.** A refresh, a snapshot and a worklist resolution each lock `svs.coverage_state`'s row
//! `FOR UPDATE` for their whole transaction ([`lock_refresh`]), so none of them computes from what another
//! is about to change: ace3's `lock_refresh`.
//!
//! **Snapshots** ([`Service::write_svs_coverage_snapshot`]) need `svs:coverage_snapshot`, which only the
//! scheduler's daily `svs_coverage_snapshot` holds (ace3's `etc/cron/daily/svs-coverage-snapshot`). It
//! refreshes, then files the rows that aren't retired under the day's date, UTC. A second snapshot on the
//! same day replaces the day, rewriting only the rows that differ. Each is audited.
//!
//! **Reading** needs `svs:run_read`, as in ace3: the rows a page at a time with the coverage screen's
//! filters, their counts per state, one technique's drill-down, and the snapshots with their counts per
//! day or month.
//!
//! How it scales. `svs.coverage` has a row per technique and platform, which the ATT&CK release bounds (a
//! few thousand), so the refresh's read of all of it, the summary's two grouped counts and a technique's
//! rows are small. A refresh's cost is its inputs': every catalog test that isn't removed or excluded (the catalog's
//! `max_tests`), and what `svs_test_state` reads of their runs and decisions, linear in those. The
//! drill-down reads three columns of every catalog test to resolve each technique as the refresh does, then
//! judges only the technique's own. `svs.coverage_snapshots` grows by the live rows each day and nothing
//! removes a day, as in ace3: its list pages by keyset along an index, the days it has are found by one
//! index probe per day, and the counts read at most [`MAX_HISTORY_PERIODS`] days' rows, the newest, saying
//! when there were more. The history's reads run under the lists' statement timeout.
//!
//! What differs from ace3's:
//! - The signatures' tags are the recorded hunts' and the current ruleset's rules' (`svs_results`), read in
//!   the refresh's transaction, so ace3's `SignatureTagsUnavailable` (a rule directory that can't be read)
//!   has no counterpart, and the drill-down has no `manual_signatures_error`. A refresh fails only when the
//!   database does.
//! - `tactics` is an array, and the Tactic filter matches its elements, where ace3 searches JSON text.
//! - The refresh and the snapshot are audited.
//! - The history's counts are capped at [`MAX_HISTORY_PERIODS`] periods.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use ace_core::svs::attack::AttackCatalog;
use ace_core::svs::coverage::{
    self, CoverageState, CoverageTest, Evaluations, RefreshState, covers, mapping_reason,
};
use ace_core::svs::signatures::{builtin_signatures, describe_signatures, signature_techniques};
use ace_core::svs::test_state::TestState;
use ace_core::svs::windows::recorded_hunts;
use chrono::{DateTime, NaiveDate, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::alerts::{SET_LIST_TIMEOUT, page_limit, timed_out};
use crate::filters::{FilterEntry, FilterScreen, Resolved};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SVS_COVERAGE_REFRESH, SVS_COVERAGE_SNAPSHOT, SVS_RUN_READ};
use crate::svs_decisions::{TestExclusion, exclusions};
use crate::svs_results::yara_signatures;
use crate::svs_run_reads::flag;
use crate::svs_test_state::{StateTest, evaluate_tests};
use crate::svs_worklist::{self, WorklistRefresh};
use crate::{Actor, Service, ServiceError};

/// The most coverage rows, and snapshot rows, one page holds.
pub const MAX_COVERAGE_PAGE: u32 = 1000;
/// The most days or months the history's counts answer for: the newest.
pub const MAX_HISTORY_PERIODS: usize = 366;
/// How many of a refresh's state changes its audit row lists; the counts are always whole.
const AUDITED_TRANSITIONS: usize = 50;

/// Coverage of one ATT&CK technique on one platform, as of the last refresh: a row of `svs.coverage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageRow {
    pub technique: String,
    pub platform: String,
    pub parent: Option<String>,
    pub is_subtechnique: bool,
    pub technique_name: Option<String>,
    pub tactics: Vec<String>,
    /// `active`, `deprecated` or `unknown`.
    pub catalog_status: String,
    pub attack_platform: bool,
    pub state: CoverageState,
    pub own_state: CoverageState,
    pub tests_total: i32,
    pub tests_validated: i32,
    pub tests_failing: i32,
    pub tests_stale: i32,
    pub manual_signatures: i32,
    pub measured_signatures: i32,
    pub last_reviewed_at: Option<DateTime<Utc>>,
    pub state_changed_at: DateTime<Utc>,
    pub first_seen_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
    /// When the row last changed: the `changed_since` key.
    pub updated_at: DateTime<Utc>,
}

/// Which coverage rows to list.
#[derive(Debug, Clone)]
pub struct CoverageQuery {
    pub filters: Vec<FilterEntry>,
    /// Only rows written or changed at or after this; the pages are then in (updated_at, id) order.
    pub changed_since: Option<DateTime<Utc>>,
    /// The timezone relative date filters resolve in.
    pub tz: Tz,
}

impl Default for CoverageQuery {
    fn default() -> Self {
        CoverageQuery {
            filters: Vec::new(),
            changed_since: None,
            tz: Tz::UTC,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveragePage {
    pub rows: Vec<CoverageRow>,
    pub next_cursor: Option<String>,
}

/// The rows of one platform, counted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCounts {
    pub platform: String,
    pub rows: i64,
    /// Rows per state, every state named.
    pub states: BTreeMap<String, i64>,
    pub own_states: BTreeMap<String, i64>,
}

/// The rows the filters match, counted, and what the last refresh did: ace3's `CoverageSummary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageSummary {
    pub rows: i64,
    pub states: BTreeMap<String, i64>,
    pub own_states: BTreeMap<String, i64>,
    /// The same per platform, in the release's platform order, then any other platform a test brought.
    pub platforms: Vec<PlatformCounts>,
    /// None before anything refreshed.
    pub refresh: Option<RefreshState>,
}

/// One catalog test on one platform, as it counts toward the technique's coverage there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageTestRow {
    pub guid: Uuid,
    pub name: String,
    /// The technique as the test's atomic file names it.
    pub test_technique: String,
    /// The technique it counts toward (a revoked id becomes its successor).
    pub technique: String,
    pub platform: String,
    /// never_run when it has no run or decision on the platform.
    pub test_state: TestState,
    /// What it counts as toward the row: failing, stale, validated or untested.
    pub contribution: CoverageState,
    pub last_reviewed_run: Option<Uuid>,
    pub last_reviewed_at: Option<DateTime<Utc>>,
    /// The signatures expected of it on the platform that no ignore applies to, sorted.
    pub expected_signatures: Vec<String>,
}

/// A signature expected of the technique's tests: a measured mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredSignature {
    pub signature_uuid: String,
    pub name: Option<String>,
    pub family: Option<String>,
    /// The (test, platform) pairs that expect it.
    pub tests: Vec<(Uuid, String)>,
}

/// A signature's `mitre:` tag naming the technique or a sub-technique: a manual mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualSignature {
    pub signature_uuid: String,
    pub name: Option<String>,
    pub family: String,
    /// The technique id the tag names.
    pub declared: String,
    /// The technique it counts toward.
    pub technique: String,
    pub counts: bool,
    /// Why it doesn't count: `not_counting` (disabled, or a YARA rule in QA mode), `unknown_technique`, or
    /// `removed` (resolved remove on the worklist).
    pub reason: Option<String>,
}

/// A test removed from its repository; it doesn't count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedTest {
    pub guid: Uuid,
    pub name: String,
    pub technique: String,
    pub removed_at: Option<DateTime<Utc>>,
}

/// A test a person excluded that is still in its repository; it doesn't count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExcludedTest {
    pub guid: Uuid,
    pub name: String,
    pub technique: String,
    pub exclusion: TestExclusion,
}

/// A technique's coverage: its rows as of the last refresh, and what counts toward them now. ace3's
/// `TechniqueCoverage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniqueCoverage {
    /// The id asked for.
    pub requested: String,
    /// The technique answered for: the requested id, or its successor when revoked.
    pub technique: String,
    pub name: Option<String>,
    pub parent: Option<String>,
    pub is_subtechnique: bool,
    pub catalog_status: String,
    pub tactics: Vec<String>,
    /// The pinned ATT&CK release.
    pub attack_release: String,
    /// When the rows were last refreshed; the tests and signatures are read now.
    pub refreshed_at: Option<DateTime<Utc>>,
    /// The technique's rows, retired ones included.
    pub rows: Vec<CoverageRow>,
    /// Its sub-techniques' rows, retired ones included.
    pub sub_technique_rows: Vec<CoverageRow>,
    /// The tests of the technique and its sub-techniques, per platform.
    pub tests: Vec<CoverageTestRow>,
    pub measured_signatures: Vec<MeasuredSignature>,
    pub manual_signatures: Vec<ManualSignature>,
    pub removed_tests: Vec<RemovedTest>,
    /// Its tests a person excluded that are still in their repository; a removed test is listed as removed,
    /// excluded or not.
    pub excluded_tests: Vec<ExcludedTest>,
}

/// A coverage row as it was on one day: a row of `svs.coverage_snapshots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageSnapshotRow {
    /// The UTC day.
    pub snapshot_date: NaiveDate,
    pub technique: String,
    pub platform: String,
    pub attack_release: String,
    pub parent: Option<String>,
    pub is_subtechnique: bool,
    pub state: CoverageState,
    pub own_state: CoverageState,
    pub tests_total: i32,
    pub tests_validated: i32,
    pub tests_failing: i32,
    pub tests_stale: i32,
    pub manual_signatures: i32,
    pub measured_signatures: i32,
    /// When the row was written; a second snapshot the same day rewrites it only when it differs.
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageHistoryPage {
    pub rows: Vec<CoverageSnapshotRow>,
    pub next_cursor: Option<String>,
}

/// How the history's counts are grouped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryGroup {
    /// Each day's snapshot.
    Day,
    /// Each month's last snapshot.
    Month,
}

impl HistoryGroup {
    pub fn as_str(self) -> &'static str {
        match self {
            HistoryGroup::Day => "day",
            HistoryGroup::Month => "month",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "day" => Some(HistoryGroup::Day),
            "month" => Some(HistoryGroup::Month),
            _ => None,
        }
    }
}

/// One period's counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodCounts {
    /// The day (2026-10-16) or the month (2026-10).
    pub period: String,
    /// The snapshot counted: the day's, or the month's last.
    pub snapshot_date: NaiveDate,
    pub rows: i64,
    pub states: BTreeMap<String, i64>,
    pub own_states: BTreeMap<String, i64>,
}

/// The snapshot rows the filters match counted per period, oldest first: ace3's `CoverageHistoryCounts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageHistoryCounts {
    pub group: HistoryGroup,
    pub periods: Vec<PeriodCounts>,
    /// There were more than [`MAX_HISTORY_PERIODS`] periods, and these are the newest.
    pub truncated: bool,
}

/// What one refresh did: ace3's `CoverageRefresh`, with what it did to the worklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageRefresh {
    pub attack_release: String,
    pub rows: usize,
    pub changed: usize,
    pub inserted: usize,
    pub retired: usize,
    pub duration_ms: i32,
    /// (technique, platform, from_state, to_state) of each row whose state changed.
    pub transitions: Vec<(String, String, String, String)>,
    /// Catalog tests whose technique isn't an ATT&CK technique id, left out.
    pub skipped_tests: Vec<Uuid>,
    pub worklist: WorklistRefresh,
}

/// What one snapshot did: ace3's `CoverageSnapshot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageSnapshot {
    pub snapshot_date: NaiveDate,
    pub attack_release: String,
    pub rows: i64,
    /// Rows of an earlier snapshot the same day that are no longer in coverage.
    pub deleted: i64,
}

/// Locks the row of `svs.coverage_state` (creating it the first time) for the caller's transaction: ace3's
/// `lock_refresh`. A refresh, a snapshot and a worklist resolution all take it first.
pub(crate) async fn lock_refresh(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query!("INSERT INTO svs.coverage_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING")
        .execute(&mut *conn)
        .await?;
    sqlx::query!("SELECT id FROM svs.coverage_state WHERE id = 1 FOR UPDATE")
        .fetch_one(conn)
        .await?;
    Ok(())
}

fn decoded<T>(what: &str, value: Option<T>) -> Result<T, ServiceError> {
    value.ok_or_else(|| ServiceError::from(ace_core::DbError::Decode(format!("a stored {what}"))))
}

fn state_of(text: &str) -> Result<CoverageState, ServiceError> {
    decoded("coverage state", CoverageState::parse(text))
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

/// A cursor's order has to be the listing's: one from a changed-since pull doesn't page the screen's order.
pub(crate) fn same_order(
    found: &str,
    changed: bool,
    screen_order: &str,
) -> Result<(), ServiceError> {
    let order = if changed { "updated_at" } else { screen_order };
    if found == order {
        return Ok(());
    }
    Err(ServiceError::InvalidRequest(format!(
        "this cursor pages a listing ordered by {found}, not {order}: pass the same changed_since (or \
         none) as the request that returned it"
    )))
}

fn key(slug: &str, inverted: bool) -> String {
    if inverted {
        format!("not_{slug}")
    } else {
        slug.to_owned()
    }
}

/// A date filter's windows as `svs.in_windows` reads them.
fn windows(
    f: &Resolved,
    slug: &'static str,
    inverted: bool,
) -> Result<Option<Value>, ServiceError> {
    Ok(f.windows(slug, inverted)?.map(|(starts, ends)| {
        Value::Array(
            starts
                .iter()
                .zip(&ends)
                .map(|(start, end)| json!([start, end]))
                .collect(),
        )
    }))
}

/// The filters the coverage screen and its history share, into `doc`.
fn shared_filters(f: &Resolved, doc: &mut Map<String, Value>) {
    for inverted in [false, true] {
        for slug in ["technique", "platform", "state", "own_state", "level"] {
            if let Some(values) = f.names(slug, inverted) {
                doc.insert(key(slug, inverted), json!(values));
            }
        }
    }
}

/// The coverage screen's filters as `svs.coverage_matches` reads them (migration 0058): ace3's
/// `coverage_filter_conditions`. A tactic is an id or a shortname of the pinned release, kept as the id.
fn coverage_filter(
    catalog: &AttackCatalog,
    query: &CoverageQuery,
    now: DateTime<Utc>,
) -> Result<Value, ServiceError> {
    let f = Resolved::new(FilterScreen::SvsCoverage, &query.filters, now, query.tz)?;
    let mut doc = Map::new();
    let mut nothing = false;
    shared_filters(&f, &mut doc);
    for inverted in [false, true] {
        if let Some(values) = f.names("catalog_status", inverted) {
            doc.insert(key("catalog_status", inverted), json!(values));
        }
        if let Some(patterns) = f.patterns("name", inverted, false) {
            doc.insert(key("name", inverted), json!(patterns));
        }
        if let Some(values) = f.names("tactic", inverted) {
            let mut tactics = Vec::with_capacity(values.len());
            for value in &values {
                let tactic = catalog.tactic(value).ok_or_else(|| {
                    ServiceError::InvalidRequest(format!(
                        "Tactic: invalid tactic {value:?} (expected an ATT&CK tactic id such as TA0002 or \
                         a shortname such as execution)"
                    ))
                })?;
                tactics.push(tactic.id.clone());
            }
            doc.insert(key("tactic", inverted), json!(tactics));
        }
        if let Some(windows) = windows(&f, "state_changed", inverted)? {
            doc.insert(key("state_changed", inverted), windows);
        }
    }
    for slug in ["attack_platform", "has_manual", "retired"] {
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

/// Which snapshot rows to list.
#[derive(Debug, Clone)]
pub struct CoverageHistoryQuery {
    pub filters: Vec<FilterEntry>,
    pub changed_since: Option<DateTime<Utc>>,
    pub tz: Tz,
}

impl Default for CoverageHistoryQuery {
    fn default() -> Self {
        CoverageHistoryQuery {
            filters: Vec::new(),
            changed_since: None,
            tz: Tz::UTC,
        }
    }
}

/// The history's filters as `svs.coverage_snapshot_matches` reads them: ace3's `history_filter_conditions`.
/// A Date value's window becomes the days it touches, in the query's timezone.
fn history_filter(
    filters: &[FilterEntry],
    tz: Tz,
    now: DateTime<Utc>,
) -> Result<Value, ServiceError> {
    let f = Resolved::new(FilterScreen::SvsCoverageHistory, filters, now, tz)?;
    let mut doc = Map::new();
    shared_filters(&f, &mut doc);
    for inverted in [false, true] {
        if let Some((starts, ends)) = f.windows("date", inverted)? {
            let days: Vec<Value> = starts
                .iter()
                .zip(&ends)
                .map(|(start, end)| {
                    json!([
                        start.with_timezone(&tz).date_naive(),
                        end.with_timezone(&tz).date_naive()
                    ])
                })
                .collect();
            doc.insert(key("date", inverted), Value::Array(days));
        }
    }
    Ok(Value::Object(doc))
}

struct ListRow {
    id: i64,
    technique: String,
    platform: String,
    parent: Option<String>,
    is_subtechnique: bool,
    technique_name: Option<String>,
    tactics: Vec<String>,
    catalog_status: String,
    attack_platform: bool,
    state: String,
    own_state: String,
    tests_total: i32,
    tests_validated: i32,
    tests_failing: i32,
    tests_stale: i32,
    manual_signatures: i32,
    measured_signatures: i32,
    last_reviewed_at: Option<DateTime<Utc>>,
    state_changed_at: DateTime<Utc>,
    first_seen_at: DateTime<Utc>,
    retired_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl ListRow {
    fn row(self) -> Result<CoverageRow, ServiceError> {
        Ok(CoverageRow {
            state: state_of(&self.state)?,
            own_state: state_of(&self.own_state)?,
            technique: self.technique,
            platform: self.platform,
            parent: self.parent,
            is_subtechnique: self.is_subtechnique,
            technique_name: self.technique_name,
            tactics: self.tactics,
            catalog_status: self.catalog_status,
            attack_platform: self.attack_platform,
            tests_total: self.tests_total,
            tests_validated: self.tests_validated,
            tests_failing: self.tests_failing,
            tests_stale: self.tests_stale,
            manual_signatures: self.manual_signatures,
            measured_signatures: self.measured_signatures,
            last_reviewed_at: self.last_reviewed_at,
            state_changed_at: self.state_changed_at,
            first_seen_at: self.first_seen_at,
            retired_at: self.retired_at,
            updated_at: self.updated_at,
        })
    }
}

/// Where a page of coverage rows left off: by (technique, platform, id), or (updated_at, id) for a
/// changed-since pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageCursor {
    /// `technique` or `updated_at`.
    o: String,
    technique: String,
    platform: String,
    at: DateTime<Utc>,
    id: i64,
}

/// The coverage rows `filter` matches, a page of them: by technique, then platform, in code point order,
/// or by (updated_at, id) for a changed-since pull, which holds back what changed in the last `settle`
/// seconds.
async fn list(
    conn: &mut PgConnection,
    filter: &Value,
    changed_since: Option<DateTime<Utc>>,
    settle: f64,
    after: Option<&CoverageCursor>,
    limit: i64,
) -> Result<Vec<ListRow>, sqlx::Error> {
    if changed_since.is_some() {
        return sqlx::query_as!(
            ListRow,
            r#"SELECT id, technique, platform, parent, is_subtechnique, technique_name, tactics,
                      catalog_status, attack_platform, state, own_state, tests_total, tests_validated,
                      tests_failing, tests_stale, manual_signatures, measured_signatures,
                      last_reviewed_at, state_changed_at, first_seen_at, retired_at, updated_at
               FROM svs.coverage c
               WHERE svs.coverage_matches(c, $1)
                 AND c.updated_at >= $2 AND c.updated_at < now() - make_interval(secs => $3)
                 AND ($4::bigint IS NULL OR (c.updated_at, c.id) > ($5::timestamptz, $4))
               ORDER BY c.updated_at, c.id
               LIMIT $6"#,
            filter,
            changed_since,
            settle,
            after.map(|c| c.id),
            after.map(|c| c.at),
            limit,
        )
        .fetch_all(conn)
        .await;
    }
    sqlx::query_as!(
        ListRow,
        r#"SELECT id, technique, platform, parent, is_subtechnique, technique_name, tactics,
                  catalog_status, attack_platform, state, own_state, tests_total, tests_validated,
                  tests_failing, tests_stale, manual_signatures, measured_signatures,
                  last_reviewed_at, state_changed_at, first_seen_at, retired_at, updated_at
           FROM svs.coverage c
           WHERE svs.coverage_matches(c, $1)
             AND ($2::bigint IS NULL
                  OR (c.technique COLLATE "C", c.platform COLLATE "C", c.id)
                     > ($3::text, $4::text, $2))
           ORDER BY c.technique COLLATE "C", c.platform COLLATE "C", c.id
           LIMIT $5"#,
        filter,
        after.map(|c| c.id),
        after.map(|c| c.technique.as_str()),
        after.map(|c| c.platform.as_str()),
        limit,
    )
    .fetch_all(conn)
    .await
}

struct SnapshotRow {
    id: i64,
    snapshot_date: NaiveDate,
    technique: String,
    platform: String,
    attack_release: String,
    parent: Option<String>,
    is_subtechnique: bool,
    state: String,
    own_state: String,
    tests_total: i32,
    tests_validated: i32,
    tests_failing: i32,
    tests_stale: i32,
    manual_signatures: i32,
    measured_signatures: i32,
    updated_at: DateTime<Utc>,
}

impl SnapshotRow {
    fn row(self) -> Result<CoverageSnapshotRow, ServiceError> {
        Ok(CoverageSnapshotRow {
            state: state_of(&self.state)?,
            own_state: state_of(&self.own_state)?,
            snapshot_date: self.snapshot_date,
            technique: self.technique,
            platform: self.platform,
            attack_release: self.attack_release,
            parent: self.parent,
            is_subtechnique: self.is_subtechnique,
            tests_total: self.tests_total,
            tests_validated: self.tests_validated,
            tests_failing: self.tests_failing,
            tests_stale: self.tests_stale,
            manual_signatures: self.manual_signatures,
            measured_signatures: self.measured_signatures,
            updated_at: self.updated_at,
        })
    }
}

/// Where a page of snapshot rows left off: by (snapshot_date, technique, platform, id), or (updated_at,
/// id) for a changed-since pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCursor {
    /// `date` or `updated_at`.
    o: String,
    day: NaiveDate,
    technique: String,
    platform: String,
    at: DateTime<Utc>,
    id: i64,
}

async fn list_history(
    conn: &mut PgConnection,
    filter: &Value,
    changed_since: Option<DateTime<Utc>>,
    settle: f64,
    after: Option<&HistoryCursor>,
    limit: i64,
) -> Result<Vec<SnapshotRow>, sqlx::Error> {
    if changed_since.is_some() {
        return sqlx::query_as!(
            SnapshotRow,
            r#"SELECT id, snapshot_date, technique, platform, attack_release, parent, is_subtechnique,
                      state, own_state, tests_total, tests_validated, tests_failing, tests_stale,
                      manual_signatures, measured_signatures, updated_at
               FROM svs.coverage_snapshots s
               WHERE svs.coverage_snapshot_matches(s, $1)
                 AND s.updated_at >= $2 AND s.updated_at < now() - make_interval(secs => $3)
                 AND ($4::bigint IS NULL OR (s.updated_at, s.id) > ($5::timestamptz, $4))
               ORDER BY s.updated_at, s.id
               LIMIT $6"#,
            filter,
            changed_since,
            settle,
            after.map(|c| c.id),
            after.map(|c| c.at),
            limit,
        )
        .fetch_all(conn)
        .await;
    }
    sqlx::query_as!(
        SnapshotRow,
        r#"SELECT id, snapshot_date, technique, platform, attack_release, parent, is_subtechnique,
                  state, own_state, tests_total, tests_validated, tests_failing, tests_stale,
                  manual_signatures, measured_signatures, updated_at
           FROM svs.coverage_snapshots s
           WHERE svs.coverage_snapshot_matches(s, $1)
             AND ($2::bigint IS NULL
                  OR (s.snapshot_date, s.technique COLLATE "C", s.platform COLLATE "C", s.id)
                     > ($3::date, $4::text, $5::text, $2))
           ORDER BY s.snapshot_date, s.technique COLLATE "C", s.platform COLLATE "C", s.id
           LIMIT $6"#,
        filter,
        after.map(|c| c.id),
        after.map(|c| c.day),
        after.map(|c| c.technique.as_str()),
        after.map(|c| c.platform.as_str()),
        limit,
    )
    .fetch_all(conn)
    .await
}

/// Every state, counted from (state, count) rows: ace3's `_counts`.
fn counted<'a>(rows: impl IntoIterator<Item = (&'a str, i64)>) -> BTreeMap<String, i64> {
    let mut counts: BTreeMap<String, i64> = CoverageState::ALL
        .iter()
        .map(|state| (state.as_str().to_owned(), 0))
        .collect();
    for (state, count) in rows {
        *counts.entry(state.to_owned()).or_default() += count;
    }
    counts
}

/// What a refresh's audit row keeps.
#[derive(Serialize)]
struct RefreshRecord<'a> {
    attack_release: &'a str,
    rows: usize,
    changed: usize,
    inserted: usize,
    retired: usize,
    /// The first of the rows whose state changed; `changed` counts every changed row.
    transitions: &'a [(String, String, String, String)],
    worklist_rows: usize,
    worklist_changed: usize,
    worklist_transitions: Vec<(&'a str, &'a str, &'a str, &'a str)>,
    worklist_cleared: &'a [(String, String, String)],
    worklist_moved: &'a [(String, String, String, String)],
}

impl Recorded for RefreshRecord<'_> {}

#[derive(Serialize)]
struct RefreshError<'a> {
    error: Option<&'a str>,
}

impl Recorded for RefreshError<'_> {}

#[derive(Serialize)]
struct SnapshotRecord<'a> {
    attack_release: &'a str,
    rows: i64,
    written: u64,
    deleted: i64,
}

impl Recorded for SnapshotRecord<'_> {}

/// What `_write` did.
#[derive(Default)]
struct Written {
    changed: usize,
    inserted: usize,
    retired: usize,
    transitions: Vec<(String, String, String, String)>,
}

struct StoredRow {
    id: i64,
    technique: String,
    platform: String,
    parent: Option<String>,
    is_subtechnique: bool,
    technique_name: Option<String>,
    tactics: Vec<String>,
    catalog_status: String,
    attack_platform: bool,
    state: String,
    own_state: String,
    tests_total: i32,
    tests_validated: i32,
    tests_failing: i32,
    tests_stale: i32,
    manual_signatures: i32,
    measured_signatures: i32,
    last_reviewed_at: Option<DateTime<Utc>>,
    retired_at: Option<DateTime<Utc>>,
}

impl StoredRow {
    /// The computed columns are the row's: ace3's `COMPUTED_COLUMNS` compared.
    fn holds(&self, row: &coverage::CoverageRow) -> bool {
        self.parent == row.parent
            && self.is_subtechnique == row.is_subtechnique
            && self.technique_name == row.technique_name
            && self.tactics == row.tactics
            && self.catalog_status == row.catalog_status.as_str()
            && self.attack_platform == row.attack_platform
            && self.state == row.state.as_str()
            && self.own_state == row.own_state.as_str()
            && self.tests_total == row.tests_total
            && self.tests_validated == row.tests_validated
            && self.tests_failing == row.tests_failing
            && self.tests_stale == row.tests_stale
            && self.manual_signatures == row.manual_signatures
            && self.measured_signatures == row.measured_signatures
            // a stored time is to the microsecond
            && self.last_reviewed_at.map(|at| at.timestamp_micros())
                == row.last_reviewed_at.map(|at| at.timestamp_micros())
    }
}

/// Writes the computed rows over the stored ones: ace3's `_write`. Only a row that differs, is new or
/// comes back from retirement is written, in one statement; one the computation no longer produces is
/// retired.
async fn write_rows(
    conn: &mut PgConnection,
    computed: &coverage::ComputedCoverage,
    now: DateTime<Utc>,
) -> Result<Written, ServiceError> {
    let stored: BTreeMap<(String, String), StoredRow> = sqlx::query_as!(
        StoredRow,
        "SELECT id, technique, platform, parent, is_subtechnique, technique_name, tactics,
                catalog_status, attack_platform, state, own_state, tests_total, tests_validated,
                tests_failing, tests_stale, manual_signatures, measured_signatures, last_reviewed_at,
                retired_at
         FROM svs.coverage"
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| ((row.technique.clone(), row.platform.clone()), row))
    .collect();

    let mut written = Written::default();
    let mut rows: Vec<Value> = Vec::new();
    for (key, row) in &computed.rows {
        match stored.get(key) {
            None => written.inserted += 1,
            Some(current) if current.holds(row) && current.retired_at.is_none() => continue,
            Some(current) => {
                if current.state != row.state.as_str() {
                    written.transitions.push((
                        row.technique.clone(),
                        row.platform.clone(),
                        current.state.clone(),
                        row.state.as_str().to_owned(),
                    ));
                }
            }
        }
        written.changed += 1;
        rows.push(json!({
            "technique": row.technique,
            "platform": row.platform,
            "parent": row.parent,
            "is_subtechnique": row.is_subtechnique,
            "technique_name": row.technique_name,
            "tactics": row.tactics,
            "catalog_status": row.catalog_status.as_str(),
            "attack_platform": row.attack_platform,
            "state": row.state.as_str(),
            "own_state": row.own_state.as_str(),
            "tests_total": row.tests_total,
            "tests_validated": row.tests_validated,
            "tests_failing": row.tests_failing,
            "tests_stale": row.tests_stale,
            "manual_signatures": row.manual_signatures,
            "measured_signatures": row.measured_signatures,
            "last_reviewed_at": row.last_reviewed_at,
        }));
    }
    if !rows.is_empty() {
        sqlx::query!(
            "INSERT INTO svs.coverage
                 (technique, platform, parent, is_subtechnique, technique_name, tactics, catalog_status,
                  attack_platform, state, own_state, tests_total, tests_validated, tests_failing,
                  tests_stale, manual_signatures, measured_signatures, last_reviewed_at,
                  state_changed_at, first_seen_at)
             SELECT u.technique, u.platform, u.parent, u.is_subtechnique, u.technique_name, u.tactics,
                    u.catalog_status, u.attack_platform, u.state, u.own_state, u.tests_total,
                    u.tests_validated, u.tests_failing, u.tests_stale, u.manual_signatures,
                    u.measured_signatures, u.last_reviewed_at, $2, $2
             FROM jsonb_to_recordset($1) AS u (
                 technique text, platform text, parent text, is_subtechnique boolean,
                 technique_name text, tactics text[], catalog_status text, attack_platform boolean,
                 state text, own_state text, tests_total integer, tests_validated integer,
                 tests_failing integer, tests_stale integer, manual_signatures integer,
                 measured_signatures integer, last_reviewed_at timestamptz)
             ON CONFLICT (technique, platform) DO UPDATE SET
                 parent = EXCLUDED.parent, is_subtechnique = EXCLUDED.is_subtechnique,
                 technique_name = EXCLUDED.technique_name, tactics = EXCLUDED.tactics,
                 catalog_status = EXCLUDED.catalog_status, attack_platform = EXCLUDED.attack_platform,
                 state_changed_at = CASE WHEN svs.coverage.state <> EXCLUDED.state
                                         THEN EXCLUDED.state_changed_at
                                         ELSE svs.coverage.state_changed_at END,
                 state = EXCLUDED.state, own_state = EXCLUDED.own_state,
                 tests_total = EXCLUDED.tests_total, tests_validated = EXCLUDED.tests_validated,
                 tests_failing = EXCLUDED.tests_failing, tests_stale = EXCLUDED.tests_stale,
                 manual_signatures = EXCLUDED.manual_signatures,
                 measured_signatures = EXCLUDED.measured_signatures,
                 last_reviewed_at = EXCLUDED.last_reviewed_at, retired_at = NULL",
            Value::Array(rows),
            now,
        )
        .execute(&mut *conn)
        .await?;
    }

    let retire: Vec<i64> = stored
        .iter()
        .filter(|(key, current)| !computed.rows.contains_key(*key) && current.retired_at.is_none())
        .map(|(_, current)| current.id)
        .collect();
    if !retire.is_empty() {
        sqlx::query!(
            "UPDATE svs.coverage SET retired_at = $2 WHERE id = ANY ($1)",
            &retire,
            now,
        )
        .execute(conn)
        .await?;
        written.changed += retire.len();
        written.retired = retire.len();
    }
    Ok(written)
}

/// The catalog tests that count toward coverage and the worklist: those not removed and not excluded.
async fn live_tests(
    conn: &mut PgConnection,
) -> Result<(Vec<CoverageTest>, Vec<StateTest>), sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT guid, technique, technique_name, platforms, content_hash
         FROM svs.catalog_tests t
         WHERE removed_at IS NULL
           AND NOT EXISTS (SELECT FROM svs.test_exclusions x WHERE x.test_guid = t.guid)"
    )
    .fetch_all(conn)
    .await?;
    let mut tests = Vec::with_capacity(rows.len());
    let mut state_tests = Vec::with_capacity(rows.len());
    for row in rows {
        state_tests.push(StateTest {
            guid: row.guid,
            content_hash: row.content_hash,
            platforms: row.platforms.clone(),
        });
        tests.push(CoverageTest {
            guid: row.guid,
            technique: row.technique,
            technique_name: row.technique_name,
            platforms: row.platforms,
        });
    }
    Ok((tests, state_tests))
}

/// The scheduler's `changed` count as the state row keeps it.
fn count(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

impl Service {
    /// The service with the ATT&CK release coverage is computed against, the overlay's
    /// `svs.attack_release` (PLAN.md 7.10 batch 8).
    pub fn with_attack_catalog(mut self, catalog: std::sync::Arc<AttackCatalog>) -> Self {
        self.attack = Some(catalog);
        self
    }

    /// The pinned ATT&CK release: the one the binary set, or ace3's default, which every build has.
    pub fn attack_catalog(&self) -> Result<std::sync::Arc<AttackCatalog>, ServiceError> {
        match &self.attack {
            Some(catalog) => Ok(catalog.clone()),
            None => ace_core::svs::attack::attack_catalog(ace_core::svs::attack::DEFAULT_RELEASE)
                .map_err(ServiceError::Unconfigured),
        }
    }

    /// Recomputes `svs.coverage` and the worklist as of `now`: ace3's `refresh_coverage`. A failure changes
    /// no row; it's recorded on `svs.coverage_state` and returned. It needs `svs:coverage_refresh`, and
    /// records a refresh that changed a row.
    pub async fn refresh_svs_coverage(
        &self,
        actor: &Actor,
        now: DateTime<Utc>,
    ) -> Result<CoverageRefresh, ServiceError> {
        let started = Instant::now();
        let catalog = &self.attack_catalog()?;
        let outcome = self
            .gate
            .write(
                actor,
                "refresh_svs_coverage",
                &SVS_COVERAGE_REFRESH,
                &|tx| {
                    Box::pin(async move {
                        let conn = tx.conn();
                        lock_refresh(conn).await?;
                        // read after the lock, so a refresh never writes what it read before another
                        // one wrote
                        let (tests, state_tests) = live_tests(conn).await?;
                        let evaluations: Evaluations = evaluate_tests(conn, &state_tests).await?;
                        let hunts = recorded_hunts(conn).await?;
                        let yara = yara_signatures(conn).await?;
                        let tags = signature_techniques(&hunts, &yara);
                        // the worklist first: what it resolved remove doesn't count
                        let measured = coverage::measured_by_signature(catalog, &tests, &evaluations);
                        let (worklist, excluded) = svs_worklist::refresh_in(
                            conn, catalog, &tags, &measured, &hunts, &yara, now,
                        )
                        .await?;
                        let computed =
                            coverage::compute_rows(catalog, &tests, &evaluations, &tags, &excluded);
                        let written = write_rows(conn, &computed, now).await?;

                        let duration_ms =
                            i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX);
                        sqlx::query!(
                            "UPDATE svs.coverage_state
                             SET attack_release = $1, refreshed_at = $2, duration_ms = $3, rows = $4,
                                 changed = $5, retired = $6, unknown_tags = $7, ignored_tags = $8,
                                 error = NULL
                             WHERE id = 1",
                            catalog.release,
                            now,
                            duration_ms,
                            count(computed.rows.len()),
                            count(written.changed),
                            count(written.retired),
                            computed.unknown_tags,
                            computed.ignored_tags,
                        )
                        .execute(tx.conn())
                        .await?;

                        let refresh = CoverageRefresh {
                            attack_release: catalog.release.clone(),
                            rows: computed.rows.len(),
                            changed: written.changed,
                            inserted: written.inserted,
                            retired: written.retired,
                            duration_ms,
                            transitions: written.transitions,
                            skipped_tests: computed.skipped_tests,
                            worklist,
                        };
                        if refresh.changed == 0 && !refresh.worklist.wrote {
                            return Ok(Audited::unchanged(refresh));
                        }
                        let listed = refresh.transitions.len().min(AUDITED_TRANSITIONS);
                        let change = Change::noted(
                            Target::svs_coverage(),
                            &RefreshRecord {
                                attack_release: &refresh.attack_release,
                                rows: refresh.rows,
                                changed: refresh.changed,
                                inserted: refresh.inserted,
                                retired: refresh.retired,
                                transitions: &refresh.transitions[..listed],
                                worklist_rows: refresh.worklist.rows,
                                worklist_changed: refresh.worklist.changed,
                                worklist_transitions: refresh
                                    .worklist
                                    .transitions
                                    .iter()
                                    .take(AUDITED_TRANSITIONS)
                                    .map(|(signature, technique, from, to)| {
                                        (
                                            signature.as_str(),
                                            technique.as_str(),
                                            from.as_str(),
                                            to.as_str(),
                                        )
                                    })
                                    .collect(),
                                worklist_cleared: &refresh.worklist.cleared,
                                worklist_moved: &refresh.worklist.moved,
                            },
                        )?;
                        Ok(Audited::changed(refresh, change))
                    })
                },
            )
            .await;
        let refresh = match outcome {
            Ok(refresh) => refresh,
            Err(error @ ServiceError::PermissionDenied { .. }) => return Err(error),
            Err(error) => {
                let message = error.to_string();
                if let Err(e) = self.record_svs_coverage_error(actor, &message).await {
                    tracing::warn!("unable to record the svs coverage refresh error: {e}");
                }
                return Err(error);
            }
        };

        // logged once committed
        svs_worklist::log_refresh(&refresh.worklist, actor);
        for (technique, platform, from_state, to_state) in &refresh.transitions {
            tracing::info!(
                technique,
                platform,
                from_state,
                to_state,
                "svs coverage of {technique} on {platform}: {from_state} -> {to_state}"
            );
        }
        if !refresh.skipped_tests.is_empty() {
            tracing::warn!(
                svs_tests = ?refresh.skipped_tests,
                "svs coverage left out {} catalog tests whose technique isn't an ATT&CK technique id",
                refresh.skipped_tests.len()
            );
        }
        tracing::info!(
            attack_release = refresh.attack_release,
            rows = refresh.rows,
            changed = refresh.changed,
            retired = refresh.retired,
            duration_ms = refresh.duration_ms,
            worklist_rows = refresh.worklist.rows,
            worklist_changed = refresh.worklist.changed,
            %actor,
            "svs coverage refreshed: {} rows, {} changed, {} retired in {}ms; worklist {} rows, {} changed",
            refresh.rows,
            refresh.changed,
            refresh.retired,
            refresh.duration_ms,
            refresh.worklist.rows,
            refresh.worklist.changed
        );
        Ok(refresh)
    }

    /// Puts why a refresh failed on `svs.coverage_state`, and returns whether the row changed: a failure
    /// it already holds writes nothing, so a refresh that stays broken doesn't add an audit row every two
    /// minutes. ace3's `_record_error`. It needs `svs:coverage_refresh`, and records the change.
    pub async fn record_svs_coverage_error(
        &self,
        actor: &Actor,
        error: &str,
    ) -> Result<bool, ServiceError> {
        // the column's bound, on a character boundary
        let error: String = error.chars().take(4096).collect();
        let error = if error.is_empty() {
            "the refresh failed"
        } else {
            error.as_str()
        };
        self.gate
            .write(
                actor,
                "record_svs_coverage_error",
                &SVS_COVERAGE_REFRESH,
                &|tx| {
                    Box::pin(async move {
                        lock_refresh(tx.conn()).await?;
                        let before = sqlx::query_scalar!(
                            "SELECT error FROM svs.coverage_state WHERE id = 1"
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        if before.as_deref() == Some(error) {
                            return Ok(Audited::unchanged(false));
                        }
                        sqlx::query!(
                            "UPDATE svs.coverage_state SET error = $1 WHERE id = 1",
                            error
                        )
                        .execute(tx.conn())
                        .await?;
                        let change = Change::updated(
                            Target::svs_coverage(),
                            &RefreshError {
                                error: before.as_deref(),
                            },
                            &RefreshError { error: Some(error) },
                        )?;
                        Ok(Audited::changed(true, change))
                    })
                },
            )
            .await
    }

    /// Refreshes coverage, then files its rows that aren't retired under `snapshot_date` (today, UTC,
    /// when None): ace3's `write_snapshot`. A second snapshot on the same day replaces the day. A failed
    /// refresh returns before anything is written. It needs `svs:coverage_snapshot` and
    /// `svs:coverage_refresh`, and records the snapshot.
    pub async fn write_svs_coverage_snapshot(
        &self,
        actor: &Actor,
        snapshot_date: Option<NaiveDate>,
        now: DateTime<Utc>,
    ) -> Result<CoverageSnapshot, ServiceError> {
        if !self.gate.allowed(actor, &SVS_COVERAGE_SNAPSHOT).await? {
            tracing::warn!(%actor, permission = %SVS_COVERAGE_SNAPSHOT, "permission denied");
            return Err(ServiceError::PermissionDenied {
                actor: actor.to_string(),
                permission: SVS_COVERAGE_SNAPSHOT,
            });
        }
        self.refresh_svs_coverage(actor, now).await?;
        let day = snapshot_date.unwrap_or_else(|| Utc::now().date_naive());
        let snapshot = self
            .gate
            .write(
                actor,
                "write_svs_coverage_snapshot",
                &SVS_COVERAGE_SNAPSHOT,
                &|tx| {
                    Box::pin(async move {
                        lock_refresh(tx.conn()).await?;
                        let attack_release = sqlx::query_scalar!(
                            "SELECT attack_release FROM svs.coverage_state WHERE id = 1"
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        let attack_release = decoded("coverage refresh", attack_release)?;
                        // a row of the day that holds the same already isn't rewritten
                        let written = sqlx::query!(
                            "INSERT INTO svs.coverage_snapshots AS s
                                 (snapshot_date, attack_release, technique, platform, parent,
                                  is_subtechnique, state, own_state, tests_total, tests_validated,
                                  tests_failing, tests_stale, manual_signatures, measured_signatures)
                             SELECT $1, $2, technique, platform, parent, is_subtechnique, state,
                                    own_state, tests_total, tests_validated, tests_failing, tests_stale,
                                    manual_signatures, measured_signatures
                             FROM svs.coverage WHERE retired_at IS NULL
                             ORDER BY technique, platform
                             ON CONFLICT (snapshot_date, technique, platform) DO UPDATE SET
                                 attack_release = EXCLUDED.attack_release, parent = EXCLUDED.parent,
                                 is_subtechnique = EXCLUDED.is_subtechnique, state = EXCLUDED.state,
                                 own_state = EXCLUDED.own_state, tests_total = EXCLUDED.tests_total,
                                 tests_validated = EXCLUDED.tests_validated,
                                 tests_failing = EXCLUDED.tests_failing,
                                 tests_stale = EXCLUDED.tests_stale,
                                 manual_signatures = EXCLUDED.manual_signatures,
                                 measured_signatures = EXCLUDED.measured_signatures
                             WHERE (s.attack_release, s.parent, s.is_subtechnique, s.state, s.own_state,
                                    s.tests_total, s.tests_validated, s.tests_failing, s.tests_stale,
                                    s.manual_signatures, s.measured_signatures)
                                   IS DISTINCT FROM
                                   (EXCLUDED.attack_release, EXCLUDED.parent, EXCLUDED.is_subtechnique,
                                    EXCLUDED.state, EXCLUDED.own_state, EXCLUDED.tests_total,
                                    EXCLUDED.tests_validated, EXCLUDED.tests_failing,
                                    EXCLUDED.tests_stale, EXCLUDED.manual_signatures,
                                    EXCLUDED.measured_signatures)",
                            day,
                            attack_release,
                        )
                        .execute(tx.conn())
                        .await?
                        .rows_affected();
                        let deleted = sqlx::query!(
                            "DELETE FROM svs.coverage_snapshots s
                             WHERE s.snapshot_date = $1
                               AND NOT EXISTS (
                                   SELECT FROM svs.coverage c
                                   WHERE c.technique = s.technique AND c.platform = s.platform
                                     AND c.retired_at IS NULL)",
                            day,
                        )
                        .execute(tx.conn())
                        .await?
                        .rows_affected() as i64;
                        let rows = sqlx::query_scalar!(
                            r#"SELECT count(*) AS "count!" FROM svs.coverage WHERE retired_at IS NULL"#
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        let change = Change::noted(
                            Target::svs_coverage_snapshot(day),
                            &SnapshotRecord {
                                attack_release: &attack_release,
                                rows,
                                written,
                                deleted,
                            },
                        )?;
                        Ok(Audited::changed(
                            CoverageSnapshot {
                                snapshot_date: day,
                                attack_release,
                                rows,
                                deleted,
                            },
                            change,
                        ))
                    })
                },
            )
            .await?;
        tracing::info!(
            snapshot_date = %snapshot.snapshot_date,
            rows = snapshot.rows,
            attack_release = snapshot.attack_release,
            %actor,
            "svs coverage snapshot of {} written: {} rows",
            snapshot.snapshot_date,
            snapshot.rows
        );
        Ok(snapshot)
    }

    /// A page of the coverage rows by technique, then platform, after where `cursor` left off: ace3's
    /// coverage listing. It needs `svs:run_read`.
    pub async fn svs_coverage(
        &self,
        actor: &Actor,
        query: &CoverageQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<CoveragePage, ServiceError> {
        let limit = page_limit(limit, MAX_COVERAGE_PAGE)?;
        let changed = query.changed_since.is_some();
        let after: Option<CoverageCursor> = cursor.map(decode_cursor).transpose()?;
        if let Some(after) = &after {
            same_order(&after.o, changed, "technique")?;
        }
        let after = &after;
        let filter = &coverage_filter(&*self.attack_catalog()?, query, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_coverage", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = list(
                        tx.conn(),
                        filter,
                        changed_since,
                        settle,
                        after.as_ref(),
                        limit + 1,
                    )
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last().map(|last| {
                            encode(&CoverageCursor {
                                o: if changed { "updated_at" } else { "technique" }.to_owned(),
                                technique: last.technique.clone(),
                                platform: last.platform.clone(),
                                at: last.updated_at,
                                id: last.id,
                            })
                        })
                    } else {
                        None
                    };
                    Ok(CoveragePage {
                        rows: rows
                            .into_iter()
                            .map(ListRow::row)
                            .collect::<Result<_, _>>()?,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// How many coverage rows `query` matches, counting up to `max` + 1, for an export to refuse one too
    /// large before it starts. It needs `svs:run_read`.
    pub async fn svs_coverage_count(
        &self,
        actor: &Actor,
        query: &CoverageQuery,
        max: i64,
    ) -> Result<i64, ServiceError> {
        let filter = &coverage_filter(&*self.attack_catalog()?, query, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_coverage_count", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let rows = list(
                        tx.conn(),
                        filter,
                        changed_since,
                        settle,
                        None,
                        max.saturating_add(1),
                    )
                    .await?;
                    Ok(rows.len() as i64)
                })
            })
            .await
    }

    /// The rows the filters match counted per state and own state, overall and per platform, and what the
    /// last refresh did: ace3's `get_summary`. It needs `svs:run_read`.
    pub async fn svs_coverage_summary(
        &self,
        actor: &Actor,
        query: &CoverageQuery,
    ) -> Result<CoverageSummary, ServiceError> {
        let catalog = &self.attack_catalog()?;
        let filter = &coverage_filter(catalog, query, Utc::now())?;
        self.gate
            .read(actor, "svs_coverage_summary", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut states: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
                    let mut own_states: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
                    for row in sqlx::query!(
                        r#"SELECT c.platform, c.state, c.own_state, count(*) AS "count!"
                           FROM svs.coverage c
                           WHERE svs.coverage_matches(c, $1)
                           GROUP BY c.platform, c.state, c.own_state"#,
                        filter,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        states
                            .entry(row.platform.clone())
                            .or_default()
                            .push((row.state, row.count));
                        own_states
                            .entry(row.platform)
                            .or_default()
                            .push((row.own_state, row.count));
                    }
                    // the release's platform order, then any other platform a test brought
                    let position = |platform: &str| {
                        catalog
                            .platforms
                            .iter()
                            .position(|(slug, _)| slug == platform)
                            .unwrap_or(catalog.platforms.len())
                    };
                    let mut platforms: Vec<&String> = states.keys().collect();
                    platforms.sort_by_key(|platform| (position(platform), (*platform).clone()));
                    let pairs = |rows: &[(String, i64)]| {
                        counted(rows.iter().map(|(state, count)| (state.as_str(), *count)))
                    };
                    let per_platform: Vec<PlatformCounts> = platforms
                        .into_iter()
                        .map(|platform| PlatformCounts {
                            platform: platform.clone(),
                            rows: states[platform].iter().map(|(_, count)| count).sum(),
                            states: pairs(&states[platform]),
                            own_states: pairs(&own_states[platform]),
                        })
                        .collect();
                    let all = |by: &BTreeMap<String, Vec<(String, i64)>>| {
                        counted(
                            by.values()
                                .flatten()
                                .map(|(state, count)| (state.as_str(), *count)),
                        )
                    };
                    Ok(CoverageSummary {
                        rows: per_platform.iter().map(|counts| counts.rows).sum(),
                        states: all(&states),
                        own_states: all(&own_states),
                        platforms: per_platform,
                        refresh: coverage::refresh_state(tx.conn()).await?,
                    })
                })
            })
            .await
    }

    /// A technique's coverage: its rows and its sub-techniques' as of the last refresh, and the tests and
    /// signatures that count toward them now. ace3's `get_technique` and `technique_detail`. A revoked id
    /// answers for its successor; something that isn't a technique id is `InvalidRequest`, and a technique
    /// with no rows that the release doesn't have `NotFound`. It needs `svs:run_read`.
    pub async fn svs_coverage_technique(
        &self,
        actor: &Actor,
        requested: &str,
    ) -> Result<TechniqueCoverage, ServiceError> {
        let catalog = &self.attack_catalog()?;
        let resolution = &catalog.resolve(requested).map_err(|_| {
            ServiceError::InvalidRequest(format!(
                "invalid technique {requested:?} (expected an ATT&CK id such as T1059 or T1059.001)"
            ))
        })?;
        let technique = resolution.technique.as_str();
        self.gate
            .read(actor, "svs_coverage_technique", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let conn = tx.conn();
                    let rows = sqlx::query_as!(
                        ListRow,
                        r#"SELECT id, technique, platform, parent, is_subtechnique, technique_name,
                                  tactics, catalog_status, attack_platform, state, own_state, tests_total,
                                  tests_validated, tests_failing, tests_stale, manual_signatures,
                                  measured_signatures, last_reviewed_at, state_changed_at,
                                  first_seen_at, retired_at, updated_at
                           FROM svs.coverage c
                           WHERE c.technique = $1 OR c.parent = $1
                           ORDER BY c.technique COLLATE "C", c.platform COLLATE "C""#,
                        technique,
                    )
                    .fetch_all(&mut *conn)
                    .await?;
                    let known = catalog.technique(technique);
                    let has_own = rows.iter().any(|row| row.technique == technique);
                    if !has_own && known.is_none() {
                        return Err(ServiceError::NotFound(format!(
                            "no coverage of technique {technique}"
                        )));
                    }
                    let first_name = rows
                        .iter()
                        .find(|row| row.technique == technique)
                        .and_then(|row| row.technique_name.clone());

                    // every test's technique, to resolve it as the refresh does; the whole rows only
                    // for the matches
                    let matching: Vec<Uuid> = sqlx::query!(
                        "SELECT guid, technique FROM svs.catalog_tests"
                    )
                    .fetch_all(&mut *conn)
                    .await?
                    .into_iter()
                    .filter(|row| {
                        catalog
                            .resolve(&row.technique)
                            .is_ok_and(|resolved| covers(catalog, technique, &resolved.technique))
                    })
                    .map(|row| row.guid)
                    .collect();
                    let found = sqlx::query!(
                        r#"SELECT guid, name, technique, technique_name, platforms, content_hash,
                                  removed_at
                           FROM svs.catalog_tests WHERE guid = ANY ($1)
                           ORDER BY technique COLLATE "C", name COLLATE "C", id"#,
                        &matching,
                    )
                    .fetch_all(&mut *conn)
                    .await?;
                    let guids: Vec<Uuid> = found.iter().map(|row| row.guid).collect();
                    let mut excluded = exclusions(&mut *conn, &guids).await?;
                    let mut removed_tests = Vec::new();
                    let mut excluded_tests = Vec::new();
                    let mut current = Vec::new();
                    for row in found {
                        if row.removed_at.is_some() {
                            removed_tests.push(RemovedTest {
                                guid: row.guid,
                                name: row.name,
                                technique: row.technique,
                                removed_at: row.removed_at,
                            });
                        } else if let Some(exclusion) = excluded.remove(&row.guid) {
                            excluded_tests.push(ExcludedTest {
                                guid: row.guid,
                                name: row.name,
                                technique: row.technique,
                                exclusion,
                            });
                        } else {
                            current.push(row);
                        }
                    }
                    let state_tests: Vec<StateTest> = current
                        .iter()
                        .map(|row| StateTest {
                            guid: row.guid,
                            content_hash: row.content_hash.clone(),
                            platforms: row.platforms.clone(),
                        })
                        .collect();
                    let evaluations = evaluate_tests(conn, &state_tests).await?;
                    let mut tests = Vec::new();
                    let mut measured: BTreeMap<String, Vec<(Uuid, String)>> = BTreeMap::new();
                    for row in &current {
                        let test = CoverageTest {
                            guid: row.guid,
                            technique: row.technique.clone(),
                            technique_name: row.technique_name.clone(),
                            platforms: row.platforms.clone(),
                        };
                        let by_platform = evaluations.get(&row.guid);
                        let (Some(counts_toward), counted) =
                            coverage::test_contributions(catalog, &test, by_platform)
                        else {
                            continue;
                        };
                        for (platform, contribution) in counted {
                            let evaluation = by_platform.and_then(|by| by.get(&platform));
                            let run = evaluation.and_then(|e| e.run.as_ref());
                            let expected: Vec<String> =
                                contribution.measured.iter().cloned().collect();
                            for signature in &expected {
                                measured
                                    .entry(signature.clone())
                                    .or_default()
                                    .push((row.guid, platform.clone()));
                            }
                            tests.push(CoverageTestRow {
                                guid: row.guid,
                                name: row.name.clone(),
                                test_technique: row.technique.clone(),
                                technique: counts_toward.clone(),
                                platform,
                                test_state: evaluation.map_or(TestState::NeverRun, |e| e.state),
                                contribution: contribution.state,
                                last_reviewed_run: run.map(|run| run.uuid),
                                last_reviewed_at: run.and_then(|run| run.reviewed_at),
                                expected_signatures: expected,
                            });
                        }
                    }

                    let hunts = recorded_hunts(conn).await?;
                    let yara = yara_signatures(conn).await?;
                    let tags = signature_techniques(&hunts, &yara);
                    let excluded = svs_worklist::excluded_mappings(conn).await?;
                    let mut manual_signatures = Vec::new();
                    for signature in tags.values() {
                        for declared in &signature.declared {
                            let Ok(resolved) = catalog.resolve(declared) else {
                                continue;
                            };
                            if !covers(catalog, technique, &resolved.technique) {
                                continue;
                            }
                            let reason = mapping_reason(
                                resolved.status,
                                signature.counts,
                                excluded
                                    .contains(&(signature.uuid.clone(), resolved.technique.clone())),
                            );
                            manual_signatures.push(ManualSignature {
                                signature_uuid: signature.uuid.clone(),
                                name: signature.name.clone(),
                                family: signature.family.clone(),
                                declared: declared.clone(),
                                technique: resolved.technique,
                                counts: reason.is_none(),
                                reason: reason.map(str::to_owned),
                            });
                        }
                    }
                    let described = describe_signatures(
                        measured.keys().map(String::as_str),
                        &builtin_signatures(),
                        &hunts,
                        &yara,
                    );
                    let refreshed_at = coverage::refresh_state(conn)
                        .await?
                        .and_then(|state| state.refreshed_at);

                    let mut own = Vec::new();
                    let mut sub_technique_rows = Vec::new();
                    for row in rows {
                        if row.technique == technique {
                            own.push(row.row()?);
                        } else {
                            sub_technique_rows.push(row.row()?);
                        }
                    }
                    Ok(TechniqueCoverage {
                        requested: requested.to_owned(),
                        technique: technique.to_owned(),
                        name: match known {
                            Some(known) => Some(known.name.clone()),
                            None => first_name,
                        },
                        parent: catalog.parent_of(technique).map(str::to_owned),
                        is_subtechnique: technique.contains('.'),
                        catalog_status: resolution.status.as_str().to_owned(),
                        tactics: known.map(|known| known.tactics.clone()).unwrap_or_default(),
                        attack_release: catalog.release.clone(),
                        refreshed_at,
                        rows: own,
                        sub_technique_rows,
                        tests,
                        measured_signatures: measured
                            .into_iter()
                            .map(|(signature_uuid, tests)| {
                                let info = described.get(&signature_uuid);
                                MeasuredSignature {
                                    name: info.and_then(|info| info.name.clone()),
                                    family: info.and_then(|info| info.family.clone()),
                                    signature_uuid,
                                    tests,
                                }
                            })
                            .collect(),
                        manual_signatures,
                        removed_tests,
                        excluded_tests,
                    })
                })
            })
            .await
    }

    /// A page of the daily snapshot rows by day, technique and platform, oldest first, after where
    /// `cursor` left off: ace3's `list_history`. It needs `svs:run_read`.
    pub async fn svs_coverage_history(
        &self,
        actor: &Actor,
        query: &CoverageHistoryQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<CoverageHistoryPage, ServiceError> {
        let limit = page_limit(limit, MAX_COVERAGE_PAGE)?;
        let changed = query.changed_since.is_some();
        let after: Option<HistoryCursor> = cursor.map(decode_cursor).transpose()?;
        if let Some(after) = &after {
            same_order(&after.o, changed, "date")?;
        }
        let after = &after;
        let filter = &history_filter(&query.filters, query.tz, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_coverage_history", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    let mut rows = list_history(
                        tx.conn(),
                        filter,
                        changed_since,
                        settle,
                        after.as_ref(),
                        limit + 1,
                    )
                    .await
                    .map_err(timed_out)?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last().map(|last| {
                            encode(&HistoryCursor {
                                o: if changed { "updated_at" } else { "date" }.to_owned(),
                                day: last.snapshot_date,
                                technique: last.technique.clone(),
                                platform: last.platform.clone(),
                                at: last.updated_at,
                                id: last.id,
                            })
                        })
                    } else {
                        None
                    };
                    Ok(CoverageHistoryPage {
                        rows: rows
                            .into_iter()
                            .map(SnapshotRow::row)
                            .collect::<Result<_, _>>()?,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// How many snapshot rows `query` matches, counting up to `max` + 1, for an export. It needs
    /// `svs:run_read`.
    pub async fn svs_coverage_history_count(
        &self,
        actor: &Actor,
        query: &CoverageHistoryQuery,
        max: i64,
    ) -> Result<i64, ServiceError> {
        let filter = &history_filter(&query.filters, query.tz, Utc::now())?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_coverage_history_count", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    let rows = list_history(
                        tx.conn(),
                        filter,
                        changed_since,
                        settle,
                        None,
                        max.saturating_add(1),
                    )
                    .await
                    .map_err(timed_out)?;
                    Ok(rows.len() as i64)
                })
            })
            .await
    }

    /// The snapshot rows the filters match counted per state and own state, per day, or per month from
    /// each month's last snapshot: ace3's `get_history_counts`. The days come from the Date filter alone:
    /// a day whose rows the other filters leave out still counts, as zeros, and is still its month's last.
    /// At most [`MAX_HISTORY_PERIODS`] periods, the newest. It needs `svs:run_read`.
    pub async fn svs_coverage_history_counts(
        &self,
        actor: &Actor,
        filters: &[FilterEntry],
        group: HistoryGroup,
        tz: Tz,
    ) -> Result<CoverageHistoryCounts, ServiceError> {
        let filter = &history_filter(filters, tz, Utc::now())?;
        self.gate
            .read(actor, "svs_coverage_history_counts", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    // the days that have a snapshot, one index probe each, oldest first
                    let days: Vec<NaiveDate> = sqlx::query_scalar!(
                        r#"WITH RECURSIVE days AS (
                               SELECT min(snapshot_date) AS day FROM svs.coverage_snapshots
                               UNION ALL
                               SELECT (SELECT min(snapshot_date) FROM svs.coverage_snapshots
                                       WHERE snapshot_date > days.day)
                               FROM days WHERE days.day IS NOT NULL)
                           SELECT day AS "day!" FROM days
                           WHERE day IS NOT NULL
                             AND ($1::jsonb -> 'date' IS NULL OR svs.on_days(day, $1 -> 'date'))
                             AND ($1 -> 'not_date' IS NULL OR NOT svs.on_days(day, $1 -> 'not_date'))
                           ORDER BY day"#,
                        filter,
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(timed_out)?;

                    // ascending, so a month keeps its last day
                    let mut periods: BTreeMap<String, NaiveDate> = BTreeMap::new();
                    for day in days {
                        let period = match group {
                            HistoryGroup::Day => day.format("%Y-%m-%d").to_string(),
                            HistoryGroup::Month => day.format("%Y-%m").to_string(),
                        };
                        periods.insert(period, day);
                    }
                    let truncated = periods.len() > MAX_HISTORY_PERIODS;
                    let mut periods: Vec<(String, NaiveDate)> = periods.into_iter().collect();
                    if truncated {
                        periods.drain(..periods.len() - MAX_HISTORY_PERIODS);
                    }
                    if periods.is_empty() {
                        return Ok(CoverageHistoryCounts {
                            group,
                            periods: Vec::new(),
                            truncated,
                        });
                    }
                    let wanted: Vec<NaiveDate> = periods.iter().map(|(_, day)| *day).collect();
                    let mut states: BTreeMap<NaiveDate, Vec<(String, i64)>> = BTreeMap::new();
                    let mut own_states: BTreeMap<NaiveDate, Vec<(String, i64)>> = BTreeMap::new();
                    for row in sqlx::query!(
                        r#"SELECT s.snapshot_date, s.state, s.own_state, count(*) AS "count!"
                           FROM svs.coverage_snapshots s
                           WHERE s.snapshot_date = ANY ($2) AND svs.coverage_snapshot_matches(s, $1)
                           GROUP BY s.snapshot_date, s.state, s.own_state"#,
                        filter,
                        &wanted,
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(timed_out)?
                    {
                        states
                            .entry(row.snapshot_date)
                            .or_default()
                            .push((row.state, row.count));
                        own_states
                            .entry(row.snapshot_date)
                            .or_default()
                            .push((row.own_state, row.count));
                    }
                    let none: Vec<(String, i64)> = Vec::new();
                    let pairs = |rows: &Vec<(String, i64)>| {
                        counted(rows.iter().map(|(state, count)| (state.as_str(), *count)))
                    };
                    Ok(CoverageHistoryCounts {
                        group,
                        periods: periods
                            .into_iter()
                            .map(|(period, day)| {
                                let of_day = states.get(&day).unwrap_or(&none);
                                PeriodCounts {
                                    period,
                                    snapshot_date: day,
                                    rows: of_day.iter().map(|(_, count)| count).sum(),
                                    states: pairs(of_day),
                                    own_states: pairs(own_states.get(&day).unwrap_or(&none)),
                                }
                            })
                            .collect(),
                        truncated,
                    })
                })
            })
            .await
    }
}

/// The (signature, technique) pairs a set of rows names, for a caller that has them as text.
pub(crate) type Excluded = BTreeSet<(String, String)>;
