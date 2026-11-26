//! `/api/svs/v1/coverage`: SVS's ATT&CK coverage (PLAN.md 7.10 batch 8), ace3's `aceapi_v2/svs/coverage`
//! router, over `ace_service`'s `svs_coverage`. Coverage per technique and platform as the scheduler's
//! `svs_coverage_refresh` last refreshed it, counted in a summary, one technique's drill-down, and the
//! daily snapshots with their counts per day or month. Everything here reads, with `svs:run_read`.
//!
//! | ace3 `/api/v2/svs/coverage` | here |
//! |---|---|
//! | `GET /?f=&changed_since=&tz=&cursor=&limit=` | `GET /api/svs/v1/coverage`, the same filters, orders and keyset paging |
//! | `GET /export/ndjson`, `GET /export/csv` | `GET /api/svs/v1/coverage/export/{format}` |
//! | `GET /summary?f=&tz=` | `GET /api/svs/v1/coverage/summary` |
//! | `GET /history?f=&changed_since=&tz=&cursor=&limit=` | `GET /api/svs/v1/coverage/history` |
//! | `GET /history/export/ndjson`, `.../csv` | `GET /api/svs/v1/coverage/history/export/{format}` |
//! | `GET /history/counts?f=&group=&tz=` | `GET /api/svs/v1/coverage/history/counts` |
//! | `GET /{technique}` | `GET /api/svs/v1/coverage/{technique}` |
//!
//! From ace3: a page is `{rows, next}`, where ace3's is `{data, next_cursor}`; a refused parameter is 400
//! where ace3 answers 422; an export is one operation with `csv` or `ndjson`, at ace3's two URLs; the
//! summary's refresh is under `refresh`, null before the first; the history's counts are `periods`, at most
//! 366 of them, the newest, with `truncated` saying when there were more; and the drill-down has no
//! `manual_signatures_error`, since the signatures' tags are read from the database with everything else.
//! Nothing here refreshes: the scheduler does, and `ace svs coverage refresh`.

use std::collections::BTreeMap;

use ace_service::filters::{FilterScreen, decode};
use ace_service::{
    CoverageHistoryCounts, CoverageHistoryQuery, CoverageQuery, CoverageRow, CoverageSnapshotRow,
    CoverageSummary, HistoryGroup, SvsCoverageRefreshState, TechniqueCoverage,
};
use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::response::Response;
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, time_cell};
use crate::params::Params;
use crate::svs_run_reads::format_of;

fn cell(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

/// Coverage of one ATT&CK technique on one platform, as of the last refresh.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoverageRowBody {
    /// The ATT&CK technique id, such as `T1059` or `T1059.001`.
    technique: String,
    /// An ATT&CK platform slug: `windows`, `linux`, `macos`, `iaas`, ...
    platform: String,
    /// The parent technique of a sub-technique.
    parent: Option<String>,
    is_subtechnique: bool,
    technique_name: Option<String>,
    /// The technique's tactic ids (`TA0002`) in the pinned release.
    tactics: Vec<String>,
    /// `active`, `deprecated`, or `unknown` (not in the pinned release).
    catalog_status: String,
    /// ATT&CK lists the platform for the technique; otherwise only a test brought the row.
    attack_platform: bool,
    /// `failing`, `stale`, `validated`, `manual`, `untested` or `none`: the worst of what counts toward
    /// the technique and its sub-techniques on the platform.
    state: String,
    /// The same, leaving the sub-techniques out.
    own_state: String,
    /// Tests counted toward `state`, the sub-techniques' included.
    tests_total: i32,
    tests_validated: i32,
    tests_failing: i32,
    tests_stale: i32,
    /// Signatures whose `mitre:` tag counts toward `state`.
    manual_signatures: i32,
    /// Signatures expected of the counted tests on the platform.
    measured_signatures: i32,
    /// The latest review of a run that counts.
    last_reviewed_at: Option<DateTime<Utc>>,
    state_changed_at: DateTime<Utc>,
    first_seen_at: DateTime<Utc>,
    /// When the computation stopped producing the row; it is never deleted.
    retired_at: Option<DateTime<Utc>>,
    /// When the row last changed: the `changed_since` key.
    updated_at: DateTime<Utc>,
}

impl From<CoverageRow> for CoverageRowBody {
    fn from(r: CoverageRow) -> Self {
        CoverageRowBody {
            technique: r.technique,
            platform: r.platform,
            parent: r.parent,
            is_subtechnique: r.is_subtechnique,
            technique_name: r.technique_name,
            tactics: r.tactics,
            catalog_status: r.catalog_status,
            attack_platform: r.attack_platform,
            state: r.state.as_str().to_owned(),
            own_state: r.own_state.as_str().to_owned(),
            tests_total: r.tests_total,
            tests_validated: r.tests_validated,
            tests_failing: r.tests_failing,
            tests_stale: r.tests_stale,
            manual_signatures: r.manual_signatures,
            measured_signatures: r.measured_signatures,
            last_reviewed_at: r.last_reviewed_at,
            state_changed_at: r.state_changed_at,
            first_seen_at: r.first_seen_at,
            retired_at: r.retired_at,
            updated_at: r.updated_at,
        }
    }
}

impl ExportRow for CoverageRowBody {
    const HEADER: &'static [&'static str] = &[
        "technique",
        "platform",
        "parent",
        "is_subtechnique",
        "technique_name",
        "tactics",
        "catalog_status",
        "attack_platform",
        "state",
        "own_state",
        "tests_total",
        "tests_validated",
        "tests_failing",
        "tests_stale",
        "manual_signatures",
        "measured_signatures",
        "last_reviewed_at",
        "state_changed_at",
        "first_seen_at",
        "retired_at",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.technique.clone(),
            self.platform.clone(),
            cell(&self.parent),
            self.is_subtechnique.to_string(),
            cell(&self.technique_name),
            // joined with ",", as ace3's CSV writes them
            self.tactics.join(","),
            self.catalog_status.clone(),
            self.attack_platform.to_string(),
            self.state.clone(),
            self.own_state.clone(),
            self.tests_total.to_string(),
            self.tests_validated.to_string(),
            self.tests_failing.to_string(),
            self.tests_stale.to_string(),
            self.manual_signatures.to_string(),
            self.measured_signatures.to_string(),
            time_cell(self.last_reviewed_at),
            time_cell(Some(self.state_changed_at)),
            time_cell(Some(self.first_seen_at)),
            time_cell(self.retired_at),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of coverage rows.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoveragePageBody {
    rows: Vec<CoverageRowBody>,
    /// Pass it as `cursor`, with the same filters, for the next page; null on the last.
    next: Option<String>,
}

/// The rows of one platform, counted.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PlatformCountsBody {
    platform: String,
    rows: i64,
    /// Rows per state, every state named.
    states: BTreeMap<String, i64>,
    /// Rows per own_state, every state named.
    own_states: BTreeMap<String, i64>,
}

/// What the last coverage refresh did.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoverageRefreshBody {
    /// The ATT&CK release of the last refresh that completed.
    attack_release: Option<String>,
    /// When the last refresh completed; null before the first.
    refreshed_at: Option<DateTime<Utc>>,
    duration_ms: Option<i32>,
    /// The rows it computed, how many it wrote, and how many of those it retired.
    rows: i32,
    changed: i32,
    retired: i32,
    /// `mitre:` tags naming an id the release doesn't have.
    unknown_tags: i32,
    /// `mitre:` tags that aren't technique ids (templated, tactics).
    ignored_tags: i32,
    /// Why the latest refresh failed; null once one completes.
    error: Option<String>,
}

impl From<SvsCoverageRefreshState> for CoverageRefreshBody {
    fn from(s: SvsCoverageRefreshState) -> Self {
        CoverageRefreshBody {
            attack_release: s.attack_release,
            refreshed_at: s.refreshed_at,
            duration_ms: s.duration_ms,
            rows: s.rows,
            changed: s.changed,
            retired: s.retired,
            unknown_tags: s.unknown_tags,
            ignored_tags: s.ignored_tags,
            error: s.error,
        }
    }
}

/// The rows the filters match, counted, and what the last refresh did.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoverageSummaryBody {
    rows: i64,
    /// Rows per state, every state named.
    states: BTreeMap<String, i64>,
    /// Rows per own_state, every state named.
    own_states: BTreeMap<String, i64>,
    /// The same per platform, in the release's platform order, then any other platform a test brought.
    platforms: Vec<PlatformCountsBody>,
    /// Null before anything refreshed.
    refresh: Option<CoverageRefreshBody>,
}

impl From<CoverageSummary> for CoverageSummaryBody {
    fn from(s: CoverageSummary) -> Self {
        CoverageSummaryBody {
            rows: s.rows,
            states: s.states,
            own_states: s.own_states,
            platforms: s
                .platforms
                .into_iter()
                .map(|p| PlatformCountsBody {
                    platform: p.platform,
                    rows: p.rows,
                    states: p.states,
                    own_states: p.own_states,
                })
                .collect(),
            refresh: s.refresh.map(CoverageRefreshBody::from),
        }
    }
}

/// One catalog test on one platform, as it counts toward the technique's coverage there.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoverageTestBody {
    guid: Uuid,
    name: String,
    /// The technique as the test's atomic file names it.
    test_technique: String,
    /// The technique it counts toward (a revoked id becomes its successor).
    technique: String,
    platform: String,
    /// `never_run` (no run or decision on the platform), `awaiting_review`, `no_expectations`, `failing`,
    /// `stale` or `validated`.
    test_state: String,
    /// What it counts as toward the row: `failing`, `stale`, `validated` or `untested`.
    contribution: String,
    last_reviewed_run_id: Option<Uuid>,
    last_reviewed_at: Option<DateTime<Utc>>,
    /// Signature uuids expected of it on the platform that no ignore applies to.
    expected_signatures: Vec<String>,
}

/// A (test, platform) pair that expects a signature.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TestPlatformBody {
    guid: Uuid,
    platform: String,
}

/// A signature expected of the technique's tests: a measured mapping.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MeasuredSignatureBody {
    signature_uuid: String,
    name: Option<String>,
    family: Option<String>,
    tests: Vec<TestPlatformBody>,
}

/// A signature's `mitre:` tag naming the technique or a sub-technique: a manual mapping.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ManualSignatureBody {
    signature_uuid: String,
    name: Option<String>,
    /// `hunt` or `yara`.
    family: String,
    /// The technique id the tag names.
    declared: String,
    /// The technique it counts toward (a revoked id becomes its successor).
    technique: String,
    counts: bool,
    /// Why it doesn't count: `not_counting` (disabled, or a YARA rule in QA mode), `unknown_technique`, or
    /// `removed` (resolved remove on the worklist).
    reason: Option<String>,
}

/// A test removed from its repository; it doesn't count.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RemovedTestBody {
    guid: Uuid,
    name: String,
    technique: String,
    removed_at: Option<DateTime<Utc>>,
}

/// A test a person excluded that is still in its repository; it doesn't count.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ExcludedTestBody {
    guid: Uuid,
    name: String,
    technique: String,
    excluded_at: DateTime<Utc>,
    excluded_by: ActorBody,
    exclusion_reason: String,
}

/// A technique's coverage: its rows as of the last refresh, and what counts toward them now.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TechniqueCoverageBody {
    /// The id asked for.
    requested: String,
    /// The technique answered for: the requested id, or its successor when revoked.
    technique: String,
    name: Option<String>,
    parent: Option<String>,
    is_subtechnique: bool,
    catalog_status: String,
    tactics: Vec<String>,
    /// The pinned ATT&CK release.
    attack_release: String,
    /// When the rows were last refreshed; the tests and signatures below are read now.
    refreshed_at: Option<DateTime<Utc>>,
    /// The technique's rows, retired ones included.
    rows: Vec<CoverageRowBody>,
    /// Its sub-techniques' rows, retired ones included.
    sub_technique_rows: Vec<CoverageRowBody>,
    /// The tests of the technique and its sub-techniques, per platform.
    tests: Vec<CoverageTestBody>,
    measured_signatures: Vec<MeasuredSignatureBody>,
    manual_signatures: Vec<ManualSignatureBody>,
    /// Tests removed from their repository; they don't count.
    removed_tests: Vec<RemovedTestBody>,
    /// Tests a person excluded that are still in their repository; they don't count.
    excluded_tests: Vec<ExcludedTestBody>,
}

impl From<TechniqueCoverage> for TechniqueCoverageBody {
    fn from(t: TechniqueCoverage) -> Self {
        TechniqueCoverageBody {
            requested: t.requested,
            technique: t.technique,
            name: t.name,
            parent: t.parent,
            is_subtechnique: t.is_subtechnique,
            catalog_status: t.catalog_status,
            tactics: t.tactics,
            attack_release: t.attack_release,
            refreshed_at: t.refreshed_at,
            rows: t.rows.into_iter().map(CoverageRowBody::from).collect(),
            sub_technique_rows: t
                .sub_technique_rows
                .into_iter()
                .map(CoverageRowBody::from)
                .collect(),
            tests: t
                .tests
                .into_iter()
                .map(|test| CoverageTestBody {
                    guid: test.guid,
                    name: test.name,
                    test_technique: test.test_technique,
                    technique: test.technique,
                    platform: test.platform,
                    test_state: test.test_state.as_str().to_owned(),
                    contribution: test.contribution.as_str().to_owned(),
                    last_reviewed_run_id: test.last_reviewed_run,
                    last_reviewed_at: test.last_reviewed_at,
                    expected_signatures: test.expected_signatures,
                })
                .collect(),
            measured_signatures: t
                .measured_signatures
                .into_iter()
                .map(|m| MeasuredSignatureBody {
                    signature_uuid: m.signature_uuid,
                    name: m.name,
                    family: m.family,
                    tests: m
                        .tests
                        .into_iter()
                        .map(|(guid, platform)| TestPlatformBody { guid, platform })
                        .collect(),
                })
                .collect(),
            manual_signatures: t
                .manual_signatures
                .into_iter()
                .map(|m| ManualSignatureBody {
                    signature_uuid: m.signature_uuid,
                    name: m.name,
                    family: m.family,
                    declared: m.declared,
                    technique: m.technique,
                    counts: m.counts,
                    reason: m.reason,
                })
                .collect(),
            removed_tests: t
                .removed_tests
                .into_iter()
                .map(|test| RemovedTestBody {
                    guid: test.guid,
                    name: test.name,
                    technique: test.technique,
                    removed_at: test.removed_at,
                })
                .collect(),
            excluded_tests: t
                .excluded_tests
                .into_iter()
                .map(|test| ExcludedTestBody {
                    guid: test.guid,
                    name: test.name,
                    technique: test.technique,
                    excluded_at: test.exclusion.excluded_at,
                    excluded_by: test.exclusion.excluded_by.into(),
                    exclusion_reason: test.exclusion.reason,
                })
                .collect(),
        }
    }
}

/// A coverage row as it was on one day.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoverageSnapshotBody {
    /// The UTC day.
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
    /// When the row was written; a second snapshot the same day rewrites it only when it differs.
    updated_at: DateTime<Utc>,
}

impl From<CoverageSnapshotRow> for CoverageSnapshotBody {
    fn from(r: CoverageSnapshotRow) -> Self {
        CoverageSnapshotBody {
            snapshot_date: r.snapshot_date,
            technique: r.technique,
            platform: r.platform,
            attack_release: r.attack_release,
            parent: r.parent,
            is_subtechnique: r.is_subtechnique,
            state: r.state.as_str().to_owned(),
            own_state: r.own_state.as_str().to_owned(),
            tests_total: r.tests_total,
            tests_validated: r.tests_validated,
            tests_failing: r.tests_failing,
            tests_stale: r.tests_stale,
            manual_signatures: r.manual_signatures,
            measured_signatures: r.measured_signatures,
            updated_at: r.updated_at,
        }
    }
}

impl ExportRow for CoverageSnapshotBody {
    const HEADER: &'static [&'static str] = &[
        "snapshot_date",
        "technique",
        "platform",
        "attack_release",
        "parent",
        "is_subtechnique",
        "state",
        "own_state",
        "tests_total",
        "tests_validated",
        "tests_failing",
        "tests_stale",
        "manual_signatures",
        "measured_signatures",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.snapshot_date.to_string(),
            self.technique.clone(),
            self.platform.clone(),
            self.attack_release.clone(),
            cell(&self.parent),
            self.is_subtechnique.to_string(),
            self.state.clone(),
            self.own_state.clone(),
            self.tests_total.to_string(),
            self.tests_validated.to_string(),
            self.tests_failing.to_string(),
            self.tests_stale.to_string(),
            self.manual_signatures.to_string(),
            self.measured_signatures.to_string(),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of snapshot rows.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoverageHistoryPageBody {
    rows: Vec<CoverageSnapshotBody>,
    /// Pass it as `cursor`, with the same filters, for the next page; null on the last.
    next: Option<String>,
}

/// One period's counts.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PeriodCountsBody {
    /// The day (`2026-10-16`) or the month (`2026-10`).
    period: String,
    /// The snapshot counted: the day's, or the month's last.
    snapshot_date: NaiveDate,
    rows: i64,
    /// Rows per state, every state named.
    states: BTreeMap<String, i64>,
    /// Rows per own_state, every state named.
    own_states: BTreeMap<String, i64>,
}

/// The snapshot rows the filters match, counted per period.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoverageHistoryCountsBody {
    /// `day` or `month`.
    group: String,
    /// Oldest first.
    periods: Vec<PeriodCountsBody>,
    /// There were more than 366 periods, and these are the newest: narrow the Date filter for the rest.
    truncated: bool,
}

impl From<CoverageHistoryCounts> for CoverageHistoryCountsBody {
    fn from(c: CoverageHistoryCounts) -> Self {
        CoverageHistoryCountsBody {
            group: c.group.as_str().to_owned(),
            periods: c
                .periods
                .into_iter()
                .map(|p| PeriodCountsBody {
                    period: p.period,
                    snapshot_date: p.snapshot_date,
                    rows: p.rows,
                    states: p.states,
                    own_states: p.own_states,
                })
                .collect(),
            truncated: c.truncated,
        }
    }
}

/// The coverage list's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct CoverageListQuery {
    /// A filter in the share-link encoding (`[!]slug:v1,v2`) with the coverage screen's slugs: technique
    /// (T1059 also finds its sub-techniques), name, tactic (an id or a shortname), platform, state,
    /// own_state, level, attack_platform, catalog_status, has_manual, state_changed, retired. Repeat it
    /// for more; filters are ANDed, the values of one ORed.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only rows written or changed at or after this time; the pages are then in (updated_at, id) order.
    changed_since: Option<String>,
    /// The timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// The filters of a summary or an export: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct CoverageFilterQuery {
    /// A filter, as the coverage list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only rows written or changed at or after this time, where the listing takes it.
    changed_since: Option<String>,
    /// The timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
}

/// The history's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct CoverageHistoryListQuery {
    /// A filter in the share-link encoding with the coverage history's slugs: date, technique (T1059 also
    /// finds its sub-techniques), platform, state, own_state, level. Repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only rows written at or after this time; the pages are then in (updated_at, id) order.
    changed_since: Option<String>,
    /// The timezone relative date filters resolve in, and a date range's days are counted in; UTC when
    /// left out.
    tz: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// The filters of the history's export.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct CoverageHistoryFilterQuery {
    /// A filter, as the history takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    changed_since: Option<String>,
    tz: Option<String>,
}

/// The history's counts' parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct CoverageHistoryCountsQuery {
    /// A filter, as the history takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// `day`, each day's snapshot, or `month`, each month's last; `day` when left out.
    group: Option<String>,
    tz: Option<String>,
}

fn coverage_query(params: &Params) -> Result<CoverageQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::SvsCoverage, &params.all("f"), true)?;
    Ok(CoverageQuery {
        filters,
        changed_since: params.time("changed_since")?,
        tz: params.tz()?,
    })
}

fn history_query(params: &Params) -> Result<CoverageHistoryQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::SvsCoverageHistory, &params.all("f"), true)?;
    Ok(CoverageHistoryQuery {
        filters,
        changed_since: params.time("changed_since")?,
        tz: params.tz()?,
    })
}

fn limit_of(params: &Params) -> Result<Option<u32>, ApiError> {
    params.parsed("limit", "a number from 1 to 1000")
}

/// The coverage rows by technique, then platform, a page at a time. Follow `next` with the same filters
/// until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/coverage",
    tag = "svs",
    params(CoverageListQuery),
    responses(
        (status = 200, description = "A page of coverage rows", body = CoveragePageBody),
        (status = 400, description = "A filter, time, timezone, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<CoveragePageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = coverage_query(&params)?;
    let page = web
        .service
        .svs_coverage(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(CoveragePageBody {
        rows: page.rows.into_iter().map(CoverageRowBody::from).collect(),
        next: page.next_cursor,
    }))
}

/// Every row the list's filters match, as CSV (its tactics joined with `,`) or NDJSON, one row as the list
/// gives it on each line. A failure part-way ends the CSV there, and the NDJSON with an `{"error": ...}`
/// line.
#[utoipa::path(
    get,
    path = "/api/svs/v1/coverage/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), CoverageFilterQuery),
    responses(
        (status = 200, description = "The rows, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, filter, time or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More rows than an export holds", body = ErrorBody),
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
    let query = coverage_query(&Params::of(raw)?)?;
    let total = service.svs_coverage_count(&actor, &query, max).await?;
    let first = service
        .svs_coverage(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.rows.into_iter().map(CoverageRowBody::from).collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-coverage",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_coverage(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.rows.into_iter().map(CoverageRowBody::from).collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// The rows the filters match, counted per state and per own state, overall and per platform, with what
/// the last refresh did.
#[utoipa::path(
    get,
    path = "/api/svs/v1/coverage/summary",
    tag = "svs",
    params(CoverageFilterQuery),
    responses(
        (status = 200, description = "The counts", body = CoverageSummaryBody),
        (status = 400, description = "A filter or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn summary(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<CoverageSummaryBody>, ApiError> {
    let query = coverage_query(&Params::of(raw)?)?;
    let summary = web.service.svs_coverage_summary(&actor, &query).await?;
    Ok(Json(summary.into()))
}

/// The daily snapshot rows by day, technique and platform, oldest first, a page at a time.
#[utoipa::path(
    get,
    path = "/api/svs/v1/coverage/history",
    tag = "svs",
    params(CoverageHistoryListQuery),
    responses(
        (status = 200, description = "A page of snapshot rows", body = CoverageHistoryPageBody),
        (status = 400, description = "A filter, time, timezone, limit or cursor that isn't one, or a query that ran too long: narrow its filters", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn history(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<CoverageHistoryPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = history_query(&params)?;
    let page = web
        .service
        .svs_coverage_history(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(CoverageHistoryPageBody {
        rows: page
            .rows
            .into_iter()
            .map(CoverageSnapshotBody::from)
            .collect(),
        next: page.next_cursor,
    }))
}

/// Every snapshot row the filters match, as CSV or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/coverage/history/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), CoverageHistoryFilterQuery),
    responses(
        (status = 200, description = "The rows, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, filter, time or timezone that isn't one, or a query that ran too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More rows than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_history(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = history_query(&Params::of(raw)?)?;
    let total = service
        .svs_coverage_history_count(&actor, &query, max)
        .await?;
    let first = service
        .svs_coverage_history(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first
            .rows
            .into_iter()
            .map(CoverageSnapshotBody::from)
            .collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-coverage-history",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_coverage_history(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.rows
                        .into_iter()
                        .map(CoverageSnapshotBody::from)
                        .collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// The snapshot rows the filters match counted per state and own state, per day, or per month from each
/// month's last snapshot. A day whose rows the filters leave out still counts, as zeros.
#[utoipa::path(
    get,
    path = "/api/svs/v1/coverage/history/counts",
    tag = "svs",
    params(CoverageHistoryCountsQuery),
    responses(
        (status = 200, description = "The counts, oldest first", body = CoverageHistoryCountsBody),
        (status = 400, description = "A filter, group or timezone that isn't one, or a query that ran too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn history_counts(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<CoverageHistoryCountsBody>, ApiError> {
    let params = Params::of(raw)?;
    let (filters, _) = decode(FilterScreen::SvsCoverageHistory, &params.all("f"), true)?;
    let group = match params.one("group")? {
        None => HistoryGroup::Day,
        Some(text) => HistoryGroup::parse(text)
            .ok_or_else(|| ApiError::bad_request(format!("group is day or month, not {text:?}")))?,
    };
    let counts = web
        .service
        .svs_coverage_history_counts(&actor, &filters, group, params.tz()?)
        .await?;
    Ok(Json(counts.into()))
}

/// A technique's coverage: its rows and its sub-techniques' as of the last refresh, and the tests and
/// signatures that count toward them now. A revoked id answers for its successor.
#[utoipa::path(
    get,
    path = "/api/svs/v1/coverage/{technique}",
    tag = "svs",
    params(("technique" = String, Path, description = "An ATT&CK technique id, such as T1059 or T1059.001")),
    responses(
        (status = 200, description = "The technique's coverage", body = TechniqueCoverageBody),
        (status = 400, description = "Something that isn't a technique id", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "A technique with no rows that the release doesn't have", body = ErrorBody),
    )
)]
pub(crate) async fn technique(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<TechniqueCoverageBody>, ApiError> {
    let Path(technique) = path?;
    let detail = web
        .service
        .svs_coverage_technique(&actor, &technique)
        .await?;
    Ok(Json(detail.into()))
}
