//! The SVS area's Tests, Coverage and Worklist tabs (PLAN.md 7.10 batch 8): ace3's `app/svs/views`
//! `tests.py`, `coverage.py` and `worklist.py`, and `svs/tests.html`, `test.html`, `coverage.html`,
//! `coverage_detail.html`, `worklist.html`, `worklist_signature.html` and `_worklist_modal.html`, over
//! `ace_service`'s `svs_catalog`, `svs_coverage`, `svs_worklist` and `svs_decisions`.
//!
//! The area's gate is `svs`'s: `svs:run_read`. ace3's pages are shells its scripts fill from
//! `/api/v2/svs`; here the server draws each one, and every control is a link or a form:
//! - `svs.tests` (`tests.html`): `GET /svs/tests`, the catalog's tests by technique, each with its state
//!   and run history, with the tests screen's filters as a `GET` form folded into `f`, pages as First and
//!   Next links, and the API's exports beside them. The tab opens on ace3's default view, the tests still
//!   in their repository.
//! - `svs.test_detail` (`test.html`): `GET /svs/tests/{guid}`, a test with its description and atomic
//!   entry, its state on each platform, its observation window's settings, its expectations and the
//!   ignores that apply to it, and a link to its runs. For `svs:run_manage` the settings are a form
//!   (`POST /svs/tests/{guid}/settings`), and each expectation and each of the test's ignores has the form
//!   that removes it (`POST /svs/tests/{guid}/decide`); a global ignore's is `svs:admin`'s.
//! - `svs.coverage` (`coverage.html`): `GET /svs/coverage`, coverage per technique and platform as the
//!   last refresh computed it, with the rows' counts per state, what the refresh did (or why it failed),
//!   the coverage screen's filters, pages and exports. Read-only. The tab opens on ace3's default view,
//!   the endpoint platforms' rows that aren't retired.
//! - `svs.coverage_detail` (`coverage_detail.html`): `GET /svs/coverage/{technique}`, a technique's rows
//!   and its sub-techniques', the tests and signatures that count toward them now, its removed tests, and
//!   its own daily snapshots of the last two months, with the year's as an export. Read-only.
//! - `svs.worklist` (`worklist.html`): `GET /svs/worklist`, each measured signature's technique tags
//!   against what its tests measure, with the worklist screen's filters, pages and exports. For
//!   `svs:run_manage` each row a person can resolve has a box, and the form under the list keeps or
//!   removes the ticked ones alike (`POST /svs/worklist/resolve`), saying what happened to each. The tab
//!   opens on ace3's default view, the tags that need a decision.
//! - `svs.worklist_signature` (`worklist_signature.html`): `GET /svs/worklist/{signature_uuid}`, a
//!   signature's rows, retired ones included, and what it is measured on now. For `svs:run_manage` each
//!   resolvable row has its keep, remove and reopen forms (`POST /svs/worklist/{signature_uuid}/resolve`),
//!   which carry the `updated_at` the row was drawn from, so a row someone else changed first is refused.
//!
//! Each post is a `SignedIn` post that passed 5.7's same-origin check, through the service, which checks
//! its permission and writes its audit row, and answers with a redirect to the page it came from.
//!
//! What a page shows comes from a catalog repository, a rule, a hunt or a person: test and signature
//! names, a test's description and commands, reasons, references. askama escapes it, and a value in a link
//! is percent-encoded. A resolution's reference is a link only because the service takes nothing but an
//! http or https URL with no white space in it.
//!
//! The Tests, Coverage and Worklist pages have the viewer's quick filters, ace3's defaults the first time
//! (`crate::saved_filters::quick_filters`). Left out: ace3's modal's confirm before a reopen, which needs a
//! script: the reopen is a button.

use ace_service::filters::FilterScreen;
use ace_service::{
    BulkResolution, CatalogTest, CatalogTestDetail, CatalogTestQuery, CoverageHistoryQuery,
    CoverageQuery, CoverageRow, CoverageSnapshotRow, CoverageSummary, Expectation,
    ExpectationQuery, FilterEntry, Ignore, IgnoreQuery, Precondition, SVS_ADMIN, SVS_RUN_MANAGE,
    ServiceError, SignatureWorklist, SvsCoverageState, TechniqueCoverage, TestSettings, TestState,
    WorklistQuery, WorklistRow, WorklistStatus,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};

use crate::Gui;
use crate::actions::encode;
use crate::list::{all, one, pairs};
use crate::remediation::{FilterField, filter_fields, list_request};
use crate::session::{SignedIn, render, see_other};
use crate::svs::{
    Fact, SVS_PER_PAGE, Tabs, bad_request, enter, failed, filter_pairs, maybe, pages, run_href,
    when, with_query,
};
use crate::templates::Layout;

/// The largest form here: a resolution's reason of 4096 characters and its reference, percent-encoded,
/// with a page of ticked rows.
pub const MAX_WORKLIST_FORM_BYTES: usize = 128 << 10;
/// The most of a technique's snapshot rows its page shows.
const TECHNIQUE_HISTORY: u32 = 1000;
/// The days of snapshots a technique's page shows, and its export holds: ace3's page reads a year; a page
/// drawn by the server shows the last two months, which stay under [`TECHNIQUE_HISTORY`] rows on every
/// platform ATT&CK has, and links to the year's export.
const PAGE_HISTORY_RANGE: &str = "-60d";
const EXPORT_HISTORY_RANGE: &str = "-365d";

/// The history's filters for one technique: its own snapshots (Technique finds a parent's sub-techniques
/// too; Level keeps them out), over `range`. ace3's `history_f`.
pub fn history_filters(technique: &str, range: &str) -> Vec<FilterEntry> {
    let level = if technique.contains('.') {
        "sub-technique"
    } else {
        "technique"
    };
    vec![
        FilterEntry::text("Technique", false, &[technique]),
        FilterEntry::text("Level", false, &[level]),
        FilterEntry::text("Date", false, &[range]),
    ]
}
/// A test's page shows this many of its decisions.
const TEST_PAGE_DECISIONS: u32 = 500;

/// A catalog test's page.
pub fn test_href(guid: impl std::fmt::Display) -> String {
    format!("/svs/tests/{guid}")
}

/// A technique's coverage page.
pub fn technique_href(technique: &str) -> String {
    format!("/svs/coverage/{}", encode(technique))
}

/// A signature's worklist page.
pub fn signature_href(signature: &str) -> String {
    format!("/svs/worklist/{}", encode(signature))
}

/// A test state's badge class.
fn test_state_class(state: TestState) -> &'static str {
    match state {
        TestState::Failing => "danger",
        TestState::Stale | TestState::AwaitingReview => "warning",
        TestState::Validated => "success",
        TestState::NoExpectations | TestState::NeverRun => "secondary",
    }
}

/// A coverage state's badge class.
fn coverage_class(state: SvsCoverageState) -> &'static str {
    match state {
        SvsCoverageState::Failing => "danger",
        SvsCoverageState::Stale => "warning",
        SvsCoverageState::Validated => "success",
        SvsCoverageState::Manual => "info",
        SvsCoverageState::Untested | SvsCoverageState::None => "secondary",
    }
}

/// A worklist status's badge class.
fn worklist_class(status: WorklistStatus) -> &'static str {
    match status {
        WorklistStatus::Confirmed => "success",
        WorklistStatus::Open | WorklistStatus::RemovePending => "warning",
        WorklistStatus::Kept => "info",
        _ => "secondary",
    }
}

/// A link's target and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub href: String,
    pub text: String,
}

fn run_link(run: Option<uuid::Uuid>, at: Option<DateTime<Utc>>) -> Option<Link> {
    run.map(|run| Link {
        href: run_href(run),
        text: at.map(when).unwrap_or_else(|| run.to_string()),
    })
}

fn filter_href(path: &str, screen: FilterScreen, entries: &[FilterEntry]) -> String {
    let filters = ace_service::filters::encode(screen, entries).unwrap_or_default();
    with_query(path, &filter_pairs(&filters))
}

// ---- the Tests tab ----

/// A catalog test as the Tests tab's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestLine {
    pub href: String,
    pub technique: String,
    pub technique_href: String,
    pub name: String,
    pub platforms: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub runs: i64,
    pub last_run: Option<Link>,
    pub last_reviewed: Option<Link>,
    pub expected: usize,
    /// `2 of 5 missed`, or nothing when no recent run missed.
    pub recent: String,
    pub removed: bool,
}

pub fn test_line(test: &CatalogTest) -> TestLine {
    let h = &test.history;
    TestLine {
        href: test_href(test.guid),
        technique_href: technique_href(&test.technique),
        technique: test.technique.clone(),
        name: test.name.clone(),
        platforms: test.platforms.join(", "),
        state: h.state.as_str(),
        state_class: test_state_class(h.state),
        runs: h.run_count,
        last_run: run_link(h.last_run, h.last_run_at),
        last_reviewed: run_link(h.last_reviewed_run, h.last_reviewed_at),
        expected: h.expected,
        recent: if h.recent_runs_missing > 0 {
            format!("{} of {} missed", h.recent_runs_missing, h.recent_runs)
        } else {
            String::new()
        },
        removed: test.removed_at.is_some(),
    }
}

/// `/svs/tests`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestsView {
    pub tabs: Tabs,
    pub fields: Vec<FilterField>,
    pub rows: Vec<TestLine>,
    pub first: Option<String>,
    pub next: Option<String>,
    pub csv: String,
    pub ndjson: String,
}

pub fn tests_view(
    tabs: Tabs,
    query: &CatalogTestQuery,
    filters: &[String],
    tests: &[CatalogTest],
    cursor: Option<&str>,
    next: Option<&str>,
) -> TestsView {
    let base = filter_pairs(filters);
    let (first, next) = pages("/svs/tests", filters, cursor, next);
    TestsView {
        tabs,
        fields: filter_fields(FilterScreen::SvsTests, &query.filters),
        rows: tests.iter().map(test_line).collect(),
        first,
        next,
        csv: with_query("/api/svs/v1/tests/export/csv", &base),
        ndjson: with_query("/api/svs/v1/tests/export/ndjson", &base),
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/tests.html")]
pub struct TestsPage {
    pub layout: Layout,
    /// The viewer's quick filters on this screen (`crate::saved_filters::quick_filters`).
    pub quick: Vec<crate::saved_filters::QuickLink>,
    pub view: TestsView,
}

/// A test on one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformLine {
    pub platform: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub last_reviewed: Option<Link>,
    pub expected: usize,
}

/// A decision about a signature for the test, as its page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionLine {
    pub platform: String,
    pub signature: String,
    pub name: String,
    /// `expected`, `rejected`, or for an ignore `this test` or `every test`.
    pub what: String,
    pub reason: String,
    pub by: String,
    pub at: String,
    /// The `decision` its remove form posts, when the viewer may remove it.
    pub remove: Option<&'static str>,
}

/// `/svs/tests/{guid}`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestView {
    pub tabs: Tabs,
    pub href: String,
    pub name: String,
    pub guid: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub facts: Vec<Fact>,
    pub description: String,
    /// The test's atomic entry, as indented JSON.
    pub entry: String,
    pub platforms: Vec<PlatformLine>,
    /// The observation window set for the test's runs; None for the computed one.
    pub minutes: Option<i32>,
    pub holds_host: bool,
    pub has_settings: bool,
    pub expectations: Vec<DecisionLine>,
    pub ignores: Vec<DecisionLine>,
    /// The runs list narrowed to the test.
    pub runs: String,
    pub manage: bool,
    pub notice: Option<String>,
}

fn actor_name(actor: &Option<ace_service::RecordedActor>) -> String {
    actor
        .as_ref()
        .map(|actor| actor.name.clone().unwrap_or_else(|| actor.id.clone()))
        .unwrap_or_default()
}

fn signature_name(name: &Option<String>) -> String {
    name.clone().unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
pub fn test_view(
    tabs: Tabs,
    detail: &CatalogTestDetail,
    settings: Option<&TestSettings>,
    expectations: &[Expectation],
    ignores: &[Ignore],
    manage: bool,
    admin: bool,
    notice: Option<String>,
) -> TestView {
    let test = &detail.test;
    let h = &test.history;
    let fact = |name: &'static str, value: String| Fact { name, value };
    let mut facts = vec![
        fact("Technique", test.technique.clone()),
        fact("Technique name", signature_name(&test.technique_name)),
        fact("Platforms", test.platforms.join(", ")),
        fact("Executor", signature_name(&test.executor)),
        fact("Repository", test.repository.clone()),
        fact("File", test.path.clone()),
        fact("Commit", test.commit.clone()),
        fact("Content hash", test.content_hash.clone()),
        fact("First seen", when(test.first_seen_at)),
        fact("Runs", h.run_count.to_string()),
        fact("Expected signatures", h.expected.to_string()),
    ];
    if let Some(removed) = test.removed_at {
        facts.push(fact("Removed from its repository", when(removed)));
    }
    let entry_filter = FilterEntry::text("Test", false, &[&test.guid.to_string()]);
    TestView {
        tabs,
        href: test_href(test.guid),
        name: test.name.clone(),
        guid: test.guid.to_string(),
        state: h.state.as_str(),
        state_class: test_state_class(h.state),
        facts,
        description: detail.description.clone().unwrap_or_default(),
        entry: serde_json::to_string_pretty(&detail.entry).unwrap_or_default(),
        platforms: h
            .platform_states
            .iter()
            .map(|(platform, state)| PlatformLine {
                platform: platform.clone(),
                state: state.state.as_str(),
                state_class: test_state_class(state.state),
                last_reviewed: run_link(state.last_reviewed_run, state.last_reviewed_at),
                expected: state.expected,
            })
            .collect(),
        minutes: settings.and_then(|s| s.observation_minutes),
        holds_host: settings.is_some_and(|s| s.holds_host),
        has_settings: settings.is_some(),
        expectations: expectations
            .iter()
            .map(|e| DecisionLine {
                platform: e.platform.clone(),
                signature: e.signature_uuid.clone(),
                name: signature_name(&e.signature_name),
                what: e.state.as_str().to_owned(),
                reason: signature_name(&e.reason),
                by: actor_name(&e.decided_by),
                at: when(e.decided_at),
                remove: manage.then_some("undecide"),
            })
            .collect(),
        ignores: ignores
            .iter()
            .map(|i| {
                let global = i.test_guid.is_none();
                DecisionLine {
                    platform: String::new(),
                    signature: i.signature_uuid.clone(),
                    name: signature_name(&i.signature_name),
                    what: if global { "every test" } else { "this test" }.to_owned(),
                    reason: signature_name(&i.reason),
                    by: actor_name(&i.created_by),
                    at: when(i.created_at),
                    remove: match (global, manage, admin) {
                        (true, _, true) => Some("unignore_globally"),
                        (false, true, _) => Some("unignore"),
                        _ => None,
                    },
                }
            })
            .collect(),
        runs: filter_href("/svs/runs", FilterScreen::SvsRuns, &[entry_filter]),
        manage,
        notice,
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/test.html")]
pub struct TestPage {
    pub layout: Layout,
    pub view: TestView,
}

// ---- the Coverage tab ----

/// A coverage row as the Coverage tab's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageLine {
    pub technique: String,
    pub href: String,
    pub name: String,
    pub platform: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub own_state: &'static str,
    /// `1 validated, 2 failing of 4`, or nothing without tests.
    pub tests: String,
    pub manual: i32,
    pub measured: i32,
    pub last_reviewed: String,
    pub changed: String,
    /// What's said beside the technique: a sub-technique, one the release doesn't have, a platform only a
    /// test brought, a retired row.
    pub notes: String,
}

pub fn coverage_line(row: &CoverageRow) -> CoverageLine {
    let mut counts = Vec::new();
    for (count, what) in [
        (row.tests_validated, "validated"),
        (row.tests_failing, "failing"),
        (row.tests_stale, "stale"),
    ] {
        if count > 0 {
            counts.push(format!("{count} {what}"));
        }
    }
    let tests = match (row.tests_total, counts.is_empty()) {
        (0, _) => String::new(),
        (total, true) => total.to_string(),
        (total, false) => format!("{} of {total}", counts.join(", ")),
    };
    let mut notes = Vec::new();
    if row.catalog_status != "active" {
        notes.push(row.catalog_status.clone());
    }
    if !row.attack_platform {
        notes.push("a test's platform".to_owned());
    }
    if row.retired_at.is_some() {
        notes.push("retired".to_owned());
    }
    CoverageLine {
        href: technique_href(&row.technique),
        technique: row.technique.clone(),
        name: row.technique_name.clone().unwrap_or_default(),
        platform: row.platform.clone(),
        state: row.state.as_str(),
        state_class: coverage_class(row.state),
        own_state: row.own_state.as_str(),
        tests,
        manual: row.manual_signatures,
        measured: row.measured_signatures,
        last_reviewed: maybe(row.last_reviewed_at),
        changed: when(row.state_changed_at),
        notes: notes.join(", "),
    }
}

/// What the summary says of the rows the filters match: `12 rows: 2 failing, 1 stale, ...`, each state
/// that has rows, worst first.
pub fn summary_line(summary: &CoverageSummary) -> String {
    let states: Vec<String> = SvsCoverageState::ALL
        .iter()
        .filter_map(|state| {
            let count = summary.states.get(state.as_str()).copied().unwrap_or(0);
            (count > 0).then(|| format!("{count} {state}"))
        })
        .collect();
    if states.is_empty() {
        format!("{} rows", summary.rows)
    } else {
        format!("{} rows: {}", summary.rows, states.join(", "))
    }
}

/// What the page says of the last refresh, and why the latest failed.
pub fn refresh_lines(summary: &CoverageSummary) -> (String, Option<String>) {
    let Some(refresh) = &summary.refresh else {
        return ("Coverage has never been refreshed.".to_owned(), None);
    };
    let line = match refresh.refreshed_at {
        Some(at) => format!(
            "Refreshed {} against ATT&CK {}: {} rows, {} changed, {} tags naming an unknown technique, \
             {} tags that aren't technique ids.",
            when(at),
            refresh.attack_release.as_deref().unwrap_or("?"),
            refresh.rows,
            refresh.changed,
            refresh.unknown_tags,
            refresh.ignored_tags
        ),
        None => "Coverage has never been refreshed.".to_owned(),
    };
    (
        line,
        refresh
            .error
            .as_ref()
            .map(|error| format!("The latest refresh failed: {error}")),
    )
}

/// `/svs/coverage`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageView {
    pub tabs: Tabs,
    pub fields: Vec<FilterField>,
    pub summary: String,
    pub refresh: String,
    pub error: Option<String>,
    pub rows: Vec<CoverageLine>,
    pub first: Option<String>,
    pub next: Option<String>,
    pub csv: String,
    pub ndjson: String,
}

pub fn coverage_view(
    tabs: Tabs,
    query: &CoverageQuery,
    filters: &[String],
    summary: &CoverageSummary,
    rows: &[CoverageRow],
    cursor: Option<&str>,
    next: Option<&str>,
) -> CoverageView {
    let base = filter_pairs(filters);
    let (first, next) = pages("/svs/coverage", filters, cursor, next);
    let (refresh, error) = refresh_lines(summary);
    CoverageView {
        tabs,
        fields: filter_fields(FilterScreen::SvsCoverage, &query.filters),
        summary: summary_line(summary),
        refresh,
        error,
        rows: rows.iter().map(coverage_line).collect(),
        first,
        next,
        csv: with_query("/api/svs/v1/coverage/export/csv", &base),
        ndjson: with_query("/api/svs/v1/coverage/export/ndjson", &base),
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/coverage.html")]
pub struct CoveragePage {
    pub layout: Layout,
    /// The viewer's quick filters on this screen (`crate::saved_filters::quick_filters`).
    pub quick: Vec<crate::saved_filters::QuickLink>,
    pub view: CoverageView,
}

/// A test on a platform, as a technique's page counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountedTest {
    pub href: String,
    pub name: String,
    pub technique: String,
    pub platform: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub contribution: &'static str,
    pub last_reviewed: Option<Link>,
    pub expected: usize,
}

/// A signature of a technique's page: a measured one, or a manual mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureLine {
    pub href: String,
    pub signature: String,
    pub name: String,
    pub family: String,
    /// A measured signature's tests, or a manual mapping's tag and what it counts as.
    pub detail: String,
    /// Why a manual mapping doesn't count; empty when it does.
    pub reason: String,
}

/// A snapshot row of a technique's page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotLine {
    pub day: String,
    pub technique: String,
    pub platform: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub own_state: &'static str,
    pub tests: i32,
    pub release: String,
}

/// `/svs/coverage/{technique}`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechniqueView {
    pub tabs: Tabs,
    pub technique: String,
    pub name: String,
    pub parent: Option<Link>,
    pub facts: Vec<Fact>,
    pub rows: Vec<CoverageLine>,
    pub sub_rows: Vec<CoverageLine>,
    pub tests: Vec<CountedTest>,
    pub measured: Vec<SignatureLine>,
    pub manual: Vec<SignatureLine>,
    pub removed: Vec<Link>,
    pub history: Vec<SnapshotLine>,
    /// The catalog's tests and the runs of the technique.
    pub tests_href: String,
    pub runs_href: String,
    pub history_csv: String,
}

pub fn technique_view(
    tabs: Tabs,
    detail: &TechniqueCoverage,
    history: &[CoverageSnapshotRow],
) -> TechniqueView {
    let fact = |name: &'static str, value: String| Fact { name, value };
    let mut facts = vec![
        fact("ATT&CK release", detail.attack_release.clone()),
        fact("Status in the release", detail.catalog_status.clone()),
        fact("Tactics", detail.tactics.join(", ")),
        fact("Rows refreshed", maybe(detail.refreshed_at)),
    ];
    if detail.requested.trim().to_uppercase() != detail.technique {
        facts.insert(
            0,
            fact(
                "Asked for",
                format!("{} (revoked, now this technique)", detail.requested.trim()),
            ),
        );
    }
    let technique_filter = FilterEntry::text("Technique", false, &[&detail.technique]);
    let history_filters = ace_service::filters::encode(
        FilterScreen::SvsCoverageHistory,
        &history_filters(&detail.technique, EXPORT_HISTORY_RANGE),
    )
    .unwrap_or_default();
    TechniqueView {
        tabs,
        technique: detail.technique.clone(),
        name: detail.name.clone().unwrap_or_default(),
        parent: detail.parent.as_ref().map(|parent| Link {
            href: technique_href(parent),
            text: parent.clone(),
        }),
        facts,
        rows: detail.rows.iter().map(coverage_line).collect(),
        sub_rows: detail
            .sub_technique_rows
            .iter()
            .map(coverage_line)
            .collect(),
        tests: detail
            .tests
            .iter()
            .map(|test| CountedTest {
                href: test_href(test.guid),
                name: test.name.clone(),
                technique: test.technique.clone(),
                platform: test.platform.clone(),
                state: test.test_state.as_str(),
                state_class: test_state_class(test.test_state),
                contribution: test.contribution.as_str(),
                last_reviewed: run_link(test.last_reviewed_run, test.last_reviewed_at),
                expected: test.expected_signatures.len(),
            })
            .collect(),
        measured: detail
            .measured_signatures
            .iter()
            .map(|m| SignatureLine {
                href: signature_href(&m.signature_uuid),
                signature: m.signature_uuid.clone(),
                name: m.name.clone().unwrap_or_default(),
                family: m.family.clone().unwrap_or_default(),
                detail: format!(
                    "{} test{} on a platform",
                    m.tests.len(),
                    if m.tests.len() == 1 { "" } else { "s" }
                ),
                reason: String::new(),
            })
            .collect(),
        manual: detail
            .manual_signatures
            .iter()
            .map(|m| SignatureLine {
                href: signature_href(&m.signature_uuid),
                signature: m.signature_uuid.clone(),
                name: m.name.clone().unwrap_or_default(),
                family: m.family.clone(),
                detail: if m.declared == m.technique {
                    format!("tagged {}", m.declared)
                } else {
                    format!("tagged {}, which counts as {}", m.declared, m.technique)
                },
                reason: match m.reason.as_deref() {
                    None => String::new(),
                    Some("not_counting") => {
                        "doesn't count: the signature is disabled, or a YARA rule in QA mode"
                            .to_owned()
                    }
                    Some("unknown_technique") => {
                        "doesn't count: the release doesn't have the technique".to_owned()
                    }
                    Some("removed") => "doesn't count: resolved remove on the worklist".to_owned(),
                    Some(other) => format!("doesn't count: {other}"),
                },
            })
            .collect(),
        removed: detail
            .removed_tests
            .iter()
            .map(|test| Link {
                href: test_href(test.guid),
                text: format!("{} ({})", test.name, test.technique),
            })
            .collect(),
        history: history
            .iter()
            .rev()
            .map(|row| SnapshotLine {
                day: row.snapshot_date.to_string(),
                technique: row.technique.clone(),
                platform: row.platform.clone(),
                state: row.state.as_str(),
                state_class: coverage_class(row.state),
                own_state: row.own_state.as_str(),
                tests: row.tests_total,
                release: row.attack_release.clone(),
            })
            .collect(),
        tests_href: filter_href(
            "/svs/tests",
            FilterScreen::SvsTests,
            std::slice::from_ref(&technique_filter),
        ),
        runs_href: filter_href(
            "/svs/runs",
            FilterScreen::SvsRuns,
            std::slice::from_ref(&technique_filter),
        ),
        history_csv: with_query(
            "/api/svs/v1/coverage/history/export/csv",
            &filter_pairs(&history_filters),
        ),
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/technique.html")]
pub struct TechniquePage {
    pub layout: Layout,
    pub view: TechniqueView,
}

// ---- the Worklist tab ----

/// A worklist row as the lists show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorklistLine {
    pub signature: String,
    pub signature_href: String,
    pub name: String,
    pub family: String,
    pub technique: String,
    pub technique_href: String,
    pub technique_name: String,
    pub kind: &'static str,
    pub status: &'static str,
    pub status_class: &'static str,
    pub declared_as: String,
    pub measured_on: String,
    /// `counts` or `doesn't count`, for a declared row.
    pub counts: &'static str,
    pub resolution: String,
    pub reason: String,
    /// The resolution's reference, a link.
    pub reference: Option<String>,
    pub resolved: String,
    /// A person can resolve it: an unconfirmed declaration.
    pub resolvable: bool,
    /// It has a resolution to clear.
    pub resolved_now: bool,
    /// What its bulk box posts: `<signature>|<technique>`.
    pub key: String,
    /// The `updated_at` the row was drawn from, which its forms carry.
    pub seen: String,
}

pub fn worklist_line(row: &WorklistRow) -> WorklistLine {
    let resolvable = is_resolvable(row.status);
    WorklistLine {
        signature_href: signature_href(&row.signature_uuid),
        signature: row.signature_uuid.clone(),
        name: row.signature_name.clone().unwrap_or_default(),
        family: row.signature_family.clone().unwrap_or_default(),
        technique_href: technique_href(&row.technique),
        technique: row.technique.clone(),
        technique_name: row.technique_name.clone().unwrap_or_default(),
        kind: row.kind.as_str(),
        status: row.status.as_str(),
        status_class: worklist_class(row.status),
        declared_as: row.declared_as.join(", "),
        measured_on: row.measured_techniques.join(", "),
        counts: match (row.kind.as_str(), row.counts) {
            ("declared", true) => "counts",
            ("declared", false) => "doesn't count",
            _ => "",
        },
        resolution: row
            .resolution
            .map(|r| r.as_str().to_owned())
            .unwrap_or_default(),
        reason: row.reason.clone().unwrap_or_default(),
        // the service takes only an http(s) URL with no white space, so it is safe as a link's target
        reference: row.reference.clone().filter(|reference| {
            let lower = reference.to_ascii_lowercase();
            lower.starts_with("http://") || lower.starts_with("https://")
        }),
        resolved: match (&row.resolved_by, row.resolved_at) {
            (by, Some(at)) => format!("{} {}", actor_name(by), when(at)).trim().to_owned(),
            _ => String::new(),
        },
        resolvable,
        resolved_now: row.resolution.is_some(),
        key: format!("{}|{}", row.signature_uuid, row.technique),
        seen: row
            .updated_at
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
    }
}

/// The statuses a person can resolve: `ace_core::svs::worklist::RESOLVABLE`.
fn is_resolvable(status: WorklistStatus) -> bool {
    matches!(
        status,
        WorklistStatus::Open | WorklistStatus::Kept | WorklistStatus::RemovePending
    )
}

/// `/svs/worklist`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorklistView {
    pub tabs: Tabs,
    pub fields: Vec<FilterField>,
    pub rows: Vec<WorklistLine>,
    pub first: Option<String>,
    pub next: Option<String>,
    pub csv: String,
    pub ndjson: String,
    pub manage: bool,
    /// This page, where a bulk resolution comes back.
    pub here: String,
    pub notice: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub fn worklist_view(
    tabs: Tabs,
    query: &WorklistQuery,
    filters: &[String],
    rows: &[WorklistRow],
    cursor: Option<&str>,
    next: Option<&str>,
    manage: bool,
    notice: Option<String>,
) -> WorklistView {
    let base = filter_pairs(filters);
    let mut here = base.clone();
    if let Some(cursor) = cursor {
        here.push(("cursor", cursor.to_owned()));
    }
    let (first, next) = pages("/svs/worklist", filters, cursor, next);
    WorklistView {
        tabs,
        fields: filter_fields(FilterScreen::SvsWorklist, &query.filters),
        rows: rows.iter().map(worklist_line).collect(),
        first,
        next,
        csv: with_query("/api/svs/v1/worklist/export/csv", &base),
        ndjson: with_query("/api/svs/v1/worklist/export/ndjson", &base),
        manage,
        here: with_query("/svs/worklist", &here),
        notice,
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/worklist.html")]
pub struct WorklistPage {
    pub layout: Layout,
    /// The viewer's quick filters on this screen (`crate::saved_filters::quick_filters`).
    pub quick: Vec<crate::saved_filters::QuickLink>,
    pub view: WorklistView,
}

/// A technique a signature is measured on now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredLine {
    pub technique: String,
    pub technique_href: String,
    pub technique_name: String,
    /// The tests that measure it, each with its platform.
    pub tests: Vec<Link>,
}

/// `/svs/worklist/{signature_uuid}`'s content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureView {
    pub tabs: Tabs,
    pub href: String,
    pub signature: String,
    pub name: String,
    pub family: String,
    pub rows: Vec<WorklistLine>,
    pub measured: Vec<MeasuredLine>,
    pub manage: bool,
    pub notice: Option<String>,
}

pub fn signature_view(
    tabs: Tabs,
    detail: &SignatureWorklist,
    manage: bool,
    notice: Option<String>,
) -> SignatureView {
    SignatureView {
        tabs,
        href: signature_href(&detail.signature_uuid),
        signature: detail.signature_uuid.clone(),
        name: detail.signature_name.clone().unwrap_or_default(),
        family: detail.signature_family.clone().unwrap_or_default(),
        rows: detail.rows.iter().map(worklist_line).collect(),
        measured: detail
            .measured
            .iter()
            .map(|m| MeasuredLine {
                technique_href: technique_href(&m.technique),
                technique: m.technique.clone(),
                technique_name: m.technique_name.clone().unwrap_or_default(),
                tests: m
                    .tests
                    .iter()
                    .map(|test| Link {
                        href: test_href(test.guid),
                        text: format!(
                            "{} on {}",
                            test.name.clone().unwrap_or_else(|| test.guid.to_string()),
                            test.platform
                        ),
                    })
                    .collect(),
            })
            .collect(),
        manage,
        notice,
    }
}

#[derive(Debug, Template)]
#[template(path = "svs/worklist_signature.html")]
pub struct SignaturePage {
    pub layout: Layout,
    pub view: SignatureView,
}

/// What a bulk resolution says it did: how many rows it resolved, how many it left alone because their
/// status can't be resolved, and how many aren't rows. The page that shows it is given the three counts,
/// never text.
pub fn bulk_notice(resolved: u32, conflicts: u32, unknown: u32) -> String {
    let rows = |count: u32| if count == 1 { "row" } else { "rows" };
    let mut parts = vec![format!("{resolved} {} resolved.", rows(resolved))];
    if conflicts > 0 {
        parts.push(format!(
            "{conflicts} {} left alone: only open, kept and remove_pending rows can be resolved.",
            rows(conflicts)
        ));
    }
    if unknown > 0 {
        parts.push(format!("{unknown} {} not found.", rows(unknown)));
    }
    parts.join(" ")
}

/// The counts a bulk resolution's redirect carries, as the page's query. None is named as a filter of the
/// worklist screen is, since the page folds those into `f`.
fn bulk_counts(result: &BulkResolution) -> [(&'static str, String); 4] {
    [
        ("done", "bulk".to_owned()),
        ("ok", result.done.len().to_string()),
        ("left", result.conflicts.len().to_string()),
        ("missing", result.unknown.len().to_string()),
    ]
}

// ---- the pages ----

/// What a page says a post did.
fn notice_of(done: Option<&str>) -> Option<String> {
    Some(
        match done? {
            "settings" => "The test's settings are set for runs registered from now on.",
            "cleared" => "The test's settings are removed: its runs get the computed window.",
            "undecide" => "The decision is removed.",
            "unignore" => "The signature is no longer ignored during this test's runs.",
            "unignore_globally" => "The signature is no longer ignored during every test's runs.",
            "keep" => "The tag is kept: it covers something no test reaches.",
            "remove" => {
                "The tag is resolved remove: it stops counting toward coverage from the next refresh."
            }
            "reopen" => "The resolution is cleared: the tag is open again.",
            _ => return None,
        }
        .to_owned(),
    )
}

/// What [`folded`] gives a list page: its filters and their share link, or the redirect to follow.
type Folded = Result<(Vec<FilterEntry>, Vec<String>), Response>;

/// A list page's request: its filters, their share link and its cursor; or the redirect that folds the
/// filter form into `f`.
fn folded(screen: FilterScreen, path: &str, raw: Option<&str>) -> Result<Folded, ServiceError> {
    let request = list_request(screen, raw)?;
    let filters = ace_service::filters::encode(screen, &request.filters).unwrap_or_default();
    if request.folded {
        return Ok(Err(see_other(
            &with_query(path, &filter_pairs(&filters)),
            None,
        )));
    }
    Ok(Ok((request.filters, filters)))
}

fn tabs(open: &'static str, admin: bool) -> Tabs {
    Tabs { open, admin }
}

/// `GET /svs/tests`.
pub(crate) async fn tests(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let (entries, filters) = match folded(FilterScreen::SvsTests, "/svs/tests", raw.0.as_deref()) {
        Ok(Ok(request)) => request,
        Ok(Err(redirect)) => return redirect,
        Err(error) => return failed(error, &parts),
    };
    let query = CatalogTestQuery {
        filters: entries,
        ..CatalogTestQuery::default()
    };
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    match gui
        .service
        .svs_catalog_tests(&viewer.actor, &query, cursor, Some(SVS_PER_PAGE))
        .await
    {
        Ok(page) => render(&TestsPage {
            quick: crate::saved_filters::quick_filters(
                &gui,
                &viewer,
                FilterScreen::SvsTests,
                "/svs/tests",
            )
            .await,
            layout: viewer.layout,
            view: tests_view(
                tabs("tests", admin),
                &query,
                &filters,
                &page.tests,
                cursor,
                page.next_cursor.as_deref(),
            ),
        }),
        Err(error) => failed(error, &parts),
    }
}

fn guid_of(path: Result<Path<String>, PathRejection>) -> Option<String> {
    path.ok()
        .map(|Path(text)| text)
        .filter(|text| text.parse::<uuid::Uuid>().is_ok())
}

/// `GET /svs/tests/{guid}`: a test's page.
pub(crate) async fn test(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let Some(guid) = guid_of(path) else {
        return bad_request("A test is named by its guid.", &parts);
    };
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let actor = &viewer.actor;
    let service = &gui.service;
    let read = async {
        let detail = service.svs_catalog_test(actor, &guid).await?;
        let settings = service.svs_test_settings(actor, &guid).await?;
        let expectations = service
            .svs_expectations(
                actor,
                &ExpectationQuery {
                    test: Some(guid.clone()),
                    ..ExpectationQuery::default()
                },
                None,
                Some(TEST_PAGE_DECISIONS),
            )
            .await?
            .expectations;
        let ignores = service
            .svs_ignores(
                actor,
                &IgnoreQuery {
                    test: Some(guid.clone()),
                    ..IgnoreQuery::default()
                },
                None,
                Some(TEST_PAGE_DECISIONS),
            )
            .await?
            .ignores;
        Ok::<_, ServiceError>(test_view(
            tabs("tests", admin),
            &detail,
            settings.as_ref(),
            &expectations,
            &ignores,
            service.allowed(actor, &SVS_RUN_MANAGE).await?,
            service.allowed(actor, &SVS_ADMIN).await?,
            notice_of(one(&form, "done")),
        ))
    };
    match read.await {
        Ok(view) => render(&TestPage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /svs/tests/{guid}/settings`: the settings of the test's runs registered from now on. `action`
/// is `set`, with `observation_minutes` (empty for the computed window) and `holds_host`, or `clear`.
pub(crate) async fn test_settings(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(guid) = guid_of(path) else {
        return bad_request("A test is named by its guid.", &parts);
    };
    let form = pairs(&body);
    let done = match one(&form, "action") {
        Some("clear") => gui
            .service
            .remove_svs_test_settings(&viewer.actor, &guid)
            .await
            .map(|()| "cleared"),
        Some("set") => {
            let minutes = match one(&form, "observation_minutes")
                .map(str::trim)
                .filter(|m| !m.is_empty())
            {
                None => None,
                Some(text) => match text.parse::<i32>() {
                    Ok(minutes) => Some(minutes),
                    Err(_) => {
                        return bad_request(
                            "The observation window is a number of minutes.",
                            &parts,
                        );
                    }
                },
            };
            gui.service
                .set_svs_test_settings(
                    &viewer.actor,
                    &guid,
                    minutes,
                    one(&form, "holds_host").is_some(),
                )
                .await
                .map(|_| "settings")
        }
        _ => return bad_request("The settings are set or cleared.", &parts),
    };
    match done {
        Ok(done) => see_other(&format!("{}?done={done}", test_href(&guid)), None),
        Err(error) => failed(error, &parts),
    }
}

/// `POST /svs/tests/{guid}/decide`: removes a decision about one signature for the test. `decision` is
/// `undecide` (with `platform`), `unignore` or `unignore_globally`; `signature` is the signature.
pub(crate) async fn test_decide(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(guid) = guid_of(path) else {
        return bad_request("A test is named by its guid.", &parts);
    };
    let form = pairs(&body);
    let (Some(decision), Some(signature)) = (one(&form, "decision"), one(&form, "signature"))
    else {
        return bad_request("A decision names a signature and what is decided.", &parts);
    };
    let (actor, service) = (&viewer.actor, &gui.service);
    let done = match decision {
        "undecide" => {
            let Some(platform) = one(&form, "platform") else {
                return bad_request("An expectation is about a platform.", &parts);
            };
            service
                .remove_svs_expectation(actor, &guid, platform, signature)
                .await
                .map(|()| "undecide")
        }
        "unignore" => service
            .remove_svs_ignore(actor, signature, Some(&guid))
            .await
            .map(|()| "unignore"),
        "unignore_globally" => service
            .remove_svs_ignore(actor, signature, None)
            .await
            .map(|()| "unignore_globally"),
        _ => return bad_request("That isn't a decision this page makes.", &parts),
    };
    match done {
        Ok(done) => see_other(&format!("{}?done={done}", test_href(&guid)), None),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /svs/coverage`.
pub(crate) async fn coverage(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let (entries, filters) =
        match folded(FilterScreen::SvsCoverage, "/svs/coverage", raw.0.as_deref()) {
            Ok(Ok(request)) => request,
            Ok(Err(redirect)) => return redirect,
            Err(error) => return failed(error, &parts),
        };
    let query = CoverageQuery {
        filters: entries,
        ..CoverageQuery::default()
    };
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    let actor = &viewer.actor;
    let read = async {
        let page = gui
            .service
            .svs_coverage(actor, &query, cursor, Some(SVS_PER_PAGE))
            .await?;
        let summary = gui.service.svs_coverage_summary(actor, &query).await?;
        Ok::<_, ServiceError>(coverage_view(
            tabs("coverage", admin),
            &query,
            &filters,
            &summary,
            &page.rows,
            cursor,
            page.next_cursor.as_deref(),
        ))
    };
    match read.await {
        Ok(view) => render(&CoveragePage {
            quick: crate::saved_filters::quick_filters(
                &gui,
                &viewer,
                FilterScreen::SvsCoverage,
                "/svs/coverage",
            )
            .await,
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /svs/coverage/{technique}`: a technique's page.
pub(crate) async fn technique(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let Ok(Path(requested)) = path else {
        return bad_request("A technique is named by its ATT&CK id.", &parts);
    };
    let actor = &viewer.actor;
    let read = async {
        let detail = gui
            .service
            .svs_coverage_technique(actor, &requested)
            .await?;
        let history = gui
            .service
            .svs_coverage_history(
                actor,
                &CoverageHistoryQuery {
                    filters: history_filters(&detail.technique, PAGE_HISTORY_RANGE),
                    ..CoverageHistoryQuery::default()
                },
                None,
                Some(TECHNIQUE_HISTORY),
            )
            .await?;
        Ok::<_, ServiceError>(technique_view(
            tabs("coverage", admin),
            &detail,
            &history.rows,
        ))
    };
    match read.await {
        Ok(view) => render(&TechniquePage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /svs/worklist`.
pub(crate) async fn worklist(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let (entries, filters) =
        match folded(FilterScreen::SvsWorklist, "/svs/worklist", raw.0.as_deref()) {
            Ok(Ok(request)) => request,
            Ok(Err(redirect)) => return redirect,
            Err(error) => return failed(error, &parts),
        };
    let query = WorklistQuery {
        filters: entries,
        ..WorklistQuery::default()
    };
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let cursor = one(&form, "cursor").filter(|c| !c.is_empty());
    let actor = &viewer.actor;
    let read = async {
        let page = gui
            .service
            .svs_worklist(actor, &query, cursor, Some(SVS_PER_PAGE))
            .await?;
        Ok::<_, ServiceError>(worklist_view(
            tabs("worklist", admin),
            &query,
            &filters,
            &page.rows,
            cursor,
            page.next_cursor.as_deref(),
            gui.service.allowed(actor, &SVS_RUN_MANAGE).await?,
            match one(&form, "done") {
                Some("bulk") => {
                    let count = |name: &str| {
                        one(&form, name)
                            .and_then(|text| text.parse::<u32>().ok())
                            .unwrap_or(0)
                    };
                    Some(bulk_notice(count("ok"), count("left"), count("missing")))
                }
                done => notice_of(done),
            },
        ))
    };
    match read.await {
        Ok(view) => render(&WorklistPage {
            quick: crate::saved_filters::quick_filters(
                &gui,
                &viewer,
                FilterScreen::SvsWorklist,
                "/svs/worklist",
            )
            .await,
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// `GET /svs/worklist/{signature_uuid}`: a signature's rows.
pub(crate) async fn worklist_signature(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Response {
    let admin = match enter(&gui, &viewer, &parts).await {
        Ok(admin) => admin,
        Err(failure) => return failure.into_response(),
    };
    let Ok(Path(signature)) = path else {
        return bad_request("A signature is named by its uuid.", &parts);
    };
    let form = pairs(raw.0.as_deref().unwrap_or("").as_bytes());
    let actor = &viewer.actor;
    let read = async {
        let detail = gui
            .service
            .svs_worklist_signature(actor, &signature)
            .await?;
        Ok::<_, ServiceError>(signature_view(
            tabs("worklist", admin),
            &detail,
            gui.service.allowed(actor, &SVS_RUN_MANAGE).await?,
            notice_of(one(&form, "done")),
        ))
    };
    match read.await {
        Ok(view) => render(&SignaturePage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => failed(error, &parts),
    }
}

/// Where a bulk resolution goes back: the worklist page it came from, and nowhere else.
fn back_of(form: &[(String, String)]) -> String {
    one(form, "back")
        .filter(|back| *back == "/svs/worklist" || back.starts_with("/svs/worklist?"))
        .unwrap_or("/svs/worklist")
        .to_owned()
}

/// `POST /svs/worklist/resolve`: keeps or removes the ticked rows alike. `row` is each ticked row's
/// `<signature>|<technique>`, `resolution` is `keep` or `remove`, with `reason` and `reference`.
pub(crate) async fn resolve_many(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let mut keys = Vec::new();
    for row in all(&form, "row") {
        // a technique id holds no `|`, so the last one splits the two
        let Some((signature, technique)) = row.rsplit_once('|') else {
            return bad_request("A ticked row names a signature and a technique.", &parts);
        };
        keys.push((signature.to_owned(), technique.to_owned()));
    }
    if keys.is_empty() {
        return bad_request("Tick the rows to resolve.", &parts);
    }
    let Some(resolution) = one(&form, "resolution") else {
        return bad_request("A resolution is keep or remove.", &parts);
    };
    match gui
        .service
        .resolve_svs_worklist_rows(
            &viewer.actor,
            &keys,
            resolution,
            one(&form, "reason"),
            one(&form, "reference"),
            Utc::now(),
        )
        .await
    {
        Ok(result) => {
            let back = back_of(&form);
            let counts = serde_urlencoded::to_string(bulk_counts(&result)).unwrap_or_default();
            let join = if back.contains('?') { '&' } else { '?' };
            see_other(&format!("{back}{join}{counts}"), None)
        }
        Err(error) => failed(error, &parts),
    }
}

/// `POST /svs/worklist/{signature_uuid}/resolve`: one row's resolution, from the signature's page.
/// `technique` is the row's, `resolution` is `keep`, `remove` or `reopen`, with `reason` and `reference`,
/// and `seen` is the row's `updated_at` as the page showed it.
pub(crate) async fn resolve(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    path: Result<Path<String>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Ok(Path(signature)) = path else {
        return bad_request("A signature is named by its uuid.", &parts);
    };
    let form = pairs(&body);
    let (Some(technique), Some(resolution)) = (one(&form, "technique"), one(&form, "resolution"))
    else {
        return bad_request(
            "A resolution names a technique and what is decided.",
            &parts,
        );
    };
    // a resolution made from the page says what the page showed: a row someone else changed first is
    // refused, not replaced
    let precondition = match one(&form, "seen").filter(|seen| !seen.is_empty()) {
        None => Precondition::None,
        Some(seen) => match Precondition::parse(Some(seen), None) {
            Ok(precondition) => precondition,
            Err(why) => return bad_request(&why, &parts),
        },
    };
    let (actor, service) = (&viewer.actor, &gui.service);
    let done = match resolution {
        "reopen" => service
            .reopen_svs_worklist_row(actor, &signature, technique, precondition, Utc::now())
            .await
            .map(|_| "reopen"),
        "keep" | "remove" => service
            .resolve_svs_worklist_row(
                actor,
                &signature,
                technique,
                resolution,
                one(&form, "reason"),
                one(&form, "reference"),
                precondition,
                Utc::now(),
            )
            .await
            .map(|_| {
                if resolution == "keep" {
                    "keep"
                } else {
                    "remove"
                }
            }),
        _ => return bad_request("A resolution is keep, remove or reopen.", &parts),
    };
    match done {
        Ok(done) => see_other(&format!("{}?done={done}", signature_href(&signature)), None),
        Err(error) => failed(error, &parts),
    }
}
