//! ATT&CK coverage per technique and platform (PLAN.md 7.10 batch 8): what ace3's `saq/svs/coverage.py`
//! computes without the database. The service's `svs_coverage` reads the inputs under the refresh lock,
//! writes only the rows that changed into `svs.coverage`, and files the daily snapshots.
//!
//! [`compute_rows`] derives every row from the inputs alone:
//! - each catalog test that isn't removed, judged on each of its platforms (`super::test_state`);
//! - the `mitre:` tags of the hunts and YARA rules (`super::signatures::signature_techniques`);
//! - the pinned ATT&CK release (`super::attack`).
//!
//! A test's contribution to the row of its technique on a platform is its state there
//! ([`contribution_state`]):
//! - validated, failing and stale count as themselves;
//! - an expectation that no reviewed run there has judged yet makes it stale;
//! - otherwise (never run there, no reviewed run there, nothing expected there) it is untested.
//!
//! A signature's `mitre:` tag naming technique t, when it counts (not resolved remove on the worklist,
//! unless measurement confirms it), makes every row of t manual (not those of t's sub-techniques). A row's
//! state is the worst of what counts toward it and toward its sub-techniques' rows on the same platform
//! ([`CoverageState`]'s order); `own_state` leaves the sub-techniques out; a row nothing counts toward is
//! none.
//!
//! How it scales: one pass over the tests, one over the tags, and one over the techniques with rows (the
//! release's, a few hundred, and whatever tests and tags name), each row summing its own tests and its
//! sub-techniques'. Nothing is quadratic in the tests.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::attack::{AttackCatalog, TechniqueStatus};
use super::catalog::platform_slugs;
use super::signatures::SignatureTags;
use super::test_state::{Evaluation, TestState};

/// Coverage of a technique on a platform, worst first: a row is in the first state any test or mapping
/// that counts toward it is in. ace3's `CoverageState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// A test's latest reviewed run there missed an expected signature.
    Failing,
    /// Validated, but the test, an expected rule or the expectations changed since.
    Stale,
    /// A test's latest reviewed run there hit every expected signature.
    Validated,
    /// Only a signature's `mitre:` tag claims it.
    Manual,
    /// Tests exist, none judged there yet.
    Untested,
    /// No tests and no tags.
    None,
}

impl CoverageState {
    /// In ace3's order, worst first.
    pub const ALL: &[CoverageState] = &[
        CoverageState::Failing,
        CoverageState::Stale,
        CoverageState::Validated,
        CoverageState::Manual,
        CoverageState::Untested,
        CoverageState::None,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CoverageState::Failing => "failing",
            CoverageState::Stale => "stale",
            CoverageState::Validated => "validated",
            CoverageState::Manual => "manual",
            CoverageState::Untested => "untested",
            CoverageState::None => "none",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|s| s.as_str() == text)
    }
}

impl std::fmt::Display for CoverageState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What coverage reads of a catalog test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageTest {
    pub guid: Uuid,
    /// The technique as the test's atomic file names it.
    pub technique: String,
    pub technique_name: Option<String>,
    /// Its `supported_platforms`, as the catalog stores them.
    pub platforms: Vec<String>,
}

/// The computed columns of one `svs.coverage` row; a refresh compares exactly these. ace3's `CoverageRow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageRow {
    pub technique: String,
    pub platform: String,
    pub parent: Option<String>,
    pub is_subtechnique: bool,
    pub technique_name: Option<String>,
    /// The technique's tactic ids, in the matrix's order.
    pub tactics: Vec<String>,
    pub catalog_status: TechniqueStatus,
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
}

/// ace3's `ComputedCoverage`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComputedCoverage {
    pub rows: BTreeMap<(String, String), CoverageRow>,
    /// `mitre:` tags naming an id the release doesn't have.
    pub unknown_tags: i32,
    /// `mitre:` tags that aren't technique ids.
    pub ignored_tags: i32,
    /// Catalog tests whose technique isn't a technique id.
    pub skipped_tests: Vec<Uuid>,
}

/// What one test counts toward one row of its technique: ace3's `Contribution`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contribution {
    pub guid: Uuid,
    pub state: CoverageState,
    pub reviewed_at: Option<DateTime<Utc>>,
    /// The signatures expected of the test on the platform, ignores applied.
    pub measured: BTreeSet<String>,
}

/// What each signature is measured on: `{signature uuid: {technique: {(test guid, platform)}}}`. ace3's
/// `Measured`.
pub type Measured = BTreeMap<String, BTreeMap<String, BTreeSet<(Uuid, String)>>>;

/// Each test's evaluations by platform: `evaluate_tests`' result as ace3's `evaluations_by_test` shapes it.
pub type Evaluations = BTreeMap<Uuid, BTreeMap<String, Evaluation>>;

/// What a test's state on a platform counts as toward coverage: ace3's `contribution_state`.
pub fn contribution_state(evaluation: Option<&Evaluation>) -> CoverageState {
    let Some(evaluation) = evaluation else {
        return CoverageState::Untested;
    };
    match evaluation.state {
        TestState::Validated => CoverageState::Validated,
        TestState::Failing => CoverageState::Failing,
        TestState::Stale => CoverageState::Stale,
        // expected only after its latest review there: what was validated no longer says enough
        TestState::AwaitingReview
            if evaluation.run.is_some() && evaluation.unjudged_expectations =>
        {
            CoverageState::Stale
        }
        _ => CoverageState::Untested,
    }
}

fn worst(states: impl IntoIterator<Item = CoverageState>) -> CoverageState {
    // the enum's order is worst first, None last
    states.into_iter().min().unwrap_or(CoverageState::None)
}

/// The technique a catalog test counts toward (None when its technique isn't a technique id), and what it
/// counts toward that technique's row on each platform. `evaluations` are the test's by platform.
/// [`compute_rows`] and the coverage drill-down both count a test through this. ace3's `test_contributions`.
pub fn test_contributions(
    catalog: &AttackCatalog,
    test: &CoverageTest,
    evaluations: Option<&BTreeMap<String, Evaluation>>,
) -> (Option<String>, BTreeMap<String, Contribution>) {
    let Ok(resolution) = catalog.resolve(&test.technique) else {
        return (None, BTreeMap::new());
    };
    // a run or a decision on a platform the test no longer supports still counts there; the empty
    // platform of a decision from before runs had one doesn't
    let mut platforms: BTreeSet<String> = platform_slugs(&test.platforms).into_iter().collect();
    if let Some(evaluations) = evaluations {
        platforms.extend(evaluations.keys().cloned());
    }
    platforms.remove("");
    let counted = platforms
        .into_iter()
        .map(|platform| {
            let evaluation = evaluations.and_then(|by| by.get(&platform));
            let contribution = Contribution {
                guid: test.guid,
                state: contribution_state(evaluation),
                reviewed_at: evaluation
                    .and_then(|e| e.run.as_ref())
                    .and_then(|run| run.reviewed_at),
                measured: evaluation.map(|e| e.expected.clone()).unwrap_or_default(),
            };
            (platform, contribution)
        })
        .collect();
    (Some(resolution.technique), counted)
}

/// Where each signature is expected, ignores applied, counted as [`compute_rows`] counts the tests: ace3's
/// `measured_by_signature`.
pub fn measured_by_signature(
    catalog: &AttackCatalog,
    tests: &[CoverageTest],
    evaluations: &Evaluations,
) -> Measured {
    let mut measured = Measured::new();
    for test in tests {
        let (Some(technique), counted) =
            test_contributions(catalog, test, evaluations.get(&test.guid))
        else {
            continue;
        };
        for (platform, contribution) in counted {
            for signature in contribution.measured {
                measured
                    .entry(signature)
                    .or_default()
                    .entry(technique.clone())
                    .or_default()
                    .insert((test.guid, platform.clone()));
            }
        }
    }
    measured
}

/// Every coverage row. `tests` are the catalog tests that count (not removed), `evaluations` theirs, `tags`
/// `signature_techniques`' result, and `excluded` the (signature uuid, technique) tags the worklist
/// resolved remove. ace3's `compute_rows`.
pub fn compute_rows(
    catalog: &AttackCatalog,
    tests: &[CoverageTest],
    evaluations: &Evaluations,
    tags: &BTreeMap<String, SignatureTags>,
    excluded: &BTreeSet<(String, String)>,
) -> ComputedCoverage {
    let mut computed = ComputedCoverage::default();

    // (technique, platform) -> what each test counts toward it
    let mut contributions: BTreeMap<(String, String), Vec<Contribution>> = BTreeMap::new();
    // technique -> its tests' platforms
    let mut test_platforms: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // technique -> the technique name a test gives it, for one the release doesn't have
    let mut test_names: BTreeMap<String, String> = BTreeMap::new();
    let mut sorted: Vec<&CoverageTest> = tests.iter().collect();
    sorted.sort_by_key(|test| test.guid);
    for test in sorted {
        let (Some(technique), counted) =
            test_contributions(catalog, test, evaluations.get(&test.guid))
        else {
            computed.skipped_tests.push(test.guid);
            continue;
        };
        if let Some(name) = test
            .technique_name
            .as_deref()
            .filter(|name| !name.is_empty())
        {
            test_names
                .entry(technique.clone())
                .or_insert_with(|| name.to_owned());
        }
        let platforms = test_platforms.entry(technique.clone()).or_default();
        for (platform, contribution) in counted {
            platforms.insert(platform.clone());
            contributions
                .entry((technique.clone(), platform))
                .or_default()
                .push(contribution);
        }
    }

    // technique -> the signatures whose tags make it manual
    let mut manual: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for signature in tags.values() {
        computed.ignored_tags += signature.ignored.len() as i32;
        for declared in &signature.declared {
            let Ok(resolution) = catalog.resolve(declared) else {
                continue;
            };
            if resolution.status == TechniqueStatus::Unknown {
                computed.unknown_tags += 1;
            } else if signature.counts
                && !excluded.contains(&(signature.uuid.clone(), resolution.technique.clone()))
            {
                manual
                    .entry(resolution.technique)
                    .or_default()
                    .insert(signature.uuid.as_str());
            }
        }
    }

    // the techniques with rows: every active one in the release, every one a test or a counting tag
    // names, and the parent of each of those
    let mut techniques: BTreeSet<String> = catalog
        .techniques
        .values()
        .filter(|technique| !technique.deprecated)
        .map(|technique| technique.id.clone())
        .collect();
    techniques.extend(test_platforms.keys().cloned());
    techniques.extend(manual.keys().cloned());
    let parents: Vec<String> = techniques
        .iter()
        .filter_map(|technique| catalog.parent_of(technique).map(str::to_owned))
        .collect();
    techniques.extend(parents);

    let mut children: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for technique in &techniques {
        if let Some(parent) = catalog.parent_of(technique) {
            children.entry(parent).or_default().insert(technique);
        }
    }

    let own_platforms = |technique: &str| -> BTreeSet<String> {
        let mut platforms: BTreeSet<String> = catalog
            .technique(technique)
            .map(|known| known.platforms.iter().cloned().collect())
            .unwrap_or_default();
        if let Some(more) = test_platforms.get(technique) {
            platforms.extend(more.iter().cloned());
        }
        platforms
    };
    let no_contributions: Vec<Contribution> = Vec::new();
    let no_manual: BTreeSet<&str> = BTreeSet::new();

    for technique in &techniques {
        let known = catalog.technique(technique);
        let attack_platforms: BTreeSet<&str> = known
            .map(|known| known.platforms.iter().map(String::as_str).collect())
            .unwrap_or_default();
        let subs: Vec<&str> = children
            .get(technique.as_str())
            .map(|subs| subs.iter().copied().collect())
            .unwrap_or_default();
        let sub_platforms: BTreeMap<&str, BTreeSet<String>> =
            subs.iter().map(|sub| (*sub, own_platforms(sub))).collect();
        let mut platforms = own_platforms(technique);
        for more in sub_platforms.values() {
            platforms.extend(more.iter().cloned());
        }
        let parent = catalog.parent_of(technique).map(str::to_owned);

        for platform in platforms {
            let key = (technique.clone(), platform.clone());
            let own = contributions.get(&key).unwrap_or(&no_contributions);
            let own_manual = manual.get(technique).unwrap_or(&no_manual);
            let mut rolled: Vec<&Contribution> = own.iter().collect();
            let mut rolled_manual: BTreeSet<&str> = own_manual.clone();
            for sub in &subs {
                if sub_platforms[sub].contains(&platform) {
                    if let Some(more) = contributions.get(&((*sub).to_owned(), platform.clone())) {
                        rolled.extend(more.iter());
                    }
                    if let Some(more) = manual.get(*sub) {
                        rolled_manual.extend(more.iter().copied());
                    }
                }
            }

            let own_state = worst(
                own.iter()
                    .map(|c| c.state)
                    .chain((!own_manual.is_empty()).then_some(CoverageState::Manual)),
            );
            let state = worst(
                rolled
                    .iter()
                    .map(|c| c.state)
                    .chain((!rolled_manual.is_empty()).then_some(CoverageState::Manual)),
            );
            let count =
                |wanted: CoverageState| rolled.iter().filter(|c| c.state == wanted).count() as i32;
            let measured: BTreeSet<&String> =
                rolled.iter().flat_map(|c| c.measured.iter()).collect();
            let row = CoverageRow {
                technique: technique.clone(),
                platform: platform.clone(),
                parent: parent.clone(),
                is_subtechnique: technique.contains('.'),
                technique_name: match known {
                    Some(known) => Some(known.name.clone()),
                    None => test_names.get(technique).cloned(),
                },
                tactics: known.map(|known| known.tactics.clone()).unwrap_or_default(),
                catalog_status: known.map_or(TechniqueStatus::Unknown, |known| known.status()),
                attack_platform: attack_platforms.contains(platform.as_str()),
                state,
                own_state,
                tests_total: rolled.len() as i32,
                tests_validated: count(CoverageState::Validated),
                tests_failing: count(CoverageState::Failing),
                tests_stale: count(CoverageState::Stale),
                manual_signatures: rolled_manual.len() as i32,
                measured_signatures: measured.len() as i32,
                last_reviewed_at: rolled.iter().filter_map(|c| c.reviewed_at).max(),
            };
            computed.rows.insert(key, row);
        }
    }
    computed
}

/// Why a signature's tag doesn't count toward a technique's coverage, None when it does: the drill-down's
/// `reason` (ace3's `technique_detail`).
pub fn mapping_reason(
    status: TechniqueStatus,
    signature_counts: bool,
    excluded: bool,
) -> Option<&'static str> {
    if status == TechniqueStatus::Unknown {
        Some("unknown_technique")
    } else if !signature_counts {
        Some("not_counting")
    } else if excluded {
        Some("removed")
    } else {
        None
    }
}

/// `candidate` is the technique or one of its sub-techniques: ace3's `_covers`.
pub fn covers(catalog: &AttackCatalog, technique: &str, candidate: &str) -> bool {
    candidate == technique || catalog.parent_of(candidate) == Some(technique)
}

/// What the last refresh did: the one row of `svs.coverage_state`, ace3's `SVSCoverageState`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshState {
    /// The ATT&CK release of the last refresh that completed.
    pub attack_release: Option<String>,
    /// When the last refresh completed; None before the first.
    pub refreshed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i32>,
    pub rows: i32,
    pub changed: i32,
    pub retired: i32,
    pub unknown_tags: i32,
    pub ignored_tags: i32,
    /// Why the latest refresh failed; None once one completes.
    pub error: Option<String>,
}

/// The refresh's state, None before anything refreshed or failed.
pub async fn refresh_state(
    conn: &mut sqlx::PgConnection,
) -> Result<Option<RefreshState>, sqlx::Error> {
    Ok(sqlx::query!(
        "SELECT attack_release, refreshed_at, duration_ms, rows, changed, retired, unknown_tags,
                ignored_tags, error
         FROM svs.coverage_state WHERE id = 1"
    )
    .fetch_optional(conn)
    .await?
    .map(|row| RefreshState {
        attack_release: row.attack_release,
        refreshed_at: row.refreshed_at,
        duration_ms: row.duration_ms,
        rows: row.rows,
        changed: row.changed,
        retired: row.retired,
        unknown_tags: row.unknown_tags,
        ignored_tags: row.ignored_tags,
        error: row.error,
    }))
}

/// What `ace svs coverage status` prints: the last refresh, the rows per state on each platform over the
/// rows that aren't retired (ace3's `coverage_counts`), and the worklist's rows per status (its
/// `worklist_counts`). Two grouped counts over tables the release and the expectations bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageStatus {
    pub state: Option<RefreshState>,
    /// `{platform: {state: rows}}`.
    pub counts: BTreeMap<String, BTreeMap<String, i64>>,
    /// `{status: rows}`.
    pub worklist: BTreeMap<String, i64>,
}

pub async fn status(conn: &mut sqlx::PgConnection) -> Result<CoverageStatus, sqlx::Error> {
    let mut status = CoverageStatus {
        state: refresh_state(&mut *conn).await?,
        ..CoverageStatus::default()
    };
    for row in sqlx::query!(
        r#"SELECT platform, state, count(*) AS "count!" FROM svs.coverage
           WHERE retired_at IS NULL GROUP BY platform, state"#
    )
    .fetch_all(&mut *conn)
    .await?
    {
        status
            .counts
            .entry(row.platform)
            .or_default()
            .insert(row.state, row.count);
    }
    for row in sqlx::query!(
        r#"SELECT status, count(*) AS "count!" FROM svs.technique_worklist GROUP BY status"#
    )
    .fetch_all(conn)
    .await?
    {
        status.worklist.insert(row.status, row.count);
    }
    Ok(status)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::attack::tests::extract_fixture;
    use super::super::signatures::FAMILY_HUNT;
    use super::super::test_state::ReviewedRun;
    use super::*;
    use chrono::TimeDelta;

    pub(crate) const GUID: Uuid = Uuid::from_u128(0xaaaaaaaa_1111_4111_8111_111111111111);
    pub(crate) const OTHER_GUID: Uuid = Uuid::from_u128(0xbbbbbbbb_2222_4222_8222_222222222222);
    pub(crate) const SIGNATURE: &str = "22222222-bbbb-4bbb-8bbb-222222222222";
    pub(crate) const OTHER_SIGNATURE: &str = "44444444-dddd-4ddd-8ddd-444444444444";

    fn t0() -> DateTime<Utc> {
        "2026-10-16T12:00:00Z".parse().expect("a time")
    }

    /// conftest.py's `attack_catalog`: the `ATTACK_EXTRACT` release.
    pub(crate) fn catalog() -> AttackCatalog {
        AttackCatalog::load(&extract_fixture().to_string(), "v99.0.json").expect("loads")
    }

    /// `_test`.
    fn test(guid: Uuid, technique: &str, platforms: &[&str], name: &str) -> CoverageTest {
        CoverageTest {
            guid,
            technique: technique.to_owned(),
            technique_name: Some(name.to_owned()),
            platforms: platforms.iter().map(|p| (*p).to_owned()).collect(),
        }
    }

    fn a_test() -> CoverageTest {
        test(GUID, "T1059.001", &["windows"], "From the test")
    }

    /// `_evaluation`.
    fn evaluation(
        state: TestState,
        reviewed_at: Option<DateTime<Utc>>,
        expected: &[&str],
        unjudged: bool,
    ) -> Evaluation {
        Evaluation {
            state,
            run: reviewed_at.map(|at| ReviewedRun {
                id: 1,
                uuid: Uuid::from_u128(7),
                reviewed_at: Some(at),
                test_content_hash: "0".repeat(64),
            }),
            expected: expected.iter().map(|s| (*s).to_owned()).collect(),
            unjudged_expectations: unjudged,
        }
    }

    fn reviewed(state: TestState) -> Evaluation {
        evaluation(state, Some(t0()), &[], false)
    }

    fn evaluations(pairs: Vec<(Uuid, &str, Evaluation)>) -> Evaluations {
        let mut by: Evaluations = BTreeMap::new();
        for (guid, platform, evaluation) in pairs {
            by.entry(guid)
                .or_default()
                .insert(platform.to_owned(), evaluation);
        }
        by
    }

    /// `_tag`.
    pub(crate) fn tag(
        uuid: &str,
        declared: &[&str],
        counts: bool,
        ignored: &[&str],
    ) -> SignatureTags {
        SignatureTags {
            uuid: uuid.to_owned(),
            family: FAMILY_HUNT.to_owned(),
            name: Some(format!("hunt {}", &uuid[..4])),
            counts,
            declared: declared.iter().map(|d| (*d).to_owned()).collect(),
            ignored: ignored.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    fn tags(all: Vec<SignatureTags>) -> BTreeMap<String, SignatureTags> {
        all.into_iter().map(|t| (t.uuid.clone(), t)).collect()
    }

    fn compute(
        tests: &[CoverageTest],
        evaluations: &Evaluations,
        tags: &BTreeMap<String, SignatureTags>,
    ) -> ComputedCoverage {
        compute_rows(&catalog(), tests, evaluations, tags, &BTreeSet::new())
    }

    fn row<'a>(computed: &'a ComputedCoverage, technique: &str, platform: &str) -> &'a CoverageRow {
        computed
            .rows
            .get(&(technique.to_owned(), platform.to_owned()))
            .unwrap_or_else(|| panic!("no row of {technique} on {platform}"))
    }

    /// `_states`.
    fn states(
        computed: &ComputedCoverage,
        technique: &str,
        platform: &str,
    ) -> (&'static str, &'static str) {
        let row = row(computed, technique, platform);
        (row.state.as_str(), row.own_state.as_str())
    }

    fn keys(computed: &ComputedCoverage) -> Vec<(&str, &str)> {
        computed
            .rows
            .keys()
            .map(|(t, p)| (t.as_str(), p.as_str()))
            .collect()
    }

    /// test_coverage.py's `test_every_active_technique_has_its_platforms`.
    #[test]
    fn every_active_technique_has_its_platforms() {
        let computed = compute(&[], &BTreeMap::new(), &BTreeMap::new());
        // T1099 is deprecated and nothing names it
        assert_eq!(
            keys(&computed),
            [
                ("T1059", "macos"),
                ("T1059", "windows"),
                ("T1059.001", "windows"),
                ("T1059.002", "macos"),
                ("T1547", "windows"),
            ]
        );
        let r = row(&computed, "T1059.001", "windows");
        assert_eq!(
            (r.state, r.own_state, r.parent.as_deref(), r.is_subtechnique),
            (
                CoverageState::None,
                CoverageState::None,
                Some("T1059"),
                true
            )
        );
        assert_eq!(
            (
                r.technique_name.as_deref(),
                r.catalog_status,
                r.attack_platform,
                r.tactics.as_slice()
            ),
            (
                Some("PowerShell"),
                TechniqueStatus::Active,
                true,
                ["TA0002".to_owned()].as_slice()
            )
        );
        assert_eq!(
            row(&computed, "T1547", "windows").tactics,
            ["TA0003", "TA0002"]
        );
    }

    /// `test_contribution_state`, each of its parameters.
    #[test]
    fn contribution_state_of_each_evaluation() {
        let cases = [
            (None, CoverageState::Untested),
            (
                Some(reviewed(TestState::Validated)),
                CoverageState::Validated,
            ),
            (Some(reviewed(TestState::Failing)), CoverageState::Failing),
            (Some(reviewed(TestState::Stale)), CoverageState::Stale),
            (
                Some(reviewed(TestState::NoExpectations)),
                CoverageState::Untested,
            ),
            // nothing reviewed yet
            (
                Some(evaluation(
                    TestState::AwaitingReview,
                    None,
                    &[SIGNATURE],
                    true,
                )),
                CoverageState::Untested,
            ),
            // expected only after its latest review
            (
                Some(evaluation(
                    TestState::AwaitingReview,
                    Some(t0()),
                    &[SIGNATURE],
                    true,
                )),
                CoverageState::Stale,
            ),
        ];
        for (evaluation, expected) in cases {
            assert_eq!(
                contribution_state(evaluation.as_ref()),
                expected,
                "{evaluation:?}"
            );
        }
    }

    /// `test_worst_first`.
    #[test]
    fn worst_first() {
        let tests = [a_test(), test(OTHER_GUID, "T1059.001", &["windows"], "x")];
        let by = evaluations(vec![
            (GUID, "windows", reviewed(TestState::Validated)),
            (OTHER_GUID, "windows", reviewed(TestState::Failing)),
        ]);
        let computed = compute(&tests, &by, &BTreeMap::new());
        let r = row(&computed, "T1059.001", "windows");
        assert_eq!(
            (
                r.state,
                r.tests_total,
                r.tests_validated,
                r.tests_failing,
                r.tests_stale
            ),
            (CoverageState::Failing, 2, 1, 1, 0)
        );
    }

    /// `test_untested_is_below_manual`.
    #[test]
    fn untested_is_below_manual() {
        let tagged = tags(vec![tag(SIGNATURE, &["T1059.001"], true, &[])]);
        let computed = compute(&[a_test()], &BTreeMap::new(), &tagged);
        assert_eq!(
            states(&computed, "T1059.001", "windows"),
            ("manual", "manual")
        );
        let by = evaluations(vec![(GUID, "windows", reviewed(TestState::Stale))]);
        let computed = compute(&[a_test()], &by, &tagged);
        assert_eq!(
            states(&computed, "T1059.001", "windows"),
            ("stale", "stale")
        );
    }

    /// `test_sub_techniques_roll_up_on_their_platform`.
    #[test]
    fn sub_techniques_roll_up_on_their_platform() {
        let by = evaluations(vec![(GUID, "windows", reviewed(TestState::Validated))]);
        let computed = compute(&[a_test()], &by, &BTreeMap::new());
        assert_eq!(
            states(&computed, "T1059.001", "windows"),
            ("validated", "validated")
        );
        assert_eq!(states(&computed, "T1059", "windows"), ("validated", "none"));
        assert_eq!(states(&computed, "T1059", "macos"), ("none", "none"));
        assert_eq!(row(&computed, "T1059", "windows").tests_validated, 1);
    }

    /// `test_a_test_platform_attack_does_not_list_gets_rows`.
    #[test]
    fn a_test_platform_attack_does_not_list_gets_rows() {
        let tests = [test(
            GUID,
            "T1059.001",
            &["windows", "linux"],
            "From the test",
        )];
        let computed = compute(&tests, &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(
            (
                row(&computed, "T1059.001", "linux").attack_platform,
                row(&computed, "T1059.001", "windows").attack_platform
            ),
            (false, true)
        );
        // the parent's rows include its sub-techniques' platforms
        let parent = row(&computed, "T1059", "linux");
        assert_eq!(
            (
                parent.state,
                parent.own_state,
                parent.attack_platform,
                parent.tests_total
            ),
            (CoverageState::Untested, CoverageState::None, false, 1)
        );
    }

    /// `test_a_platform_the_test_has_a_run_on_counts`.
    #[test]
    fn a_platform_the_test_has_a_run_on_counts() {
        let by = evaluations(vec![
            (GUID, "linux", reviewed(TestState::Failing)),
            (GUID, "", reviewed(TestState::Failing)),
        ]);
        let computed = compute(&[a_test()], &by, &BTreeMap::new());
        assert_eq!(
            row(&computed, "T1059.001", "linux").state,
            CoverageState::Failing
        );
        assert!(
            !computed
                .rows
                .contains_key(&("T1059.001".to_owned(), String::new()))
        );
    }

    /// `test_manual_reaches_every_platform_but_not_the_sub_techniques`.
    #[test]
    fn manual_reaches_every_platform_but_not_the_sub_techniques() {
        let tagged = tags(vec![tag(SIGNATURE, &["T1059"], true, &[])]);
        let computed = compute(&[], &BTreeMap::new(), &tagged);
        assert_eq!(states(&computed, "T1059", "windows"), ("manual", "manual"));
        assert_eq!(states(&computed, "T1059", "macos"), ("manual", "manual"));
        assert_eq!(states(&computed, "T1059.001", "windows"), ("none", "none"));
        assert_eq!(states(&computed, "T1059.002", "macos"), ("none", "none"));
    }

    /// `test_a_sub_technique_tag_rolls_up`.
    #[test]
    fn a_sub_technique_tag_rolls_up() {
        let tagged = tags(vec![
            tag(SIGNATURE, &["T1059.002"], true, &[]),
            tag(OTHER_SIGNATURE, &["T1059"], true, &[]),
        ]);
        let computed = compute(&[], &BTreeMap::new(), &tagged);
        assert_eq!(
            states(&computed, "T1059.002", "macos"),
            ("manual", "manual")
        );
        assert_eq!(states(&computed, "T1059", "macos"), ("manual", "manual"));
        assert_eq!(row(&computed, "T1059", "macos").manual_signatures, 2);
        assert_eq!(row(&computed, "T1059", "windows").manual_signatures, 1);
    }

    /// `test_tags_that_do_not_count`.
    #[test]
    fn tags_that_do_not_count() {
        let tagged = tags(vec![tag(
            SIGNATURE,
            &["T1059"],
            false,
            &["mitre:TA0002", "mitre:{{ t }}"],
        )]);
        let computed = compute(&[], &BTreeMap::new(), &tagged);
        assert_eq!(states(&computed, "T1059", "windows"), ("none", "none"));
        assert_eq!(computed.ignored_tags, 2);
    }

    /// `test_tags_the_worklist_resolved_remove_do_not_count`.
    #[test]
    fn tags_the_worklist_resolved_remove_do_not_count() {
        let tagged = tags(vec![
            tag(SIGNATURE, &["T1547", "T1086"], true, &[]),
            tag(OTHER_SIGNATURE, &["T1547"], true, &[]),
        ]);
        let excluded = BTreeSet::from([
            (SIGNATURE.to_owned(), "T1547".to_owned()),
            (SIGNATURE.to_owned(), "T1059.001".to_owned()),
        ]);
        let computed = compute_rows(&catalog(), &[], &BTreeMap::new(), &tagged, &excluded);
        assert_eq!(row(&computed, "T1547", "windows").manual_signatures, 1);
        // excluded by the technique the tag counts as
        assert_eq!(states(&computed, "T1059.001", "windows"), ("none", "none"));
    }

    /// `test_revoked_ids_count_as_their_successor`.
    #[test]
    fn revoked_ids_count_as_their_successor() {
        let tests = [test(GUID, "T1086", &["windows"], "From the test")];
        let by = evaluations(vec![(GUID, "windows", reviewed(TestState::Validated))]);
        let tagged = tags(vec![tag(SIGNATURE, &["T1150"], true, &[])]);
        let computed = compute(&tests, &by, &tagged);
        assert_eq!(
            row(&computed, "T1059.001", "windows").state,
            CoverageState::Validated
        );
        assert!(
            !computed
                .rows
                .contains_key(&("T1086".to_owned(), "windows".to_owned()))
        );
        // T1150 was revoked by the deprecated T1099, which has rows while something names it
        let deprecated = row(&computed, "T1099", "windows");
        assert_eq!(
            (deprecated.state, deprecated.catalog_status),
            (CoverageState::Manual, TechniqueStatus::Deprecated)
        );
    }

    /// `test_unknown_ids`.
    #[test]
    fn unknown_ids() {
        let tests = [
            test(GUID, "T1234.001", &["windows"], "Custom"),
            test(OTHER_GUID, "not a technique", &["windows"], "From the test"),
        ];
        let tagged = tags(vec![tag(SIGNATURE, &["T9999"], true, &[])]);
        let computed = compute(&tests, &BTreeMap::new(), &tagged);
        let r = row(&computed, "T1234.001", "windows");
        assert_eq!(
            (
                r.state,
                r.catalog_status,
                r.technique_name.as_deref(),
                r.parent.as_deref(),
                r.attack_platform,
                r.tactics.is_empty()
            ),
            (
                CoverageState::Untested,
                TechniqueStatus::Unknown,
                Some("Custom"),
                Some("T1234"),
                false,
                true
            )
        );
        let parent = row(&computed, "T1234", "windows");
        assert_eq!(
            (
                parent.state,
                parent.own_state,
                parent.catalog_status,
                parent.technique_name.as_deref()
            ),
            (
                CoverageState::Untested,
                CoverageState::None,
                TechniqueStatus::Unknown,
                None
            )
        );
        // an unknown tag doesn't count; it is counted
        assert!(!computed.rows.keys().any(|(t, _)| t == "T9999"));
        assert_eq!(computed.unknown_tags, 1);
        assert_eq!(computed.skipped_tests, [OTHER_GUID]);
    }

    /// `test_measured_signatures_and_last_review`.
    #[test]
    fn measured_signatures_and_last_review() {
        let later = t0() + TimeDelta::days(1);
        let tests = [a_test(), test(OTHER_GUID, "T1059", &["windows"], "x")];
        let by = evaluations(vec![
            (
                GUID,
                "windows",
                evaluation(TestState::Validated, Some(t0()), &[SIGNATURE], false),
            ),
            (
                OTHER_GUID,
                "windows",
                evaluation(
                    TestState::Failing,
                    Some(later),
                    &[SIGNATURE, OTHER_SIGNATURE],
                    false,
                ),
            ),
        ]);
        let computed = compute(&tests, &by, &BTreeMap::new());
        let parent = row(&computed, "T1059", "windows");
        assert_eq!(
            (
                parent.measured_signatures,
                parent.last_reviewed_at,
                parent.tests_total
            ),
            (2, Some(later), 2)
        );
        let sub = row(&computed, "T1059.001", "windows");
        assert_eq!(
            (sub.measured_signatures, sub.last_reviewed_at),
            (1, Some(t0()))
        );
        // and where each signature is measured
        let measured = measured_by_signature(&catalog(), &tests, &by);
        assert_eq!(
            measured[SIGNATURE].keys().collect::<Vec<_>>(),
            ["T1059", "T1059.001"]
        );
        assert_eq!(
            measured[OTHER_SIGNATURE]["T1059"],
            BTreeSet::from([(OTHER_GUID, "windows".to_owned())])
        );
    }

    #[test]
    fn the_states_are_ace3_s() {
        assert_eq!(
            CoverageState::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            [
                "failing",
                "stale",
                "validated",
                "manual",
                "untested",
                "none"
            ]
        );
        assert_eq!(worst([]), CoverageState::None);
        assert_eq!(
            worst([CoverageState::Untested, CoverageState::Manual]),
            CoverageState::Manual
        );
        assert_eq!(
            mapping_reason(TechniqueStatus::Unknown, true, false),
            Some("unknown_technique")
        );
        assert_eq!(
            mapping_reason(TechniqueStatus::Active, false, true),
            Some("not_counting")
        );
        assert_eq!(
            mapping_reason(TechniqueStatus::Active, true, true),
            Some("removed")
        );
        assert_eq!(mapping_reason(TechniqueStatus::Active, true, false), None);
    }
}
