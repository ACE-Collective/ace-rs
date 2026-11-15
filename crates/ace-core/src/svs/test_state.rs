//! What the Tests screen shows of each Atomic Red Team test's runs (PLAN.md 7.10 batch 8): ace3's
//! `saq/svs/test_state.py`, the part that needs no database. The service's `svs_test_state` reads the runs,
//! the decisions and the signed-off results, for any number of tests in a fixed number of queries; nothing
//! here is stored.
//!
//! A test is judged on each platform on its own ([`judge`]), by its latest reviewed run on that platform
//! against what is expected of it there:
//! - awaiting_review: none of its runs on the platform is reviewed yet, or something was expected of it
//!   there only after that run was reviewed, so no reviewed run has judged it;
//! - no_expectations: it has a reviewed run there, and nothing is expected of it there;
//! - failing: that run, as signed off, missed an expected signature (possibly suppressed counts as
//!   missed);
//! - stale: it would be validated, but the test or the rule of an expected signature changed since that
//!   run was reviewed (a rule whose current content ACE can't read doesn't count as changed);
//! - validated: that run, as signed off, hit every expected signature.
//!
//! Expected signatures are those expected of the test on the platform that no ignore applies to.
//!
//! A test's state is never_run when no run was ever registered for it, else the worst of its platforms'
//! states: failing, stale, awaiting_review, validated, no_expectations ([`history`]). A platform counts
//! when the test has a run or a decision there.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::signatures::SignatureInfo;

/// How many of a test's latest ended or reviewed runs "missing in recent runs" looks at: ace3's
/// `RECENT_RUNS`.
pub const RECENT_RUNS: i64 = 5;

/// The result statuses that miss an expected signature: ace3's `MISSED`.
pub const MISSED: [&str; 2] = ["missing", "possibly_suppressed"];
const HIT: &str = "hit";

/// How a test does: ace3's `TestState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestState {
    NeverRun,
    AwaitingReview,
    NoExpectations,
    Failing,
    Stale,
    Validated,
}

impl TestState {
    /// In ace3's order.
    pub const ALL: &[TestState] = &[
        TestState::NeverRun,
        TestState::AwaitingReview,
        TestState::NoExpectations,
        TestState::Failing,
        TestState::Stale,
        TestState::Validated,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            TestState::NeverRun => "never_run",
            TestState::AwaitingReview => "awaiting_review",
            TestState::NoExpectations => "no_expectations",
            TestState::Failing => "failing",
            TestState::Stale => "stale",
            TestState::Validated => "validated",
        }
    }
}

impl std::fmt::Display for TestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A test's state over its platforms: the first of these any platform is in. ace3's `WORST_FIRST`.
pub const WORST_FIRST: [TestState; 5] = [
    TestState::Failing,
    TestState::Stale,
    TestState::AwaitingReview,
    TestState::Validated,
    TestState::NoExpectations,
];

/// A test's latest reviewed run on a platform: what [`judge`] reads of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedRun {
    pub id: i64,
    pub uuid: Uuid,
    pub reviewed_at: Option<DateTime<Utc>>,
    /// The test's content hash when the run was registered.
    pub test_content_hash: String,
}

/// One signature of a run's result as signed off.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedOff {
    pub reviewed_status: Option<String>,
    pub reviewed_content_hash: Option<String>,
}

/// How a test does on one platform: ace3's `Evaluation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub state: TestState,
    /// Its latest reviewed run on the platform.
    pub run: Option<ReviewedRun>,
    /// The signatures expected of it there that no ignore applies to.
    pub expected: BTreeSet<String>,
    /// Something is expected of it there that its latest reviewed run there didn't judge.
    pub unjudged_expectations: bool,
}

/// Every expected signature is in the signed-off result as a hit: ace3's `_all_hit`.
pub fn all_hit(expected: &BTreeSet<String>, signed_off: &BTreeMap<String, SignedOff>) -> bool {
    expected.iter().all(|uuid| {
        signed_off
            .get(uuid)
            .is_some_and(|row| row.reviewed_status.as_deref() == Some(HIT))
    })
}

/// How a test does on a platform: `run` is its latest reviewed run there, `expected` what is expected of
/// it there, `signed_off` that run's result rows by signature and `current` what ACE knows of the expected
/// signatures now. ace3's `judge`.
pub fn judge(
    run: Option<&ReviewedRun>,
    expected: &BTreeSet<String>,
    signed_off: &BTreeMap<String, SignedOff>,
    test_content_hash: &str,
    current: &BTreeMap<String, SignatureInfo>,
) -> Evaluation {
    let Some(run) = run else {
        return Evaluation {
            state: TestState::AwaitingReview,
            run: None,
            expected: expected.clone(),
            unjudged_expectations: !expected.is_empty(),
        };
    };
    if expected.is_empty() {
        return Evaluation {
            state: TestState::NoExpectations,
            run: Some(run.clone()),
            expected: BTreeSet::new(),
            unjudged_expectations: false,
        };
    }
    let missed = expected.iter().any(|uuid| {
        signed_off
            .get(uuid)
            .and_then(|row| row.reviewed_status.as_deref())
            .is_some_and(|status| MISSED.contains(&status))
    });
    if missed {
        return Evaluation {
            state: TestState::Failing,
            run: Some(run.clone()),
            expected: expected.clone(),
            unjudged_expectations: false,
        };
    }
    if !all_hit(expected, signed_off) {
        // expected only after the review: no reviewed run has judged it
        return Evaluation {
            state: TestState::AwaitingReview,
            run: Some(run.clone()),
            expected: expected.clone(),
            unjudged_expectations: true,
        };
    }
    let changed = test_content_hash != run.test_content_hash
        || expected.iter().any(|uuid| {
            current
                .get(uuid)
                .and_then(|info| info.content_hash.as_deref())
                .is_some_and(|now| {
                    signed_off
                        .get(uuid)
                        .and_then(|row| row.reviewed_content_hash.as_deref())
                        != Some(now)
                })
        });
    Evaluation {
        state: if changed {
            TestState::Stale
        } else {
            TestState::Validated
        },
        run: Some(run.clone()),
        expected: expected.clone(),
        unjudged_expectations: false,
    }
}

/// A test on one platform, as the Tests screen shows it: ace3's `PlatformHistory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformHistory {
    pub state: TestState,
    pub last_reviewed_run: Option<Uuid>,
    pub last_reviewed_at: Option<DateTime<Utc>>,
    /// How many signatures are expected of it there.
    pub expected: usize,
}

/// A test's state and run history: ace3's `TestHistory`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestHistory {
    pub state: TestState,
    pub run_count: i64,
    pub last_run: Option<Uuid>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_reviewed_run: Option<Uuid>,
    pub last_reviewed_at: Option<DateTime<Utc>>,
    /// Signatures expected of it on any platform.
    pub expected: usize,
    /// Of the test's latest [`RECENT_RUNS`] ended or reviewed runs: how many there are, and how many of
    /// them miss an expected signature in their live result.
    pub recent_runs: i64,
    pub recent_runs_missing: i64,
    /// By platform: each one it has a run or a decision on, and each supported one (never_run when it has
    /// neither there).
    pub platform_states: BTreeMap<String, PlatformHistory>,
}

impl TestHistory {
    /// A test nothing was ever registered or decided for, on no platform.
    pub fn never_run() -> TestHistory {
        TestHistory {
            state: TestState::NeverRun,
            run_count: 0,
            last_run: None,
            last_run_at: None,
            last_reviewed_run: None,
            last_reviewed_at: None,
            expected: 0,
            recent_runs: 0,
            recent_runs_missing: 0,
            platform_states: BTreeMap::new(),
        }
    }
}

/// What the runs' own rows say of a test: how many there are, the latest, and the recent ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunCounts {
    pub run_count: i64,
    /// The latest run by creation, and when it was registered.
    pub last_run: Option<(Uuid, DateTime<Utc>)>,
    pub recent_runs: i64,
    pub recent_runs_missing: i64,
}

/// A test's history from its evaluations by platform, what its runs count to, and the platforms it
/// supports (as slugs): the body of ace3's `catalog_histories`' loop.
pub fn history(
    platform_slugs: &[String],
    runs: &RunCounts,
    evaluations: &BTreeMap<String, Evaluation>,
) -> TestHistory {
    let state = if runs.run_count == 0 {
        TestState::NeverRun
    } else {
        let states: BTreeSet<TestState> = evaluations.values().map(|e| e.state).collect();
        WORST_FIRST
            .into_iter()
            .find(|state| states.contains(state))
            // a run on a platform is always evaluated there, so this is never reached
            .unwrap_or(TestState::AwaitingReview)
    };

    let platforms: BTreeSet<&str> = platform_slugs
        .iter()
        .map(String::as_str)
        .chain(evaluations.keys().map(String::as_str))
        .collect();
    let platform_states = platforms
        .into_iter()
        .map(|platform| {
            let history = match evaluations.get(platform) {
                None => PlatformHistory {
                    state: TestState::NeverRun,
                    last_reviewed_run: None,
                    last_reviewed_at: None,
                    expected: 0,
                },
                Some(evaluation) => PlatformHistory {
                    state: evaluation.state,
                    last_reviewed_run: evaluation.run.as_ref().map(|run| run.uuid),
                    last_reviewed_at: evaluation.run.as_ref().and_then(|run| run.reviewed_at),
                    expected: evaluation.expected.len(),
                },
            };
            (platform.to_owned(), history)
        })
        .collect();

    let latest_reviewed = evaluations
        .values()
        .filter_map(|evaluation| evaluation.run.as_ref())
        .max_by_key(|run| (run.reviewed_at, run.id));
    let expected: BTreeSet<&String> = evaluations
        .values()
        .flat_map(|evaluation| evaluation.expected.iter())
        .collect();
    TestHistory {
        state,
        run_count: runs.run_count,
        last_run: runs.last_run.map(|(uuid, _)| uuid),
        last_run_at: runs.last_run.map(|(_, at)| at),
        last_reviewed_run: latest_reviewed.map(|run| run.uuid),
        last_reviewed_at: latest_reviewed.and_then(|run| run.reviewed_at),
        expected: expected.len(),
        recent_runs: runs.recent_runs,
        recent_runs_missing: runs.recent_runs_missing,
        platform_states,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNATURE: &str = "22222222-bbbb-4bbb-8bbb-222222222222";
    const OTHER: &str = "44444444-dddd-4ddd-8ddd-444444444444";

    fn run() -> ReviewedRun {
        ReviewedRun {
            id: 1,
            uuid: Uuid::from_u128(1),
            reviewed_at: Some("2026-10-16T12:00:00Z".parse().expect("a time")),
            test_content_hash: "a".repeat(64),
        }
    }

    fn set(uuids: &[&str]) -> BTreeSet<String> {
        uuids.iter().map(|uuid| (*uuid).to_owned()).collect()
    }

    fn signed(rows: &[(&str, &str, &str)]) -> BTreeMap<String, SignedOff> {
        rows.iter()
            .map(|(uuid, status, hash)| {
                (
                    (*uuid).to_owned(),
                    SignedOff {
                        reviewed_status: Some((*status).to_owned()),
                        reviewed_content_hash: Some((*hash).to_owned()),
                    },
                )
            })
            .collect()
    }

    fn known(uuid: &str, hash: Option<&str>) -> BTreeMap<String, SignatureInfo> {
        BTreeMap::from([(
            uuid.to_owned(),
            SignatureInfo {
                uuid: uuid.to_owned(),
                name: Some("rule".to_owned()),
                family: Some("yara".to_owned()),
                content_hash: hash.map(str::to_owned),
            },
        )])
    }

    /// What `judge` decides, each branch: the states of test_test_state.py's `TestStates`, which the
    /// service's tests port against the database.
    #[test]
    fn judge_decides_each_state() {
        let hash = "a".repeat(64);
        let none: BTreeMap<String, SignedOff> = BTreeMap::new();
        let unknown: BTreeMap<String, SignatureInfo> = BTreeMap::new();
        // no reviewed run: awaiting review, unjudged only when something is expected
        let e = judge(None, &set(&[SIGNATURE]), &none, &hash, &unknown);
        assert_eq!(
            (e.state, e.unjudged_expectations),
            (TestState::AwaitingReview, true)
        );
        let e = judge(None, &set(&[]), &none, &hash, &unknown);
        assert_eq!(
            (e.state, e.unjudged_expectations),
            (TestState::AwaitingReview, false)
        );
        // a reviewed run and nothing expected
        let e = judge(Some(&run()), &set(&[]), &none, &hash, &unknown);
        assert_eq!(e.state, TestState::NoExpectations);
        assert!(e.expected.is_empty());
        // missed, either way
        for status in MISSED {
            let e = judge(
                Some(&run()),
                &set(&[SIGNATURE]),
                &signed(&[(SIGNATURE, status, "r")]),
                &hash,
                &unknown,
            );
            assert_eq!(e.state, TestState::Failing, "{status}");
        }
        // one expected after the review
        let e = judge(
            Some(&run()),
            &set(&[SIGNATURE, OTHER]),
            &signed(&[(SIGNATURE, "hit", "r")]),
            &hash,
            &unknown,
        );
        assert_eq!(
            (e.state, e.unjudged_expectations),
            (TestState::AwaitingReview, true)
        );
        // a miss wins over one not judged
        let e = judge(
            Some(&run()),
            &set(&[SIGNATURE, OTHER]),
            &signed(&[(SIGNATURE, "missing", "r")]),
            &hash,
            &unknown,
        );
        assert_eq!(e.state, TestState::Failing);
        // validated, then stale by the rule and by the test
        let hit = signed(&[(SIGNATURE, "hit", "r")]);
        let judged = |test_hash: &str, current: &BTreeMap<String, SignatureInfo>| {
            judge(Some(&run()), &set(&[SIGNATURE]), &hit, test_hash, current).state
        };
        assert_eq!(
            judged(&hash, &known(SIGNATURE, Some("r"))),
            TestState::Validated
        );
        assert_eq!(
            judged(&hash, &known(SIGNATURE, Some("changed"))),
            TestState::Stale
        );
        assert_eq!(
            judged(&"c".repeat(64), &known(SIGNATURE, Some("r"))),
            TestState::Stale
        );
        // a rule ACE can't read now isn't counted as changed
        assert_eq!(judged(&hash, &unknown), TestState::Validated);
        assert_eq!(judged(&hash, &known(SIGNATURE, None)), TestState::Validated);
    }

    #[test]
    fn a_history_is_the_worst_of_its_platforms() {
        let evaluation = |state, with_run: bool, expected: &[&str]| Evaluation {
            state,
            run: with_run.then(run),
            expected: set(expected),
            unjudged_expectations: false,
        };
        let slugs = ["windows".to_owned(), "macos".to_owned()];
        let runs = RunCounts {
            run_count: 2,
            ..RunCounts::default()
        };
        let evaluations = BTreeMap::from([
            (
                "windows".to_owned(),
                evaluation(TestState::Validated, true, &[SIGNATURE]),
            ),
            (
                "linux".to_owned(),
                evaluation(TestState::Failing, true, &[SIGNATURE, OTHER]),
            ),
        ]);
        let h = history(&slugs, &runs, &evaluations);
        assert_eq!(h.state, TestState::Failing);
        assert_eq!(h.expected, 2);
        assert_eq!(
            h.platform_states
                .iter()
                .map(|(platform, state)| (platform.as_str(), state.state, state.expected))
                .collect::<Vec<_>>(),
            [
                ("linux", TestState::Failing, 2),
                ("macos", TestState::NeverRun, 0),
                ("windows", TestState::Validated, 1),
            ]
        );
        assert_eq!(h.last_reviewed_run, Some(Uuid::from_u128(1)));
        // no run at all: never run, whatever was decided
        let h = history(&slugs, &RunCounts::default(), &evaluations);
        assert_eq!(h.state, TestState::NeverRun);
        assert_eq!(
            TestState::ALL
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>(),
            [
                "never_run",
                "awaiting_review",
                "no_expectations",
                "failing",
                "stale",
                "validated"
            ]
        );
    }
}
