//! A run's result (PLAN.md 7.10 batch 5, part 5b): what ace3's `saq/svs/results.py` decides without the
//! database, and `saq/svs/preconditions.py`'s `If-Match`. The service's `svs_results` reads what fired and
//! what was decided and writes the rows.
//!
//! What fired is the run's attributions that hold, by the signature of each attributed detection. Each
//! signature that fired is, in this order of precedence:
//! - ignored: globally or for the test (launcher noise);
//! - hit: expected for the test on the run's platform;
//! - rejected: decided, for the run's platform, not to be what the test is about;
//! - candidate: nobody has decided about it yet.
//!
//! A signature that fired only in the test's cleanup is cleanup, unless it is expected, when it is
//! missing: it is neither a hit nor a candidate.
//!
//! Each expected signature that did not fire (and is not ignored) is missing, or possibly suppressed when
//! it is a hunt and either the hunter recorded that it dropped a match during the run, or the hunt
//! suppresses as a whole and alerted within its suppression period before the run's window closed, on an
//! alert not attributed to the run.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::signatures::SignatureInfo;

/// One signature of a run's result: ace3's `ResultStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    /// Expected, and it fired.
    Hit,
    /// Expected, and it did not fire.
    Missing,
    /// Missing, and its hunt dropped a match or alerted within its suppression period.
    PossiblySuppressed,
    /// It fired, and nobody has decided about it yet.
    Candidate,
    /// It fired, and it was rejected for the test.
    Rejected,
    /// It fired, and it is ignored, globally or for the test.
    Ignored,
    /// It fired only during the test's cleanup, and isn't expected.
    Cleanup,
}

impl ResultStatus {
    pub const ALL: &[ResultStatus] = &[
        ResultStatus::Hit,
        ResultStatus::Missing,
        ResultStatus::PossiblySuppressed,
        ResultStatus::Candidate,
        ResultStatus::Rejected,
        ResultStatus::Ignored,
        ResultStatus::Cleanup,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ResultStatus::Hit => "hit",
            ResultStatus::Missing => "missing",
            ResultStatus::PossiblySuppressed => "possibly_suppressed",
            ResultStatus::Candidate => "candidate",
            ResultStatus::Rejected => "rejected",
            ResultStatus::Ignored => "ignored",
            ResultStatus::Cleanup => "cleanup",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|status| status.as_str() == text)
    }

    /// Missing or possibly suppressed: an expected signature that didn't fire.
    pub fn is_missing(self) -> bool {
        matches!(
            self,
            ResultStatus::Missing | ResultStatus::PossiblySuppressed
        )
    }
}

impl std::fmt::Display for ResultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The built-in signatures a result never counts, beside the SVS built-ins (`super::RUN_SIGNATURES`):
/// ace3's `UNTRACKED_SIGNATURES`. `generic`, `legacy` and `yara_rule_match` stand for many unrelated
/// detections (no specific signature, a detection from before attribution, a YARA rule without a uuid);
/// `observable_flagged_for_detection` fires on whatever analysts flagged, so flagging a value would change
/// results.
pub const GENERIC_SIGNATURE: &str = "87fe1a4a-0e60-4e3b-b712-da9d3db12fa7";
pub const LEGACY_SIGNATURE: &str = "3c649355-160e-405c-ad91-6916ab539849";
pub const YARA_RULE_MATCH_SIGNATURE: &str = "3557435e-da7f-4b1b-a5dd-655107839530";
pub const OBSERVABLE_FLAGGED_SIGNATURE: &str = "97a0bcb8-1bde-4cf0-8fa2-72d6343c6458";

/// Every signature a result never counts.
pub fn untracked_signatures() -> Vec<String> {
    [
        GENERIC_SIGNATURE,
        LEGACY_SIGNATURE,
        YARA_RULE_MATCH_SIGNATURE,
        OBSERVABLE_FLAGGED_SIGNATURE,
    ]
    .into_iter()
    .chain(super::RUN_SIGNATURES)
    .map(str::to_owned)
    .collect()
}

/// How many stale results one pass of the timers recomputes at most; the next pass does the rest. ace3's
/// `RECOMPUTE_BATCH`.
pub const RECOMPUTE_BATCH: i64 = 200;

/// The event time sources that aren't the event's own: ace3's `FALLBACK_EVENT_TIME_SOURCES`.
pub const FALLBACK_EVENT_TIME_SOURCES: [&str; 3] = ["query_time", "now", "insert_time"];

/// A signature attributed detections of the run carry: ace3's `Fired`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fired {
    pub signature_uuid: String,
    pub family: Option<String>,
    pub alert_count: i64,
    pub late_only: bool,
    pub context_only: bool,
    /// Every attribution of it is the test's cleanup's: it neither hits nor is a candidate.
    pub cleanup: bool,
    /// Some attribution of it was judged by a fallback event time.
    pub fallback_time: bool,
}

/// The signatures that fired, from one group per signature and side of the cleanup: a signature the test
/// fired outside its cleanup is counted by those attributions alone, so the cleanup's group never
/// replaces the test's own. ace3's `fired_signatures`, after its query.
pub fn merge_fired(mut groups: Vec<Fired>) -> BTreeMap<String, Fired> {
    groups.sort_by(|a, b| (&a.signature_uuid, a.cleanup).cmp(&(&b.signature_uuid, b.cleanup)));
    let mut fired = BTreeMap::new();
    for group in groups {
        fired.entry(group.signature_uuid.clone()).or_insert(group);
    }
    fired
}

/// What a decision or an earlier result row knows of a signature, for one ACE no longer knows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LastKnown {
    pub family: Option<String>,
    pub name: Option<String>,
}

/// What has been decided about the test's signatures: ace3's `Decisions`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decisions {
    pub expected: BTreeMap<String, LastKnown>,
    pub rejected: BTreeMap<String, LastKnown>,
    pub ignored: BTreeSet<String>,
}

/// One signature of a computed result: the live columns of its row. ace3's `ResultRow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultRow {
    pub signature_uuid: String,
    pub status: ResultStatus,
    pub family: Option<String>,
    pub name: Option<String>,
    pub alert_count: i64,
    pub late_only: bool,
    pub context_only: bool,
    pub fallback_time: bool,
    pub content_hash: Option<String>,
    /// possibly suppressed: the hunt's latest alert inside its suppression period.
    pub suppressing_alert: Option<Uuid>,
}

/// The expected signatures that didn't fire and aren't ignored, sorted: what fired only in the test's
/// cleanup is not what the test fires.
pub fn missing(fired: &BTreeMap<String, Fired>, decisions: &Decisions) -> Vec<String> {
    decisions
        .expected
        .keys()
        .filter(|uuid| {
            fired.get(*uuid).is_none_or(|fired| fired.cleanup) && !decisions.ignored.contains(*uuid)
        })
        .cloned()
        .collect()
}

/// The result's rows, by signature within what fired and then what's missing: ace3's `_rows`. `info` is
/// what ACE knows now of each signature that fired or is missing, `known` what the run's rows already
/// say, `suppressed` the hunts the hunter recorded as dropping a match during the run, and `suppressing`
/// each missing hunt's alert inside its suppression period, for the hunts that suppress as a whole.
pub fn rows(
    fired: &BTreeMap<String, Fired>,
    decisions: &Decisions,
    info: &BTreeMap<String, SignatureInfo>,
    known: &BTreeMap<String, LastKnown>,
    suppressed: &BTreeSet<String>,
    suppressing: &BTreeMap<String, Uuid>,
) -> Vec<ResultRow> {
    let missing = missing(fired, decisions);
    let described = |uuid: &str, family: Option<&str>| {
        let signature = info.get(uuid);
        let decision = decisions
            .expected
            .get(uuid)
            .or_else(|| decisions.rejected.get(uuid));
        let row = known.get(uuid);
        let family = signature
            .and_then(|s| s.family.clone())
            .or_else(|| family.map(str::to_owned))
            .or_else(|| decision.and_then(|d| d.family.clone()))
            .or_else(|| row.and_then(|r| r.family.clone()));
        let name = signature
            .and_then(|s| s.name.clone())
            .or_else(|| decision.and_then(|d| d.name.clone()))
            .or_else(|| row.and_then(|r| r.name.clone()));
        (family, name, signature.and_then(|s| s.content_hash.clone()))
    };

    let mut rows = Vec::new();
    for (uuid, signature) in fired {
        let is_missing = missing.contains(uuid);
        if signature.cleanup && is_missing {
            continue;
        }
        let status = if signature.cleanup {
            ResultStatus::Cleanup
        } else if decisions.ignored.contains(uuid) {
            ResultStatus::Ignored
        } else if decisions.expected.contains_key(uuid) {
            ResultStatus::Hit
        } else if decisions.rejected.contains_key(uuid) {
            ResultStatus::Rejected
        } else {
            ResultStatus::Candidate
        };
        let (family, name, content_hash) = described(uuid, signature.family.as_deref());
        rows.push(ResultRow {
            signature_uuid: uuid.clone(),
            status,
            family,
            name,
            alert_count: signature.alert_count,
            late_only: signature.late_only,
            context_only: signature.context_only,
            fallback_time: signature.fallback_time,
            content_hash,
            suppressing_alert: None,
        });
    }
    for uuid in &missing {
        let (family, name, content_hash) = described(uuid, None);
        // the hunter's record says it dropped a match, not because of which alert: the hunt's latest
        // alert may be another group's or key's, so none is named
        let (status, suppressing_alert) = if suppressed.contains(uuid) {
            (ResultStatus::PossiblySuppressed, None)
        } else if let Some(alert) = suppressing.get(uuid) {
            (ResultStatus::PossiblySuppressed, Some(*alert))
        } else {
            (ResultStatus::Missing, None)
        };
        rows.push(ResultRow {
            signature_uuid: uuid.clone(),
            status,
            family,
            name,
            alert_count: 0,
            late_only: false,
            context_only: false,
            fallback_time: false,
            content_hash,
            suppressing_alert,
        });
    }
    rows
}

/// The signatures per status of some rows, by status name: what a `result_computed` event carries.
pub fn counts<'a>(statuses: impl IntoIterator<Item = &'a str>) -> BTreeMap<String, i64> {
    let mut counts = BTreeMap::new();
    for status in statuses {
        *counts.entry(status.to_owned()).or_insert(0) += 1;
    }
    counts
}

/// What a person's write expects of the row it changes: ace3's `Precondition` (`saq/svs/preconditions.py`,
/// docs/SVS_API.md's *Conflicting writes*). Two people working from the same page would otherwise
/// overwrite each other without knowing. A write may say what it was made from, as HTTP preconditions:
/// `If-Match`, the row's `updated_at` as the client last read it, so the write applies only while the row
/// is unchanged since; or `If-None-Match: *`, the client saw no row, so the write applies only while there
/// still is none. A write without either applies whatever the row holds, which is what a script wants.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Precondition {
    /// Neither header: the write applies whatever the row holds.
    #[default]
    None,
    /// `If-Match`: the row's `updated_at` when the client read it.
    UpdatedAt(DateTime<Utc>),
    /// `If-None-Match: *`: the client saw no row.
    Absent,
}

impl Precondition {
    /// The precondition of a request's `If-Match` (an `updated_at`, quoted or not, as an ETag may be, UTC
    /// when it has no offset) and `If-None-Match` (only `*` means something for a write), or why they
    /// can't be used: ace3's `parse_precondition`.
    pub fn parse(
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Precondition, String> {
        match (if_match, if_none_match) {
            (Some(_), Some(_)) => Err("send If-Match or If-None-Match, not both".to_owned()),
            (None, Some(value)) => {
                if value.trim() == "*" {
                    Ok(Precondition::Absent)
                } else {
                    Err("If-None-Match on a write must be *".to_owned())
                }
            }
            (None, None) => Ok(Precondition::None),
            (Some(value), None) => {
                let trimmed = value.trim();
                let trimmed = trimmed.strip_prefix("W/").unwrap_or(trimmed);
                let trimmed = trimmed.trim_matches('"');
                let invalid = || format!("If-Match must be the row's updated_at, not {value:?}");
                if let Ok(at) = DateTime::parse_from_rfc3339(trimmed) {
                    return Ok(Precondition::UpdatedAt(at.with_timezone(&Utc)));
                }
                // no offset: UTC
                for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
                    if let Ok(at) = chrono::NaiveDateTime::parse_from_str(trimmed, format) {
                        return Ok(Precondition::UpdatedAt(at.and_utc()));
                    }
                }
                Err(invalid())
            }
        }
    }

    /// Why the write can't apply to a row that is absent (None) or was last changed at `updated_at`, or
    /// None when it can: ace3's `Precondition.check`. `what` names the row for the message.
    pub fn refuses(self, updated_at: Option<DateTime<Utc>>, what: &str) -> Option<String> {
        match (self, updated_at) {
            (Precondition::None, _) | (Precondition::Absent, None) => None,
            (Precondition::Absent, Some(_)) => Some(format!(
                "{what} was decided by someone else since you loaded it"
            )),
            (Precondition::UpdatedAt(_), None) => Some(format!(
                "{what} was removed by someone else since you loaded it"
            )),
            (Precondition::UpdatedAt(seen), Some(now)) => {
                // a client reads the time as JSON writes it, to the microsecond
                (seen.timestamp_micros() != now.timestamp_micros())
                    .then(|| format!("{what} was changed by someone else since you loaded it"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUNT: &str = "11111111-aaaa-4aaa-8aaa-111111111111";
    const YARA: &str = "22222222-bbbb-4bbb-8bbb-222222222222";
    const NOISE: &str = "33333333-cccc-4ccc-8ccc-333333333333";
    const OTHER: &str = "44444444-dddd-4ddd-8ddd-444444444444";
    const NEVER: &str = "55555555-eeee-4eee-8eee-555555555555";

    fn fired(uuid: &str, cleanup: bool, alerts: i64) -> Fired {
        Fired {
            signature_uuid: uuid.to_owned(),
            family: Some("yara".to_owned()),
            alert_count: alerts,
            late_only: false,
            context_only: false,
            cleanup,
            fallback_time: false,
        }
    }

    fn decided(uuids: &[&str]) -> BTreeMap<String, LastKnown> {
        uuids
            .iter()
            .map(|uuid| ((*uuid).to_owned(), LastKnown::default()))
            .collect()
    }

    fn statuses(rows: &[ResultRow]) -> BTreeMap<&str, &str> {
        rows.iter()
            .map(|row| (row.signature_uuid.as_str(), row.status.as_str()))
            .collect()
    }

    /// test_results.py's `test_each_status`, without the database.
    #[test]
    fn each_status() {
        let fired = merge_fired(
            [HUNT, YARA, NOISE, OTHER]
                .iter()
                .map(|uuid| fired(uuid, false, 1))
                .collect(),
        );
        let decisions = Decisions {
            expected: decided(&[HUNT, NEVER]),
            rejected: decided(&[YARA]),
            ignored: BTreeSet::from([NOISE.to_owned()]),
        };
        let rows = rows(
            &fired,
            &decisions,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(
            statuses(&rows),
            BTreeMap::from([
                (HUNT, "hit"),
                (YARA, "rejected"),
                (NOISE, "ignored"),
                (OTHER, "candidate"),
                (NEVER, "missing"),
            ])
        );
        assert_eq!(
            counts(rows.iter().map(|row| row.status.as_str())),
            BTreeMap::from([
                ("candidate".to_owned(), 1),
                ("hit".to_owned(), 1),
                ("ignored".to_owned(), 1),
                ("missing".to_owned(), 1),
                ("rejected".to_owned(), 1),
            ])
        );
    }

    /// test_results.py's `test_what_fired_only_in_the_cleanup` and `test_an_ignore_wins_over_an_
    /// expectation`, without the database.
    #[test]
    fn cleanup_and_ignores() {
        // fired by the test and again by its cleanup: counted by the test's alerts alone
        let fired = merge_fired(vec![
            fired(HUNT, true, 2),
            fired(HUNT, false, 1),
            fired(OTHER, true, 1),
            fired(YARA, true, 1),
        ]);
        assert_eq!((fired[HUNT].cleanup, fired[HUNT].alert_count), (false, 1));
        let decisions = Decisions {
            expected: decided(&[YARA]),
            ..Decisions::default()
        };
        let none = (BTreeMap::new(), BTreeMap::new(), BTreeSet::new());
        let result = rows(
            &fired,
            &decisions,
            &none.0,
            &none.1,
            &none.2,
            &BTreeMap::new(),
        );
        assert_eq!(
            statuses(&result),
            BTreeMap::from([(HUNT, "candidate"), (OTHER, "cleanup"), (YARA, "missing")])
        );

        // an ignored signature that fired is ignored, and one that didn't is not missing
        let fired = merge_fired(vec![super::tests::fired(HUNT, false, 1)]);
        let decisions = Decisions {
            expected: decided(&[HUNT, YARA]),
            rejected: BTreeMap::new(),
            ignored: BTreeSet::from([HUNT.to_owned(), YARA.to_owned()]),
        };
        let result = rows(
            &fired,
            &decisions,
            &none.0,
            &none.1,
            &none.2,
            &BTreeMap::new(),
        );
        assert_eq!(statuses(&result), BTreeMap::from([(HUNT, "ignored")]));
    }

    /// A signature ACE knows is named by what it knows; one it doesn't keeps what the attribution, the
    /// decision and the row before said, in that order, and has no rule hash.
    #[test]
    fn names_fall_back_to_what_was_known() {
        let fired = merge_fired(vec![fired(YARA, false, 1), fired(OTHER, false, 1)]);
        let decisions = Decisions {
            expected: BTreeMap::from([(
                HUNT.to_owned(),
                LastKnown {
                    family: Some("hunt".to_owned()),
                    name: Some("an old name".to_owned()),
                },
            )]),
            ..Decisions::default()
        };
        let info = BTreeMap::from([(
            YARA.to_owned(),
            SignatureInfo {
                uuid: YARA.to_owned(),
                name: Some("Suspicious_Macro".to_owned()),
                family: Some("yara".to_owned()),
                content_hash: Some("abc".to_owned()),
            },
        )]);
        let known = BTreeMap::from([(
            OTHER.to_owned(),
            LastKnown {
                family: Some("hunt".to_owned()),
                name: Some("kept".to_owned()),
            },
        )]);
        let suppressing = BTreeMap::from([(HUNT.to_owned(), Uuid::from_u128(7))]);
        let result = rows(
            &fired,
            &decisions,
            &info,
            &known,
            &BTreeSet::new(),
            &suppressing,
        );
        let by: BTreeMap<&str, &ResultRow> = result
            .iter()
            .map(|row| (row.signature_uuid.as_str(), row))
            .collect();
        assert_eq!(
            (by[YARA].name.as_deref(), by[YARA].content_hash.as_deref()),
            (Some("Suspicious_Macro"), Some("abc"))
        );
        // the attribution's family wins over the row's, and the row's name is all there is
        assert_eq!(
            (
                by[OTHER].family.as_deref(),
                by[OTHER].name.as_deref(),
                by[OTHER].content_hash.as_deref()
            ),
            (Some("yara"), Some("kept"), None)
        );
        assert_eq!(
            (
                by[HUNT].status,
                by[HUNT].family.as_deref(),
                by[HUNT].name.as_deref(),
                by[HUNT].suppressing_alert
            ),
            (
                ResultStatus::PossiblySuppressed,
                Some("hunt"),
                Some("an old name"),
                Some(Uuid::from_u128(7))
            )
        );
        // the hunter's record names no alert, whatever the hunt's alerts
        let recorded = rows(
            &fired,
            &decisions,
            &info,
            &known,
            &BTreeSet::from([HUNT.to_owned()]),
            &suppressing,
        );
        let hunt = recorded
            .iter()
            .find(|row| row.signature_uuid == HUNT)
            .expect("the hunt");
        assert_eq!(
            (hunt.status, hunt.suppressing_alert),
            (ResultStatus::PossiblySuppressed, None)
        );
    }

    /// The signatures that stand for many are the four built-ins and the SVS built-ins.
    #[test]
    fn untracked() {
        let untracked = untracked_signatures();
        assert_eq!(untracked.len(), 6);
        for uuid in super::super::RUN_SIGNATURES {
            assert!(untracked.iter().any(|u| u == uuid));
        }
    }

    /// ace3's `parse_precondition` and `Precondition.check`.
    #[test]
    fn preconditions() {
        let at: DateTime<Utc> = "2026-10-14T12:00:00.123456Z".parse().expect("a time");
        assert_eq!(Precondition::parse(None, None), Ok(Precondition::None));
        assert_eq!(
            Precondition::parse(None, Some(" * ")),
            Ok(Precondition::Absent)
        );
        for value in [
            "2026-10-14T12:00:00.123456Z",
            "\"2026-10-14T12:00:00.123456Z\"",
            "W/\"2026-10-14T12:00:00.123456+00:00\"",
            "2026-10-14T14:00:00.123456+02:00",
            "2026-10-14T12:00:00.123456",
            " 2026-10-14 12:00:00.123456 ",
        ] {
            assert_eq!(
                Precondition::parse(Some(value), None),
                Ok(Precondition::UpdatedAt(at)),
                "{value}"
            );
        }
        assert_eq!(
            Precondition::parse(Some("x"), Some("*")),
            Err("send If-Match or If-None-Match, not both".to_owned())
        );
        assert_eq!(
            Precondition::parse(None, Some("\"abc\"")),
            Err("If-None-Match on a write must be *".to_owned())
        );
        assert_eq!(
            Precondition::parse(Some("yesterday"), None),
            Err("If-Match must be the row's updated_at, not \"yesterday\"".to_owned())
        );

        let what = "the decision";
        assert_eq!(Precondition::None.refuses(Some(at), what), None);
        assert_eq!(Precondition::None.refuses(None, what), None);
        assert_eq!(Precondition::Absent.refuses(None, what), None);
        assert_eq!(
            Precondition::Absent.refuses(Some(at), what).as_deref(),
            Some("the decision was decided by someone else since you loaded it")
        );
        assert_eq!(Precondition::UpdatedAt(at).refuses(Some(at), what), None);
        assert_eq!(
            Precondition::UpdatedAt(at).refuses(None, what).as_deref(),
            Some("the decision was removed by someone else since you loaded it")
        );
        assert_eq!(
            Precondition::UpdatedAt(at)
                .refuses(Some(at + chrono::TimeDelta::microseconds(1)), what)
                .as_deref(),
            Some("the decision was changed by someone else since you loaded it")
        );
    }
}
