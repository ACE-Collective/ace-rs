//! Comparing a corpus scanned under two commits: ace3's `saq/svs/yara/diff.py` (ace3's `docs/SVS.md`,
//! Part 2, *Report and baseline*).
//!
//! The baseline is the set of labels. Every (sample, rule uuid) pair is decided under base and under head,
//! and only a difference (or a TP that misses on both) is listed. A **match** means the rule would make a
//! detection: it matched, it's enabled, its modifiers include neither `qa` nor `no_alert`, and it isn't
//! tagged `whitelisted`, decided by `ace_yara::detection_blocker`, which the YARA module calls too (ace3
//! 91211a66). The raw match is kept beside it, so a rule that still matches
//! but was switched to QA mode reads as what it is.
//!
//! | own label | base | head | category |
//! |---|---|---|---|
//! | tp | match | miss | regression (regression_unconfirmed for an inherited_multi label) |
//! | tp | miss | match | recovered |
//! | tp | miss | miss | already_broken |
//! | fp | match | miss | improvement |
//! | fp | miss | match | new_fp |
//! | fp | match | match | known_fp (counted) |
//! | none / conflicted | differs | differs | unlabeled_change |
//!
//! A pair that isn't a sample is a rule matching a file captured for another rule. A new match there is
//! judged by the labels the file has: all fp makes it new_fp_other_rule, any tp new_match_real_hit
//! (informational), anything else unlabeled_change. A rule's own label always wins over the file's.
//!
//! Before any of that: a retired pair is only counted; a rule in neither commit belongs to another
//! repository and is dropped; a rule whose uuid two rules of head share is not_testable; a sample whose rule
//! head no longer has at all is rule_removed; and a side that couldn't scan the file in the rule's namespace
//! (an error) makes it scan_error, never a miss.

use std::collections::{BTreeMap, BTreeSet};

use ace_yara::{DetectionBlocker, Meta, detection_blocker};
use serde::{Deserialize, Serialize};

use super::corpus::Corpus;

macro_rules! categories {
    ($($variant:ident => $text:literal,)+) => {
        /// What a change does to one pair.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum Category {
            $($variant,)+
        }

        impl Category {
            /// Every category, in the order of the report's bands.
            pub const ALL: [Category; 15] = [$(Category::$variant,)+];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(Category::$variant => $text,)+
                }
            }

            pub fn parse(text: &str) -> Option<Category> {
                Self::ALL.into_iter().find(|c| c.as_str() == text)
            }
        }
    };
}

categories! {
    Regression => "regression",
    RegressionUnconfirmed => "regression_unconfirmed",
    NewFp => "new_fp",
    NewFpOtherRule => "new_fp_other_rule",
    RuleRemoved => "rule_removed",
    ScanError => "scan_error",
    Recovered => "recovered",
    Improvement => "improvement",
    AlreadyBroken => "already_broken",
    NewMatchRealHit => "new_match_real_hit",
    UnlabeledChange => "unlabeled_change",
    KnownFp => "known_fp",
    Retired => "retired",
    NotTestable => "not_testable",
    Unchanged => "unchanged",
}

impl Category {
    /// Counted, never listed.
    pub fn counted_only(self) -> bool {
        matches!(
            self,
            Category::KnownFp | Category::Retired | Category::NotTestable | Category::Unchanged
        )
    }

    /// The categories a report lists rows for, in its bands' order.
    pub fn listed() -> impl Iterator<Item = Category> {
        Category::ALL.into_iter().filter(|c| !c.counted_only())
    }
}

/// What one commit did to a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Match,
    Miss,
    Error,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Match => "match",
            Outcome::Miss => "miss",
            Outcome::Error => "error",
        }
    }

    pub fn parse(text: &str) -> Option<Outcome> {
        [Outcome::Match, Outcome::Miss, Outcome::Error]
            .into_iter()
            .find(|o| o.as_str() == text)
    }
}

/// A rule a commit loaded.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleInfo {
    pub uuid: String,
    pub name: String,
    pub namespace: String,
    /// Relative to the repository's top.
    pub file: String,
    pub meta: Meta,
}

/// One match of a replayed unit: `(namespace, rule name, meta, YARA tags)`.
pub type SideMatch = (String, String, Meta, Vec<String>);

/// What one commit's rules did over the corpus, as the diff needs it.
#[derive(Debug, Clone, Default)]
pub struct SideScan {
    /// Rules in files that compiled, by uuid (two or more when the uuid is shared).
    pub loaded: BTreeMap<String, Vec<RuleInfo>>,
    /// The uuids of every rule in the commit's source, compiled or not.
    pub source_uuids: BTreeSet<String>,
    /// Unit id to every match.
    pub matches: BTreeMap<u64, Vec<SideMatch>>,
    /// Unit id to the namespaces whose scan of the unit failed.
    pub errors: BTreeMap<u64, BTreeSet<String>>,
}

impl SideScan {
    pub fn knows(&self, rule_uuid: &str) -> bool {
        self.source_uuids.contains(rule_uuid) || self.loaded.contains_key(rule_uuid)
    }
}

/// One pair the report lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultRow {
    pub sha256: String,
    pub rule_uuid: String,
    pub rule_name: String,
    pub namespace: Option<String>,
    pub label: Option<String>,
    pub label_source: Option<String>,
    pub base: Outcome,
    pub head: Outcome,
    pub raw_base: bool,
    pub raw_head: bool,
    pub category: Category,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct PairState {
    raw: bool,
    detects: bool,
    blocker: Option<&'static str>,
}

fn side_pairs(corpus: &Corpus, side: &SideScan) -> BTreeMap<(String, String), PairState> {
    let units: BTreeMap<u64, &str> = corpus
        .units
        .iter()
        .filter(|u| u.path.is_some())
        .map(|u| (u.id, u.sha256.as_str()))
        .collect();
    let mut result: BTreeMap<(String, String), PairState> = BTreeMap::new();
    for (unit_id, matches) in &side.matches {
        let Some(sha256) = units.get(unit_id) else {
            continue;
        };
        for (_, _, meta, tags) in matches {
            let Some(rule_uuid) = meta.uuid().filter(|u| !u.is_empty()) else {
                continue;
            };
            let state = result.entry(((*sha256).to_owned(), rule_uuid)).or_default();
            state.raw = true;
            match detection_blocker(meta, tags).map(DetectionBlocker::reason) {
                None => state.detects = true,
                Some(blocker) => state.blocker = Some(blocker),
            }
        }
    }
    result
}

/// sha256 to the namespaces in which a scan of one of its units failed.
fn errored(corpus: &Corpus, side: &SideScan) -> BTreeMap<String, BTreeSet<String>> {
    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for unit in corpus.units.iter().filter(|u| u.path.is_some()) {
        if let Some(namespaces) = side.errors.get(&unit.id) {
            result
                .entry(unit.sha256.clone())
                .or_default()
                .extend(namespaces.iter().cloned());
        }
    }
    result
}

fn outcome(
    pair: &PairState,
    rule_uuid: &str,
    sha256: &str,
    side: &SideScan,
    errored: &BTreeMap<String, BTreeSet<String>>,
) -> Outcome {
    if pair.detects {
        return Outcome::Match;
    }
    let failed = errored.get(sha256);
    let in_failed_namespace = side
        .loaded
        .get(rule_uuid)
        .into_iter()
        .flatten()
        .any(|rule| failed.is_some_and(|f| f.contains(&rule.namespace)));
    if in_failed_namespace {
        Outcome::Error
    } else {
        Outcome::Miss
    }
}

fn note(
    rule_uuid: &str,
    base: &PairState,
    head: &PairState,
    head_scan: &SideScan,
) -> Option<String> {
    let mut notes = Vec::new();
    if head.raw && !head.detects {
        notes.push(format!(
            "matches in head but makes no detection ({})",
            head.blocker.unwrap_or_default()
        ));
    }
    if base.raw && !base.detects {
        notes.push(format!(
            "matches in base but makes no detection ({})",
            base.blocker.unwrap_or_default()
        ));
    }
    if head_scan.source_uuids.contains(rule_uuid) && !head_scan.loaded.contains_key(rule_uuid) {
        notes.push("its file does not compile in head".to_owned());
    }
    (!notes.is_empty()).then(|| notes.join("; "))
}

/// The category of one pair whose rule both commits know and neither scan failed on.
pub fn categorize(
    own_label: Option<&str>,
    label_source: Option<&str>,
    is_sample: bool,
    file_labels: &[Option<&str>],
    base: Outcome,
    head: Outcome,
) -> Category {
    let (b, h) = (base == Outcome::Match, head == Outcome::Match);
    if is_sample && own_label == Some("tp") {
        return match (b, h) {
            (true, false) if label_source == Some("inherited_multi") => {
                Category::RegressionUnconfirmed
            }
            (true, false) => Category::Regression,
            (false, true) => Category::Recovered,
            (false, false) => Category::AlreadyBroken,
            (true, true) => Category::Unchanged,
        };
    }
    if is_sample && own_label == Some("fp") {
        return match (b, h) {
            (true, false) => Category::Improvement,
            (false, true) => Category::NewFp,
            (true, true) => Category::KnownFp,
            (false, false) => Category::Unchanged,
        };
    }
    if b == h {
        return Category::Unchanged;
    }
    if !is_sample && h {
        if !file_labels.is_empty() && file_labels.iter().all(|l| *l == Some("fp")) {
            return Category::NewFpOtherRule;
        }
        if file_labels.contains(&Some("tp")) {
            return Category::NewMatchRealHit;
        }
    }
    Category::UnlabeledChange
}

/// The uuids more than one rule of the commit carries: among its loaded rules, or in its source.
pub fn duplicate_uuids(
    side: &SideScan,
    source_counts: &BTreeMap<String, usize>,
) -> BTreeSet<String> {
    side.loaded
        .iter()
        .filter(|(_, rules)| rules.len() > 1)
        .map(|(uuid, _)| uuid.clone())
        .chain(
            source_counts
                .iter()
                .filter(|(_, count)| **count > 1)
                .map(|(uuid, _)| uuid.clone()),
        )
        .collect()
}

/// Every listed pair as a row (counted-only categories are counted only), and every category's count.
pub fn diff(
    corpus: &Corpus,
    base: &SideScan,
    head: &SideScan,
    retired: &BTreeSet<(String, String)>,
    not_testable: &BTreeSet<String>,
) -> (Vec<ResultRow>, BTreeMap<Category, u64>) {
    let base_pairs = side_pairs(corpus, base);
    let head_pairs = side_pairs(corpus, head);
    let base_errors = errored(corpus, base);
    let head_errors = errored(corpus, head);
    let replayed = corpus.replayed_sha256s();
    let mut file_labels: BTreeMap<&str, Vec<Option<&str>>> = BTreeMap::new();
    for ((sha256, _), sample) in &corpus.samples {
        file_labels
            .entry(sha256.as_str())
            .or_default()
            .push(sample.label.as_deref());
    }

    let mut pairs: BTreeSet<(String, String)> = corpus
        .samples
        .keys()
        .filter(|(sha256, _)| replayed.contains(sha256))
        .cloned()
        .collect();
    pairs.extend(base_pairs.keys().cloned());
    pairs.extend(head_pairs.keys().cloned());

    let mut rows = Vec::new();
    let mut counts: BTreeMap<Category, u64> = BTreeMap::new();
    let none = PairState::default();
    for (sha256, rule_uuid) in pairs {
        if !(base.knows(&rule_uuid) || head.knows(&rule_uuid)) {
            // a rule of another repository
            continue;
        }
        let sample = corpus.samples.get(&(sha256.clone(), rule_uuid.clone()));
        if sample.is_none() && !head.knows(&rule_uuid) {
            // a rule head removed, matching a file it was never captured for
            continue;
        }
        let key = (sha256.clone(), rule_uuid.clone());
        let base_pair = base_pairs.get(&key).unwrap_or(&none);
        let head_pair = head_pairs.get(&key).unwrap_or(&none);
        let base_outcome = outcome(base_pair, &rule_uuid, &sha256, base, &base_errors);
        let head_outcome = outcome(head_pair, &rule_uuid, &sha256, head, &head_errors);

        let category = if retired.contains(&key) {
            Category::Retired
        } else if not_testable.contains(&rule_uuid) {
            Category::NotTestable
        } else if !head.knows(&rule_uuid) {
            Category::RuleRemoved
        } else if base_outcome == Outcome::Error || head_outcome == Outcome::Error {
            Category::ScanError
        } else {
            categorize(
                sample.and_then(|s| s.label.as_deref()),
                sample.and_then(|s| s.label_source.as_deref()),
                sample.is_some(),
                file_labels
                    .get(sha256.as_str())
                    .map_or(&[][..], Vec::as_slice),
                base_outcome,
                head_outcome,
            )
        };

        *counts.entry(category).or_default() += 1;
        if category.counted_only() {
            continue;
        }
        let rules = head
            .loaded
            .get(&rule_uuid)
            .or_else(|| base.loaded.get(&rule_uuid));
        let first = rules.and_then(|r| r.first());
        rows.push(ResultRow {
            rule_name: first
                .map(|r| r.name.clone())
                .or_else(|| sample.map(|s| s.rule_name.clone()))
                .unwrap_or_default(),
            namespace: first.map(|r| r.namespace.clone()),
            label: sample.and_then(|s| s.label.clone()),
            label_source: sample.and_then(|s| s.label_source.clone()),
            base: base_outcome,
            head: head_outcome,
            raw_base: base_pair.raw,
            raw_head: head_pair.raw,
            category,
            note: note(&rule_uuid, base_pair, head_pair, head),
            sha256,
            rule_uuid,
        });
    }
    (rows, counts)
}

#[cfg(test)]
mod tests {
    //! test_diff.py's cases.

    use ace_yara::MetaValue;

    use super::*;
    use crate::svs::yara::corpus::{Sample, Unit};

    use Outcome::{Match as MATCH, Miss as MISS};

    const EXPLICIT: &str = "explicit";
    const SINGLE: &str = "inherited_single";
    const MULTI: &str = "inherited_multi";

    fn a() -> String {
        "a".repeat(64)
    }
    fn b() -> String {
        "b".repeat(64)
    }
    fn c() -> String {
        "c".repeat(64)
    }

    /// test_diff.py's `test_a_sample_is_judged_by_its_own_label`.
    #[test]
    fn a_sample_is_judged_by_its_own_label() {
        let cases = [
            (Some("tp"), Some(SINGLE), MATCH, MISS, Category::Regression),
            (
                Some("tp"),
                Some(EXPLICIT),
                MATCH,
                MISS,
                Category::Regression,
            ),
            (
                Some("tp"),
                Some(MULTI),
                MATCH,
                MISS,
                Category::RegressionUnconfirmed,
            ),
            (Some("tp"), Some(SINGLE), MISS, MATCH, Category::Recovered),
            (
                Some("tp"),
                Some(SINGLE),
                MISS,
                MISS,
                Category::AlreadyBroken,
            ),
            (Some("tp"), Some(SINGLE), MATCH, MATCH, Category::Unchanged),
            (Some("fp"), Some(SINGLE), MATCH, MISS, Category::Improvement),
            (Some("fp"), Some(SINGLE), MISS, MATCH, Category::NewFp),
            (Some("fp"), Some(SINGLE), MATCH, MATCH, Category::KnownFp),
            (Some("fp"), Some(SINGLE), MISS, MISS, Category::Unchanged),
            (
                Some("conflicted"),
                Some(EXPLICIT),
                MATCH,
                MISS,
                Category::UnlabeledChange,
            ),
            (None, None, MISS, MATCH, Category::UnlabeledChange),
            (None, None, MATCH, MATCH, Category::Unchanged),
        ];
        for (label, source, base, head, expected) in cases {
            // the other samples of the file never change it
            let file_labels = [Some("fp"), Some("tp"), label];
            assert_eq!(
                categorize(label, source, true, &file_labels, base, head),
                expected,
                "{label:?} {source:?} {base:?} {head:?}"
            );
        }
    }

    /// test_diff.py's `test_another_rule_is_judged_by_the_files_labels`.
    #[test]
    fn another_rule_is_judged_by_the_files_labels() {
        let cases: [(&[Option<&str>], Outcome, Outcome, Category); 7] = [
            (
                &[Some("fp"), Some("fp")],
                MISS,
                MATCH,
                Category::NewFpOtherRule,
            ),
            (
                &[Some("fp"), Some("tp")],
                MISS,
                MATCH,
                Category::NewMatchRealHit,
            ),
            (&[Some("fp"), None], MISS, MATCH, Category::UnlabeledChange),
            (
                &[Some("conflicted")],
                MISS,
                MATCH,
                Category::UnlabeledChange,
            ),
            (&[Some("fp")], MATCH, MISS, Category::UnlabeledChange),
            (&[Some("fp")], MATCH, MATCH, Category::Unchanged),
            (&[Some("tp")], MISS, MISS, Category::Unchanged),
        ];
        for (labels, base, head, expected) in cases {
            assert_eq!(categorize(None, None, false, labels, base, head), expected);
        }
    }

    /// A sample's (sha256, rule uuid), and its (label, source).
    type SampleSpec<'a> = ((String, &'a str), (Option<&'a str>, Option<&'a str>));

    /// One replayed unit per file.
    fn corpus(samples: &[SampleSpec<'_>]) -> Corpus {
        let mut corpus = Corpus::default();
        let sha256s: BTreeSet<&String> = samples.iter().map(|((s, _), _)| s).collect();
        for (index, sha256) in sha256s.into_iter().enumerate() {
            corpus.units.push(Unit {
                id: index as u64,
                sha256: sha256.clone(),
                file_path: format!("{index}.bin"),
                meta_tags: vec![],
                path: Some(format!("/work/u/{index}/files/{index}.bin").into()),
                truncated: false,
            });
        }
        for ((sha256, rule_uuid), (label, source)) in samples {
            corpus.samples.insert(
                (sha256.clone(), (*rule_uuid).to_owned()),
                Sample {
                    sha256: sha256.clone(),
                    rule_uuid: (*rule_uuid).to_owned(),
                    rule_name: format!("rule_{rule_uuid}"),
                    label: label.map(str::to_owned),
                    label_source: source.map(str::to_owned),
                },
            );
        }
        corpus
    }

    fn rule_meta(uuid: &str, extra: &[(&str, MetaValue)]) -> Meta {
        Meta::from_pairs(
            std::iter::once(("uuid".to_owned(), MetaValue::Str(uuid.to_owned())))
                .chain(extra.iter().map(|(k, v)| ((*k).to_owned(), v.clone()))),
        )
    }

    /// `rules`: uuid to extra meta, each in namespace ns. `matches`: sha256 to the uuids that matched it.
    fn side(
        corpus: &Corpus,
        rules: &[(&str, Vec<(&str, MetaValue)>)],
        matches: &[(String, &[&str])],
        errors: &[(String, &[&str])],
        source: Option<&[&str]>,
    ) -> SideScan {
        let unit_of: BTreeMap<&String, u64> =
            corpus.units.iter().map(|u| (&u.sha256, u.id)).collect();
        let metas: BTreeMap<&str, Meta> = rules
            .iter()
            .map(|(u, extra)| (*u, rule_meta(u, extra)))
            .collect();
        let mut scan = SideScan {
            loaded: rules
                .iter()
                .map(|(u, _)| {
                    (
                        (*u).to_owned(),
                        vec![RuleInfo {
                            uuid: (*u).to_owned(),
                            name: format!("rule_{u}"),
                            namespace: "ns".to_owned(),
                            file: "yara/ns/r.yar".to_owned(),
                            meta: metas[u].clone(),
                        }],
                    )
                })
                .collect(),
            source_uuids: match source {
                Some(source) => source.iter().map(|s| (*s).to_owned()).collect(),
                None => rules.iter().map(|(u, _)| (*u).to_owned()).collect(),
            },
            ..SideScan::default()
        };
        for (sha256, uuids) in matches {
            scan.matches.insert(
                unit_of[sha256],
                uuids
                    .iter()
                    .map(|u| {
                        let meta = metas.get(u).cloned().unwrap_or_else(|| rule_meta(u, &[]));
                        ("ns".to_owned(), format!("rule_{u}"), meta, Vec::new())
                    })
                    .collect(),
            );
        }
        for (sha256, namespaces) in errors {
            scan.errors.insert(
                unit_of[sha256],
                namespaces.iter().map(|n| (*n).to_owned()).collect(),
            );
        }
        scan
    }

    fn by_pair(rows: &[ResultRow]) -> BTreeMap<(String, String), &ResultRow> {
        rows.iter()
            .map(|r| ((r.sha256.clone(), r.rule_uuid.clone()), r))
            .collect()
    }

    fn key(sha256: String, rule: &str) -> (String, String) {
        (sha256, rule.to_owned())
    }

    /// test_diff.py's `test_diff_lists_changes_and_counts_the_rest`.
    #[test]
    fn diff_lists_changes_and_counts_the_rest() {
        let corpus = corpus(&[
            ((a(), "r1"), (Some("tp"), Some(SINGLE))),
            ((b(), "r2"), (Some("fp"), Some(SINGLE))),
            ((c(), "r3"), (Some("fp"), Some(SINGLE))),
        ]);
        let base = side(
            &corpus,
            &[("r1", vec![]), ("r2", vec![]), ("r3", vec![])],
            &[(a(), &["r1"]), (c(), &["r3"])],
            &[],
            None,
        );
        let head = side(
            &corpus,
            &[
                ("r1", vec![]),
                ("r2", vec![]),
                ("r3", vec![]),
                ("new", vec![]),
            ],
            &[(b(), &["r2", "new"]), (c(), &["r3"]), (a(), &["new"])],
            &[],
            None,
        );
        let (rows, counts) = diff(&corpus, &base, &head, &BTreeSet::new(), &BTreeSet::new());
        let pairs = by_pair(&rows);
        assert_eq!(pairs[&key(a(), "r1")].category, Category::Regression);
        assert_eq!(pairs[&key(b(), "r2")].category, Category::NewFp);
        assert_eq!(pairs[&key(b(), "new")].category, Category::NewFpOtherRule);
        assert_eq!(pairs[&key(a(), "new")].category, Category::NewMatchRealHit);
        assert!(!pairs.contains_key(&key(c(), "r3")));
        assert_eq!(counts[&Category::KnownFp], 1);
        assert_eq!(pairs[&key(a(), "r1")].label.as_deref(), Some("tp"));
        assert_eq!(pairs[&key(a(), "new")].label, None);
    }

    /// test_diff.py's `test_a_rule_that_no_longer_makes_a_detection_regresses_with_a_note`.
    #[test]
    fn a_rule_that_no_longer_makes_a_detection_regresses_with_a_note() {
        let corpus = corpus(&[((a(), "r1"), (Some("tp"), Some(SINGLE)))]);
        let base = side(&corpus, &[("r1", vec![])], &[(a(), &["r1"])], &[], None);
        let head = side(
            &corpus,
            &[("r1", vec![("modifiers", MetaValue::Str("qa".into()))])],
            &[(a(), &["r1"])],
            &[],
            None,
        );
        let (rows, _) = diff(&corpus, &base, &head, &BTreeSet::new(), &BTreeSet::new());
        let [row] = &rows[..] else {
            panic!("one row: {rows:?}")
        };
        assert_eq!(row.category, Category::Regression);
        assert_eq!((row.raw_base, row.raw_head), (true, true));
        assert_eq!((row.base, row.head), (MATCH, MISS));
        assert!(row.note.as_deref().unwrap().contains("QA mode"));
    }

    /// ace3 91211a66: a rule whose head is tagged `whitelisted` makes no detection there, as the YARA
    /// module decides, so its TP sample regresses, with the reason in the note.
    #[test]
    fn a_rule_tagged_whitelisted_makes_no_detection() {
        let corpus = corpus(&[((a(), "r1"), (Some("tp"), Some(SINGLE)))]);
        let base = side(&corpus, &[("r1", vec![])], &[(a(), &["r1"])], &[], None);
        let mut head = side(&corpus, &[("r1", vec![])], &[(a(), &["r1"])], &[], None);
        for matches in head.matches.values_mut() {
            for (_, _, _, tags) in matches {
                tags.push("whitelisted".to_owned());
            }
        }
        let (rows, _) = diff(&corpus, &base, &head, &BTreeSet::new(), &BTreeSet::new());
        let [row] = &rows[..] else {
            panic!("one row: {rows:?}")
        };
        assert_eq!(row.category, Category::Regression);
        assert_eq!((row.raw_base, row.raw_head), (true, true));
        assert_eq!((row.base, row.head), (MATCH, MISS));
        assert!(row.note.as_deref().unwrap().contains("tagged whitelisted"));
    }

    /// test_diff.py's `test_retired_not_testable_removed_and_foreign_rules`.
    #[test]
    fn retired_not_testable_removed_and_foreign_rules() {
        let corpus = corpus(&[
            ((a(), "retired"), (Some("tp"), Some(SINGLE))),
            ((a(), "shared"), (Some("tp"), Some(SINGLE))),
            ((a(), "removed"), (Some("tp"), Some(SINGLE))),
            ((a(), "foreign"), (Some("tp"), Some(SINGLE))),
            ((b(), "dropped"), (Some("tp"), Some(SINGLE))),
        ]);
        let base = side(
            &corpus,
            &[
                ("retired", vec![]),
                ("shared", vec![]),
                ("removed", vec![]),
                ("dropped", vec![]),
            ],
            &[
                (a(), &["retired", "shared", "removed"]),
                (b(), &["dropped"]),
            ],
            &[],
            None,
        );
        // "dropped" is still in head's source, but its file doesn't compile
        let head = side(
            &corpus,
            &[("shared", vec![])],
            &[],
            &[],
            Some(&["retired", "shared", "dropped"]),
        );
        let retired = BTreeSet::from([key(a(), "retired")]);
        let not_testable = BTreeSet::from(["shared".to_owned()]);
        let (rows, counts) = diff(&corpus, &base, &head, &retired, &not_testable);
        let pairs = by_pair(&rows);
        assert_eq!(counts[&Category::Retired], 1);
        assert!(!pairs.contains_key(&key(a(), "retired")));
        assert_eq!(counts[&Category::NotTestable], 1);
        assert!(!pairs.contains_key(&key(a(), "shared")));
        assert_eq!(pairs[&key(a(), "removed")].category, Category::RuleRemoved);
        assert!(!pairs.contains_key(&key(a(), "foreign")));
        assert_eq!(counts.values().sum::<u64>(), 4);
        assert_eq!(pairs[&key(b(), "dropped")].category, Category::Regression);
        assert!(
            pairs[&key(b(), "dropped")]
                .note
                .as_deref()
                .unwrap()
                .contains("does not compile in head")
        );
    }

    /// test_diff.py's `test_a_scan_that_failed_is_never_a_miss`.
    #[test]
    fn a_scan_that_failed_is_never_a_miss() {
        let corpus = corpus(&[
            ((a(), "r1"), (Some("tp"), Some(SINGLE))),
            ((b(), "r1"), (Some("tp"), Some(SINGLE))),
        ]);
        let base = side(
            &corpus,
            &[("r1", vec![])],
            &[(a(), &["r1"]), (b(), &["r1"])],
            &[],
            None,
        );
        let head = side(
            &corpus,
            &[("r1", vec![])],
            &[(b(), &["r1"])],
            &[(a(), &["ns"]), (b(), &["ns"])],
            None,
        );
        let (rows, _) = diff(&corpus, &base, &head, &BTreeSet::new(), &BTreeSet::new());
        let pairs = by_pair(&rows);
        assert_eq!(pairs[&key(a(), "r1")].category, Category::ScanError);
        assert_eq!(pairs[&key(a(), "r1")].head, Outcome::Error);
        // a match found despite the error elsewhere still counts
        assert!(!pairs.contains_key(&key(b(), "r1")));

        // an error in another namespace doesn't touch the rule
        let head = side(
            &corpus,
            &[("r1", vec![])],
            &[(b(), &["r1"])],
            &[(a(), &["other"])],
            None,
        );
        let (rows, _) = diff(&corpus, &base, &head, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(
            by_pair(&rows)[&key(a(), "r1")].category,
            Category::Regression
        );
    }

    /// test_diff.py's `test_a_file_matches_if_any_of_its_scans_matches`.
    #[test]
    fn a_file_matches_if_any_of_its_scans_matches() {
        let mut corpus = corpus(&[((a(), "r1"), (Some("tp"), Some(SINGLE)))]);
        corpus.units.push(Unit {
            id: 1,
            sha256: a(),
            file_path: "renamed.txt".to_owned(),
            meta_tags: vec![],
            path: Some("/work/u/1/files/renamed.txt".into()),
            truncated: false,
        });
        let base = side(&corpus, &[("r1", vec![])], &[(a(), &["r1"])], &[], None);
        let mut head = side(&corpus, &[("r1", vec![])], &[], &[], None);
        head.matches.insert(
            1,
            vec![(
                "ns".to_owned(),
                "rule_r1".to_owned(),
                rule_meta("r1", &[]),
                Vec::new(),
            )],
        );
        let (rows, counts) = diff(&corpus, &base, &head, &BTreeSet::new(), &BTreeSet::new());
        assert!(rows.is_empty());
        assert_eq!(counts[&Category::Unchanged], 1);
    }

    /// test_diff.py's `test_duplicate_uuids`.
    #[test]
    fn duplicate_uuids_of_loaded_rules_and_source() {
        let rule = |name: &str| RuleInfo {
            uuid: "x".to_owned(),
            name: name.to_owned(),
            namespace: "ns".to_owned(),
            file: "f".to_owned(),
            meta: Meta::default(),
        };
        let scan = SideScan {
            loaded: BTreeMap::from([
                ("x".to_owned(), vec![rule("one"), rule("two")]),
                ("y".to_owned(), vec![]),
            ]),
            ..SideScan::default()
        };
        let counts = BTreeMap::from([("z".to_owned(), 2), ("y".to_owned(), 1)]);
        assert_eq!(
            duplicate_uuids(&scan, &counts),
            BTreeSet::from(["x".to_owned(), "z".to_owned()])
        );
    }
}
