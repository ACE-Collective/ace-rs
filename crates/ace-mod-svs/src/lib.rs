//! SVS's sample capture, a port of ace3's `YaraSampleCapture` (`saq/modules/svs.py`), with the
//! candidates of `saq/svs/capture.py` (PLAN.md 7.10 batch 2).
//!
//! ace3 runs it in dispositioned mode, in post-analysis of every pass: for an alert whose disposition
//! classifies `tp` or `fp` and that no test run still under review holds, it keeps every file a YARA rule
//! with a uuid matched as an SVS sample. Here it's a lookup module on each file of a dispositioned root,
//! which the core queues again on each disposition, as ace3 reruns it on each dispositioned pass
//! (`Orchestrator::stop_for_disposition`). It reads what ace3 reads of its database with
//! `svs-capture-state`, finds its candidates in the detections on the file and the YARA result, which
//! comes with the task (`Module::DEPENDS_ON`), and hands them to the core as its `svs-capture` write, which
//! lands with its end (`crates/ace-core/src/reads.md`, `ace_core::svs::samples`). It stores no result, as
//! ace3's creates no analysis and changes nothing in the tree.
//!
//! What differs from ace3: a file is one observable per sha256 here, so the same bytes under two names
//! are one task and one candidate per rule, as ace3's "first file observable with a given sha256 wins";
//! the path is the one the task is for. A rule without a uuid shares the built-in fallback signature, and
//! one with a uuid longer than 36 characters doesn't fit ace3's column: neither is captured, as in ace3.

use std::collections::BTreeSet;
use std::time::Duration;

use ace_results::types::svs::YaraSampleCaptureAnalysis;
use ace_results::types::yara::YaraScanResults;
use ace_results::{AnalysisType, ObservableKind};
use ace_sdk::reads::{
    Read, ReadKind, SvsCaptureState, SvsCaptureStateAnswer, SvsCaptureStateRequest, SvsDetection,
};
use ace_sdk::writes::{SvsCapture, SvsCaptureCandidate, SvsCaptures, Write, WriteKind};
use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use serde_json::Value;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<YaraSampleCapture>();

/// ace3's `SIGNATURE_UUID_MAX_LENGTH`.
pub const MAX_RULE_UUID: usize = 36;
/// ace3's `SIGNATURE_VERSION_UNKNOWN`.
const SIGNATURE_VERSION_UNKNOWN: &str = "unknown";
/// The keys a YARA detection's details have: ace3's `YARA_DETECTION_DETAIL_KEYS`. A detection from
/// before the details existed (ace3's D-3) has none of them.
const YARA_DETECTION_DETAIL_KEYS: [&str; 4] = ["sha256", "rule", "namespace", "rule_uuid"];

/// SVS's sample capture.
pub struct YaraSampleCapture;

impl Module for YaraSampleCapture {
    const NAME: &'static str = "svs_yara_sample_capture";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    /// The YARA result's scan results, whose entry for a rule is a capture's match record. The
    /// dispositioned mode doesn't run the YARA module, so this never holds the capture back.
    const DEPENDS_ON: &'static [&'static str] = &[YaraScanResults::MODULE];
    const READS: &'static [Read] = &[SvsCaptureState::READ];
    const WRITES: &'static [Write] = &[SvsCapture::WRITE];
    const STORES_RESULTS: bool = false;
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(60),
        ..Resources::DEFAULT
    };
    type Output = YaraSampleCaptureAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(YaraSampleCapture)
    }
}

impl Lookup for YaraSampleCapture {
    const TCP_PORTS: &'static [u16] = &[];

    async fn analyze(
        &self,
        ctx: &TaskContext<()>,
    ) -> Result<Outcome<YaraSampleCaptureAnalysis>, ModuleError> {
        let state = ctx
            .read::<SvsCaptureState>(&SvsCaptureStateRequest::default())
            .await?;
        if !state.alert {
            return Ok(Outcome::Skipped(
                "not an alert: nothing to capture".to_owned(),
            ));
        }
        // an unclassified alert, or one of a test run that isn't reviewed, teaches nothing (ace3's
        // docs/SVS.md, Part 2)
        if !state.classified || state.unreviewed_run {
            return Ok(Outcome::Skipped(
                "the alert's disposition doesn't grade its files".to_owned(),
            ));
        }
        if state.detections_truncated {
            // ace3 reads every detection of the alert; past the read's bound some aren't seen
            tracing::warn!(
                sha256 = %ctx.observable().value,
                "the file has more detections than the read answers; only the first are captured"
            );
        }
        let scan = ctx.dependency_result::<YaraScanResults>()?;
        let observable = ctx.observable();
        let path = observable.path.as_ref().map(|p| p.as_str().to_owned());
        let candidates = candidates(&observable.value, path.as_deref(), &state, scan.as_ref());
        let wanted: Vec<SvsCaptureCandidate> = candidates
            .into_iter()
            .filter(|candidate| !captured(&state, candidate))
            .collect();
        if state.deleted {
            tracing::info!(
                sha256 = %observable.value,
                "svs sample {} was deleted from svs; it is not captured again",
                observable.value
            );
            return Ok(Outcome::Skipped("the file was deleted from svs".to_owned()));
        }
        if wanted.is_empty() {
            return Ok(Outcome::Skipped("nothing to capture".to_owned()));
        }
        let count = wanted.len();
        ctx.write::<SvsCapture>(&SvsCaptures { captures: wanted })?;
        Ok(Outcome::Skipped(format!("{count} svs captures")))
    }
}

/// Whether SVS already has the candidate as it will: stored, and with its match record or none to add.
/// The core checks again as it lands; this only saves a write.
fn captured(state: &SvsCaptureStateAnswer, candidate: &SvsCaptureCandidate) -> bool {
    state.captures.iter().any(|capture| {
        capture.rule_uuid == candidate.rule_uuid
            && capture.state == "stored"
            && (capture.missing_reason.as_deref() != Some("match_record")
                || candidate.match_record.is_none())
    })
}

/// Whether a detection is one the YARA module put on a file, with its structured details: ace3's
/// `is_yara_detection`.
pub fn is_yara_detection(detection: &SvsDetection) -> bool {
    detection
        .details
        .as_ref()
        .and_then(Value::as_object)
        .is_some_and(|details| {
            YARA_DETECTION_DETAIL_KEYS
                .iter()
                .all(|key| details.contains_key(*key))
        })
}

/// Every (file sha256, rule uuid) pair a YARA detection on the file names, one candidate each: ace3's
/// `candidates_from_root` over one file. `sha256` is the file's, `task_path` the path its task is for,
/// and `scan` its YARA result, whose entry for the rule is the match record.
pub fn candidates(
    sha256: &str,
    task_path: Option<&str>,
    state: &SvsCaptureStateAnswer,
    scan: Option<&YaraScanResults>,
) -> Vec<SvsCaptureCandidate> {
    let path = state
        .paths
        .iter()
        .find(|p| Some(p.path.as_str()) == task_path)
        .or_else(|| state.paths.first());
    let Some(path) = path else {
        tracing::warn!(
            sha256,
            "the file has no path in its root; nothing to capture"
        );
        return Vec::new();
    };
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut candidates = Vec::new();
    for detection in &state.detections {
        if !is_yara_detection(detection) {
            continue;
        }
        let Some(details) = detection.details.as_ref() else {
            continue;
        };
        let rule = text(&details["rule"]);
        let rule_uuid = match details["rule_uuid"].as_str() {
            Some(uuid) if !uuid.is_empty() => uuid.to_owned(),
            _ => {
                tracing::debug!(
                    rule,
                    "yara rule {rule} has no uuid; its matches are not captured"
                );
                continue;
            }
        };
        if rule_uuid.chars().count() > MAX_RULE_UUID {
            tracing::warn!(
                rule,
                "yara rule {rule} has a uuid longer than {MAX_RULE_UUID} characters; its matches are not captured"
            );
            continue;
        }
        let detected = text(&details["sha256"]).to_lowercase();
        if detected != sha256 {
            // the YARA module names the file it's on
            continue;
        }
        if !seen.insert((detected.clone(), rule_uuid.clone())) {
            continue;
        }
        candidates.push(SvsCaptureCandidate {
            sha256: detected,
            match_record: match_record(scan, &rule, &rule_uuid),
            rule_uuid,
            rule_name: rule,
            namespace: details["namespace"].as_str().map(str::to_owned),
            signature_version: detection
                .signature_version
                .clone()
                .unwrap_or_else(|| SIGNATURE_VERSION_UNKNOWN.to_owned()),
            file_path: path.path.clone(),
            yara_meta_tags: path.yara_meta.clone(),
        });
    }
    candidates
}

fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// The file's scan result for the rule, as its YARA result has it, or None when the result is gone:
/// ace3's `_match_record`.
fn match_record(scan: Option<&YaraScanResults>, rule: &str, rule_uuid: &str) -> Option<Value> {
    let entry = scan?.scan_results.iter().find(|entry| {
        entry.rule == rule && entry.meta.get("uuid").and_then(Value::as_str) == Some(rule_uuid)
    })?;
    serde_json::to_value(entry).ok()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ace_results::types::yara::ScanResult;
    use ace_sdk::Observable;
    use ace_sdk::reads::{SvsCaptureRow, SvsFilePath};
    use ace_sdk::writes::WireWrite;
    use ace_testkit::Harness;
    use ace_testkit::reads::FakeReads;
    use serde_json::{Map, json};

    use super::*;

    const RULE_UUID: &str = "7d1c2a4e-5b6f-4c3d-9e8f-0a1b2c3d4e5f";
    const OTHER_RULE_UUID: &str = "1e2d3c4b-5a69-4788-9a0b-1c2d3e4f5a6b";
    const COMMIT: &str = "cccccccccccccccccccccccccccccccccccccccc";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// What the YARA module leaves for one match: its detection on the file, with its details.
    fn detection(rule: &str, rule_uuid: Option<&str>, commit: Option<&str>) -> SvsDetection {
        SvsDetection {
            description: format!("dir/invoice.doc matched yara rule {rule}"),
            details: Some(json!({
                "sha256": SHA256, "rule": rule, "namespace": "unittest", "rule_uuid": rule_uuid,
            })),
            signature_uuid: Some(rule_uuid.unwrap_or("a-fallback").to_owned()),
            signature_version: Some(commit.unwrap_or(SIGNATURE_VERSION_UNKNOWN).to_owned()),
        }
    }

    /// The scan_results entry of one match, ace3's `scan_result`.
    fn scan_result(rule: &str, rule_uuid: Option<&str>) -> ScanResult {
        let mut meta = Map::new();
        meta.insert("author".to_owned(), json!("unittest"));
        if let Some(uuid) = rule_uuid {
            meta.insert("uuid".to_owned(), json!(uuid));
        }
        let hit = |offset: u64, identifier: &str, bytes: &[u8]| {
            (
                offset,
                identifier.to_owned(),
                ace_results::Bytes::from(bytes),
            )
        };
        ScanResult {
            rule: rule.to_owned(),
            namespace: "unittest".to_owned(),
            meta,
            tags: vec!["unittest".to_owned()],
            commit: Some(COMMIT.to_owned()),
            ruleset: None,
            target: "dir/invoice.doc".to_owned(),
            strings: vec![
                hit(0, "$a", b"abc"),
                hit(10, "$a", b"abc"),
                hit(5, "$b", b"x"),
            ],
            context: Vec::new(),
            match_context: Vec::new(),
        }
    }

    fn state(detections: Vec<SvsDetection>) -> SvsCaptureStateAnswer {
        SvsCaptureStateAnswer {
            alert: true,
            disposition: Some("DELIVERY".to_owned()),
            classified: true,
            unreviewed_run: false,
            paths: vec![SvsFilePath {
                path: "dir/invoice.doc".to_owned(),
                yara_meta: vec!["source=email".to_owned()],
            }],
            detections,
            detections_truncated: false,
            deleted: false,
            captures: Vec::new(),
        }
    }

    /// test_capture.py's `test_a_yara_detection_is_a_candidate`.
    #[test]
    fn a_yara_detection_is_a_candidate() {
        let scan = YaraScanResults {
            scan_results: vec![scan_result("svs_rule", Some(RULE_UUID))],
        };
        let state = state(vec![detection("svs_rule", Some(RULE_UUID), Some(COMMIT))]);
        let [candidate] = candidates(SHA256, Some("dir/invoice.doc"), &state, Some(&scan))
            .try_into()
            .expect("one candidate");
        assert_eq!(candidate.sha256, SHA256);
        assert_eq!(candidate.rule_uuid, RULE_UUID);
        assert_eq!(candidate.rule_name, "svs_rule");
        assert_eq!(candidate.namespace.as_deref(), Some("unittest"));
        assert_eq!(candidate.signature_version, COMMIT);
        assert_eq!(candidate.file_path, "dir/invoice.doc");
        assert_eq!(candidate.yara_meta_tags, ["source=email"]);
        let record = candidate.match_record.expect("a record");
        assert_eq!(record["rule"], "svs_rule");
        assert_eq!(record["meta"]["uuid"], RULE_UUID);
    }

    /// test_capture.py's `test_rules_without_a_uuid_and_legacy_detections_are_not_candidates`, with a
    /// uuid longer than ace3's column. A detection that isn't on the file never reaches the module: the
    /// read answers only the file's.
    #[test]
    fn rules_without_a_uuid_and_legacy_detections_are_not_candidates() {
        let legacy = SvsDetection {
            description: "file matched yara rule old_rule".to_owned(),
            details: None,
            signature_uuid: None,
            signature_version: None,
        };
        let long = "a".repeat(MAX_RULE_UUID + 1);
        let state = state(vec![
            detection("no_uuid_rule", None, Some(COMMIT)),
            detection("empty_uuid_rule", Some(""), Some(COMMIT)),
            detection("long_uuid_rule", Some(&long), Some(COMMIT)),
            legacy,
        ]);
        assert_eq!(candidates(SHA256, None, &state, None), []);
    }

    /// test_capture.py's `test_one_candidate_per_file_and_rule`: each rule's candidate carries its own
    /// record. The same bytes under a second name are this observable with another path, so its second
    /// match of a rule is the same candidate.
    #[test]
    fn one_candidate_per_file_and_rule() {
        let scan = YaraScanResults {
            scan_results: vec![
                scan_result("svs_rule", Some(RULE_UUID)),
                scan_result("other_rule", Some(OTHER_RULE_UUID)),
            ],
        };
        let state = state(vec![
            detection("svs_rule", Some(RULE_UUID), Some(COMMIT)),
            detection("other_rule", Some(OTHER_RULE_UUID), Some(COMMIT)),
            detection("svs_rule", Some(RULE_UUID), Some(COMMIT)),
        ]);
        let found = candidates(SHA256, None, &state, Some(&scan));
        let records: Vec<(&str, Value)> = found
            .iter()
            .map(|c| {
                (
                    c.rule_uuid.as_str(),
                    c.match_record.as_ref().expect("a record")["rule"].clone(),
                )
            })
            .collect();
        assert_eq!(
            records,
            [
                (RULE_UUID, json!("svs_rule")),
                (OTHER_RULE_UUID, json!("other_rule"))
            ]
        );
    }

    /// test_capture.py's `test_a_candidate_without_its_analysis_has_no_record`, and an unknown signature
    /// version, which ace3's `add_yara_match(commit=None)` makes.
    #[test]
    fn a_candidate_without_its_analysis_has_no_record() {
        let state = state(vec![detection("svs_rule", Some(RULE_UUID), None)]);
        let [candidate] = candidates(SHA256, None, &state, None)
            .try_into()
            .expect("one candidate");
        assert_eq!(candidate.match_record, None);
        assert_eq!(candidate.signature_version, "unknown");
    }

    fn file() -> Observable {
        let mut observable = Observable::new(ObservableKind::File, SHA256);
        observable.path = Some(ace_results::AlertPath::new("dir/invoice.doc").expect("a path"));
        observable
    }

    async fn run(state: SvsCaptureStateAnswer) -> (String, Vec<WireWrite>) {
        let reads = FakeReads::new().answer(
            "svs-capture-state",
            serde_json::to_value(state).expect("serializes"),
        );
        let harness = Harness::<YaraSampleCapture>::new()
            .expect("a harness")
            .reader(Arc::new(reads))
            .dependency_result(
                "yara_scanner_v3_4",
                serde_json::to_value(YaraScanResults {
                    scan_results: vec![scan_result("svs_rule", Some(RULE_UUID))],
                })
                .expect("serializes"),
            );
        let (outcome, writes) = harness.run_lookup_writing(file()).await.expect("runs");
        let Outcome::Skipped(why) = outcome else {
            panic!("the module stores no result: {outcome:?}");
        };
        (why, writes)
    }

    /// test_config.py's `test_capture_runs_in_dispositioned_mode`, the module's half: it's enabled by
    /// default, stores nothing, and declares its read and write. `ace_core::modes`' tests hold the mode to
    /// list it.
    #[test]
    fn the_module_is_a_lookup_that_writes_its_captures() {
        assert_eq!(MANIFEST.name, "svs_yara_sample_capture");
        const { assert!(MANIFEST.enabled_by_default) };
        const { assert!(!MANIFEST.stores_results) };
        assert_eq!(MANIFEST.reads, [SvsCaptureState::READ]);
        assert_eq!(MANIFEST.writes, [SvsCapture::WRITE]);
    }

    /// ace3's `execute_post_analysis`: a graded alert's matches are written; an unclassified alert, one a
    /// test run under review holds, a root that isn't an alert and a deleted file write nothing; and a
    /// capture that's stored with its record isn't written again.
    #[tokio::test]
    async fn only_a_graded_alert_s_matches_are_captured() {
        let graded = state(vec![detection("svs_rule", Some(RULE_UUID), Some(COMMIT))]);
        let (_, writes) = run(graded.clone()).await;
        let [write] = writes.try_into().expect("one write");
        assert_eq!(write.write, "svs-capture");
        let captures: SvsCaptures = serde_json::from_value(write.body).expect("reads");
        assert_eq!(captures.captures.len(), 1);
        assert_eq!(
            captures.captures[0]
                .match_record
                .as_ref()
                .expect("a record")["rule"],
            "svs_rule"
        );

        for change in [
            |s: &mut SvsCaptureStateAnswer| s.classified = false,
            |s: &mut SvsCaptureStateAnswer| s.unreviewed_run = true,
            |s: &mut SvsCaptureStateAnswer| s.alert = false,
            |s: &mut SvsCaptureStateAnswer| s.deleted = true,
        ] {
            let mut skipped = graded.clone();
            change(&mut skipped);
            assert_eq!(run(skipped).await.1, []);
        }

        let mut stored = graded.clone();
        stored.captures = vec![SvsCaptureRow {
            rule_uuid: RULE_UUID.to_owned(),
            state: "stored".to_owned(),
            missing_reason: None,
        }];
        assert_eq!(run(stored.clone()).await.1, []);
        // one stored without its record is written again, to add it
        stored.captures[0].missing_reason = Some("match_record".to_owned());
        assert_eq!(run(stored).await.1.len(), 1);
    }
}
