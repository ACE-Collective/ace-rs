//! PLAN.md 7.4: the snort signature module against ace3's reference dumps. ace3 read an index of
//! tools/ace3/dumps/fixtures/snort/snort.rules that its own code built; here the core's
//! `snort-signature` read indexes the same file, and the lease API's half of it is faked with what
//! the core answers for each subject (`ace_core::reads`'s tests and ace-pool's lease_api test call
//! the core itself). Every difference is listed in differences.md, next to this file.

use std::path::Path;
use std::sync::Arc;

use ace_mod_snort::SnortSignatureAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::{ModuleError, Outcome};
use ace_testkit::reads::FakeReads;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use ace_testkit::{Harness, HarnessError};
use serde_json::json;

/// The rule the fixture has for `<sid>:<rev>`, as the core's index answers it: the line, stripped,
/// with the last `sid:N;` and `rev:N;` in it.
fn rule_in_fixture(sid: &str, rev: &str) -> Option<String> {
    let rules = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/ace3/dumps/fixtures/snort/snort.rules"),
    )
    .expect("the fixture reads");
    rules
        .lines()
        .map(str::trim)
        .rfind(|line| {
            line.contains(&format!("sid:{sid};")) && line.contains(&format!("rev:{rev};"))
        })
        .map(str::to_owned)
}

#[tokio::test]
async fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = Vec::new();
    let dumps = Dump::all("snort_signature_analysis_v1").expect("the dumps read");
    assert_eq!(dumps.len(), 5);
    for dump in dumps {
        let value = dump.value["input"]["observable"]["value"]
            .as_str()
            .expect("a value")
            .to_owned();
        let parts: Vec<&str> = value.split(':').collect();
        let rule = match parts.as_slice() {
            [_, sid, rev] => rule_in_fixture(sid, rev),
            _ => None,
        };
        let reads = Arc::new(FakeReads::new().answer("snort-signature", json!({"rule": rule})));
        let harness = Harness::<SnortSignatureAnalyzer>::new()
            .expect("harness")
            .reader(reads.clone());
        let outcome = harness
            .run_lookup(harness.observable(ObservableKind::SnortSig, &value))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        // a value that isn't gid:sid:rev reads nothing
        assert_eq!(
            reads.requests().len(),
            usize::from(parts.len() == 3),
            "{value}"
        );
        if dump.short_name() == "snort_sig_1:9000001:3" {
            ace_testkit::check_view_fixture("snort_sig_9000001", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("SnortSignatureAnalysis_v1"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

#[tokio::test]
async fn the_task_s_own_observable_is_the_read_s_subject() {
    let reads = Arc::new(FakeReads::new().answer("snort-signature", json!({"rule": null})));
    let harness = Harness::<SnortSignatureAnalyzer>::new()
        .expect("harness")
        .reader(reads.clone());
    let Outcome::Done(result) = harness
        .run_lookup(harness.observable(ObservableKind::SnortSig, " 1:2:3 "))
        .await
        .expect("runs")
    else {
        panic!("a result");
    };
    assert_eq!(
        reads.requests(),
        [("snort-signature", json!({"subject": null}))]
    );
    assert_eq!(result.summary, None);
    assert_eq!(
        result.details.signature.as_deref(),
        Some(ace_mod_snort::UNKNOWN_SIGNATURE)
    );
}

#[tokio::test]
async fn a_core_that_can_t_answer_fails_the_task_as_unavailable() {
    let harness = Harness::<SnortSignatureAnalyzer>::new()
        .expect("harness")
        .reader(Arc::new(FakeReads::new().unavailable("snort-signature")));
    let err = harness
        .run_lookup(harness.observable(ObservableKind::SnortSig, "1:2:3"))
        .await
        .expect_err("unavailable");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
}
