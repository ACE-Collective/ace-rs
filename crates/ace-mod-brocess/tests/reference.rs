//! PLAN.md 7.4: the brocess modules against ace3's reference dumps. ace3 counted from
//! tools/ace3/dumps/fixtures/brocess/smtplog.json in place of brocess
//! (`tools/ace3/dumps/run_module.py --brocess`); here each read is answered with what the core's
//! query answers for those rows. The core's query itself runs on the same rows, against the same
//! dumps, in ace-pool's lease_api test. Every difference is listed in differences.md, next to this
//! file.

use std::path::Path;
use std::sync::Arc;

use ace_mod_brocess::EmailConversationFrequencyAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::{ModuleError, Outcome};
use ace_testkit::reads::FakeReads;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use ace_testkit::{Harness, HarnessError};
use serde_json::{Value, json};

/// `smtp-counts` over the fixture's rows, as the core's SQL sums them: addresses compared byte for
/// byte, NULL counts left out, and no row a 0.
fn counts_in_fixture(value: &str) -> Value {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/ace3/dumps/fixtures/brocess/smtplog.json"),
        )
        .expect("the fixture reads"),
    )
    .expect("JSON");
    let parts: Vec<&str> = value.splitn(3, '|').collect();
    let (sender, recipient) = match parts.as_slice() {
        [sender, recipient] => (*sender, *recipient),
        _ => (value, ""),
    };
    let (mut source, mut conversation) = (0, 0);
    for row in fixture["smtplog"].as_array().expect("rows") {
        let (Some(from), Some(to), Some(count)) =
            (row[0].as_str(), row[1].as_str(), row[2].as_i64())
        else {
            continue;
        };
        if from == sender {
            source += count;
            if to == recipient {
                conversation += count;
            }
        }
    }
    json!({"source_count": source, "conversation_count": conversation})
}

#[tokio::test]
async fn the_frequency_module_matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = Vec::new();
    let dumps = Dump::all("email_conversation_frequency_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 8);
    for dump in dumps {
        let value = dump.value["input"]["observable"]["value"]
            .as_str()
            .expect("a value")
            .to_owned();
        let reads = Arc::new(FakeReads::new().answer("smtp-counts", counts_in_fixture(&value)));
        let harness = Harness::<EmailConversationFrequencyAnalyzer>::new()
            .expect("harness")
            .reader(reads.clone());
        let outcome = harness
            .run_lookup(harness.observable(ObservableKind::EmailConversation, &value))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        assert_eq!(
            reads.requests(),
            [("smtp-counts", json!({"subject": null}))],
            "{value}"
        );
        if dump.short_name() == "email_conversation_sender@example.com|recipient@example.com" {
            ace_testkit::check_view_fixture("brocess_frequent_conversation", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("EmailConversationFrequencyAnalysis"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

#[tokio::test]
async fn the_threshold_is_a_setting() {
    let reads = Arc::new(FakeReads::new().answer(
        "smtp-counts",
        json!({"source_count": 3, "conversation_count": 2}),
    ));
    let harness = Harness::<EmailConversationFrequencyAnalyzer>::with_settings(
        json!({"conversation_count_threshold": 2}),
    )
    .expect("harness")
    .reader(reads);
    let Outcome::Done(result) = harness
        .run_lookup(harness.observable(ObservableKind::EmailConversation, "a@x|b@y"))
        .await
        .expect("runs")
    else {
        panic!("a result");
    };
    assert_eq!(result.analyzed.tags, ["frequent_conversation"]);
}

#[tokio::test]
async fn a_core_that_can_t_answer_fails_the_task_as_unavailable() {
    let harness = Harness::<EmailConversationFrequencyAnalyzer>::new()
        .expect("harness")
        .reader(Arc::new(FakeReads::new().unavailable("smtp-counts")));
    let err = harness
        .run_lookup(harness.observable(ObservableKind::EmailConversation, "a@x|b@y"))
        .await
        .expect_err("unavailable");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
}
