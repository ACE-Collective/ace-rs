//! PLAN.md 7.6: the tagging and detection modules against ace3's reference dumps
//! (`tools/ace3/dumps/make-dumps user_defined_tagging observable_detection site_tagger`). ace3 read
//! the fixtures in `tools/ace3/dumps/fixtures/tag/`: its database's tag mappings and its Redis cache
//! of detections, which run_module.py faked from `observable_tags.json` and `detections.json`, and the
//! site tags CSV. Here the same tags answer the `observable-tags` read, the same detections are the
//! `observable_detection` list's entries, and the CSV is the site tagger's setting. Every difference
//! is listed in differences.md, next to this file.

use std::path::Path;
use std::sync::Arc;

use ace_mod_tag::detection::DETECTION_LIST;
use ace_mod_tag::{ObservableDetection, SiteTagger, UserDefinedTagging};
use ace_results::ObservableKind;
use ace_sdk::Outcome;
use ace_sdk::lists::{Entry, MatchKind};
use ace_testkit::reads::FakeReads;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use ace_testkit::{Harness, HarnessError};
use serde_json::{Value, json};

/// The sample the file dumps analyzed.
const TAG_FILE: &str = "ace3/pcap/sslkeylog.txt";

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/ace3/dumps/fixtures/tag")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).expect("the fixture reads")).expect("JSON")
}

fn listed() -> ListedDifferences {
    ListedDifferences::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"))
        .expect("differences.md reads")
}

/// The dump's input observable, as the harness makes it.
fn input<M: ace_sdk::Module>(
    harness: &Harness<M>,
    dump: &Dump,
) -> Result<ace_sdk::Observable, HarnessError> {
    let observable = &dump.value["input"]["observable"];
    if observable["type"] == "file" {
        return harness.sample(TAG_FILE);
    }
    let kind: ObservableKind = observable["type"]
        .as_str()
        .expect("a type")
        .parse()
        .expect("a kind");
    Ok(harness.observable(kind, observable["value"].as_str().expect("a value")))
}

fn type_and_value(dump: &Dump) -> (String, String) {
    let observable = &dump.value["input"]["observable"];
    (
        observable["type"].as_str().expect("a type").to_owned(),
        observable["value"].as_str().expect("a value").to_owned(),
    )
}

/// The detections of detections.json as the list's entries, as the `detection` router adds them.
fn detection_entries() -> Vec<Entry> {
    fixture("detections.json")["detections"]
        .as_array()
        .expect("detections")
        .iter()
        .enumerate()
        .map(|(i, d)| Entry {
            id: i64::try_from(i).expect("small") + 1,
            kind: MatchKind::Exact,
            value: d["value"].as_str().expect("a value").to_owned(),
            ignore_case: false,
            observable_type: Some(d["type"].as_str().expect("a type").to_owned()),
            expires_at: None,
        })
        .collect()
}

#[tokio::test]
async fn observable_detection_matches_the_reference_dumps_or_lists_each_difference() {
    let mut compared = Vec::new();
    let dumps = Dump::all("observable_detection").expect("the dumps read");
    assert_eq!(dumps.len(), 8);
    for dump in dumps {
        let harness = Harness::<ObservableDetection>::new()
            .expect("harness")
            .list(&DETECTION_LIST, detection_entries());
        let outcome = harness
            .run_lookup(input(&harness, &dump).expect("the input"))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        match dump.short_name() {
            "fqdn_flagged.example" => {
                ace_testkit::check_view_fixture("observable_detection_flagged", &outcome);
            }
            "fqdn_other.example" => {
                ace_testkit::check_view_fixture("observable_detection_not_flagged", &outcome);
            }
            _ => {}
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("ObservableDetectionAnalysis"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed().check(&compared, &[]) {
        panic!("{report}");
    }
}

/// An entry past its expiry matches nothing, as ace3's export leaves an expired detection out of
/// Redis; one that expires later still matches.
#[tokio::test]
async fn an_expired_detection_matches_nothing() {
    let now = ace_testkit::fixed_now();
    for (expires_at, flagged) in [
        (now - chrono::Duration::seconds(1), false),
        (now + chrono::Duration::days(1), true),
    ] {
        let mut entries = detection_entries();
        for entry in &mut entries {
            entry.expires_at = Some(expires_at);
        }
        let harness = Harness::<ObservableDetection>::new()
            .expect("harness")
            .at(now)
            .list(&DETECTION_LIST, entries);
        let Outcome::Done(result) = harness
            .run_lookup(harness.observable(ObservableKind::Fqdn, "flagged.example"))
            .await
            .expect("runs")
        else {
            panic!("a result");
        };
        assert_eq!(result.details.for_detection, flagged);
        assert_eq!(result.analyzed.detections.len(), usize::from(flagged));
    }
}

#[tokio::test]
async fn user_defined_tagging_matches_the_reference_dumps_or_lists_each_difference() {
    let mappings = fixture("observable_tags.json");
    let mut compared = Vec::new();
    let dumps = Dump::all("user_defined_tagging").expect("the dumps read");
    assert_eq!(dumps.len(), 8);
    for dump in dumps {
        let (kind, value) = type_and_value(&dump);
        // the core's answer: the tags mapped to this type and value, in the order they were added
        let tags: Vec<&str> = mappings["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .filter(|m| m["type"] == kind.as_str() && m["value"] == value.as_str())
            .map(|m| m["tag"].as_str().expect("a tag"))
            .collect();
        let reads = Arc::new(
            FakeReads::new().answer("observable-tags", json!({"tags": tags, "truncated": false})),
        );
        let harness = Harness::<UserDefinedTagging>::new()
            .expect("harness")
            .reader(reads.clone());
        let outcome = harness
            .run_lookup(input(&harness, &dump).expect("the input"))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        assert_eq!(
            reads.requests(),
            [("observable-tags", json!({"subject": null}))]
        );
        match dump.short_name() {
            "fqdn_tagged.example" => {
                ace_testkit::check_view_fixture("user_defined_tagging_tagged", &outcome);
            }
            "fqdn_untagged.example" => {
                ace_testkit::check_view_fixture("user_defined_tagging_untagged", &outcome);
            }
            _ => {}
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("UserDefinedTaggingAnalysis"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed().check(&compared, &[]) {
        panic!("{report}");
    }
}

#[tokio::test]
async fn a_core_that_can_t_answer_fails_user_defined_tagging_as_unavailable() {
    let harness = Harness::<UserDefinedTagging>::new()
        .expect("harness")
        .reader(Arc::new(FakeReads::new().unavailable("observable-tags")));
    let err = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "tagged.example"))
        .await
        .expect_err("unavailable");
    assert!(
        matches!(
            err,
            HarnessError::Module(ace_sdk::ModuleError::Unavailable(_))
        ),
        "{err}"
    );
}

#[test]
fn site_tagger_matches_the_reference_dumps_or_lists_each_difference() {
    let csv = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/ace3/dumps/fixtures/tag/site_tags.csv"),
    )
    .expect("the CSV reads");
    let mut compared = Vec::new();
    let dumps = Dump::all("site_tagger").expect("the dumps read");
    assert_eq!(dumps.len(), 17);
    for dump in dumps {
        let harness = Harness::<SiteTagger>::with_settings(json!({"csv": csv})).expect("harness");
        let outcome = harness
            .run_parser(input(&harness, &dump).expect("the input"))
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if dump.short_name() == "fqdn_two.example" {
            ace_testkit::check_view_fixture("site_tagger_two_rows", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(&dump.normal_form("SiteTagAnalysis"), &normal_form(&outcome)),
        ));
    }
    if let Err(report) = listed().check(&compared, &[]) {
        panic!("{report}");
    }
}
