//! PLAN.md 1.30: the YARA module against ace3's reference dumps, which scan test.zip with the
//! fixture rules in tools/ace3/dumps/fixtures/yara/ three times: tagged type=email.attachment,
//! untagged, and tagged type=email.headers. Every difference is listed and explained in
//! differences.md, next to this file.

use std::path::{Path, PathBuf};

use ace_mod_yara::YaraScanner;
use ace_sdk::Outcome;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use ace_testkit::{Harness, samples_dir};
use serde_json::json;

fn rules() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/yara")
}

fn harness() -> Harness<YaraScanner> {
    Harness::with_settings(json!({"signature_dir": rules()})).expect("the fixture rules load")
}

/// Runs the module on test.zip with these `yara_meta` tags.
fn scan(
    harness: &Harness<YaraScanner>,
    tags: &[&str],
) -> Outcome<ace_results::types::yara::YaraScanResults> {
    let zip = harness
        .file(
            "test.zip",
            samples_dir().join("ace3/archive/test.zip"),
            tags,
        )
        .expect("the sample");
    harness.run_parser(zip).expect("scans")
}

fn matched(outcome: &Outcome<ace_results::types::yara::YaraScanResults>) -> Vec<String> {
    match outcome {
        Outcome::Done(result) => result
            .details
            .scan_results
            .iter()
            .map(|r| r.rule.clone())
            .collect(),
        _ => Vec::new(),
    }
}

#[test]
fn the_fixture_rule_matches_only_with_the_right_meta_tag() {
    let harness = harness();
    assert_eq!(
        matched(&scan(&harness, &["type=email.attachment"])),
        ["ace_rs_fixture_zip_attachment", "ace_rs_fixture_zip_any"]
    );
    assert_eq!(matched(&scan(&harness, &[])), ["ace_rs_fixture_zip_any"]);
    assert_eq!(
        matched(&scan(&harness, &["type=email.headers"])),
        ["ace_rs_fixture_zip_any"]
    );
}

#[test]
fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let harness = harness();
    let mut compared = Vec::new();
    let dumps = Dump::all("yara_scanner_v3_4").expect("the dumps read");
    assert_eq!(dumps.len(), 3);
    for dump in dumps {
        let tags: Vec<&str> = dump.value["input"]["meta_tags"]
            .as_array()
            .expect("meta tags")
            .iter()
            .filter_map(|t| t.as_str())
            .collect();
        let outcome = scan(&harness, &tags);
        if dump.short_name() == "ace3/archive/test.zip.tagged-attachment" {
            // the fixture ace-gui's analysis view test draws (PLAN.md 5.9)
            ace_testkit::check_view_fixture("yara_test_zip_attachment", &outcome);
        }
        let differences = diff(
            &dump.normal_form("YaraScanResults_v3_4"),
            &normal_form(&outcome),
        );
        compared.push((dump.short_name().to_owned(), differences));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
