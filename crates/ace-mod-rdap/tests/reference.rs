//! PLAN.md 1.27: the RDAP module against ace3's reference dumps for a domain and an IP address,
//! with the HTTP exchanges ace3 made replayed from the recording beside each dump. Nothing reaches
//! the internet. Every difference is listed and explained in differences.md, next to this file.

use std::path::Path;

use ace_mod_rdap::RdapAnalyzer;
use ace_results::ObservableKind;
use ace_testkit::Harness;
use ace_testkit::reference::{Dump, ListedDifferences, diff, dumps_dir, normal_form};
use ace_testkit::replay::HttpReplay;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

/// rdap_raw_json is the same response written by two JSON encoders, so it's compared as JSON.
fn parse_raw_json(form: &mut Value) {
    if let Some(raw) = form["details"]["rdap_raw_json"].as_str() {
        form["details"]["rdap_raw_json"] =
            serde_json::from_str(raw).expect("rdap_raw_json is JSON");
    }
}

#[tokio::test]
async fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = Vec::new();
    let dumps = Dump::all("rdap_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 2, "a domain and an IP address");
    for dump in dumps {
        let replay = HttpReplay::start(
            &dumps_dir().join(format!("{}.http", dump.name)),
            &["https://data.iana.org/"],
        )
        .await
        .expect("the recording loads");
        let details = &dump.analysis("RdapAnalysis").expect("an analysis")["details"];
        // the lookup runs at the time ace3's did, so the ages agree
        let now: DateTime<Utc> = DateTime::parse_from_str(
            details["datetime_of_analysis"].as_str().expect("a time"),
            "%Y-%m-%d %H:%M:%S%.f%:z",
        )
        .expect("ace3's time parses")
        .with_timezone(&Utc);
        let harness = Harness::<RdapAnalyzer>::with_settings(json!({
            "bootstrap_url": replay.local_url("https://data.iana.org/rdap/"),
        }))
        .expect("harness")
        .at(now);

        let input = &dump.value["input"]["observable"];
        let kind: ObservableKind = input["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a known type");
        let value = input["value"].as_str().expect("a value");
        let outcome = harness
            .run_lookup(harness.observable(kind, value))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));

        assert!(
            replay.unmatched().is_empty(),
            "{}: requests nothing was recorded for: {:?}",
            dump.name,
            replay.unmatched()
        );
        println!("{}: replayed {:?}", dump.name, replay.requested());

        let mut ace3 = dump.normal_form("RdapAnalysis");
        let mut ace4 = normal_form(&outcome);
        parse_raw_json(&mut ace3);
        parse_raw_json(&mut ace4);
        compared.push((dump.short_name().to_owned(), diff(&ace3, &ace4)));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
