//! PLAN.md 1.28: the Splunk module against ace3's reference dumps of proxy_domain_lookup, a
//! search that finishes and one that never does, with the HTTP exchanges ace3 made with the
//! fake Splunk replayed from the recording beside each dump. Every difference is listed and
//! explained in differences.md, next to this file.

mod common;

use std::path::Path;

use ace_mod_splunk::{PASSWORD, SplunkAnalyzer};
use ace_results::ObservableKind;
use ace_testkit::Harness;
use ace_testkit::reference::{Dump, ListedDifferences, diff, dumps_dir, normal_form};
use ace_testkit::replay::HttpReplay;
use serde_json::json;

use common::{SPLUNKD, proxy_domain_lookup, run_through_delays};

#[tokio::test]
async fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = Vec::new();
    let dumps = Dump::all("proxy_domain_lookup").expect("the dumps read");
    assert_eq!(
        dumps.len(),
        2,
        "a search that finishes and one that doesn't"
    );
    for dump in dumps {
        let replay = HttpReplay::start(&dumps_dir().join(format!("{}.http", dump.name)), &[])
            .await
            .expect("the recording loads");
        let mut settings = proxy_domain_lookup(&replay.local_url(SPLUNKD));
        if dump.name.ends_with(".never-done") {
            // as make-dumps ran it
            settings["query_timeout"] = json!(3);
        }
        let harness = Harness::<SplunkAnalyzer>::with_settings(settings)
            .expect("harness")
            .secret(PASSWORD, common::PASSWORD);

        let input = &dump.value["input"]["observable"];
        let kind: ObservableKind = input["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a known type");
        let value = input["value"].as_str().expect("a value");
        let (delays, outcome) = run_through_delays(&harness, harness.observable(kind, value)).await;

        assert!(
            replay.unmatched().is_empty(),
            "{}: requests nothing was recorded for: {:?}",
            dump.name,
            replay.unmatched()
        );
        println!(
            "{}: {} delays, replayed {:?}",
            dump.name,
            delays.len(),
            replay.requested()
        );
        if dump.short_name() == "fqdn_www.example.com" {
            // the fixture ace-gui's alert view test lands and draws (PLAN.md 5.8)
            ace_testkit::check_view_fixture("splunk_proxy_domain_lookup", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("SplunkAPIAnalysis"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
