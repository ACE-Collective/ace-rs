//! PLAN.md 1.28: the Splunk module against ace3's reference dumps of proxy_domain_lookup, a
//! search that finishes and one that never does, with the HTTP exchanges ace3 made with the
//! fake Splunk replayed from the recording beside each dump. Every difference is listed and
//! explained in differences.md, next to this file.

mod common;

use std::path::Path;

use ace_mod_splunk::SplunkAnalyzer;
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
        let harness = common::logged_in(
            Harness::<SplunkAnalyzer>::with_settings(settings.clone()).expect("harness"),
            &settings,
        );

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

// ---- clicker_detection_splunk (PLAN.md 7.4) ----

/// The clicker module's settings as make-dumps ran ace3's: the fake Splunk's connection and
/// defaults, and fixtures/clicker/clicker_detection.yaml.
fn clicker_settings(base_url: &str) -> serde_json::Value {
    json!({
        "splunk": common::instance(base_url),
        "config_path": Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tools/ace3/dumps/fixtures/clicker/clicker_detection.yaml"),
    })
}

/// The time ace3's searches were around: the first search's `earliest`, seven days before it.
fn clicker_anchor(http: &Path) -> chrono::DateTime<chrono::Utc> {
    let recording: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(http.join("http.json")).expect("reads"))
            .expect("JSON");
    let body = recording["exchanges"]
        .as_array()
        .expect("exchanges")
        .iter()
        .find(|e| e["method"] == "POST" && e["url"].as_str().is_some_and(|u| u.ends_with("/jobs/")))
        .and_then(|e| e["request_body"].as_str())
        .expect("a search");
    let search: String = form_urlencoded::parse(body.as_bytes())
        .find(|(k, _)| k == "search")
        .map(|(_, v)| v.into_owned())
        .expect("the search");
    let earliest = regex::Regex::new(r"earliest = (\S+)")
        .expect("valid")
        .captures(&search)
        .map(|c| c[1].to_owned())
        .expect("an earliest");
    chrono::NaiveDateTime::parse_from_str(&earliest, "%m/%d/%Y:%H:%M:%S")
        .expect("ace3's time")
        .and_utc()
        + chrono::TimeDelta::days(7)
}

#[tokio::test]
async fn the_clicker_module_matches_the_reference_dumps_or_lists_each_difference() {
    use ace_mod_splunk::ClickerDetection;
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/clicker_differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = Vec::new();
    let dumps = Dump::all("clicker_detection_splunk").expect("the dumps read");
    assert_eq!(dumps.len(), 7);
    for dump in dumps {
        let input = &dump.value["input"];
        let directives: Vec<String> = input["directives"]
            .as_array()
            .expect("directives")
            .iter()
            .map(|d| d.as_str().expect("a directive").to_owned())
            .collect();
        if directives.is_empty() {
            // the core queues the module only for an observable with clicker_detection
            assert!(dump.analysis("SplunkClickerDetectionAnalysis").is_none());
            assert_eq!(
                ace_mod_splunk::clicker::MANIFEST.required_directives,
                ["clicker_detection"]
            );
            continue;
        }
        let http = dumps_dir().join(format!("{}.http", dump.name));
        let replay = HttpReplay::start(&http, &[])
            .await
            .expect("the recording loads");
        let mut settings = clicker_settings(&replay.local_url(common::SPLUNKD));
        if dump.name.ends_with(".never-done") {
            settings["query_timeout"] = json!(3);
        }
        // the root's event time the searches were around, and ace3's clock when its first run
        // began, some seconds later: the searches are around the event time, not the clock
        let anchor = clicker_anchor(&http);
        let started = dump
            .analysis("SplunkClickerDetectionAnalysis")
            .and_then(|a| a["details"]["query_start"].as_f64())
            .and_then(|seconds| {
                chrono::DateTime::from_timestamp_micros((seconds * 1e6).round() as i64)
            })
            .unwrap_or(anchor);
        assert!(
            started > anchor,
            "{}: ace3's run began after its event time",
            dump.name
        );
        let harness = common::logged_in(
            Harness::<ClickerDetection>::with_settings(settings.clone()).expect("harness"),
            &settings,
        )
        .event_time(anchor)
        .at(started);
        let kind: ObservableKind = input["observable"]["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a kind");
        let value = input["observable"]["value"].as_str().expect("a value");
        let mut observable = harness.observable(kind, value);
        observable.directives = directives;
        let mut outcome = harness.run_lookup(observable.clone()).await.expect("runs");
        let mut delays = 0;
        let mut waited = std::time::Duration::ZERO;
        while let ace_sdk::Outcome::Delay(delay) = &outcome {
            assert!(
                delays < 50,
                "{}: the module keeps asking for delays",
                dump.name
            );
            delays += 1;
            waited += delay.run_after;
            let delayed = harness.after_delay(delay, delays, waited);
            outcome = harness
                .rerun_lookup(observable.clone(), delayed)
                .await
                .expect("a delayed run");
        }
        assert!(
            replay.unmatched().is_empty(),
            "{}: requests nothing was recorded for: {:?}",
            dump.name,
            replay.unmatched()
        );
        // the module's searches are ace3's, in order, word for word
        let sent: Vec<String> = replay
            .requests()
            .iter()
            .filter(|r| r.method == "POST" && r.url.ends_with("/jobs/"))
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect();
        let recording: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(http.join("http.json")).expect("reads"))
                .expect("JSON");
        let asked: Vec<String> = recording["exchanges"]
            .as_array()
            .expect("exchanges")
            .iter()
            .filter(|e| {
                e["method"] == "POST" && e["url"].as_str().is_some_and(|u| u.ends_with("/jobs/"))
            })
            .map(|e| e["request_body"].as_str().expect("a body").to_owned())
            .collect();
        let search = |body: &String| {
            form_urlencoded::parse(body.as_bytes())
                .find(|(k, _)| k == "search")
                .map(|(_, v)| v.into_owned())
        };
        if !dump.short_name().contains("?u=") {
            assert_eq!(
                sent.iter().map(search).collect::<Vec<_>>(),
                asked.iter().map(search).collect::<Vec<_>>(),
                "{}",
                dump.name
            );
        }
        if dump.short_name() == "url_https:__click.example.com_login" {
            ace_testkit::check_view_fixture("splunk_clicker_click_example_com", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("SplunkClickerDetectionAnalysis"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
