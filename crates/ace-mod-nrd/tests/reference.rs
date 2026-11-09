//! PLAN.md 7.4: the newly registered domains module against ace3's reference dumps. ace3 read the
//! SQLite list its own refresh built from tools/ace3/dumps/fixtures/nrd/lists; here the module's
//! `newly-registered` read is answered with what the core answers from the same domains (the core's
//! read is tested against the same list through the lease API in ace-pool's lease_api test). RDAP is
//! the recorded bootstrap and example.com of the RDAP module's dump with fixtures/nrd/rdap's
//! hand-written registrations, replayed on 127.0.0.1, so an error naming a URL names the replay's,
//! which the test writes back as the recorded one. Every difference is listed in
//! differences.md, next to this file.

use std::path::Path;
use std::sync::Arc;

use ace_mod_nrd::NrdAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::{ModuleError, Outcome};
use ace_testkit::reads::FakeReads;
use ace_testkit::reference::{Dump, ListedDifferences, diff, dumps_dir, normal_form};
use ace_testkit::replay::HttpReplay;
use ace_testkit::{Harness, HarnessError};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

/// The domains ace3's first refresh left in the list the dumps read.
fn listed_domains() -> Vec<String> {
    let reference: Value = serde_json::from_str(
        &std::fs::read_to_string(dumps_dir().join("nrd/reference.json")).expect("reads"),
    )
    .expect("JSON");
    reference["refresh"][0]["database"]["domains"]
        .as_array()
        .expect("domains")
        .iter()
        .map(|d| d.as_str().expect("a domain").to_owned())
        .collect()
}

/// What the core's `newly-registered` read answers for `value` over `domains`.
fn core_answer(value: &str, domains: &[String]) -> bool {
    let normalized = ace_sdk::nrd::normalize_lookup(value);
    !normalized.is_empty()
        && ace_sdk::nrd::candidates(&normalized)
            .iter()
            .any(|c| domains.contains(c))
}

async fn rdap_replay() -> HttpReplay {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binds");
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/nrd/rdap");
    let recorded = dumps_dir().join("rdap_analyzer/fqdn_example.com.http");
    HttpReplay::serve(
        &[
            (fixtures.as_path(), &[][..]),
            (recorded.as_path(), &["https://data.iana.org/"][..]),
        ],
        listener,
        None,
    )
    .await
    .expect("the recordings load")
}

#[tokio::test]
async fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let domains = listed_domains();
    let mut compared = Vec::new();
    let dumps = Dump::all("nrd_analyzer").expect("the dumps read");
    assert_eq!(dumps.len(), 10);
    for dump in dumps {
        let input = &dump.value["input"]["observable"];
        let kind: ObservableKind = input["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a kind");
        let value = input["value"].as_str().expect("a value");
        let label = dump.value["input"]["label"].as_str().expect("a label");
        let max_age: i64 = label
            .rsplit(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .expect("the label names the age");
        // the lookup runs when ace3's did, so the ages agree
        let now: DateTime<Utc> = dump
            .analysis("NRDAnalysis")
            .and_then(|a| a["details"]["matched_at"].as_str())
            .map(|t| t.parse().expect("ace3's time parses"))
            .unwrap_or_else(|| "2026-11-08T23:04:30Z".parse().expect("a time"));
        let replay = rdap_replay().await;
        let reads = Arc::new(FakeReads::new().answer(
            "newly-registered",
            json!({"listed": core_answer(value, &domains)}),
        ));
        let harness = Harness::<NrdAnalyzer>::with_settings(json!({
            "max_registration_age_days": max_age,
            "bootstrap_url": replay.local_url("https://data.iana.org/rdap/"),
        }))
        .expect("harness")
        .reader(reads.clone())
        .at(now);
        let outcome = harness
            .run_lookup(harness.observable(kind, value))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        assert_eq!(
            reads.requests(),
            [("newly-registered", json!({"subject": null}))],
            "{}: only the task's own observable is asked about",
            dump.name
        );
        assert!(
            replay.unmatched().is_empty(),
            "{}: requests nothing was recorded for: {:?}",
            dump.name,
            replay.unmatched()
        );
        if dump.short_name() == "fqdn_ace4-fresh.com" {
            ace_testkit::check_view_fixture("nrd_fqdn_ace4_fresh_com", &outcome);
        }
        // an error names the URL asked, which here is the replay's
        let local = replay.local_url("https://");
        let ace4: Value = serde_json::from_str(
            &serde_json::to_string(&normal_form(&outcome))
                .expect("serializes")
                .replace(&local, "https://"),
        )
        .expect("JSON");
        compared.push((
            dump.short_name().to_owned(),
            diff(&dump.normal_form("NRDAnalysis"), &ace4),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

/// A name the list doesn't have reads the list and asks RDAP nothing.
#[tokio::test]
async fn a_miss_asks_rdap_nothing() {
    let replay = rdap_replay().await;
    let harness = Harness::<NrdAnalyzer>::with_settings(json!({
        "bootstrap_url": replay.local_url("https://data.iana.org/rdap/"),
    }))
    .expect("harness")
    .reader(Arc::new(
        FakeReads::new().answer("newly-registered", json!({"listed": false})),
    ));
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "example.org"))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
    assert!(replay.requested().is_empty());
}

/// A core that can't answer fails the task as unavailable, so it runs again later; ace3's SQLite
/// read can't fail that way, and its failed query is a miss.
#[tokio::test]
async fn a_core_that_can_t_answer_fails_the_task_as_unavailable() {
    let harness = Harness::<NrdAnalyzer>::new()
        .expect("harness")
        .reader(Arc::new(FakeReads::new().unavailable("newly-registered")));
    let err = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "ace4-fresh.com"))
        .await
        .expect_err("unavailable");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
}

/// The RDAP lookup's successes are remembered for the process, as ace3's memo does, so a second
/// hit on the same domain asks RDAP nothing more.
#[tokio::test]
async fn a_verified_domain_is_looked_up_once() {
    let replay = rdap_replay().await;
    let harness = Harness::<NrdAnalyzer>::with_settings(json!({
        "bootstrap_url": replay.local_url("https://data.iana.org/rdap/"),
    }))
    .expect("harness")
    .reader(Arc::new(
        FakeReads::new().answer("newly-registered", json!({"listed": true})),
    ))
    .at("2026-11-08T00:00:00Z".parse().expect("a time"));
    for value in ["ace4-fresh.com", "login.ace4-fresh.com"] {
        let outcome = harness
            .run_lookup(harness.observable(ObservableKind::Fqdn, value))
            .await
            .expect("runs");
        assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
    }
    let asked: Vec<String> = replay
        .requested()
        .into_iter()
        .filter(|u| u.contains("/domain/"))
        .collect();
    assert_eq!(
        asked,
        ["https://rdap.verisign.com/com/v1/domain/ace4-fresh.com"]
    );
}
