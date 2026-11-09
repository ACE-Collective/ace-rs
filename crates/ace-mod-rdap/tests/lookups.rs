//! What the reference dumps don't show: a domain that doesn't exist, a TLD without RDAP, an
//! address with no public registration, and a registry that can't be reached. The recordings
//! beside the dumps serve the bootstrap registries; nothing reaches the internet.

use ace_mod_rdap::RdapAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::{ModuleError, Outcome};
use ace_testkit::reference::dumps_dir;
use ace_testkit::replay::HttpReplay;
use ace_testkit::{Harness, HarnessError};
use serde_json::json;

async fn replay() -> HttpReplay {
    HttpReplay::start(
        &dumps_dir().join("rdap_analyzer/fqdn_example.com.http"),
        &["https://data.iana.org/"],
    )
    .await
    .expect("the recording loads")
}

fn harness(replay: &HttpReplay) -> Harness<RdapAnalyzer> {
    Harness::with_settings(json!({
        "bootstrap_url": replay.local_url("https://data.iana.org/rdap/"),
    }))
    .expect("harness")
}

#[tokio::test]
async fn a_domain_the_registry_doesnt_know_is_an_error_without_a_fallback() {
    let replay = replay().await;
    let harness = harness(&replay);
    // the replay answers 404 for anything it has no recording of
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "www.no-such-domain-here.com"))
        .await
        .expect("runs");
    let Outcome::Done(result) = outcome else {
        panic!("expected a result");
    };
    let error = result.details.error.as_deref().expect("an error");
    assert!(
        error.starts_with("rdap: domain not found: RDAP GET request to "),
        "{error}"
    );
    assert!(
        error
            .ends_with("no-such-domain-here.com returned a 404 error, the resource does not exist"),
        "{error}"
    );
    assert_eq!(result.details.lookup_protocol, None);
    assert_eq!(result.details.rdap_attempt_error, None);
    assert_eq!(
        replay.unmatched(),
        ["GET https://rdap.verisign.com/com/v1/domain/no-such-domain-here.com"]
    );
    assert!(
        result
            .summary
            .expect("a summary")
            .starts_with("RDAP Analysis: error: rdap: domain not found")
    );
}

#[tokio::test]
async fn a_tld_without_rdap_records_the_rdap_error() {
    let replay = replay().await;
    let harness = harness(&replay);
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "example.not-a-tld"))
        .await
        .expect("runs");
    let Outcome::Done(result) = outcome else {
        panic!("expected a result");
    };
    let attempt = result
        .details
        .rdap_attempt_error
        .as_deref()
        .expect("an RDAP error");
    // whoisit's UnsupportedError, naming the last label, as ace3 records it
    assert_eq!(
        attempt,
        "no RDAP service for TLD: TLD \"not-a-tld\" has no known RDAP endpoint and is unsupported. \
         It may be supported by overrides, try using whoisit.bootstrap(overrides=True)"
    );
    assert_eq!(
        result.details.error.as_deref(),
        Some(format!("rdap: {attempt}").as_str())
    );
    assert_eq!(replay.requested(), ["https://data.iana.org/rdap/dns.json"]);
}

#[tokio::test]
async fn a_private_address_is_skipped() {
    let replay = replay().await;
    let harness = harness(&replay);
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::Ip, "10.1.2.3"))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
    assert!(replay.requested().is_empty());
}

#[tokio::test]
async fn an_unreachable_registry_fails_the_task_as_unavailable() {
    // nothing listens on port 9 of the loopback address
    let harness = Harness::<RdapAnalyzer>::with_settings(json!({
        "bootstrap_url": "http://127.0.0.1:9/rdap/",
    }))
    .expect("harness");
    let err = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "example.com"))
        .await
        .expect_err("the registry can't be reached");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
}
