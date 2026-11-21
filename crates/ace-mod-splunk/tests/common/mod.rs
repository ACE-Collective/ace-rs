//! What the Splunk module's tests share: proxy_domain_lookup's settings, and a loop that runs
//! the module through its delays.

use std::time::Duration;

use ace_mod_splunk::SplunkAnalyzer;
use ace_results::types::splunk::SplunkApiAnalysis;
use ace_sdk::{Observable, Outcome};
use ace_testkit::Harness;
use serde_json::{Value, json};

/// Where ace3 reached the fake Splunk, which the recordings are of.
pub const SPLUNKD: &str = "https://127.0.0.1:8089";

/// The password the dumps' config gave ace3; the fake takes any.
pub const PASSWORD: &str = "ace4-fake-password";

/// proxy_domain_lookup, the example ace3 ships in etc/saq.splunk_modules.yaml, as make-dumps
/// ran it: on fqdn rather than the `domain` type ace3 doesn't have.
pub fn proxy_domain_lookup(base_url: &str) -> Value {
    json!({
        "base_url": base_url,
        "username": "ace4",
        "request_timeout_seconds": 10,
        "question": "Was this domain seen in proxy logs?",
        "summary": "Proxy correlation",
        "query": "index=proxy (transport=HTTPS OR transport=HTTP) hostname=\"<O_VALUE>\"\n| eval full_url = lower(transport) . \"://\" . url\n",
        "valid_observable_types": ["fqdn"],
        "observable_mapping": [
            {"field": "src_ip", "type": "ip", "display_type": "Source IP"},
            {"field": "src_translated_ip", "type": "ip", "display_type": "Source IP"},
            {"field": "dest_ip", "type": "ip", "display_type": "Destination IP"},
            {"field": "full_url", "type": "url"},
            {"field": "user", "type": "email_address"},
        ],
    })
}

/// Runs the module, and again after each delay it asks for, as if each delay had passed, until
/// it stores a result. Returns every delay's outcome, then the last.
pub async fn run_through_delays(
    harness: &Harness<SplunkAnalyzer>,
    observable: Observable,
) -> (Vec<Outcome<SplunkApiAnalysis>>, Outcome<SplunkApiAnalysis>) {
    let mut outcome = harness
        .run_lookup(observable.clone())
        .await
        .expect("the first run");
    let mut delays = Vec::new();
    let mut waited = Duration::ZERO;
    while let Outcome::Delay(delay) = &outcome {
        assert!(delays.len() < 50, "the module keeps asking for delays");
        waited += delay.run_after;
        let delayed = harness.after_delay(delay, delays.len() as u32 + 1, waited);
        let next = harness
            .rerun_lookup(observable.clone(), delayed)
            .await
            .expect("a delayed run");
        delays.push(std::mem::replace(&mut outcome, next));
    }
    (delays, outcome)
}
