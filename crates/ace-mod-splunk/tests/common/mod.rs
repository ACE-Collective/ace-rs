//! What the Splunk module's tests share: proxy_domain_lookup's settings, and a loop that runs
//! the module through its delays.

use std::time::Duration;

use ace_mod_splunk::SplunkAnalyzer;
use ace_mod_splunk::connection::{PASSWORD as PASSWORD_ROLE, SLOT};
use ace_results::types::splunk::SplunkApiAnalysis;
use ace_sdk::{Connection, Module, Observable, Outcome, Secret};
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
        "splunk": instance(base_url),
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

/// The fake Splunk's instance, as make-dumps's `splunk_config_default`, at `base_url`: the settings
/// of the connection the module's slot `splunk` is bound to.
pub fn instance(base_url: &str) -> Value {
    json!({
        "host": "127.0.0.1",
        "base_url": base_url,
        "username": "ace4",
        "request_timeout_seconds": 10,
    })
}

/// `harness` with the connection its `settings` hold under `splunk` bound to its slot, filling
/// `role` with `secret`, as a pool binds the overlay's instance `default`.
pub fn connected<M: Module>(
    harness: Harness<M>,
    settings: &Value,
    role: &str,
    secret: &str,
) -> Harness<M> {
    harness.connection(
        SLOT.name,
        Connection::new("default", "splunk", Some(settings["splunk"].clone()))
            .with_secret(role, Secret::new(secret)),
    )
}

/// `harness` logging in as `ace4` with the dumps' password.
pub fn logged_in<M: Module>(harness: Harness<M>, settings: &Value) -> Harness<M> {
    connected(harness, settings, PASSWORD_ROLE, PASSWORD)
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
