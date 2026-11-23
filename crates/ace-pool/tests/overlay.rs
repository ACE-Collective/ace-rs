//! PLAN.md 2.23's Done check, end to end: two instances of 1.28's Splunk module, declared in a
//! site overlay, run different queries on the same observable. Each is its own component in the
//! core's catalog and the pool, its own task in the queue and its own result row, and its inputs
//! keep it off the observables the searches add. Each instance talks to its own replay of the
//! recorded Splunk API (tools/ace3/dumps/reference/proxy_domain_lookup/), so nothing reaches a
//! real Splunk. The overlay's other rules are unit tests in ace-sdk's `overlay`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use ace_core::eligibility::Catalog;
use ace_core::modes::{AnalysisMode, Modes};
use ace_core::tree::{self, NewRoot};
use ace_mod_splunk::SplunkAnalyzer;
use ace_pool::client::LeaseClient;
use ace_pool::modules::Registry;
use ace_pool::pool::{AsyncPool, PoolDefinition};
use ace_results::{NewObservable, ObservableKind};
use ace_sdk::{Overlay, Secret, Secrets};
use ace_testkit::reference::dumps_dir;
use ace_testkit::replay::HttpReplay;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use common::{Core, TOKEN, wait_until_idle};

/// Where ace3 reached the fake Splunk the recording is of.
const SPLUNKD: &str = "https://127.0.0.1:8089";

async fn splunkd() -> HttpReplay {
    HttpReplay::start(
        &dumps_dir().join("proxy_domain_lookup/fqdn_www.example.com.http"),
        &[],
    )
    .await
    .expect("the recording loads")
}

/// A Splunk instance (`connections:`) at `replay`, logging in as ace-rs with the secret
/// `splunk_<name>_password`, ace3's name for it.
fn splunk(replay: &HttpReplay, name: &str) -> Value {
    json!({
        "type": "splunk",
        "settings": {
            "host": "127.0.0.1",
            "base_url": replay.local_url(SPLUNKD),
            "username": "ace-rs",
            "request_timeout_seconds": 10,
        },
        "secrets": {"password": format!("splunk_{name}_password")},
    })
}

/// One instance's section: proxy_domain_lookup's settings (ace-mod-splunk's tests/common) with
/// its own query and summary, on the Splunk instance `splunk`.
fn instance(splunk: &str, summary: &str, query: &str) -> Value {
    json!({
        "inputs": ["fqdn"],
        "connections": {"splunk": splunk},
        "settings": {
            "question": "Was this domain seen?",
            "summary": summary,
            "query": query,
            "observable_mapping": [
                {"field": "src_ip", "type": "ip"},
                {"field": "user", "type": "email_address"},
            ],
        },
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_splunk_instances_run_different_queries_on_one_observable() {
    let (proxy, dns) = (splunkd().await, splunkd().await);
    // JSON is YAML, so the overlay goes through the same parser a site's file does
    let overlay = json!({
        "connections": {"proxy": splunk(&proxy, "proxy"), "dns": splunk(&dns, "dns")},
        "modules": {
            "splunk_api": {
                "instances": {
                    "proxy_domain_lookup": instance(
                        "proxy",
                        "Proxy correlation",
                        "index=proxy hostname=\"<O_VALUE>\"",
                    ),
                    "dns_domain_lookup": instance(
                        "dns",
                        "DNS correlation",
                        "index=dns query=\"<O_VALUE>\" | stats count by src_ip",
                    ),
                },
            },
        },
        "secrets": {
            "splunk_proxy_password": "env:ACE_RS_TEST_UNSET",
            "splunk_dns_password": "env:ACE_RS_TEST_UNSET",
        },
    });
    let overlay = Overlay::from_yaml(&overlay.to_string()).expect("the overlay loads");
    let registry = Registry::new().lookup::<SplunkAnalyzer>();
    let components = overlay
        .components(&registry.manifests())
        .expect("the overlay's components");
    let keys: Vec<&str> = components.iter().map(|c| c.key.as_str()).collect();
    assert_eq!(keys, ["dns_domain_lookup", "proxy_domain_lookup"]);

    let modes = Modes::ace3().with_mode(AnalysisMode {
        name: "test".to_owned(),
        module_groups: Vec::new(),
        enabled_modules: keys.iter().map(|k| (*k).to_owned()).collect(),
        disabled_modules: Vec::new(),
    });
    let core = Core::start_with(
        Catalog::of(components.clone()),
        modes,
        &keys,
        Duration::from_secs(30),
    )
    .await;

    let db = core.test_db.db();
    let root = NewRoot::new("test");
    let mut tx = db.begin().await.expect("begins");
    tree::create_root(&mut tx, &root).await.expect("creates");
    tree::upsert_observable(
        &mut tx,
        root.id,
        &NewObservable::new(ObservableKind::Fqdn, "www.example.com"),
    )
    .await
    .expect("adds");
    let queued = core
        .orchestrator
        .start(&mut tx, root.id)
        .await
        .expect("starts");
    tx.commit().await.expect("commits");
    assert_eq!(queued.len(), 2, "one task per instance");

    let secrets = Secrets::new()
        .with("splunk_proxy_password", Secret::new("ace-rs-fake-password"))
        .with("splunk_dns_password", Secret::new("ace-rs-fake-password"));
    let modules = registry
        .build(&components, &secrets)
        .expect("the pool's modules");
    let definition = PoolDefinition {
        name: "lookups".to_owned(),
        modules: Arc::new(modules),
        concurrency: 4,
        sandbox: Default::default(),
    };
    let client = LeaseClient::new(&core.url, TOKEN, "pool").expect("a client");
    let pool = AsyncPool::new(client, &definition).lease_wait(Duration::from_secs(1));
    let stop = CancellationToken::new();
    let running = tokio::spawn({
        let stop = stop.clone();
        async move { pool.run(stop).await }
    });
    wait_until_idle(&core, root.id, Duration::from_secs(60)).await;
    stop.cancel();
    let stats = running.await.expect("the pool stops");
    println!("{stats:?}");

    // one task per instance, both on the fqdn: the ips and email addresses the searches added
    // aren't among the instances' inputs
    let tasks = core.tasks(root.id).await;
    println!("{tasks:#?}");
    let mut tasks: Vec<_> = tasks
        .iter()
        .map(|(module, value, state)| format!("{module} {value} {state}"))
        .collect();
    tasks.sort();
    assert_eq!(
        tasks,
        [
            "dns_domain_lookup www.example.com done",
            "proxy_domain_lookup www.example.com done",
        ]
    );

    // two result rows on the one observable, each under its instance, each with its own query
    let results: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT r.module, r.analysis_type, r.details->>'query', r.summary
         FROM analysis.results r JOIN analysis.observables o ON o.id = r.observable_id
         WHERE r.root_id = $1 AND o.value = 'www.example.com' ORDER BY r.module",
    )
    .bind(root.id)
    .fetch_all(db.pool())
    .await
    .expect("reads the results");
    println!("{results:#?}");
    assert_eq!(
        results,
        [
            (
                "dns_domain_lookup".to_owned(),
                "splunk_api_analysis".to_owned(),
                Some("index=dns query=\"www.example.com\" | stats count by src_ip".to_owned()),
                Some("DNS correlation: (3 results)".to_owned()),
            ),
            (
                "proxy_domain_lookup".to_owned(),
                "splunk_api_analysis".to_owned(),
                Some("index=proxy hostname=\"www.example.com\"".to_owned()),
                Some("Proxy correlation: (3 results)".to_owned()),
            ),
        ]
    );

    // each instance's search went to its own splunkd, with its own text
    for (replay, text) in [
        (&proxy, "search index=proxy hostname=\"www.example.com\""),
        (
            &dns,
            "search index=dns query=\"www.example.com\" | stats count by src_ip",
        ),
    ] {
        let submitted: Vec<String> = replay
            .requests()
            .iter()
            .filter(|r| r.method == "POST" && r.url.ends_with("/search/v2/jobs/"))
            .map(|r| form_value(&r.body, "search").unwrap_or_default())
            .collect();
        assert_eq!(submitted, [text]);
        assert!(replay.unmatched().is_empty(), "{:?}", replay.unmatched());
    }
}

/// One field of a form-encoded body.
fn form_value(body: &[u8], name: &str) -> Option<String> {
    form_urlencoded::parse(body)
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}
