//! PLAN.md 2.22's Done check: one task's spans appear together in the collector. The pool is the
//! test pool, contained, in a process of its own; the core is this test process. Both export
//! spans to the telemetry profile's collector, and the task's spans from both land in one trace,
//! each carrying the task id. Needs `docker compose --profile telemetry up -d --wait collector`.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use ace_pool::testing;
use ace_sdk::http::HttpClient;
use chrono::Utc;
use serde_json::Value;

use common::{Core, PoolProcess, root_with_tasks, test_pool, wait_until_idle};

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} isn't set; this test runs in the dev container with the telemetry profile")
    })
}

/// Every span in a v3 query answer, as (service, name, trace id, task attribute).
fn spans(answer: &Value) -> Vec<(String, String, String, Option<String>)> {
    let mut found = Vec::new();
    let resources = answer["result"]["resourceSpans"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for resource in resources {
        let service = resource["resource"]["attributes"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|a| a["key"] == "service.name")
            .and_then(|a| a["value"]["stringValue"].as_str())
            .unwrap_or_default()
            .to_owned();
        for scope in resource["scopeSpans"].as_array().into_iter().flatten() {
            for span in scope["spans"].as_array().into_iter().flatten() {
                let task = span["attributes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|a| a["key"] == "task")
                    .map(|a| {
                        let value = &a["value"];
                        value["intValue"]
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| value["intValue"].to_string())
                    });
                found.push((
                    service.clone(),
                    span["name"].as_str().unwrap_or_default().to_owned(),
                    span["traceId"].as_str().unwrap_or_default().to_owned(),
                    task,
                ));
            }
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_tasks_spans_appear_together_in_the_collector() {
    let endpoint = var("ACE_RS_TEST_OTLP_ENDPOINT");
    let traces = var("ACE_RS_TEST_TRACES_URL");
    let mut telemetry = ace_pool::telemetry::init("ace-rs-core-test", "info");
    telemetry.export_to(&endpoint).expect("exports spans");
    let started = Utc::now();

    let core = Core::start(
        testing::test_manifests(),
        &["test_panicky"],
        Duration::from_secs(30),
    )
    .await;
    let root = root_with_tasks(&core, &["fine.example.com".to_owned()], "test_panicky").await;
    let task: i64 = sqlx::query_scalar("SELECT id FROM queue.tasks WHERE root_id = $1")
        .bind(root)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the task");
    let mut pool = test_pool(&core, &["lookups", "--contained"]);
    pool.env("ACE_RS_OTLP_ENDPOINT", &endpoint);
    let mut pool = PoolProcess::start(pool);
    wait_until_idle(&core, root, Duration::from_secs(60)).await;
    // a pool that stops on SIGTERM flushes its spans on the way out
    let stderr = pool.terminate(Duration::from_secs(10));
    assert!(stderr.contains("exporting spans"), "{stderr}");
    tokio::task::spawn_blocking(move || telemetry.flush())
        .await
        .expect("flushes");

    let http = HttpClient::builder().build().expect("a client");
    let search = format!(
        "{traces}/api/v3/traces?query.service_name=ace-rs-test-pool&query.start_time_min={}&query.start_time_max={}",
        started.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        (Utc::now() + chrono::TimeDelta::minutes(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
    );
    let task_text = task.to_string();
    let mut trace_id = None;
    for _ in 0..50 {
        let answer: Value = http
            .send(http.get(&search))
            .await
            .expect("queries the collector")
            .json()
            .await
            .unwrap_or_default();
        trace_id = spans(&answer)
            .into_iter()
            .find(|(_, name, _, t)| name == "pool.task" && t.as_deref() == Some(task_text.as_str()))
            .map(|(_, _, trace, _)| trace);
        if trace_id.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let trace_id = trace_id.expect("the task's pool span reached the collector");

    // the collector batches what it receives, so the core's spans may land a moment later
    let mut in_trace = Vec::new();
    for _ in 0..50 {
        let answer: Value = http
            .send(http.get(&format!("{traces}/api/v3/traces/{trace_id}")))
            .await
            .expect("fetches the trace")
            .json()
            .await
            .expect("a trace");
        in_trace = spans(&answer);
        if in_trace
            .iter()
            .any(|(service, _, _, _)| service == "ace-rs-core-test")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!("{in_trace:#?}");
    assert!(in_trace.iter().all(|(_, _, trace, _)| *trace == trace_id));
    let names: BTreeSet<(String, String)> = in_trace
        .iter()
        .map(|(service, name, _, _)| (service.clone(), name.clone()))
        .collect();
    for wanted in [
        ("ace-rs-test-pool", "pool.task"),
        ("ace-rs-test-pool", "fetch_input"),
        ("ace-rs-test-pool", "task"),
        ("ace-rs-test-pool", "send_end"),
        ("ace-rs-core-test", "lease_api"),
    ] {
        assert!(
            names.contains(&(wanted.0.to_owned(), wanted.1.to_owned())),
            "{wanted:?} in {names:?}"
        );
    }
    // the module's span carries the task id beside 1.22's identifiers, and so does the core's
    for (service, name) in [
        ("ace-rs-test-pool", "task"),
        ("ace-rs-core-test", "lease_api"),
    ] {
        assert!(
            in_trace.iter().any(|(s, n, _, t)| s == service
                && n == name
                && t.as_deref() == Some(task_text.as_str())),
            "{service} {name} carries task {task}"
        );
    }
}
