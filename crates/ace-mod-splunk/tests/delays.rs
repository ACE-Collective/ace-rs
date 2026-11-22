//! PLAN.md 1.28: the delay loop against the Splunk REST API ace3 talked to, replayed from the
//! recordings beside the reference dumps (tools/ace3/dumps/reference/proxy_domain_lookup/). A
//! search that finishes gives delays and then a result; one that never finishes times out.
//! Nothing here reaches a real Splunk.

mod common;

use std::path::Path;
use std::time::Duration;

use ace_mod_splunk::SplunkAnalyzer;
use ace_mod_splunk::connection::TOKEN;
use ace_results::ObservableKind;
use ace_results::types::splunk::SplunkApiAnalysis;
use ace_sdk::{ModuleError, Outcome};
use ace_testkit::reference::dumps_dir;
use ace_testkit::replay::HttpReplay;
use ace_testkit::{Harness, HarnessError};
use serde_json::{Value, json};

use common::{SPLUNKD, proxy_domain_lookup, run_through_delays};

async fn replay(dump: &str) -> HttpReplay {
    HttpReplay::start(
        &dumps_dir().join(format!("proxy_domain_lookup/{dump}.http")),
        &[],
    )
    .await
    .expect("the recording loads")
}

fn harness(settings: Value) -> Harness<SplunkAnalyzer> {
    common::logged_in(
        Harness::with_settings(settings.clone()).expect("harness"),
        &settings,
    )
}

/// A delay's dispatch state, from what it left for the next run.
fn dispatch_state(outcome: &Outcome<SplunkApiAnalysis>) -> String {
    match outcome {
        Outcome::Delay(delay) => format!(
            "delay {:?} {}",
            delay.run_after,
            delay.state["dispatch_state"]
                .as_str()
                .unwrap_or("submitted")
        ),
        Outcome::Done(result) => format!("done {:?}", result.summary),
        Outcome::Incomplete(result) => format!("incomplete {:?}", result.summary),
        Outcome::Skipped(why) => format!("skipped {why}"),
    }
}

/// Each request as `METHOD path`.
fn requests(replay: &HttpReplay) -> Vec<String> {
    replay
        .requests()
        .iter()
        .map(|r| format!("{} {}", r.method, r.url.trim_start_matches(SPLUNKD)))
        .collect()
}

#[tokio::test]
async fn a_search_is_delayed_while_it_runs_and_then_gives_its_rows() {
    let replay = replay("fqdn_www.example.com").await;
    let harness = harness(proxy_domain_lookup(&replay.local_url(SPLUNKD)));
    let (delays, outcome) = run_through_delays(
        &harness,
        harness.observable(ObservableKind::Fqdn, "www.example.com"),
    )
    .await;

    let seen: Vec<String> = delays.iter().map(dispatch_state).collect();
    println!("{seen:#?}\n{}", dispatch_state(&outcome));
    assert_eq!(
        seen,
        [
            "delay 1s submitted",
            "delay 1s RUNNING",
            "delay 1s RUNNING",
            "delay 1s RUNNING",
        ]
    );
    let Outcome::Done(result) = outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert_eq!(
        result.summary.as_deref(),
        Some("Proxy correlation: (3 results)")
    );
    assert_eq!(result.details.search_id.as_deref(), Some("1767225600.1"));
    assert_eq!(result.details.dispatch_state.as_deref(), Some("DONE"));
    assert_eq!(result.error, None);
    assert_eq!(result.details.query_results.as_ref().map(Vec::len), Some(3));
    let observables: Vec<String> = result
        .observables
        .iter()
        .map(|o| format!("{}:{}", o.kind, o.value))
        .collect();
    assert_eq!(
        observables,
        [
            "ip:192.0.2.10",
            "ip:198.51.100.7",
            "ip:198.51.100.20",
            "url:https://www.example.com/login",
            "email_address:alice@example.com",
            "ip:192.0.2.11",
            "url:http://www.example.com/",
            "email_address:bob@example.com",
            "ip:192.0.2.12",
            "ip:198.51.100.21",
            "url:https://www.example.com/static/app.js",
        ]
    );

    // one login, kept for every run; the job read once a poll; its rows and its deletion in the
    // namespace of its acl, as splunk-sdk does them
    assert_eq!(
        requests(&replay),
        [
            "POST /services/auth/login",
            "GET /services/server/info",
            "POST /services/search/v2/jobs/",
            "GET /services/search/v2/jobs/1767225600.1",
            "GET /services/search/v2/jobs/1767225600.1",
            "GET /services/search/v2/jobs/1767225600.1",
            "GET /services/search/v2/jobs/1767225600.1",
            "POST /servicesNS/nobody/search/search/v2/jobs/1767225600.1/results",
            "DELETE /servicesNS/nobody/search/search/v2/jobs/1767225600.1/",
        ]
    );
    assert!(replay.unmatched().is_empty(), "{:?}", replay.unmatched());
    let sent = replay.requests();
    // the same form ace3 sent
    let recorded: Value = serde_json::from_str(
        &std::fs::read_to_string(
            dumps_dir().join("proxy_domain_lookup/fqdn_www.example.com.http/http.json"),
        )
        .expect("the recording reads"),
    )
    .expect("the recording parses");
    let ace3_form = |method: &str, path: &str| {
        recorded["exchanges"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["method"] == method && e["url"] == format!("{SPLUNKD}{path}"))
            .and_then(|e| e["request_body"].as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let body = |i: usize| String::from_utf8_lossy(&sent[i].body).into_owned();
    assert_eq!(body(2), ace3_form("POST", "/services/search/v2/jobs/"));
    assert_eq!(
        body(7),
        ace3_form(
            "POST",
            "/servicesNS/nobody/search/search/v2/jobs/1767225600.1/results"
        )
    );
    assert_eq!(body(0), "username=ace4&password=ace4-fake-password");
    for request in &sent[1..] {
        assert_eq!(
            request.header("authorization"),
            Some("Splunk ace4-fake-session-0000000000000000"),
            "{} {}",
            request.method,
            request.url
        );
    }
}

#[tokio::test]
async fn a_search_that_never_finishes_times_out() {
    let replay = replay("fqdn_www.example.com.never-done").await;
    let mut settings = proxy_domain_lookup(&replay.local_url(SPLUNKD));
    // as make-dumps ran it
    settings["query_timeout"] = json!(3);
    let harness = harness(settings);
    let (delays, outcome) = run_through_delays(
        &harness,
        harness.observable(ObservableKind::Fqdn, "www.example.com"),
    )
    .await;

    let seen: Vec<String> = delays.iter().map(dispatch_state).collect();
    println!("{seen:#?}\n{}", dispatch_state(&outcome));
    assert_eq!(
        seen,
        ["delay 1s submitted", "delay 1s RUNNING", "delay 1s RUNNING",]
    );
    let Outcome::Done(result) = outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert_eq!(
        result.summary.as_deref(),
        Some("Proxy correlation: ERROR: timed out")
    );
    assert_eq!(result.error.as_deref(), Some("timed out"));
    assert_eq!(result.details.query_results, None);
    assert_eq!(result.details.dispatch_state.as_deref(), Some("RUNNING"));
    assert_eq!(result.details.end_time, None);
    assert!(result.observables.is_empty());
    // as in ace3, the job is left to splunkd
    assert!(
        !requests(&replay).iter().any(|r| r.starts_with("DELETE")),
        "{:?}",
        requests(&replay)
    );
    assert!(replay.unmatched().is_empty(), "{:?}", replay.unmatched());
}

#[tokio::test]
async fn a_correlation_delay_comes_before_the_search() {
    let replay = replay("fqdn_www.example.com").await;
    let mut settings = proxy_domain_lookup(&replay.local_url(SPLUNKD));
    settings["correlation_delay"] = json!("00:00:30");
    let harness = harness(settings);
    let observable = harness.observable(ObservableKind::Fqdn, "www.example.com");
    let Outcome::Delay(delay) = harness.run_lookup(observable.clone()).await.expect("runs") else {
        panic!("expected a delay");
    };
    assert_eq!(delay.run_after, Duration::from_secs(30));
    assert!(
        replay.requests().is_empty(),
        "nothing is sent before the delay"
    );

    let delayed = harness.after_delay(&delay, 1, Duration::from_secs(30));
    let outcome = harness
        .rerun_lookup(observable, delayed)
        .await
        .expect("runs");
    assert_eq!(dispatch_state(&outcome), "delay 1s submitted");
    assert_eq!(
        requests(&replay),
        [
            "POST /services/auth/login",
            "GET /services/server/info",
            "POST /services/search/v2/jobs/",
        ]
    );
}

#[tokio::test]
async fn the_query_timeout_counts_the_correlation_delay() {
    // ace3's query_start is before the correlation delay, so a delay as long as the timeout
    // leaves the search no time: it's submitted and then timed out
    let replay = replay("fqdn_www.example.com.never-done").await;
    let mut settings = proxy_domain_lookup(&replay.local_url(SPLUNKD));
    settings["correlation_delay"] = json!("5");
    settings["query_timeout"] = json!(5);
    let harness = harness(settings);
    let (delays, outcome) = run_through_delays(
        &harness,
        harness.observable(ObservableKind::Fqdn, "www.example.com"),
    )
    .await;
    assert_eq!(delays.len(), 1, "the correlation delay only");
    assert_eq!(
        dispatch_state(&outcome),
        "done Some(\"Proxy correlation: ERROR: timed out\")"
    );
}

#[tokio::test]
async fn a_job_splunkd_lost_is_submitted_again() {
    let replay = replay("fqdn_www.example.com").await;
    let harness = harness(proxy_domain_lookup(&replay.local_url(SPLUNKD)));
    let observable = harness.observable(ObservableKind::Fqdn, "www.example.com");
    let Outcome::Delay(mut delay) = harness.run_lookup(observable.clone()).await.expect("runs")
    else {
        panic!("expected a delay");
    };
    // a job id the recording has no status for: the replay answers 404
    delay.state["search_id"] = json!("1767225600.9");
    let outcome = harness
        .rerun_lookup(
            observable,
            harness.after_delay(&delay, 1, Duration::from_secs(1)),
        )
        .await
        .expect("runs");
    let Outcome::Delay(delay) = outcome else {
        panic!("expected a delay, got {outcome:?}");
    };
    assert_eq!(delay.state["search_id"], json!("1767225600.1"));
    assert_eq!(
        replay.unmatched(),
        [format!(
            "GET {SPLUNKD}/services/search/v2/jobs/1767225600.9"
        )]
    );
    assert_eq!(
        requests(&replay)[3..],
        [
            "GET /services/search/v2/jobs/1767225600.9",
            "GET /services/server/info",
            "POST /services/search/v2/jobs/",
        ]
    );
}

#[tokio::test]
async fn a_token_is_sent_as_splunks_session_header() {
    let replay = replay("fqdn_www.example.com").await;
    let mut settings = proxy_domain_lookup(&replay.local_url(SPLUNKD));
    settings["splunk"]
        .as_object_mut()
        .expect("an object")
        .remove("username");
    let harness = common::connected(
        Harness::<SplunkAnalyzer>::with_settings(settings.clone()).expect("harness"),
        &settings,
        TOKEN,
        "made-up-token",
    );
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "www.example.com"))
        .await
        .expect("runs");
    assert_eq!(dispatch_state(&outcome), "delay 1s submitted");
    let sent = replay.requests();
    assert_eq!(
        requests(&replay),
        [
            "GET /services/server/info",
            "POST /services/search/v2/jobs/"
        ],
        "no login"
    );
    for request in &sent {
        assert_eq!(
            request.header("authorization"),
            Some("Splunk made-up-token")
        );
    }
}

#[tokio::test]
async fn other_observable_types_are_skipped() {
    let harness = harness(proxy_domain_lookup("http://127.0.0.1:1"));
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::Ip, "192.0.2.1"))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
}

#[tokio::test]
async fn an_unreachable_splunkd_fails_the_task_so_it_runs_again() {
    // nothing listens on port 1
    let harness = harness(proxy_domain_lookup("http://127.0.0.1:1"));
    let error = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "www.example.com"))
        .await
        .expect_err("fails");
    assert!(
        matches!(error, HarnessError::Module(ModuleError::Unavailable(_))),
        "{error}"
    );
}

#[tokio::test]
async fn a_query_with_a_token_the_port_doesnt_fill_fails_at_init() {
    let mut settings = proxy_domain_lookup("http://127.0.0.1:1");
    settings["query"] = json!("index=proxy hostname=\"<O_VALUE>\" <O_TIMESPEC>");
    let error = Harness::<SplunkAnalyzer>::with_settings(settings)
        .err()
        .expect("init fails");
    assert!(error.to_string().contains("<O_TIMESPEC>"), "{error}");
}

/// A recording made up from the dump's, with `exchanges` in place of its own: (method, path,
/// status, body).
fn made_up_recording(dir: &Path, exchanges: &[(&str, &str, u16, &[u8])]) {
    let mut recorded = Vec::new();
    for (i, (method, path, status, body)) in exchanges.iter().enumerate() {
        let name = format!("{i:03}.body");
        std::fs::write(dir.join(&name), body).expect("writes");
        recorded.push(json!({
            "method": method,
            "url": format!("{SPLUNKD}{path}"),
            "status": status,
            "response_headers": {"Content-Type": "text/xml; charset=UTF-8"},
            "body_file": name,
        }));
    }
    std::fs::write(
        dir.join("http.json"),
        serde_json::to_vec(&json!({"exchanges": recorded})).expect("serializes"),
    )
    .expect("writes");
}

fn dump_body(index: &str) -> Vec<u8> {
    let dir = dumps_dir().join("proxy_domain_lookup/fqdn_www.example.com.http");
    let name = std::fs::read_dir(&dir)
        .expect("lists")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with(index))
        .expect("a body");
    std::fs::read(dir.join(name)).expect("reads")
}

#[tokio::test]
async fn a_search_splunkd_refuses_ends_with_its_message_as_the_error() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let refused = br#"<?xml version="1.0" encoding="UTF-8"?>
<response><messages><msg type="FATAL">Unknown search command 'nosuchcommand'.</msg></messages></response>"#;
    made_up_recording(
        dir.path(),
        &[
            ("POST", "/services/auth/login", 200, &dump_body("000")),
            ("GET", "/services/server/info", 200, &dump_body("001")),
            ("POST", "/services/search/v2/jobs/", 400, refused),
        ],
    );
    let replay = HttpReplay::start(dir.path(), &[]).await.expect("loads");
    let harness = harness(proxy_domain_lookup(&replay.local_url(SPLUNKD)));
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "www.example.com"))
        .await
        .expect("runs");
    let Outcome::Done(result) = outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    let error = "HTTP 500: Splunk search failed: HTTP 400 Bad Request -- Unknown search command 'nosuchcommand'.";
    assert_eq!(result.error.as_deref(), Some(error));
    assert_eq!(
        result.summary,
        Some(format!("Proxy correlation: ERROR: {error}"))
    );
}

#[tokio::test]
async fn an_expired_session_logs_in_again_once() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let expired = br#"<response><messages><msg type="WARN">call not properly authenticated</msg></messages></response>"#;
    made_up_recording(
        dir.path(),
        &[
            ("POST", "/services/auth/login", 200, &dump_body("000")),
            ("GET", "/services/server/info", 401, expired),
            ("GET", "/services/server/info", 200, &dump_body("001")),
            ("POST", "/services/search/v2/jobs/", 201, &dump_body("003")),
        ],
    );
    let replay = HttpReplay::start(dir.path(), &[]).await.expect("loads");
    let harness = harness(proxy_domain_lookup(&replay.local_url(SPLUNKD)));
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::Fqdn, "www.example.com"))
        .await
        .expect("runs");
    assert_eq!(dispatch_state(&outcome), "delay 1s submitted");
    assert_eq!(
        requests(&replay),
        [
            "POST /services/auth/login",
            "GET /services/server/info",
            "POST /services/auth/login",
            "GET /services/server/info",
            "POST /services/search/v2/jobs/",
        ]
    );
}
