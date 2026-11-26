//! PLAN.md 1.28: the delay loop against the Splunk REST API ace3 talked to, replayed from the
//! recordings beside the reference dumps (tools/ace3/dumps/reference/proxy_domain_lookup/). A
//! search that finishes gives delays and then a result; one that never finishes times out.
//! Nothing here reaches a real Splunk.

use crate::common;

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
        Outcome::DoneNotKept(result) => format!("done, not kept {:?}", result.summary),
        Outcome::DoneKeptFor(result, ttl) => format!("done, kept for {ttl:?} {:?}", result.summary),
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
    assert_eq!(body(0), "username=ace-rs&password=ace-rs-fake-password");
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

// ---- named time ranges, pivot links and required directives (PLAN.md decisions 52 and 53) ----

/// Where the hand-written recordings reach Splunk.
const EXAMPLE_SPLUNKD: &str = "https://splunk.example.com:8089";

/// The hand-written recordings in `tests/recordings/`, made up in the shape of splunkd's answers.
async fn example(name: &str) -> HttpReplay {
    HttpReplay::start(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/recordings/{name}.http")),
        &[],
    )
    .await
    .expect("the recording loads")
}

/// An example instance's settings on the replay's Splunk, its time range `before` the anchor and a
/// minute after, on the index's time.
fn example_search(replay: &HttpReplay, query: &str, before: &str) -> Value {
    json!({
        "splunk": {
            "host": "splunk.example.com",
            "base_url": replay.local_url(EXAMPLE_SPLUNKD),
            "timezone": "GMT",
            "request_timeout_seconds": 10,
        },
        "question": "Are there any recent tickets?",
        "summary": "Example tickets",
        "query": query,
        "time_ranges": {"TIMESPEC": {"duration_before": before, "duration_after": "00:00:01:00"}},
        "use_index_time": true,
    })
}

/// The harness on a token, with the root's event time the recordings were written for.
fn example_harness(settings: &Value) -> Harness<SplunkAnalyzer> {
    let event_time = chrono::DateTime::parse_from_rfc3339("2026-11-02T12:00:00Z")
        .expect("a time")
        .with_timezone(&chrono::Utc);
    common::connected(
        Harness::with_settings(settings.clone())
            .expect("harness")
            .event_time(event_time),
        settings,
        TOKEN,
        "example-token",
    )
}

/// The `search` field of the job a replay was sent.
fn job_search(replay: &HttpReplay) -> String {
    let sent = replay.requests();
    let job = sent
        .iter()
        .find(|r| r.method == "POST" && r.url.ends_with("/search/v2/jobs/"))
        .expect("a job was submitted");
    form_urlencoded::parse(&job.body)
        .find(|(key, _)| key == "search")
        .map(|(_, value)| value.into_owned())
        .expect("a search")
}

/// The line the recording says the module should have sent, under its `NNN.request`.
fn recorded_search(name: &str, request: &str) -> String {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/recordings/{name}.http/{request}")),
    )
    .expect("the request reads");
    let lines: Vec<&str> = text.lines().collect();
    // the first line says how it's sent, and a line about the headers may close it
    lines[1..]
        .iter()
        .take_while(|line| !line.starts_with("headers:"))
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
}

const TICKETS_QUERY: &str = "index=example sourcetype=example:tickets <TIMESPEC> \"<O_VALUE>\"\n\
                             | dedup ticket\n\
                             | table ticket assigned_to description updated link search_link term\n\
                             | sort -updated";

#[tokio::test]
async fn a_time_range_is_filled_once_and_ticket_links_go_on_the_alert_up_to_their_limit() {
    let replay = example("tickets_overflow").await;
    let mut settings = example_search(&replay, TICKETS_QUERY, "07:00:00:00");
    settings["pivot_links"] = json!([{
        "url": "{{ link }}",
        "text": "Ticket {{ ticket }} on {{ term }} ({{ description | truncate(80) }})",
        "icon": "servicenow",
        "limit": 5,
        "overflow": {
            "url": "{{ search_link }}",
            "text": "More ticket results ({{ overflow_count }} more)",
        },
    }]);
    let harness = example_harness(&settings);
    let (delays, outcome) = run_through_delays(
        &harness,
        harness.observable(ObservableKind::EmailAddress, "alice@example.com"),
    )
    .await;
    assert!(!delays.is_empty(), "the job runs on the first poll");
    // the query, with the window around the root's event time, kept in the delay's state
    for delay in &delays {
        let Outcome::Delay(delay) = delay else {
            panic!("a delay");
        };
        assert!(
            delay.state["query"]
                .as_str()
                .is_some_and(|q| q.contains("_index_earliest = 10/26/2026:12:00:00")),
            "{}",
            delay.state
        );
    }
    assert_eq!(
        job_search(&replay),
        recorded_search("tickets_overflow", "002.request")
    );
    let Outcome::Done(result) = outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert_eq!(
        result.summary.as_deref(),
        Some("Example tickets: (8 results)")
    );
    assert!(result.pivot_links.is_empty(), "the links go on the alert");
    let root = result.root.expect("links on the root");
    assert!(root.description.is_none() && root.details.is_none());
    let links: Vec<String> = root
        .pivot_links
        .iter()
        .map(|l| format!("{} | {} | {:?}", l.url, l.text, l.icon))
        .collect();
    let ticket = |id: &str, text: &str| {
        format!(
            "https://tickets.example.com/ticket.do?id=0000000000000000000000000000{id} | {text} | Some(\"servicenow\")"
        )
    };
    // row 3 repeats row 1, and row 5's http:// link is dropped before the limit counts it
    assert_eq!(
        links,
        [
            ticket(
                "03e9",
                "Ticket TKT0001001 on alice (Laptop replacement for alice)"
            ),
            ticket(
                "03ea",
                "Ticket TKT0001002 on alice (Password reset after lockout)"
            ),
            ticket(
                "03eb",
                "Ticket TKT0001003 on alice (VPN access request with a long justification that runs past eighty...)"
            ),
            links[3].clone(),
            links[4].clone(),
            "https://tickets.example.com/search.do?q=alice | More ticket results (1 more) | Some(\"servicenow\")"
                .to_owned(),
        ]
    );
    assert!(
        !links[3].contains("03ec") && !links[4].contains("03ec"),
        "{links:#?}"
    );
    assert!(replay.unmatched().is_empty(), "{:?}", replay.unmatched());
}

#[tokio::test]
async fn a_time_range_on_a_site_s_type_maps_its_rows_and_no_rows_give_no_links() {
    let replay = example("risk_mapping").await;
    let mut settings = example_search(
        &replay,
        "index=example sourcetype=example:risk <TIMESPEC> <O_VALUE> (riskLevel IN (\"low\",\"medium\",\"high\"))\n\
         | table _time userPrincipalName ipAddress related_client_ip user_agent riskLevel riskEventType",
        "30:00:00:00",
    );
    settings["observable_mapping"] = json!([
        {"field": "userPrincipalName", "type": "email_address", "ignored_values": [""]},
        {"field": "ipAddress", "type": "ip", "ignored_values": [""]},
        {"field": "related_client_ip", "type": "ip", "ignored_values": [""]},
        {"field": "user_agent", "type": "user_agent", "ignored_values": [""]},
    ]);
    let harness = example_harness(&settings);
    let (_, outcome) = run_through_delays(
        &harness,
        harness.observable(ObservableKind::User, "0b6c2c56-1d1e-4f7a-9d3e-6a2f00000001"),
    )
    .await;
    assert_eq!(
        job_search(&replay),
        recorded_search("risk_mapping", "002.request")
    );
    let Outcome::Done(result) = outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert_eq!(
        result.summary.as_deref(),
        Some("Example tickets: (3 results)")
    );
    let observables: Vec<String> = result
        .observables
        .iter()
        .map(|o| format!("{}:{}", o.kind, o.value))
        .collect();
    assert_eq!(
        observables,
        [
            "email_address:alice@example.com",
            "ip:203.0.113.45",
            "user_agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "ip:198.51.100.77",
            "ip:198.51.100.78",
            "user_agent:curl/8.5.0",
        ]
    );

    let replay = example("asset_no_rows").await;
    let mut settings = example_search(
        &replay,
        "index=example sourcetype=example:tickets <TIMESPEC>\n    [ | makeresults\n      | eval search = \"\\\"\" . mvindex(split(\"<O_VALUE>\",\".\"),0) . \"\\\"\"\n      | fields search ]\n| eval term=mvindex(split(\"<O_VALUE>\",\".\"),0)\n| where len(term) > 4\n| dedup ticket\n| table ticket assigned_to description updated link search_link term",
        "30:00:00:00",
    );
    settings["pivot_links"] = json!([{"url": "{{ link }}", "text": "{{ ticket }}", "limit": 5,
                                     "overflow": {"url": "{{ search_link }}", "text": "more"}}]);
    let harness = example_harness(&settings);
    let (_, outcome) = run_through_delays(
        &harness,
        harness.observable(ObservableKind::Hostname, "ws01.example.com"),
    )
    .await;
    assert_eq!(
        job_search(&replay),
        recorded_search("asset_no_rows", "002.request")
    );
    let Outcome::Done(result) = outcome else {
        panic!("expected a result, got {outcome:?}");
    };
    assert_eq!(result.summary, None, "no rows, no summary");
    assert!(result.root.is_none() && result.pivot_links.is_empty());
}

#[test]
fn an_instance_takes_any_type_needs_its_directives_and_refuses_what_it_cant_fill() {
    use ace_sdk::Module;
    let manifest = ace_mod_splunk::MANIFEST;
    assert!(manifest.any_input && manifest.accepts(ObservableKind::FileLocation));
    assert!(manifest.adds_root_pivot_links && manifest.reads_event_time);
    let settings = |extra: Value| {
        let mut settings = json!({
            "splunk": {"host": "splunk.example.com"},
            "query": "index=x <O_VALUE> <TIMESPEC>",
            "time_ranges": {"TIMESPEC": "01:00:00"},
        });
        for (key, value) in extra.as_object().expect("an object") {
            settings[key] = value.clone();
        }
        serde_json::from_value::<ace_mod_splunk::SplunkSettings>(settings).expect("settings")
    };
    assert!(SplunkAnalyzer::init(&settings(json!({}))).is_ok());
    let refused = |extra: Value| match SplunkAnalyzer::init(&settings(extra)) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("refused"),
    };
    assert!(refused(json!({"time_ranges": {}})).contains("<TIMESPEC>"));
    assert!(refused(json!({"query": "index=x <O_TIMESPEC>"})).contains("<O_TIMESPEC>"));
    assert!(refused(json!({"time_ranges": {"TIMESPEC": "soon"}})).contains("TIMESPEC"));
    assert!(
        refused(json!({"pivot_links": [{"url": "{{ a }}", "text": "a",
                                        "icon": "data:image/png;base64,AA=="}]}))
        .contains("App::pivot_link_icon")
    );

    // required_directives: its declaration declines an observable without each of them
    let declaration = manifest
        .declaration(Some(
            &json!({"query": "x", "required_directives": ["pivot_on_ip"]}),
        ))
        .expect("a declaration");
    assert!(!declaration.is_everything());
    let described = declaration.describe().to_string();
    assert!(described.contains("pivot_on_ip"), "{described}");
    assert!(
        manifest
            .declaration(Some(&json!({"query": "x"})))
            .expect("a declaration")
            .is_everything()
    );
}
