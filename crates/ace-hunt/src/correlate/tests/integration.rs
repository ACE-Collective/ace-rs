//! `test_integration.py`: 9 cases; the 2 whose executable ran a one-liner run [`super::Echo`].

use std::sync::Arc;

use serde_json::{Value as Json, json};

use super::{Fixture, TestSource, config, echo_path, evs, hunt, js, logic, predefined, time, utc};

fn ids(events: &[crate::value::Map], key: &str) -> Vec<Json> {
    events.iter().map(|e| js(e)[key].clone()).collect()
}

#[test]
fn test_full_pipeline_filter_and_alert() {
    let config = config(
        json!([
            {"when": {"type": "glob", "value": "*.internal.corp", "property": "hostname"},
             "execute": [{"action": "filter"}]},
            {"when": {"type": "regex", "value": "admin|root", "property": "username"},
             "execute": [{"action": {"type": "alert", "queue": "high_priority"}}]},
        ]),
        "5m",
    );
    let result = Fixture::default().simple(
        &config,
        evs(json!([
            {"hostname": "web1.internal.corp", "username": "admin"},
            {"hostname": "external.evil.com", "username": "admin"},
            {"hostname": "external.evil.com", "username": "guest"},
            {"hostname": "db.internal.corp", "username": "root"},
        ])),
    );
    assert_eq!(
        ids(&result.events, "username"),
        [json!("admin"), json!("guest")]
    );
    assert_eq!(
        result.event_actions[&1].queue_override.as_deref(),
        Some("high_priority")
    );
}

#[test]
fn test_predefined_command_with_executable() {
    let predef = [predefined(
        json!({"name": "enrich_user", "type": "executable", "path": echo_path(),
        "args": ["print", "default"]}),
    )];
    let config = logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "enrichment",
        "command": {"type": "defined", "name": "enrich_user",
            "arguments": {"args": ["print", "enriched_{{ _event.user }}"]}}}}]),
    );
    let f = Fixture::default();
    let start = *f.now.lock().expect("clock");
    let result = f.run(
        &config,
        &predef,
        crate::correlate::engine::HuntRun::at(start),
        evs(json!([{"user": "admin"}, {"user": "guest"}])),
    );
    assert_eq!(
        ids(&result.events, "enrichment"),
        [json!("enriched_admin"), json!("enriched_guest")]
    );
}

#[test]
fn test_condition_with_nested_logic() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "high", "property": "severity"},
        "execute": [{
            "when": {"type": "equals", "value": "admin", "property": "user"},
            "execute": [{"action": {"type": "alert", "queue": "critical"}}],
            "else": [{"action": {"type": "alert", "queue": "high"}}],
        }],
        "else": [{"action": "filter"}],
    }]));
    let result = Fixture::default().simple(
        &config,
        evs(json!([
            {"severity": "high", "user": "admin"},
            {"severity": "high", "user": "guest"},
            {"severity": "low", "user": "admin"},
        ])),
    );
    assert_eq!(result.events.len(), 2);
    assert_eq!(
        result.event_actions[&0].queue_override.as_deref(),
        Some("critical")
    );
    assert_eq!(
        result.event_actions[&1].queue_override.as_deref(),
        Some("high")
    );
}

#[test]
fn test_stop_preserves_earlier_alerts() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "stop", "property": "cmd"},
        "execute": [{"action": "stop"}],
    }]));
    let result = Fixture::default().simple(
        &config,
        evs(json!([
            {"cmd": "continue", "id": 1},
            {"cmd": "continue", "id": 2},
            {"cmd": "stop", "id": 3},
            {"cmd": "continue", "id": 4},
        ])),
    );
    assert_eq!(ids(&result.events, "id"), [json!(1), json!(2)]);
}

#[test]
fn test_stream_mutate_transform() {
    let config = logic(json!([{"transform": {"type": "stream", "method": "mutate",
        "command": {"type": "executable", "path": echo_path(),
            "args": ["print", "{\"new\": 1}\n{\"new\": 2}"]}}}]));
    let result =
        Fixture::default().simple(&config, evs(json!([{"old": 1}, {"old": 2}, {"old": 3}])));
    let events: Vec<Json> = result.events.iter().map(js).collect();
    assert_eq!(events, [json!({"new": 1}), json!({"new": 2})]);
}

#[test]
fn test_stream_merge_transform() {
    // ace3's MockQuerySource here declares no default time field
    let mut source = TestSource::rows(json!([{"ts": "1500", "src": "merged"}]));
    source.field = None;
    source.format = None;
    let f = Fixture::default().source("splunk", Arc::new(source));
    let config = logic(json!([{"transform": {"type": "stream", "method": "merge",
        "merge_time_spec": {"l_field": "ts", "l_format": "epoch", "r_field": "ts", "r_format": "epoch"},
        "command": {"type": "query", "source": "splunk", "query": "search all", "time_range": {"before": "1h"}}}}]));
    let result = f.simple(
        &config,
        evs(json!([{"ts": "1000", "src": "original1"}, {"ts": "2000", "src": "original2"}])),
    );
    assert_eq!(
        ids(&result.events, "src"),
        [json!("original1"), json!("merged"), json!("original2")]
    );
    assert!(
        result
            .trace
            .stream_events
            .iter()
            .any(|s| s.event_type == "stream_reset")
    );
    let triggering = &result.trace.event_traces[0];
    assert_eq!(triggering.outcome, "stream_reset");
    let t = triggering.steps[0].step.transform().expect("a transform");
    assert_eq!(t.method, "merge");
    assert_eq!(t.result_count, Some(1));
    assert_eq!(t.merge_dropped, Some(0));
}

#[test]
fn test_secrets_not_bound_in_jinja_condition() {
    // `is undefined` is asserted, not just a false condition, which an error would also give
    let config =
        logic(json!([{"when": "{{ _secrets is undefined }}", "execute": [{"action": "filter"}]}]));
    let f = Fixture::default().secrets(&["secret_value"]);
    let result = f.simple(&config, evs(json!([{"id": 1}])));
    assert!(result.events.is_empty());
}

#[test]
fn test_config_not_bound_in_jinja_condition() {
    let config =
        logic(json!([{"when": "{{ _config is undefined }}", "execute": [{"action": "filter"}]}]));
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    assert!(result.events.is_empty());
}

#[test]
fn test_splunk_hunt_omits_relative_time_field_uses_default() {
    // the query's time range omits its field and format, and the splunk source's defaults anchor
    // it to the event's `_time`, not the hunt's window in 2099
    let splunk = TestSource::new(json!([{"matched": true}]));
    let f = Fixture::default().source("splunk", splunk.clone());
    let config = config(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "context",
            "property_type": "list",
            "command": {"type": "query", "source": "splunk", "query": "search context lookup",
                        "time_range": {"before": "1h", "after": "1h"}}}}]),
        "5m",
    );
    let result = f.run(
        &config,
        &[],
        hunt(utc("2099-01-01T00:00:00+00:00"), "splunk"),
        evs(json!([{"_time": "2024-06-01T12:00:00+00:00", "host": "web1"}])),
    );
    let calls = splunk.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].start, time("2024-06-01T11:00:00+00:00"));
    assert_eq!(calls[0].end, time("2024-06-01T13:00:00+00:00"));
    assert_eq!(js(&result.events[0])["context"], json!([{"matched": true}]));
}
