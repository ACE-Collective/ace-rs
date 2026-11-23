//! `test_engine.py`: 18 cases; the one whose executable ran a one-liner runs [`super::Echo`]. ace3 patches the engine's
//! `datetime` to drive its timeout; here the run's clock is the fixture's, which a source moves.

use std::sync::Arc;

use chrono::TimeDelta;
use serde_json::{Value as Json, json};

use super::{Fixture, TestSource, ev, evs, hunt, js, logic, predefined, time, utc, v};
use crate::correlate::Command;
use crate::correlate::engine::{Engine, HuntRun};

#[test]
fn test_alert_action_with_overrides() {
    let config = logic(
        json!([{"action": {"type": "alert", "queue": "high_priority", "analysis_mode": "deep"}}]),
    );
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    assert_eq!(result.events.len(), 1);
    assert_eq!(
        result.event_actions[&0].queue_override.as_deref(),
        Some("high_priority")
    );
}

#[test]
fn test_default_alert() {
    // an event that falls through without an action alerts
    let config = logic(json!([{
        "when": {"type": "equals", "value": "special", "property": "type"},
        "execute": [{"action": {"type": "log", "log_message": "found special"}}],
    }]));
    let result = Fixture::default().simple(&config, evs(json!([{"type": "normal"}])));
    assert_eq!(result.events.len(), 1);
}

#[test]
fn test_multiple_conditions_sequential() {
    let config = logic(json!([
        {"when": {"type": "equals", "value": "noise", "property": "category"}, "execute": [{"action": "filter"}]},
        {"when": {"type": "equals", "value": "critical", "property": "severity"},
         "execute": [{"action": {"type": "alert", "queue": "critical"}}]},
    ]));
    let result = Fixture::default().simple(
        &config,
        evs(json!([
            {"category": "noise", "severity": "low"},
            {"category": "alert", "severity": "critical"},
            {"category": "alert", "severity": "low"},
        ])),
    );
    assert_eq!(result.events.len(), 2);
    // the critical event has the queue override, by its index in the stream
    assert_eq!(
        result.event_actions[&1].queue_override.as_deref(),
        Some("critical")
    );
}

#[test]
fn test_empty_events() {
    let config = logic(json!([{"action": "alert"}]));
    let result = Fixture::default().simple(&config, Vec::new());
    assert!(result.events.is_empty());
    assert!(!result.discarded);
}

#[test]
fn test_alert_event_origin_indices_tracks_pre_correlation_index() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "drop", "property": "tag"},
        "execute": [{"action": "filter"}],
    }]));
    let result = Fixture::default().simple(
        &config,
        evs(json!([{"id": 1, "tag": "keep"}, {"id": 2, "tag": "drop"}, {"id": 3, "tag": "keep"}])),
    );
    let ids: Vec<Json> = result.events.iter().map(|e| js(e)["id"].clone()).collect();
    assert_eq!(ids, [json!(1), json!(3)]);
    assert_eq!(result.origins, [0, 2]);
    for origin in &result.origins {
        let trace = result
            .trace
            .event_traces
            .iter()
            .find(|t| t.event_index == *origin)
            .expect("a trace");
        assert_eq!(trace.outcome, "alert");
    }
}

#[test]
fn test_missing_default_field_routes_event_to_alert_with_error() {
    let splunk = TestSource::new(json!([]));
    let f = Fixture::default().source("splunk", splunk.clone());
    let config = logic(json!([{"transform": {
        "type": "event", "method": "property", "property_name": "lookup",
        "command": {"type": "query", "source": "splunk", "query": "search index=main",
                    "time_range": {"before": "1h", "after": "1h"}},
    }}]));
    // the event lacks the default `_time` field
    let result = f.run(
        &config,
        &[],
        hunt(utc("2024-06-01T12:00:00+00:00"), "splunk"),
        evs(json!([{"host": "web1"}])),
    );
    // the query never ran: resolving its window failed
    assert!(splunk.calls().is_empty());
    assert_eq!(result.trace.event_traces.len(), 1);
    assert_eq!(result.trace.event_traces[0].outcome, "error");
    // the event still alerts, the fail-safe policy for an error
    assert_eq!(result.events.len(), 1);
    // the error path still stamps durations: the event's and the failing step's
    assert!(result.trace.event_traces[0].duration_ms.is_some());
    assert!(result.trace.event_traces[0].steps[0].duration_ms.is_some());
}

#[test]
fn test_stream_mutate_query_switches_current_source() {
    let splunk = TestSource::new(json!([{"_time": "2099-01-01T00:00:00+00:00"}]));
    let mut epoch = TestSource::rows(json!([{"ts": "1717200000"}])); // 2024-06-01 00:00:00 UTC
    epoch.field = Some("ts");
    epoch.format = Some("epoch");
    let epoch = Arc::new(epoch);
    let f = Fixture::default()
        .source("splunk", splunk.clone())
        .source("epoch_src", epoch);
    // a stream mutate against epoch_src replaces the stream and makes it the current source, so
    // the next event transform's default field is `ts`, read as an epoch
    let config = logic(json!([
        {"transform": {"type": "stream", "method": "mutate",
            "command": {"type": "query", "source": "epoch_src", "query": "epoch search", "time_range": {"before": "1h"}}}},
        {"transform": {"type": "event", "method": "property", "property_name": "context",
            "command": {"type": "query", "source": "splunk", "query": "search lookup",
                        "time_range": {"before": "30m", "after": "30m"}}}},
    ]));
    f.run(
        &config,
        &[],
        hunt(utc("2024-06-01T12:00:00+00:00"), "splunk"),
        evs(json!([{"_time": "2024-05-31T00:00:00+00:00"}])),
    );
    let calls = splunk.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].start, time("2024-05-31T23:30:00+00:00"));
    assert_eq!(calls[0].end, time("2024-06-01T00:30:00+00:00"));
}

#[test]
fn test_stream_transform_query_anchored_to_hunt_window() {
    // a stream transform's window is the hunt's, `before` before its start and `after` after its
    // end, not the clock or an event's time
    let splunk = TestSource::new(json!([]));
    let f = Fixture::default().source("splunk", splunk.clone());
    let config = logic(json!([{"transform": {"type": "stream", "method": "mutate",
        "command": {"type": "query", "source": "splunk", "query": "search index=main",
                    "time_range": {"before": "3h", "after": "1h"}}}}]));
    let mut run = hunt(utc("2026-05-04T00:00:00+00:00"), "splunk");
    run.end = Some(time("2026-05-05T00:00:00+00:00"));
    let result = f.run(
        &config,
        &[],
        run,
        evs(json!([{"_time": "2099-01-01T00:00:00+00:00"}])),
    );
    let calls = splunk.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].start, time("2026-05-03T21:00:00+00:00"));
    assert_eq!(calls[0].end, time("2026-05-05T01:00:00+00:00"));
    // the trace records the same window, on the triggering event's trace, which survives the reset
    let transform = result.trace.event_traces[0].steps[0]
        .step
        .transform()
        .expect("a transform");
    assert_eq!(
        transform.query_start_time,
        Some(time("2026-05-03T21:00:00+00:00"))
    );
    assert_eq!(
        transform.query_end_time,
        Some(time("2026-05-05T01:00:00+00:00"))
    );
    assert_eq!(transform.query_time_spec, None);
}

#[test]
fn test_stream_merge_preserves_triggering_trace() {
    // the trace of the event that triggered a stream transform survives its reset: it's the only
    // record of the transform's rendered command, result count and merge_dropped
    let splunk = TestSource::new(json!([
        {"ts": "1717200000", "data": "new1"},
        {"data": "no_timestamp"},
    ]));
    let f = Fixture::default().source("splunk", splunk);
    let config = logic(json!([{"transform": {"type": "stream", "method": "merge",
        "merge_time_spec": {"l_field": "ts", "l_format": "epoch", "r_field": "ts", "r_format": "epoch"},
        "command": {"type": "query", "source": "splunk", "query": "search host={{ _event.host }}",
                    "time_range": {"before": "1h"}}}}]));
    let result = f.run(
        &config,
        &[],
        hunt(utc("2024-06-01T12:00:00+00:00"), "splunk"),
        evs(json!([{"ts": "1717100000", "host": "web1", "id": 1}])),
    );
    // one existing and one new event with a time
    assert_eq!(result.events.len(), 2);
    assert!(
        result
            .trace
            .stream_events
            .iter()
            .any(|s| s.event_type == "stream_reset")
    );
    let triggering = &result.trace.event_traces[0];
    assert_eq!(triggering.outcome, "stream_reset");
    assert_eq!(triggering.steps.len(), 1);
    let step = triggering.steps[0].step.transform().expect("a transform");
    assert_eq!(step.transform_type, "stream");
    assert_eq!(step.method, "merge");
    assert_eq!(step.rendered_command.as_deref(), Some("search host=web1"));
    assert_eq!(step.result_count, Some(2));
    assert_eq!(step.merge_dropped, Some(1));
}

#[test]
fn test_resolve_command_source_handles_defined_query() {
    let f = Fixture::default().source("splunk", TestSource::new(json!([])));
    let config = logic(json!([]));
    let query = [predefined(
        json!({"name": "splunk_lookup", "type": "query", "source": "splunk", "query": "search foo"}),
    )];
    let defined = Command::from_value(&v(json!({"type": "defined", "name": "splunk_lookup"})))
        .expect("valid");
    let source = f.with(|rt| {
        Engine::new(
            rt,
            &config,
            &query,
            hunt(utc("2024-06-01T12:00:00+00:00"), "splunk"),
        )
        .command_source(&defined)
    });
    assert_eq!(source.as_deref(), Some("splunk"));
    // a defined executable has no source, so a stream mutate doesn't switch to one
    let executable = [predefined(
        json!({"name": "ext", "type": "executable", "path": "/bin/true"}),
    )];
    let defined =
        Command::from_value(&v(json!({"type": "defined", "name": "ext"}))).expect("valid");
    let source = f.with(|rt| {
        Engine::new(
            rt,
            &config,
            &executable,
            hunt(utc("2024-06-01T12:00:00+00:00"), "splunk"),
        )
        .command_source(&defined)
    });
    assert_eq!(source, None);
}

#[test]
fn test_event_query_captures_event_anchored_time_range() {
    let f = Fixture::default().source("splunk", TestSource::new(json!([])));
    let config = logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "lookup",
        "command": {"type": "query", "source": "splunk", "query": "search index=main",
                    "time_range": {"before": "30d", "after": "0s"}}}}]),
    );
    let result = f.run(
        &config,
        &[],
        hunt(utc("2026-05-18T12:31:32+00:00"), "splunk"),
        evs(json!([{"_time": "2026-05-18T12:31:32+00:00"}])),
    );
    let t = result.trace.event_traces[0].steps[0]
        .step
        .transform()
        .expect("a transform");
    assert_eq!(t.query_start_time, Some(time("2026-04-18T12:31:32+00:00")));
    assert_eq!(t.query_end_time, Some(time("2026-05-18T12:31:32+00:00")));
    // a source that doesn't format its bounds leaves the display text None
    assert_eq!(t.query_time_spec, None);
}

#[test]
fn test_executable_transform_has_no_query_timespec() {
    // an executable runs against no query source, so the timespec fields stay None; /bin/echo is
    // no script type in ace-rs, so the step fails, and they stay None all the same
    let config = logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "enriched",
        "property_type": "str", "command": {"type": "executable", "path": "/bin/echo", "args": ["x"]}}}]),
    );
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    let t = result.trace.event_traces[0].steps[0]
        .step
        .transform()
        .expect("a transform");
    assert_eq!(t.query_start_time, None);
    assert_eq!(t.query_end_time, None);
    assert_eq!(t.query_time_spec, None);
}

#[test]
fn test_defined_query_command_captures_time_range() {
    let f = Fixture::default().source("splunk", TestSource::new(json!([])));
    let predef = [predefined(
        json!({"name": "splunk_lookup", "type": "query", "source": "splunk",
        "query": "search index=main", "time_range": {"before": "1h"}}),
    )];
    let config = logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "lookup",
        "command": {"type": "defined", "name": "splunk_lookup"}}}]),
    );
    let result = f.run(
        &config,
        &predef,
        hunt(utc("2026-05-18T12:00:00+00:00"), "splunk"),
        evs(json!([{"_time": "2026-05-18T11:30:00+00:00"}])),
    );
    let t = result.trace.event_traces[0].steps[0]
        .step
        .transform()
        .expect("a transform");
    assert_eq!(t.query_start_time, Some(time("2026-05-18T10:30:00+00:00")));
    assert_eq!(t.query_end_time, Some(time("2026-05-18T11:30:00+00:00")));
}

fn replay_config() -> crate::correlate::Correlate {
    // a per-event query: capture and replay key on the rendered text
    logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "lookup",
        "property_type": "list",
        "command": {"type": "query", "source": "splunk", "query": "search host={{ _event.host }}",
                    "time_range": {"before": "1h", "after": "1h"}}}}]),
    )
}

#[test]
fn test_live_run_captures_rendered_queries() {
    let splunk = TestSource::new(json!([{"found": true}]));
    let f = Fixture::default().source("splunk", splunk.clone());
    let result = f.run(
        &replay_config(),
        &[],
        hunt(utc("2024-06-01T12:00:00+00:00"), "splunk"),
        evs(json!([
            {"host": "web1", "_time": "2024-06-01T11:00:00+00:00"},
            {"host": "web2", "_time": "2024-06-01T11:00:00+00:00"},
        ])),
    );
    assert!(
        result
            .events
            .iter()
            .all(|e| js(e)["lookup"] == json!([{"found": true}]))
    );
    assert_eq!(splunk.calls().len(), 2);
    let captured: Vec<(String, Vec<Json>)> = result
        .captured
        .iter()
        .map(|r| (r.query.clone(), r.results.clone()))
        .collect();
    assert_eq!(
        captured,
        [
            ("search host=web1".to_owned(), vec![json!({"found": true})]),
            ("search host=web2".to_owned(), vec![json!({"found": true})]),
        ]
    );
}

#[test]
fn test_replay_skips_live_source() {
    let splunk = TestSource::new(json!([{"should": "not be used"}]));
    let f = Fixture::default().source("splunk", splunk.clone());
    let mut run = hunt(utc("2024-06-01T12:00:00+00:00"), "splunk");
    run.replay = vec![
        json!({"source": "splunk", "query": "search host=web1", "results": [{"saved": "web1"}]}),
        json!({"source": "splunk", "query": "search host=web2", "results": [{"saved": "web2"}]}),
    ];
    let result = f.run(
        &replay_config(),
        &[],
        run,
        evs(json!([
            {"host": "web1", "_time": "2024-06-01T11:00:00+00:00"},
            {"host": "web2", "_time": "2024-06-01T11:00:00+00:00"},
        ])),
    );
    // no live query on a full replay
    assert!(splunk.calls().is_empty());
    let by_host: Vec<(Json, Json)> = result
        .events
        .iter()
        .map(|e| (js(e)["host"].clone(), js(e)["lookup"].clone()))
        .collect();
    assert_eq!(
        by_host,
        [
            (json!("web1"), json!([{"saved": "web1"}])),
            (json!("web2"), json!([{"saved": "web2"}])),
        ]
    );
}

/// A password-spray hunt's shape: condition(success) -> [log, transform(query -> count),
/// when(count > 0 -> filter)].
fn spray_like_config(timeout: &str) -> crate::correlate::Correlate {
    super::config(
        json!([{
            "when": {"type": "equals", "value": "yes", "property": "is_success"},
            "execute": [
                {"action": {"type": "log", "log_message": "{{ _event.ip }} success"}},
                {"description": "Step: Filter if trusted named location",
                 "transform": {"type": "event", "method": "property", "property_name": "correlate_trusted_location",
                    "property_type": "list",
                    "command": {"type": "query", "source": "splunk", "query": "search trusted ip={{ _event.ip }}",
                                "time_range": {"before": "3d"}}}},
                {"when": {"type": "jinja", "value": "{{ (_event.correlate_trusted_location[0].count | int) > 0 }}"},
                 "execute": [{"action": {"type": "filter", "log_message": "trusted"}}],
                 "else": [{"action": {"type": "log", "log_message": "not trusted"}}]},
            ],
        }]),
        timeout,
    )
}

#[test]
fn test_filtering_condition_after_transform_runs() {
    // the `when` after an event transform runs: an event whose query counts more than 0 is
    // filtered, not alerted
    let f = Fixture::default().source("splunk", TestSource::new(json!([{"count": "1"}])));
    let result = f.run(
        &spray_like_config("15m"),
        &[],
        hunt(utc("2024-06-01T12:00:00+00:00"), "splunk"),
        evs(json!([{"_time": "2024-06-01T00:00:00+00:00", "ip": "1.2.3.4", "is_success": "yes"}])),
    );
    assert!(result.events.is_empty());
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "filter");
    let branch = &et.steps[0]
        .step
        .condition()
        .expect("a condition")
        .branch_steps;
    let kinds: Vec<&str> = branch.iter().map(|s| s.step.trace_type()).collect();
    assert_eq!(kinds, ["action", "transform", "condition"]);
    assert_eq!(
        branch[2]
            .step
            .condition()
            .expect("a condition")
            .branch_taken,
        crate::correlate::trace::Branch::Execute
    );
}

#[test]
fn test_midevent_timeout_is_visible_and_fails_safe() {
    // a timeout partway through an event shows: outcome timeout, a timeout stream event, the
    // partial trace (the log and the transform, no `when`), and the event still alerts
    let f = Fixture::default();
    let mut slow = TestSource::rows(json!([{"count": "1"}]));
    // the query takes 20 minutes of a 15 minute budget, so the next step's check trips
    slow.clock = Some((f.now.clone(), TimeDelta::minutes(20)));
    let slow = Arc::new(slow);
    let f = f.source("splunk", slow.clone());
    let mut run = hunt(utc("2024-06-01T12:00:00+00:00"), "splunk");
    run.name = Some("password spray".to_owned());
    run.uuid = Some("abc-123".to_owned());
    let result = f.run(
        &spray_like_config("15m"),
        &[],
        run,
        evs(json!([{"_time": "2024-06-01T00:00:00+00:00", "ip": "1.2.3.4", "is_success": "yes"}])),
    );
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.event_actions[&0].action_type, "alert");
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "timeout");
    assert!(
        result
            .trace
            .stream_events
            .iter()
            .any(|s| s.event_type == "timeout" && s.at_event_index == Some(0))
    );
    let branch = &et.steps[0]
        .step
        .condition()
        .expect("a condition")
        .branch_steps;
    let kinds: Vec<&str> = branch.iter().map(|s| s.step.trace_type()).collect();
    assert_eq!(kinds, ["action", "transform"]);
    assert_eq!(slow.calls().len(), 1);
    assert!(
        result
            .logs
            .iter()
            .any(|l| l.message.contains("hunt password spray (uuid=abc-123)"))
    );
}

#[test]
fn test_secret_export_failure_does_not_fail_steps() {
    // ace3 loads its secret store only to scrub output, so a store that fails doesn't stop a step;
    // ace-rs's caller hands over the secrets, and this case's step is an executable printing "ok"
    let config = logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "result",
        "command": {"type": "executable", "path": super::echo_path(), "args": ["print", "ok"]}}}]),
    );
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    assert_ne!(result.trace.event_traces[0].outcome, "error");
    assert_eq!(js(&result.events[0])["result"], json!("ok"));
    let _ = ev(json!({}));
    let _ = HuntRun::at(utc("2024-06-01T12:00:00+00:00"));
}
