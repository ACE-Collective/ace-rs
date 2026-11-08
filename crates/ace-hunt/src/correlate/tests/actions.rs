//! `test_actions.py`: 22 cases. ace3's `caplog` is the run's log lines.

use serde_json::json;

use super::{Fixture, ev, v};
use crate::correlate::Action;
use crate::correlate::action::{ActionResult, Level, LogLine, execute_action};
use crate::correlate::expr::Scope;

fn action(json: serde_json::Value) -> Action {
    Action::from_value(&v(json)).expect("a valid action")
}

fn run(action: &Action, event: serde_json::Value) -> (ActionResult, Vec<LogLine>) {
    let f = Fixture::default();
    let event = ev(event);
    let events = vec![event.clone()];
    let mut logs = Vec::new();
    let result = execute_action(
        action,
        &f.renderer,
        Scope {
            event: &event,
            events: &events,
        },
        &mut logs,
    )
    .expect("executes");
    (result, logs)
}

/// TestActionResult.test_is_interrupt, five parameters.
#[test]
fn test_is_interrupt() {
    for (kind, expected) in [
        ("filter", true),
        ("stop", true),
        ("discard", true),
        ("alert", true),
        ("log", false),
    ] {
        assert_eq!(ActionResult::of(kind).is_interrupt(), expected, "{kind}");
    }
}

/// test_is_stream_interrupt, five parameters.
#[test]
fn test_is_stream_interrupt() {
    for (kind, expected) in [
        ("stop", true),
        ("discard", true),
        ("filter", false),
        ("alert", false),
        ("log", false),
    ] {
        assert_eq!(
            ActionResult::of(kind).is_stream_interrupt(),
            expected,
            "{kind}"
        );
    }
}

#[test]
fn test_alert_with_overrides() {
    let (result, _) = run(
        &action(json!({"type": "alert", "queue": "my_queue", "analysis_mode": "deep"})),
        json!({}),
    );
    assert_eq!(result.action_type, "alert");
    assert_eq!(result.queue_override.as_deref(), Some("my_queue"));
    assert_eq!(result.analysis_mode_override.as_deref(), Some("deep"));
}

#[test]
fn test_alert_no_overrides() {
    let (result, _) = run(&action(json!({"type": "alert"})), json!({}));
    assert_eq!(result.queue_override, None);
    assert_eq!(result.analysis_mode_override, None);
}

#[test]
fn test_log() {
    let (result, logs) = run(
        &action(
            json!({"type": "log", "log_message": "user={{ _event.user }}", "log_level": "WARNING"}),
        ),
        json!({"user": "admin"}),
    );
    assert_eq!(result.action_type, "log");
    assert!(
        logs.iter()
            .any(|l| l.level == Level::Warning && l.message.contains("user=admin")),
        "{logs:?}"
    );
}

#[test]
fn test_log_default_level() {
    let (_, logs) = run(
        &action(json!({"type": "log", "log_message": "test message"})),
        json!({}),
    );
    let levels: Vec<Level> = logs
        .iter()
        .filter(|l| l.message == "correlation log: test message")
        .map(|l| l.level)
        .collect();
    assert_eq!(levels, [Level::Info]);
}

/// TestUniversalActionLogging.test_default_log_message, five parameters.
#[test]
fn test_default_log_message() {
    for kind in ["filter", "stop", "discard", "alert", "log"] {
        let (result, logs) = run(&action(json!({"type": kind})), json!({}));
        assert_eq!(result.action_type, kind);
        assert!(
            logs.iter()
                .any(|l| l.message.contains(&format!("executed {kind} action"))),
            "{kind}: {logs:?}"
        );
    }
}

#[test]
fn test_custom_log_message_on_non_log_action() {
    let (_, logs) = run(
        &action(json!({"type": "filter", "log_message": "filtering event {{ _event.id }}"})),
        json!({"id": 42}),
    );
    assert!(
        logs.iter()
            .any(|l| l.message.contains("filtering event 42"))
    );
}

#[test]
fn test_custom_log_level_on_non_log_action() {
    let (result, logs) = run(
        &action(json!({"type": "stop", "log_level": "WARNING", "log_message": "stopping"})),
        json!({}),
    );
    assert_eq!(result.action_type, "stop");
    assert!(
        logs.iter()
            .any(|l| l.level == Level::Warning && l.message.contains("stopping"))
    );
}

#[test]
fn test_log_message_render_error() {
    // a render error in log_message doesn't keep the action from returning
    let (result, logs) = run(
        &action(json!({"type": "filter", "log_message": "{{ invalid | bad_filter }}"})),
        json!({}),
    );
    assert_eq!(result.action_type, "filter");
    let records: Vec<&LogLine> = logs
        .iter()
        .filter(|l| l.message.contains("failed to render log message template"))
        .collect();
    assert_eq!(records.len(), 1);
    // a broken template is the hunt author's to fix, not an ACE error to report
    assert_eq!(records[0].level, Level::Warning);
}
