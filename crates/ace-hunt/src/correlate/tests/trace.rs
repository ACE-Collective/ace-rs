//! `test_trace.py`: 35 cases, 3 waiting (an executable's output). ace3 stores secrets in its
//! encrypted store for the engine to load; ace4's caller hands the run its secrets.

use serde_json::{Value as Json, json};

use super::{Fixture, config, ev, evs, logic, v};
use crate::correlate::action::Level;
use crate::correlate::expr::{Evaluator, Scope};
use crate::correlate::trace::{Branch, EventTrace, ExpressionTrace, sanitize, sanitize_opt};
use crate::correlate::{Action, Expression, StepKind};

fn secrets(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).to_owned()).collect()
}

// TestSanitizeValue: ace3's secrets are a nested dict whose string leaves are the secrets; ace4's
// caller hands over the leaves, so a nested secret is one of them

#[test]
fn test_none_value() {
    assert_eq!(sanitize_opt(None, &secrets(&["secret"])), None);
}

#[test]
fn test_replaces_secret() {
    assert_eq!(sanitize("token=abc123", &secrets(&["abc123"])), "token=***");
}

#[test]
fn test_nested_secrets() {
    assert_eq!(
        sanitize("my secret_val here", &secrets(&["secret_val"])),
        "my *** here"
    );
}

#[test]
fn test_empty_secret_ignored() {
    assert_eq!(sanitize("hello", &secrets(&[""])), "hello");
}

#[test]
fn test_multiple_occurrences() {
    assert_eq!(sanitize("abc abc", &secrets(&["abc"])), "*** ***");
}

fn traced(expr: Json, event: Json) -> (bool, ExpressionTrace) {
    let f = Fixture::default();
    let expr = Expression::from_value(&v(expr)).expect("a valid expression");
    let event = ev(event);
    Evaluator::new(&f.renderer)
        .evaluate_traced(
            &expr,
            Scope {
                event: &event,
                events: &[],
            },
        )
        .expect("evaluates")
}

#[test]
fn test_jinja_true() {
    let (result, trace) = traced(
        json!({"type": "jinja", "value": "{{ _event.name }}"}),
        json!({"name": "admin"}),
    );
    assert!(result);
    assert_eq!(trace.expression_type, "jinja");
    assert!(trace.result);
    assert_eq!(trace.rendered_value.as_deref(), Some("admin"));
}

#[test]
fn test_jinja_false() {
    let (result, trace) = traced(
        json!({"type": "jinja", "value": "{{ _event.missing }}"}),
        json!({}),
    );
    assert!(!result);
    assert!(!trace.result);
    assert_eq!(trace.rendered_value.as_deref(), Some(""));
}

#[test]
fn test_equals() {
    let (result, trace) = traced(
        json!({"type": "equals", "value": "admin", "property": "user"}),
        json!({"user": "admin"}),
    );
    assert!(result);
    assert_eq!(trace.expression_type, "equals");
    assert_eq!(trace.property_name.as_deref(), Some("user"));
    assert_eq!(trace.property_value.as_deref(), Some("admin"));
    assert_eq!(trace.compare_value.as_deref(), Some("admin"));
}

#[test]
fn test_equals_mismatch() {
    let (result, trace) = traced(
        json!({"type": "equals", "value": "admin", "property": "user"}),
        json!({"user": "guest"}),
    );
    assert!(!result);
    assert_eq!(trace.property_value.as_deref(), Some("guest"));
}

#[test]
fn test_glob() {
    let (result, trace) = traced(
        json!({"type": "glob", "value": "*.exe", "property": "file"}),
        json!({"file": "malware.exe"}),
    );
    assert!(result);
    assert_eq!(trace.expression_type, "glob");
    assert_eq!(trace.property_value.as_deref(), Some("malware.exe"));
}

#[test]
fn test_regex() {
    let (result, trace) = traced(
        json!({"type": "regex", "value": "\\d+", "property": "code"}),
        json!({"code": "error 404"}),
    );
    assert!(result);
    assert_eq!(trace.expression_type, "regex");
}

#[test]
fn test_and_all_true() {
    let (result, trace) = traced(
        json!({"type": "and", "value": [
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "login", "property": "action"},
        ]}),
        json!({"user": "admin", "action": "login"}),
    );
    assert!(result);
    assert_eq!(trace.expression_type, "and");
    let subs = trace.sub_expressions.expect("subs");
    assert_eq!(subs.len(), 2);
    assert!(subs.iter().all(|s| s.result));
}

#[test]
fn test_and_short_circuits() {
    let (result, trace) = traced(
        json!({"type": "and", "value": [
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "login", "property": "action"},
        ]}),
        json!({"user": "guest", "action": "login"}),
    );
    assert!(!result);
    // only the first sub-expression is evaluated
    let subs = trace.sub_expressions.expect("subs");
    assert_eq!(subs.len(), 1);
    assert!(!subs[0].result);
}

#[test]
fn test_or_short_circuits() {
    let (result, trace) = traced(
        json!({"type": "or", "value": [
            {"type": "equals", "value": "admin", "property": "user"},
            {"type": "equals", "value": "root", "property": "user"},
        ]}),
        json!({"user": "admin"}),
    );
    assert!(result);
    let subs = trace.sub_expressions.expect("subs");
    assert_eq!(subs.len(), 1);
    assert!(subs[0].result);
}

#[test]
fn test_not() {
    let (result, trace) = traced(
        json!({"type": "not", "value": {"type": "equals", "value": "admin", "property": "user"}}),
        json!({"user": "guest"}),
    );
    assert!(result);
    assert_eq!(trace.expression_type, "not");
    assert!(trace.result);
    let subs = trace.sub_expressions.expect("subs");
    assert_eq!(subs.len(), 1);
    assert!(!subs[0].result);
}

#[test]
fn test_jinja_error() {
    let (result, trace) = traced(
        json!({"type": "jinja", "value": "{{ _event.x | bad_filter }}"}),
        json!({"x": "val"}),
    );
    assert!(!result);
    assert!(trace.error.is_some());
}

#[test]
fn test_no_logic_produces_trace() {
    let result = Fixture::default().simple(&logic(json!([])), evs(json!([{"id": 1}, {"id": 2}])));
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.trace.event_traces.len(), 2);
    assert!(
        result
            .trace
            .event_traces
            .iter()
            .all(|e| e.outcome == "alert")
    );
    assert!(result.trace.event_traces.iter().all(|e| e.steps.is_empty()));
}

#[test]
fn test_condition_filter_trace() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "admin", "property": "user"},
        "execute": [{"action": "filter"}],
    }]));
    let result =
        Fixture::default().simple(&config, evs(json!([{"user": "admin"}, {"user": "guest"}])));
    let traces = &result.trace.event_traces;
    assert_eq!(traces.len(), 2);
    // admin, filtered
    assert_eq!(traces[0].outcome, "filter");
    assert_eq!(traces[0].steps.len(), 1);
    let cond = traces[0].steps[0].step.condition().expect("a condition");
    assert!(cond.expression.result);
    assert_eq!(cond.branch_taken, Branch::Execute);
    assert_eq!(cond.branch_steps.len(), 1);
    assert_eq!(
        cond.branch_steps[0]
            .step
            .action()
            .expect("an action")
            .action_type,
        "filter"
    );
    // guest, alert: the condition was false and there's no else
    assert_eq!(traces[1].outcome, "alert");
    let cond = traces[1].steps[0].step.condition().expect("a condition");
    assert!(!cond.expression.result);
    assert_eq!(cond.branch_taken, Branch::None);
}

#[test]
fn test_condition_else_branch_trace() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "admin", "property": "user"},
        "execute": [{"action": "filter"}],
        "else": [{"action": {"type": "log", "log_message": "not admin: {{ _event.user }}"}}],
    }]));
    let result = Fixture::default().simple(&config, evs(json!([{"user": "guest"}])));
    let cond = result.trace.event_traces[0].steps[0]
        .step
        .condition()
        .expect("a condition");
    assert_eq!(cond.branch_taken, Branch::Else);
    assert_eq!(cond.branch_steps.len(), 1);
    let action = cond.branch_steps[0].step.action().expect("an action");
    assert_eq!(action.action_type, "log");
    assert_eq!(
        action.rendered_log_message.as_deref(),
        Some("not admin: guest")
    );
}

#[test]
fn test_nested_condition_trace() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "admin", "property": "user"},
        "execute": [{
            "when": {"type": "equals", "value": "login", "property": "action"},
            "execute": [{"action": "filter"}],
        }],
    }]));
    let result =
        Fixture::default().simple(&config, evs(json!([{"user": "admin", "action": "login"}])));
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "filter");
    let outer = et.steps[0].step.condition().expect("a condition");
    assert_eq!(outer.branch_taken, Branch::Execute);
    let inner = outer.branch_steps[0].step.condition().expect("a condition");
    assert_eq!(inner.branch_taken, Branch::Execute);
    assert!(inner.branch_steps[0].step.action().is_some());
}

#[test]
fn test_discard_trace() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "bad", "property": "status"},
        "execute": [{"action": "discard"}],
    }]));
    let result = Fixture::default().simple(
        &config,
        evs(json!([{"status": "ok"}, {"status": "bad"}, {"status": "ok"}])),
    );
    assert!(result.discarded);
    // the first event (alert) and the second (discard)
    assert_eq!(result.trace.event_traces.len(), 2);
    assert_eq!(result.trace.event_traces[0].outcome, "alert");
    assert_eq!(result.trace.event_traces[1].outcome, "discard");
    assert_eq!(result.trace.stream_events.len(), 1);
    assert_eq!(result.trace.stream_events[0].event_type, "discard");
    assert_eq!(result.trace.stream_events[0].at_event_index, Some(1));
}

#[test]
fn test_stop_trace() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "stop_here", "property": "action"},
        "execute": [{"action": "stop"}],
    }]));
    let result = Fixture::default().simple(
        &config,
        evs(json!([
            {"action": "continue", "id": 1},
            {"action": "stop_here", "id": 2},
            {"action": "continue", "id": 3},
        ])),
    );
    let traces = &result.trace.event_traces;
    assert_eq!(traces.len(), 2);
    assert_eq!(traces[0].outcome, "alert");
    assert_eq!(traces[1].outcome, "stop");
}

#[test]
fn test_timeout_trace() {
    // ace3 sets the engine's timeout to zero; a timeout of 0s is the same
    let result =
        Fixture::default().simple(&config(json!([]), "0s"), evs(json!([{"id": 1}, {"id": 2}])));
    // the events the timeout cut off still alert
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.trace.stream_events.len(), 1);
    assert_eq!(result.trace.stream_events[0].event_type, "timeout");
    assert!(
        result
            .trace
            .event_traces
            .iter()
            .all(|e| e.outcome == "timeout")
    );
}

#[test]
fn test_description_in_trace() {
    let config = logic(json!([{
        "description": "Check for admin users",
        "when": {"type": "equals", "value": "admin", "property": "user"},
        "execute": [{"action": "filter"}],
    }]));
    let result = Fixture::default().simple(&config, evs(json!([{"user": "admin"}])));
    assert_eq!(
        result.trace.event_traces[0].steps[0].description.as_deref(),
        Some("Check for admin users")
    );
}

#[test]
#[ignore = "runs a type: executable command, which waits for the owner's decision on how one runs (PLAN.md 6.6)"]
fn test_transform_with_property_trace() {
    let config = logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "enriched",
        "property_type": "str", "command": {"type": "executable", "path": "/bin/echo", "args": ["enriched_value"]}}}]),
    );
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    let et = &result.trace.event_traces[0];
    assert_eq!(et.steps.len(), 1);
    let t = et.steps[0].step.transform().expect("a transform");
    assert_eq!(t.transform_type, "event");
    assert_eq!(t.method, "property");
    assert_eq!(t.command_type, "executable");
    assert_eq!(t.property_name.as_deref(), Some("enriched"));
    assert!(
        t.property_value
            .as_deref()
            .is_some_and(|p| p.contains("enriched_value"))
    );
    assert_eq!(t.result_count, Some(1));
    assert_eq!(t.error, None);
    assert!(
        t.rendered_command
            .as_deref()
            .is_some_and(|c| c.contains("/bin/echo enriched_value"))
    );
    assert_eq!(t.merge_dropped, None);
}

#[test]
fn test_step_duration_defaults_to_none() {
    // ace3 checks a persisted trace without durations still loads; ace4's trace starts with none
    assert_eq!(EventTrace::new(0).duration_ms, None);
}

#[test]
fn test_execute_populates_step_and_event_durations() {
    let config = logic(json!([{
        "when": {"type": "equals", "value": "admin", "property": "user"},
        "execute": [{"action": "filter"}],
    }]));
    let result = Fixture::default().simple(&config, evs(json!([{"user": "admin"}])));
    let et = &result.trace.event_traces[0];
    assert!(et.duration_ms.is_some_and(|d| d >= 0.0));
    let cond = &et.steps[0];
    let cond_ms = cond.duration_ms.expect("a duration");
    let nested = &cond.step.condition().expect("a condition").branch_steps[0];
    let nested_ms = nested.duration_ms.expect("a duration");
    assert!(cond_ms >= 0.0 && nested_ms >= 0.0);
    // a condition's time includes its branch's
    assert!(cond_ms >= nested_ms);
}

#[test]
fn test_transform_error_skips_remaining_steps() {
    // an error stops the event's steps: the filter after it doesn't run (ace3's /bin/false fails,
    // and so does ace4's executable step)
    let config = logic(json!([
        {"transform": {"type": "event", "method": "property", "property_name": "result", "property_type": "str",
            "command": {"type": "executable", "path": "/bin/false"}}},
        {"action": "filter"},
    ]));
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "error");
    assert_eq!(result.event_actions[&0].action_type, "alert");
    assert_eq!(et.steps.len(), 1);
    assert!(
        et.steps[0]
            .step
            .transform()
            .expect("a transform")
            .error
            .is_some()
    );
}

#[test]
fn test_condition_expression_error_short_circuits() {
    let config = logic(json!([
        {"when": "{{ _event.x | bad_filter }}", "execute": [{"action": "filter"}]},
        {"action": "filter"},
    ]));
    let result = Fixture::default().simple(&config, evs(json!([{"x": "val"}])));
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "error");
    assert_eq!(result.event_actions[&0].action_type, "alert");
    let cond = et.steps[0].step.condition().expect("a condition");
    assert!(cond.error.is_some());
    assert!(cond.expression.error.is_some());
    assert_eq!(et.steps.len(), 1);
}

#[test]
fn test_nested_transform_error_surfaces_through_condition() {
    let config = logic(json!([
        {"when": {"type": "equals", "value": "admin", "property": "user"},
         "execute": [
            {"transform": {"type": "event", "method": "property", "property_name": "result", "property_type": "str",
                "command": {"type": "executable", "path": "/bin/false"}}},
            {"action": "filter"},
         ]},
        {"action": "filter"},
    ]));
    let result = Fixture::default().simple(&config, evs(json!([{"user": "admin"}])));
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "error");
    assert_eq!(result.event_actions[&0].action_type, "alert");
    // the condition at the top, the transform's error inside it
    assert_eq!(et.steps.len(), 1);
    let cond = et.steps[0].step.condition().expect("a condition");
    assert_eq!(cond.branch_taken, Branch::Execute);
    // only the failing transform, not the filter after it
    assert_eq!(cond.branch_steps.len(), 1);
    assert!(
        cond.branch_steps[0]
            .step
            .transform()
            .expect("a transform")
            .error
            .is_some()
    );
}

#[test]
fn test_action_error_recorded() {
    // ace3 patches execute_action to raise; an action the schema would refuse raises here
    let mut config = logic(json!([{"action": "filter"}, {"action": "filter"}]));
    config.logic[0].step = StepKind::Action(Action {
        kind: "boom".to_owned(),
        queue: None,
        analysis_mode: None,
        log_level: "INFO".to_owned(),
        log_message: None,
    });
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "error");
    assert_eq!(result.event_actions[&0].action_type, "alert");
    // only the failing action; the second never ran
    assert_eq!(et.steps.len(), 1);
    assert_eq!(
        et.steps[0]
            .step
            .action()
            .expect("an action")
            .error
            .as_deref(),
        Some("unknown action type: 'boom'")
    );
    assert!(
        result
            .logs
            .iter()
            .any(|l| l.level == Level::Error && l.message.contains("error executing action"))
    );
}

#[test]
fn test_secrets_stripped_from_expression_trace() {
    let config = logic(json!([{"when": "{{ _event.token }}", "execute": [{"action": "filter"}]}]));
    let f = Fixture::default().secrets(&["supersecret"]);
    let result = f.simple(&config, evs(json!([{"id": 1, "token": "supersecret"}])));
    let cond = result.trace.event_traces[0].steps[0]
        .step
        .condition()
        .expect("a condition");
    let rendered = cond.expression.rendered_value.clone().unwrap_or_default();
    assert!(!rendered.contains("supersecret"));
    assert!(rendered.contains("***"));
}

#[test]
fn test_secrets_stripped_from_action_log_message() {
    let config =
        logic(json!([{"action": {"type": "log", "log_message": "key={{ _event.token }}"}}]));
    let f = Fixture::default().secrets(&["supersecret"]);
    let result = f.simple(&config, evs(json!([{"id": 1, "token": "supersecret"}])));
    let action = result.trace.event_traces[0].steps[0]
        .step
        .action()
        .expect("an action");
    let message = action.rendered_log_message.clone().unwrap_or_default();
    assert!(!message.contains("supersecret"));
    assert!(message.contains("***"));
}

#[test]
#[ignore = "runs a type: executable command, which waits for the owner's decision on how one runs (PLAN.md 6.6)"]
fn test_env_value_absent_from_rendered_command_trace() {
    // the summary renders the path and arguments, never env, so an env value stays out of it
    let config = logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "result",
        "command": {"type": "executable", "path": "/usr/bin/python3",
            "args": ["-c", "import os; print(os.environ['API_KEY'][:2])"], "env": {"API_KEY": "{{ _event.token }}"}}}}]),
    );
    let result =
        Fixture::default().simple(&config, evs(json!([{"id": 1, "token": "supersecret"}])));
    assert_eq!(super::js(&result.events[0])["result"], json!("su"));
    let t = result.trace.event_traces[0].steps[0]
        .step
        .transform()
        .expect("a transform");
    assert!(
        !t.rendered_command
            .clone()
            .unwrap_or_default()
            .contains("supersecret")
    );
    assert!(
        !result
            .logs
            .iter()
            .any(|l| l.message.contains("supersecret"))
    );
}

#[test]
#[ignore = "runs a type: executable command, which waits for the owner's decision on how one runs (PLAN.md 6.6)"]
fn test_transform_error_is_sanitized() {
    // a script that echoes a credential to stderr doesn't write it into the trace
    let config = logic(
        json!([{"transform": {"type": "event", "method": "property", "property_name": "result",
        "command": {"type": "executable", "path": "/usr/bin/python3",
            "args": ["-c", "import os, sys; sys.stderr.write(os.environ['API_KEY']); sys.exit(1)"],
            "env": {"API_KEY": "{{ _event.token }}"}}}}]),
    );
    let f = Fixture::default().secrets(&["supersecret"]);
    let result = f.simple(&config, evs(json!([{"id": 1, "token": "supersecret"}])));
    let t = result.trace.event_traces[0].steps[0]
        .step
        .transform()
        .expect("a transform");
    let error = t.error.clone().unwrap_or_default();
    assert!(!error.contains("supersecret"));
    assert!(error.contains("***"));
    assert!(
        !result
            .logs
            .iter()
            .any(|l| l.message.contains("supersecret"))
    );
}
