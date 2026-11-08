//! `test_expressions.py`: 13 cases.

use serde_json::json;

use super::{Fixture, ev, v};
use crate::correlate::Expression;
use crate::correlate::expr::{Evaluator, Scope, context};
use crate::value::Value;

fn expression(json: serde_json::Value) -> Expression {
    Expression::from_value(&v(json)).expect("a valid expression")
}

fn evaluate(expr: &Expression, event: serde_json::Value) -> bool {
    let f = Fixture::default();
    let event = ev(event);
    Evaluator::new(&f.renderer)
        .evaluate(
            expr,
            Scope {
                event: &event,
                events: &[],
            },
        )
        .expect("evaluates")
}

/// TestBuildJinjaContext.test_context_is_event_data_only: the context is `_event` and `_events`,
/// the same values (ace3 checks identity, `is`; a Rust render copies), and nothing else.
#[test]
fn test_context_is_event_data_only() {
    let event = ev(json!({"field1": "value1", "field2": 42}));
    let events = vec![event.clone()];
    let ctx = context(
        "{{ _event }}{{ _events }}",
        Scope {
            event: &event,
            events: &events,
        },
    );
    let keys: Vec<String> = ctx.iter().map(|(k, _)| k.key_text()).collect();
    assert_eq!(keys, ["_events", "_event"]);
    assert!(
        matches!(ctx.get("_event"), Some(Value::Map(m)) if crate::value::py_eq(&Value::Map(m.clone()), &Value::Map(event.clone())))
    );
    assert!(matches!(ctx.get("_events"), Some(Value::Seq(s)) if s.len() == 1));
}

/// TestEvaluateExpression.test_equals, three parameters.
#[test]
fn test_equals() {
    for (value, wanted, expected) in [
        ("admin", "admin", true),
        ("admin", "user", false),
        ("Admin", "admin", false),
    ] {
        let expr = expression(json!({"type": "equals", "value": wanted, "property": "user"}));
        assert_eq!(
            evaluate(&expr, json!({"user": value})),
            expected,
            "{value} {wanted}"
        );
    }
}

#[test]
fn test_equals_case_insensitive() {
    let expr = expression(
        json!({"type": "equals", "value": "ADMIN", "property": "user", "case_sensitive": false}),
    );
    assert!(evaluate(&expr, json!({"user": "Admin"})));
}

#[test]
fn test_equals_missing_property() {
    // "None" is what a missing value would become if it were stringified rather than skipped
    let expr = expression(json!({"type": "equals", "value": "None", "property": "missing"}));
    assert!(!evaluate(&expr, json!({})));
}

/// test_glob, two parameters.
#[test]
fn test_glob() {
    for (value, pattern, expected) in [
        ("admin_user", "admin*", true),
        ("admin_user", "user*", false),
    ] {
        let expr = expression(json!({"type": "glob", "value": pattern, "property": "name"}));
        assert_eq!(
            evaluate(&expr, json!({"name": value})),
            expected,
            "{pattern}"
        );
    }
}

#[test]
fn test_glob_case_insensitive() {
    let expr = expression(
        json!({"type": "glob", "value": "ADMIN*", "property": "name", "case_sensitive": false}),
    );
    assert!(evaluate(&expr, json!({"name": "Admin_User"})));
}

/// test_regex, three parameters.
#[test]
fn test_regex() {
    for (value, pattern, expected) in [
        ("admin123", r"admin\d+", true),
        ("user123", r"admin\d+", false),
        // a match anywhere in the value, not only at its start
        ("login by admin123", r"admin\d+", true),
    ] {
        let expr = expression(json!({"type": "regex", "value": pattern, "property": "field"}));
        assert_eq!(
            evaluate(&expr, json!({"field": value})),
            expected,
            "{value}"
        );
    }
}

#[test]
fn test_regex_case_insensitive() {
    let expr = expression(
        json!({"type": "regex", "value": "ADMIN", "property": "field", "case_sensitive": false}),
    );
    assert!(evaluate(&expr, json!({"field": "admin"})));
}
