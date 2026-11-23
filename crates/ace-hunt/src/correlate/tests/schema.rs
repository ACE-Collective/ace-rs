//! `test_schema.py`: 66 cases, against the schema 6.2 ported (`crate::correlate`). ace3 builds
//! some models from model instances; here every model validates from its loaded value. A
//! ConditionConfig is only validated inside its step in ace-rs, as a hunt's is in ace3.

use chrono::TimeDelta;
use serde_json::{Value as Json, json};

use super::{predefined, v};
use crate::HuntError;
use crate::correlate::command::timespec;
use crate::correlate::{
    Action, Command, CommandTimeRange, Correlate, Expression, MergeTimeSpec, PredefinedCommand,
    Step, StepKind, Transform,
};
use crate::validate::Errors;

fn expression(json: Json) -> Result<Expression, HuntError> {
    Expression::from_value(&v(json))
}

fn command(json: Json) -> Result<Command, HuntError> {
    Command::from_value(&v(json))
}

fn transform(json: Json) -> Result<Transform, HuntError> {
    let mut json = json;
    json["command"] = json!({"type": "defined", "name": "test"});
    Transform::from_value(&v(json))
}

fn message(r: Result<impl std::fmt::Debug, HuntError>) -> String {
    match r {
        Err(e) => e.to_string(),
        Ok(x) => panic!("valid: {x:?}"),
    }
}

#[test]
fn test_string_shorthand() {
    let e = Expression::from_value(&v(json!("{{ field1 }}"))).expect("valid");
    assert_eq!(e.kind, "jinja");
    assert_eq!(e.value, json!("{{ field1 }}"));
}

/// Three parameters.
#[test]
fn test_comparison_requires_property() {
    for kind in ["equals", "glob", "regex"] {
        assert!(
            expression(json!({"type": kind, "value": "test"})).is_err(),
            "{kind}"
        );
    }
}

#[test]
fn test_not_rejects_list() {
    assert!(expression(json!({"type": "not", "value": ["a", "b"]})).is_err());
}

/// Two parameters.
#[test]
fn test_logical_requires_list() {
    for kind in ["and", "or"] {
        assert!(
            expression(json!({"type": kind, "value": "single"})).is_err(),
            "{kind}"
        );
    }
}

#[test]
fn test_and_with_list() {
    let e = expression(json!({"type": "and", "value": ["{{ a }}", "{{ b }}"]})).expect("valid");
    assert_eq!(e.value.as_array().map(Vec::len), Some(2));
}

#[test]
fn test_query_requires_source() {
    assert!(command(json!({"type": "query", "query": "search index=main"})).is_err());
}

#[test]
fn test_executable_requires_path() {
    assert!(command(json!({"type": "executable"})).is_err());
}

#[test]
fn test_defined_requires_name() {
    assert!(command(json!({"type": "defined"})).is_err());
}

#[test]
fn test_default_timeout_is_a_backstop() {
    // the default clears real correlate query durations (p99 about 400s)
    let c = command(json!({"type": "query", "source": "splunk", "query": "search index=main"}))
        .expect("valid");
    assert!(timespec(&c.timeout).expect("a timespec") >= TimeDelta::minutes(10));
}

#[test]
fn test_executable_env_defaults_none() {
    let c = command(json!({"type": "executable", "path": "/usr/bin/test"})).expect("valid");
    assert_eq!(c.env, None);
}

#[test]
fn test_source_options_defaults_to_empty_dict() {
    let c = command(json!({"type": "query", "source": "splunk", "query": "search index=main"}))
        .expect("valid");
    assert!(c.source_options.is_empty());
}

#[test]
fn test_predefined_command_source_options_round_trip() {
    let p = predefined(
        json!({"name": "rapid7_default", "type": "query", "source": "rapid7",
        "query": "where(...)", "source_options": {"log_names": ["Authentication"]}}),
    );
    let c = p.to_command(None).expect("converts");
    assert_eq!(
        Json::Object(c.source_options),
        json!({"log_names": ["Authentication"]})
    );
}

#[test]
fn test_property_method_requires_event_type() {
    assert!(
        transform(json!({"type": "stream", "method": "property", "property_name": "x"})).is_err()
    );
}

#[test]
fn test_merge_requires_stream_type() {
    assert!(
        transform(json!({"type": "event", "method": "merge",
            "merge_time_spec": {"l_field": "t1", "l_format": "epoch", "r_field": "t2", "r_format": "epoch"}}))
        .is_err()
    );
}

#[test]
fn test_property_requires_name() {
    assert!(transform(json!({"type": "event", "method": "property"})).is_err());
}

#[test]
fn test_merge_requires_time_spec() {
    assert!(transform(json!({"type": "stream", "method": "merge"})).is_err());
}

/// Four parameters.
#[test]
fn test_valid_short_form() {
    for kind in ["filter", "stop", "discard", "alert"] {
        assert_eq!(
            Action::from_value(&v(json!(kind))).expect("valid").kind,
            kind
        );
    }
}

#[test]
fn test_invalid_type() {
    assert!(Action::from_value(&v(json!({"type": "bogus"}))).is_err());
}

#[test]
fn test_dispatch_transform() {
    let s = Step::from_value(&v(
        json!({"transform": {"type": "event", "method": "property",
        "property_name": "result", "command": {"type": "defined", "name": "test"}}}),
    ))
    .expect("valid");
    assert!(matches!(s.step, StepKind::Transform(_)));
}

#[test]
fn test_dispatch_action() {
    let s = Step::from_value(&v(json!({"action": "filter"}))).expect("valid");
    assert!(matches!(s.step, StepKind::Action(_)));
}

#[test]
fn test_missing_key_raises() {
    assert!(Step::from_value(&v(json!({"bogus": "value"}))).is_err());
}

#[test]
fn test_description_and_debug() {
    let s = Step::from_value(&v(
        json!({"action": "filter", "description": "test desc", "debug": "{{ x }}"}),
    ))
    .expect("valid");
    assert_eq!(s.description.as_deref(), Some("test desc"));
    assert_eq!(s.debug.as_deref(), Some("{{ x }}"));
}

#[test]
fn test_condition_with_else() {
    let s = Step::from_value(&v(
        json!({"when": "{{ x }}", "execute": [{"action": "filter"}],
        "else": [{"action": "alert"}]}),
    ))
    .expect("valid");
    let StepKind::Condition(c) = s.step else {
        panic!("a condition");
    };
    assert_eq!(c.otherwise.map(|o| o.len()), Some(1));
}

#[test]
fn test_valid_minimal() {
    let c = Correlate::from_value(&v(json!({"logic": [{"action": "alert"}]}))).expect("valid");
    assert_eq!(c.timeout, "15m");
}

#[test]
fn test_invalid_timeout() {
    assert!(
        Correlate::from_value(&v(
            json!({"timeout": "invalid", "logic": [{"action": "alert"}]})
        ))
        .is_err()
    );
}

#[test]
fn test_full_correlate_yaml() {
    let c = Correlate::from_value(&v(json!({
        "timeout": "5m",
        "logic": [
            {"when": {"type": "equals", "value": "admin", "property": "username"},
             "execute": [{"action": "alert"}], "else": [{"action": "filter"}]},
            {"transform": {"type": "event", "method": "property", "property_name": "enrichment",
                "property_type": "dict",
                "command": {"type": "executable", "path": "/usr/bin/lookup.sh", "args": ["{{ userId }}"]}}},
            {"action": "alert"},
        ],
    })))
    .expect("valid");
    assert_eq!(c.timeout, "5m");
    assert_eq!(c.logic.len(), 3);
}

#[test]
fn test_default_timeout_matches_command_config() {
    // the two declare their own copies of the default, which must agree
    let p =
        predefined(json!({"name": "lookup", "type": "query", "source": "splunk", "query": "x"}));
    let c = command(json!({"type": "query", "source": "splunk", "query": "x"})).expect("valid");
    assert_eq!(timespec(&p.timeout), timespec(&c.timeout));
}

#[test]
fn test_to_command_config() {
    let p = predefined(
        json!({"name": "lookup", "type": "executable", "path": "/usr/bin/lookup.sh", "args": []}),
    );
    let mut overrides = serde_json::Map::new();
    overrides.insert("args".to_owned(), json!(["arg1"]));
    let c = p.to_command(Some(&overrides)).expect("converts");
    assert_eq!(c.kind, "executable");
    assert_eq!(c.args, Some(vec!["arg1".to_owned()]));
}

#[test]
fn test_env_carried_to_command_config() {
    let p = predefined(
        json!({"name": "lookup", "type": "executable", "path": "/usr/bin/lookup.sh", "env": {"KEY": "value"}}),
    );
    let c = p.to_command(None).expect("converts");
    assert_eq!(c.env, Some(vec![("KEY".to_owned(), "value".to_owned())]));
}

#[test]
fn test_minimal_custom_command_accepted() {
    let c = command(json!({"type": "wiz_lookup", "timeout": "2m", "cache": "1d",
        "options": {"ip": "{{ _event.ip }}", "nested": {"a": [1, 2]}}}))
    .expect("valid");
    assert_eq!(c.kind, "wiz_lookup");
    assert_eq!(
        Json::Object(c.options),
        json!({"ip": "{{ _event.ip }}", "nested": {"a": [1, 2]}})
    );
}

#[test]
fn test_custom_command_without_options_accepted() {
    assert!(
        command(json!({"type": "wiz_lookup"}))
            .expect("valid")
            .options
            .is_empty()
    );
}

/// Two parameters.
#[test]
fn test_options_rejected_on_builtin_types() {
    for builtin in [
        json!({"type": "executable", "path": "/bin/true"}),
        json!({"type": "defined", "name": "c"}),
    ] {
        let mut b = builtin.clone();
        b["options"] = json!({"x": 1});
        assert!(
            message(command(b)).contains("only valid for custom command types"),
            "{builtin}"
        );
    }
}

#[test]
fn test_options_on_query_points_at_source_options() {
    let r =
        command(json!({"type": "query", "source": "splunk", "query": "q", "options": {"x": 1}}));
    assert!(message(r).contains("did you mean 'source_options'"));
}

/// Eleven parameters.
#[test]
fn test_builtin_fields_rejected_on_custom_type() {
    for (field, value) in [
        ("source", json!("splunk")),
        ("query", json!("search")),
        ("time_range", json!({"before": "1h"})),
        ("source_options", json!({"log_names": ["x"]})),
        ("path", json!("/bin/true")),
        ("stdin", json!(false)),
        ("args", json!(["a"])),
        ("env", json!({"K": "v"})),
        ("files", json!(["f"])),
        ("name", json!("c")),
        ("arguments", json!({"x": 1})),
    ] {
        let mut c = json!({"type": "wiz_lookup"});
        c[field] = value;
        assert!(
            message(command(c)).contains(&format!("does not accept ['{field}']")),
            "{field}"
        );
    }
}

#[test]
fn test_builtin_fields_rejected_on_custom_predefined() {
    let r = PredefinedCommand::from_value(&v(
        json!({"name": "c", "type": "wiz_lookup", "source": "splunk"}),
    ));
    assert!(message(r).contains("does not accept ['source']"));
}

#[test]
fn test_predefined_custom_command_round_trips() {
    let p = predefined(
        json!({"name": "c", "type": "wiz_lookup", "cache": "1d", "options": {"ip": "1.2.3.4"}}),
    );
    let mut overrides = serde_json::Map::new();
    overrides.insert("options".to_owned(), json!({"ip": "5.6.7.8"}));
    let c = p.to_command(Some(&overrides)).expect("converts");
    assert_eq!(c.kind, "wiz_lookup");
    assert_eq!(c.cache.as_deref(), Some("1d"));
    assert_eq!(Json::Object(c.options), json!({"ip": "5.6.7.8"}));
}

/// Nine parameters: each model refuses a field it doesn't have, naming it.
#[test]
fn test_extra_field_rejected() {
    let bad = |payload: Json| {
        let mut p = payload;
        p["not_a_real_field"] = json!("oops");
        v(p)
    };
    let check = |name: &str, text: String| {
        assert!(text.contains("not_a_real_field"), "{name}: {text}");
    };
    check(
        "ExpressionConfig",
        message(Expression::from_value(&bad(
            json!({"type": "jinja", "value": "{{ x }}"}),
        ))),
    );
    let mut errs = Errors::new();
    assert!(
        CommandTimeRange::validate(&bad(json!({"before": "1h"})), &[], &mut errs)
            .expect("no exception")
            .is_none()
    );
    check("TimeRangeConfig", format!("{errs:?}"));
    check(
        "CommandConfig",
        message(Command::from_value(&bad(
            json!({"type": "query", "source": "splunk", "query": "search"}),
        ))),
    );
    let mut errs = Errors::new();
    assert!(
        MergeTimeSpec::validate(
            &bad(json!({"l_field": "a", "l_format": "x", "r_field": "b", "r_format": "y"})),
            &[],
            &mut errs
        )
        .expect("no exception")
        .is_none()
    );
    check("MergeTimeSpecConfig", format!("{errs:?}"));
    check(
        "TransformConfig",
        message(Transform::from_value(&bad(
            json!({"type": "event", "method": "property",
            "property_name": "p", "command": {"type": "query", "source": "splunk", "query": "q"}}),
        ))),
    );
    check(
        "ActionConfig",
        message(Action::from_value(&bad(json!({"type": "filter"})))),
    );
    check(
        "ConditionConfig",
        message(Step::from_value(&bad(
            json!({"when": "{{ true }}", "execute": []}),
        ))),
    );
    check(
        "PredefinedCommandConfig",
        message(PredefinedCommand::from_value(&bad(
            json!({"name": "c", "type": "executable", "path": "/bin/true"}),
        ))),
    );
    check(
        "CorrelateConfig",
        message(Correlate::from_value(&bad(json!({"logic": []})))),
    );
}

#[test]
fn test_step_config_rejects_extra_at_step_level() {
    let r = Step::from_value(&v(
        json!({"when": "{{ true }}", "execute": [], "typo_field": "x"}),
    ));
    assert!(message(r).contains("typo_field"));
}

#[test]
fn test_step_config_rejects_extra_next_to_transform() {
    let r = Step::from_value(&v(
        json!({"transform": {"type": "event", "method": "property", "property_name": "p",
        "command": {"type": "query", "source": "splunk", "query": "q"}}, "typo_field": "x"}),
    ));
    assert!(message(r).contains("typo_field"));
}

/// Two parameters: a step with more than one of when, transform and action fails.
#[test]
fn test_step_config_rejects_multiple_step_keys() {
    for keys in [
        json!({"when": "{{ true }}", "action": "log"}),
        json!({"when": "{{ true }}", "transform": {}, "action": "log"}),
    ] {
        assert!(
            message(Step::from_value(&v(keys.clone()))).contains("exactly one"),
            "{keys}"
        );
    }
}
