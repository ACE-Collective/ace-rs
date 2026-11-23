//! `test_validation.py`: 34 cases. Two pass ace3's checks a raw dict where a parsed model belongs
//! (`test_unparsed_config_objects_are_ignored`, and the second half of
//! `test_non_correlate_hunt_is_a_no_op`); ace-rs's checks take the parsed models, so that's the
//! type system's. A type that failed to load is the registry's record of it, which `App` makes
//! from a factory's error.

use std::sync::Arc;

use serde_json::{Value as Json, json};

use super::{predefined, v};
use crate::HuntError;
use crate::correlate::check::{custom_command_types, removed_names};
use crate::correlate::command::{CommandContext, CommandType, CommandTypes};
use crate::correlate::{Correlate, commands};
use crate::validate::{Errors, Obj, integer, string};
use crate::value::Value;

/// `_correlate(*commands)`: one event transform per command.
fn correlate(cmds: &[Json]) -> Correlate {
    let logic: Vec<Json> = cmds
        .iter()
        .enumerate()
        .map(|(i, c)| {
            json!({"transform": {"type": "event", "method": "property", "property_name": format!("p{i}"), "command": c}})
        })
        .collect();
    Correlate::from_value(&v(json!({"logic": logic}))).expect("a valid correlate block")
}

#[test]
fn test_walks_nested_conditions() {
    let config = Correlate::from_value(&v(json!({"logic": [
        {"when": "{{ _event.x }}",
         "execute": [{"transform": {"method": "property", "property_name": "a", "command": {"type": "defined", "name": "cmd_a"}}}],
         "else": [{"transform": {"method": "property", "property_name": "b", "command": {"type": "defined", "name": "cmd_b"}}}]},
        {"transform": {"method": "property", "property_name": "c", "command": {"type": "defined", "name": "cmd_c"}}},
    ]})))
    .expect("valid");
    let names: Vec<&str> = commands(&config.logic)
        .iter()
        .map(|c| c.name.as_deref().unwrap_or(""))
        .collect();
    assert_eq!(names, ["cmd_a", "cmd_b", "cmd_c"]);
}

fn substitute(value: &Json, name: &str) -> Json {
    match value {
        Json::String(s) => Json::String(s.replace("NAME", name)),
        Json::Object(m) => Json::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), substitute(v, name)))
                .collect(),
        ),
        Json::Array(items) => Json::Array(items.iter().map(|v| substitute(v, name)).collect()),
        other => other.clone(),
    }
}

/// Ten parameters: each name with each of the five commands.
#[test]
fn test_command_templates_are_rejected() {
    let cmds = [
        json!({"type": "executable", "path": "/x/a.py", "env": {"API_KEY": "{{ NAME['vendor.api_key'] }}"}}),
        json!({"type": "executable", "path": "/x/a.py", "args": ["--key", "{{ NAME.vendor.api_key }}"]}),
        json!({"type": "query", "source": "splunk", "query": "search key={{ NAME['vendor'] }}"}),
        json!({"type": "lookup", "options": {"nested": {"deep": ["{{ NAME }}"]}}}),
        json!({"type": "defined", "name": "cmd", "arguments": {"args": ["{% if NAME %}x{% endif %}"]}}),
    ];
    for name in ["_secrets", "_config"] {
        for cmd in &cmds {
            let errors = removed_names(Some(&correlate(&[substitute(cmd, name)])), None);
            assert_eq!(errors.len(), 1, "{name} {cmd}");
            assert!(errors[0].contains(name));
            assert!(errors[0].contains("custom command type"));
        }
    }
}

/// Two parameters.
#[test]
fn test_condition_action_and_debug_templates_are_rejected() {
    for name in ["_secrets", "_config"] {
        let config = Correlate::from_value(&v(json!({"logic": [{
            "when": {"type": "and", "value": ["{{ _event.x }}", {"type": "not", "value": format!("{{{{ {name}.a }}}}")}]},
            "execute": [{"action": {"type": "log", "log_message": "ok"}}],
            "else": [{"action": {"type": "log", "log_message": format!("{{{{ {name}.b }}}}")}, "debug": format!("{{{{ {name}.c }}}}")}],
        }]})))
        .expect("valid");
        let errors = removed_names(Some(&config), None);
        assert_eq!(errors.len(), 3, "{name}: {errors:?}");
        assert!(errors.iter().all(|e| e.contains(name)));
    }
}

#[test]
fn test_predefined_command_is_checked() {
    // commands shared through an include are checked under their own name
    let p = [predefined(
        json!({"name": "get_r7_investigation_comments", "type": "executable",
        "path": "/x/r7.py", "env": {"R7_API_KEY": "{{ _secrets['rapid7.api_key'] }}"}}),
    )];
    let errors = removed_names(None, Some(&p));
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("get_r7_investigation_comments"));
    assert!(errors[0].contains("_secrets"));
}

#[test]
fn test_event_templates_are_accepted() {
    let c = correlate(&[
        json!({"type": "executable", "path": "/x/a.py", "args": ["{{ _event.domain }}"],
               "env": {"USER": "{{ _event['properties.userId'] }}", "MODE": "fast"}}),
        json!({"type": "query", "source": "splunk", "query": "search host={{ _event.host }} | stats count by {{ _events|length }}"}),
    ]);
    assert!(removed_names(Some(&c), None).is_empty());
}

#[test]
fn test_a_locally_assigned_name_is_not_a_reference() {
    let c = correlate(&[json!({"type": "executable", "path": "/x/a.py",
        "args": ["{% set _config = _event.x %}{{ _config }}"]})]);
    assert!(removed_names(Some(&c), None).is_empty());
}

#[test]
fn test_unrendered_fields_are_not_checked() {
    // `description` and `source_options` are passed as written, never rendered
    let p = [predefined(
        json!({"name": "cmd", "description": "do not use {{ _secrets }} here",
        "type": "query", "source": "splunk", "query": "search x", "source_options": {"note": "{{ _config }}"}}),
    )];
    assert!(removed_names(None, Some(&p)).is_empty());
}

#[test]
fn test_template_that_does_not_parse_is_skipped() {
    let c =
        correlate(&[json!({"type": "executable", "path": "/x/a.py", "args": ["{{ _secrets["]})]);
    assert!(removed_names(Some(&c), None).is_empty());
}

#[test]
fn test_same_template_in_several_places_is_one_error() {
    let cmd = json!({"type": "executable", "path": "/x/a.py", "env": {"K": "{{ _secrets.k }}"}});
    assert_eq!(
        removed_names(Some(&correlate(&[cmd.clone(), cmd])), None).len(),
        1
    );
}

/// `_LookupOptions`: `ip: str`, `limit: int = 10`, no extra keys.
struct Lookup;

impl CommandType for Lookup {
    fn has_options(&self) -> bool {
        true
    }
    fn validate_options(&self, options: &Value) -> Result<Json, HuntError> {
        let mut errs = Errors::new();
        let invalid = |errors| HuntError::Validation {
            title: "_LookupOptions".to_owned(),
            errors,
        };
        let Some(mut o) = Obj::new(options, &[], "_LookupOptions", &mut errs) else {
            return Err(invalid(errs));
        };
        let ip = o.required(&mut errs, "ip", string)?;
        let limit = o.default(&mut errs, "limit", 10, integer)?;
        if !o.finish(&mut errs) {
            return Err(invalid(errs));
        }
        Ok(json!({"ip": ip, "limit": limit.map(|l| l as i64)}))
    }
    fn execute(&self, _: &CommandContext<'_>, _: &Json) -> Result<String, String> {
        Ok(String::new())
    }
}

/// `_LiveCommand`.
struct Live;

impl CommandType for Live {
    fn cacheable(&self) -> bool {
        false
    }
    fn execute(&self, _: &CommandContext<'_>, _: &Json) -> Result<String, String> {
        Ok(String::new())
    }
}

fn custom_types() -> CommandTypes {
    let mut types = CommandTypes::new();
    types
        .register("lookup", Arc::new(Lookup))
        .expect("registers");
    types.register("live", Arc::new(Live)).expect("registers");
    types
}

#[test]
fn test_valid_custom_command() {
    let c = correlate(&[
        json!({"type": "lookup", "cache": "1d", "options": {"ip": "{{ _event.ip }}"}}),
    ]);
    assert!(custom_command_types(Some(&c), None, &custom_types()).is_empty());
}

#[test]
fn test_builtin_commands_are_ignored() {
    let c = correlate(&[
        json!({"type": "query", "source": "not_even_registered", "query": "q"}),
        json!({"type": "executable", "path": "/bin/true"}),
    ]);
    assert!(custom_command_types(Some(&c), None, &custom_types()).is_empty());
}

#[test]
fn test_unknown_type_is_reported_with_known_types() {
    let errors = custom_command_types(
        Some(&correlate(&[json!({"type": "lookpu"})])),
        None,
        &custom_types(),
    );
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("unknown command type 'lookpu'"));
    assert!(errors[0].contains("live, lookup"));
}

#[test]
fn test_load_failure_is_reported() {
    let mut types = custom_types();
    types.failed("broken", "RuntimeError: no api key");
    let errors = custom_command_types(Some(&correlate(&[json!({"type": "broken"})])), None, &types);
    assert_eq!(
        errors,
        [
            "command 'broken': command type 'broken' failed to load on this node: RuntimeError: no api key"
        ]
    );
}

#[test]
fn test_bad_options_are_reported() {
    let errors = custom_command_types(
        Some(&correlate(&[
            json!({"type": "lookup", "options": {"ipp": "1.2.3.4"}}),
        ])),
        None,
        &custom_types(),
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("options.ip") && e.contains("Field required")),
        "{errors:?}"
    );
    assert!(errors.iter().any(|e| e.contains("options.ipp")));
}

#[test]
fn test_template_in_typed_field_is_tolerated() {
    // "{{ _event.n }}" isn't an int yet: it's judged once rendered, at run time
    let c =
        correlate(&[json!({"type": "lookup", "options": {"ip": "x", "limit": "{{ _event.n }}"}})]);
    assert!(custom_command_types(Some(&c), None, &custom_types()).is_empty());
}

#[test]
fn test_literal_bad_value_in_typed_field_is_reported() {
    let c = correlate(&[json!({"type": "lookup", "options": {"ip": "x", "limit": "lots"}})]);
    let errors = custom_command_types(Some(&c), None, &custom_types());
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("options.limit"));
}

#[test]
fn test_options_on_type_without_config_class_are_reported() {
    let errors = custom_command_types(
        Some(&correlate(&[json!({"type": "live", "options": {"x": 1}})])),
        None,
        &custom_types(),
    );
    assert_eq!(
        errors,
        ["command 'live': command type 'live' takes no options, got ['x']"]
    );
}

#[test]
fn test_cache_on_uncacheable_type_is_reported() {
    let errors = custom_command_types(
        Some(&correlate(&[json!({"type": "live", "cache": "1h"})])),
        None,
        &custom_types(),
    );
    assert_eq!(
        errors,
        ["command 'live': command type 'live' is not cacheable; remove 'cache'"]
    );
}

#[test]
fn test_predefined_custom_command_is_checked() {
    let p = [predefined(
        json!({"name": "ip_lookup", "type": "lookup", "options": {"limit": 5}}),
    )];
    let errors = custom_command_types(None, Some(&p), &custom_types());
    assert_eq!(errors.len(), 1);
    assert!(errors[0].starts_with("predefined command 'ip_lookup': options.ip"));
}

#[test]
fn test_defined_arguments_are_applied_before_checking() {
    // a predefined command may leave an option for each reference to give
    let p = [predefined(
        json!({"name": "ip_lookup", "type": "lookup", "options": {"ip": "placeholder"}}),
    )];
    let c = correlate(&[
        json!({"type": "defined", "name": "ip_lookup", "arguments": {"options": {"limit": 5}}}),
    ]);
    let errors = custom_command_types(Some(&c), Some(&p), &custom_types());
    // arguments.options replaced the whole dict, which dropped `ip`
    assert_eq!(errors.len(), 1);
    assert!(errors[0].starts_with("defined command 'ip_lookup': options.ip"));
}

#[test]
fn test_unargumented_defined_reference_is_not_double_reported() {
    let p = [predefined(json!({"name": "gone", "type": "lookpu"}))];
    let c = correlate(&[
        json!({"type": "defined", "name": "gone"}),
        json!({"type": "defined", "name": "gone"}),
    ]);
    assert_eq!(
        custom_command_types(Some(&c), Some(&p), &custom_types()).len(),
        1
    );
}

#[test]
fn test_nested_commands_are_checked() {
    let c = Correlate::from_value(&v(json!({"logic": [{"when": "{{ true }}",
        "execute": [{"transform": {"method": "property", "property_name": "a", "command": {"type": "nope"}}}]}]})))
    .expect("valid");
    assert_eq!(
        custom_command_types(Some(&c), None, &custom_types()).len(),
        1
    );
}

#[test]
fn test_non_correlate_hunt_is_a_no_op() {
    assert!(custom_command_types(None, None, &custom_types()).is_empty());
}
