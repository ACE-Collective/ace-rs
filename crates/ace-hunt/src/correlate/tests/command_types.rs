//! `test_command_types.py`: 44 cases. ace3's handlers are Python classes with a pydantic
//! `config_class`; here they're Rust types whose options validate through `crate::validate`, as
//! pydantic does. Two cases are the type system's in Rust: a handler that isn't a
//! `CorrelationCommand` (`test_handler_must_be_a_correlation_command`) and one that returns a
//! list (`test_non_string_return_raises`) don't compile. `TestLoadCommandTypesFromConfig` loads
//! classes named in ace3's configuration; ace-rs's binary registers its types with
//! `App::command_type`, whose tests (`ace_app`) port those six: the registry's part of
//! `test_failing_type_does_not_abort_others` is here too. ace3's context also carries the
//! configuration and a temporary directory, which ace-rs's doesn't (the `command` module says why),
//! so those assertions are dropped.

use std::sync::{Arc, Mutex};

use chrono::TimeDelta;
use serde_json::{Map as JsonMap, Value as Json, json};

use super::{Fixture, TestCache, evs, js, logic, predefined, utc, v};
use crate::HuntError;
use crate::correlate::cache::cache_key;
use crate::correlate::command::{Call, CommandContext, CommandType, CommandTypes};
use crate::correlate::engine::{Engine, HuntRun};
use crate::correlate::expr::Scope;
use crate::correlate::pyjson::dumps_json;
use crate::correlate::{Command, PredefinedCommand};
use crate::validate::{Errors, Obj, integer, string};
use crate::value::Value;

/// One call a handler served.
#[derive(Debug, Clone)]
struct Served {
    command_type: String,
    event: Json,
    events: Vec<Json>,
    transform_type: String,
    timeout: TimeDelta,
    options: Json,
}

/// How an `_Echo` variant behaves.
#[derive(Default, Clone, Copy)]
struct Shape {
    narrow_key: bool,
    uncacheable: bool,
    literal: bool,
    sneaky: bool,
    summarized: bool,
}

/// `_EchoCommand`, with `_EchoOptions` (`message: str`, `count: int = 1`, no extra keys): one
/// JSON line per `count`.
struct Echo {
    prefix: String,
    shape: Shape,
    calls: Mutex<Vec<Served>>,
}

impl Echo {
    fn new(prefix: &str, shape: Shape) -> Arc<Echo> {
        Arc::new(Echo {
            prefix: prefix.to_owned(),
            shape,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<Served> {
        self.calls.lock().expect("calls").clone()
    }
}

fn served(context: &CommandContext<'_>, options: &Json) -> Served {
    Served {
        command_type: context.command_type.to_owned(),
        event: js(context.event),
        events: context.events.iter().map(js).collect(),
        transform_type: context.transform_type.to_owned(),
        timeout: context.timeout,
        options: options.clone(),
    }
}

impl CommandType for Echo {
    fn has_options(&self) -> bool {
        true
    }

    fn validate_options(&self, options: &Value) -> Result<Json, HuntError> {
        let mut errs = Errors::new();
        let invalid = |errors: Errors| HuntError::Validation {
            title: "_EchoOptions".to_owned(),
            errors,
        };
        let Some(mut o) = Obj::new(options, &[], "_EchoOptions", &mut errs) else {
            return Err(invalid(errs));
        };
        let message = o.required(&mut errs, "message", string)?;
        let count = o.default(&mut errs, "count", 1, integer)?;
        if !o.finish(&mut errs) {
            return Err(invalid(errs));
        }
        Ok(json!({"message": message, "count": count.map(|c| c as i64)}))
    }

    fn cacheable(&self) -> bool {
        !self.shape.uncacheable
    }

    fn render_options(&self) -> bool {
        !self.shape.literal
    }

    fn execute(&self, context: &CommandContext<'_>, options: &Json) -> Result<String, String> {
        self.calls
            .lock()
            .expect("calls")
            .push(served(context, options));
        let message = format!(
            "{}{}",
            self.prefix,
            options["message"].as_str().unwrap_or("")
        );
        let count = options["count"].as_i64().unwrap_or(1);
        Ok((0..count)
            .map(|_| dumps_json(&json!({"message": message}), false))
            .collect::<Vec<_>>()
            .join("\n"))
    }

    fn cache_key(&self, context: &CommandContext<'_>, options: &Json) -> JsonMap<String, Json> {
        if self.shape.sneaky {
            return obj(json!({"type": "query", "query": "x"}));
        }
        if self.shape.narrow_key {
            return obj(json!({"message": options["message"]}));
        }
        let mut key = JsonMap::new();
        key.insert("options".to_owned(), options.clone());
        key.insert(
            "input".to_owned(),
            if context.transform_type == "stream" {
                Json::Array(context.events.iter().map(js).collect())
            } else {
                js(context.event)
            },
        );
        key
    }

    fn render_summary(&self, context: &CommandContext<'_>, options: &Json) -> Option<String> {
        if self.shape.summarized {
            return Some(format!(
                "lookup {}",
                options["message"].as_str().unwrap_or("")
            ));
        }
        Some(format!(
            "{} {}",
            context.command_type,
            dumps_json(options, true)
        ))
    }
}

/// `_NoOptionsCommand`.
struct NoOptions;

impl CommandType for NoOptions {
    fn execute(&self, context: &CommandContext<'_>, _: &Json) -> Result<String, String> {
        let id = js(context.event)["id"].clone();
        Ok(dumps_json(&json!({"event_id": id}), false))
    }
}

fn obj(json: Json) -> JsonMap<String, Json> {
    match json {
        Json::Object(m) => m,
        _ => panic!("an object"),
    }
}

fn command(json: Json) -> Command {
    Command::from_value(&v(json)).expect("a valid command")
}

fn with_types(types: &[(&str, Arc<dyn CommandType>)]) -> Fixture {
    let mut f = Fixture::default().cache(Arc::new(TestCache::default()));
    for (name, handler) in types {
        f.types.register(name, handler.clone()).expect("registers");
    }
    f
}

/// `_run(command, event, events, transform_type, secrets, predefined)`.
fn run(
    f: &Fixture,
    command: &Command,
    event: Json,
    events: Option<Json>,
    transform_type: &str,
    predefined: &[PredefinedCommand],
) -> Result<String, String> {
    let config = logic(json!([]));
    let event = super::ev(event.clone());
    let events = match events {
        Some(e) => evs(e),
        None => vec![event.clone()],
    };
    f.with(|rt| {
        Engine::new(
            rt,
            &config,
            predefined,
            HuntRun::at(utc("2024-06-01T12:00:00+00:00")),
        )
        .execute_command(
            command,
            Call {
                scope: Scope {
                    event: &event,
                    events: &events,
                },
                transform_type,
            },
        )
    })
}

#[test]
fn test_register_and_get() {
    let handler: Arc<dyn CommandType> = Echo::new("", Shape::default());
    let mut types = CommandTypes::new();
    types.register("echo", handler.clone()).expect("registers");
    assert!(Arc::ptr_eq(
        types.get("echo").expect("registered"),
        &handler
    ));
    assert_eq!(types.names(), ["echo"]);
}

/// Three parameters.
#[test]
fn test_builtin_names_are_reserved() {
    for name in ["query", "executable", "defined"] {
        let mut types = CommandTypes::new();
        let r = types.register(name, Echo::new("", Shape::default()));
        assert!(matches!(r, Err(e) if e.contains("built-in")), "{name}");
    }
}

/// Five parameters.
#[test]
fn test_invalid_names_rejected() {
    for name in ["Echo", "1echo", "echo-lookup", "echo lookup", ""] {
        let mut types = CommandTypes::new();
        let r = types.register(name, Echo::new("", Shape::default()));
        assert!(
            matches!(r, Err(e) if e.contains("invalid correlation command type name")),
            "{name:?}"
        );
    }
}

#[test]
fn test_overwrite_warns() {
    let mut types = CommandTypes::new();
    types
        .register("echo", Echo::new("", Shape::default()))
        .expect("registers");
    let replacement: Arc<dyn CommandType> = Echo::new("", Shape::default());
    // ace3 warns of the overwrite; register says it replaced one
    assert_eq!(types.register("echo", replacement.clone()), Ok(true));
    assert!(Arc::ptr_eq(
        types.get("echo").expect("registered"),
        &replacement
    ));
}

#[test]
fn test_clear() {
    let mut types = CommandTypes::new();
    types
        .register("echo", Echo::new("", Shape::default()))
        .expect("registers");
    types.clear();
    assert!(types.names().is_empty());
}

#[test]
fn test_failing_type_does_not_abort_others() {
    // the registry's part: a type that failed to build is told as that, not a bare unknown type
    let mut types = CommandTypes::new();
    types.failed("boom", "RuntimeError: constructor boom");
    types
        .register("echo", Echo::new("", Shape::default()))
        .expect("registers");
    assert!(types.get("echo").is_ok());
    assert!(types.load_errors()["boom"].contains("constructor boom"));
    assert!(
        matches!(types.get("boom"), Err(e) if e.contains("failed to load: RuntimeError: constructor boom"))
    );
}

#[test]
fn test_options_rendered_then_validated() {
    let echo = Echo::new("", Shape::default());
    let f = with_types(&[("echo", echo.clone())]);
    let cmd = command(
        json!({"type": "echo", "options": {"message": "hi {{ _event.user }}", "count": "{{ _event.n }}"}}),
    );
    let output = run(
        &f,
        &cmd,
        json!({"user": "alice", "n": 2}),
        None,
        "event",
        &[],
    )
    .expect("runs");
    let line = dumps_json(&json!({"message": "hi alice"}), false);
    assert_eq!(
        output.lines().collect::<Vec<_>>(),
        [line.as_str(), line.as_str()]
    );
    let call = &echo.calls()[0];
    // the rendered "2" was coerced by the options model
    assert_eq!(call.options["count"], json!(2));
    assert_eq!(call.command_type, "echo");
    assert_eq!(call.event, json!({"user": "alice", "n": 2}));
    assert_eq!(call.transform_type, "event");
    assert_eq!(call.timeout, TimeDelta::minutes(10));
}

#[test]
fn test_nested_options_rendered() {
    /// `_Nested`: `items: list[str]`, `meta: dict[str, str]`.
    struct Nested;
    impl CommandType for Nested {
        fn has_options(&self) -> bool {
            true
        }
        fn validate_options(&self, options: &Value) -> Result<Json, HuntError> {
            Ok(options.to_json())
        }
        fn execute(&self, _: &CommandContext<'_>, options: &Json) -> Result<String, String> {
            Ok(dumps_json(options, false))
        }
    }
    let f = with_types(&[("nested", Arc::new(Nested))]);
    let cmd = command(
        json!({"type": "nested", "options": {"items": ["{{ _event.a }}", "literal"], "meta": {"k": "{{ _event.b }}"}}}),
    );
    let output = run(&f, &cmd, json!({"a": "x", "b": "y"}), None, "event", &[]).expect("runs");
    assert_eq!(
        serde_json::from_str::<Json>(&output).expect("JSON"),
        json!({"items": ["x", "literal"], "meta": {"k": "y"}})
    );
}

#[test]
fn test_timeout_passed_to_context() {
    let echo = Echo::new("", Shape::default());
    let f = with_types(&[("echo", echo.clone())]);
    run(
        &f,
        &command(json!({"type": "echo", "timeout": "45s", "options": {"message": "m"}})),
        json!({}),
        None,
        "event",
        &[],
    )
    .expect("runs");
    assert_eq!(echo.calls()[0].timeout, TimeDelta::seconds(45));
}

#[test]
fn test_invalid_options_raise() {
    let f = with_types(&[("echo", Echo::new("", Shape::default()))]);
    let r = run(
        &f,
        &command(json!({"type": "echo", "options": {"mesage": "typo"}})),
        json!({}),
        None,
        "event",
        &[],
    );
    assert!(matches!(r, Err(e) if e.starts_with("ValidationError") && e.contains("mesage")));
}

#[test]
fn test_rendered_value_that_fails_validation_raises() {
    let f = with_types(&[("echo", Echo::new("", Shape::default()))]);
    let r = run(
        &f,
        &command(json!({"type": "echo", "options": {"message": "m", "count": "{{ _event.n }}"}})),
        json!({"n": "many"}),
        None,
        "event",
        &[],
    );
    assert!(matches!(r, Err(e) if e.starts_with("ValidationError")));
}

#[test]
fn test_options_on_type_without_config_class_raise() {
    let f = with_types(&[("plain", Arc::new(NoOptions))]);
    let r = run(
        &f,
        &command(json!({"type": "plain", "options": {"x": 1}})),
        json!({}),
        None,
        "event",
        &[],
    );
    assert!(matches!(r, Err(e) if e.contains("does not take options")));
}

#[test]
fn test_type_without_options() {
    let f = with_types(&[("plain", Arc::new(NoOptions))]);
    let r = run(
        &f,
        &command(json!({"type": "plain"})),
        json!({"id": 7}),
        None,
        "event",
        &[],
    );
    assert_eq!(r.as_deref(), Ok("{\"event_id\": 7}"));
}

#[test]
fn test_output_is_sanitized() {
    let f = with_types(&[("echo", Echo::new("token=hunter2 ", Shape::default()))])
        .secrets(&["hunter2"]);
    let output = run(
        &f,
        &command(json!({"type": "echo", "options": {"message": "m"}})),
        json!({}),
        None,
        "event",
        &[],
    )
    .expect("runs");
    assert!(!output.contains("hunter2"));
    assert!(output.contains("***"));
}

/// Two parameters.
#[test]
fn test_secrets_and_config_not_bound_in_options() {
    for name in ["_secrets", "_config"] {
        let f = with_types(&[("echo", Echo::new("", Shape::default()))]).secrets(&["hunter2"]);
        let cmd = command(
            json!({"type": "echo", "options": {"message": format!("[{{{{ {name} is defined }}}}]")}}),
        );
        let output = run(&f, &cmd, json!({}), None, "event", &[]).expect("runs");
        assert_eq!(
            serde_json::from_str::<Json>(&output).expect("JSON"),
            json!({"message": "[False]"}),
            "{name}"
        );
    }
}

#[test]
fn test_render_options_false_passes_templates_through() {
    let literal = Echo::new(
        "",
        Shape {
            literal: true,
            ..Shape::default()
        },
    );
    let f = with_types(&[("literal", literal.clone())]);
    run(
        &f,
        &command(json!({"type": "literal", "options": {"message": "{{ _event.user }}"}})),
        json!({"user": "alice"}),
        None,
        "event",
        &[],
    )
    .expect("runs");
    assert_eq!(
        literal.calls()[0].options["message"],
        json!("{{ _event.user }}")
    );
}

#[test]
fn test_stream_transform_context() {
    let echo = Echo::new("", Shape::default());
    let f = with_types(&[("echo", echo.clone())]);
    run(
        &f,
        &command(json!({"type": "echo", "options": {"message": "{{ _events | length }}"}})),
        json!({"id": 1}),
        Some(json!([{"id": 1}, {"id": 2}])),
        "stream",
        &[],
    )
    .expect("runs");
    let call = &echo.calls()[0];
    assert_eq!(call.transform_type, "stream");
    assert_eq!(call.events, [json!({"id": 1}), json!({"id": 2})]);
    assert_eq!(call.options["message"], json!("2"));
}

fn cached(answer: Option<&str>) -> Arc<TestCache> {
    Arc::new(TestCache {
        answer: answer.map(str::to_owned),
        ..TestCache::default()
    })
}

#[test]
fn test_cache_hit_skips_execution() {
    let echo = Echo::new("", Shape::default());
    let cache = cached(Some("cached"));
    let f = with_types(&[("echo", echo.clone())]).cache(cache.clone());
    let output = run(
        &f,
        &command(json!({"type": "echo", "cache": "1h", "options": {"message": "m"}})),
        json!({}),
        None,
        "event",
        &[],
    );
    assert_eq!(output.as_deref(), Ok("cached"));
    assert!(echo.calls().is_empty());
    // the key holds the type
    assert_eq!(
        cache.gets(),
        [cache_key(&obj(
            json!({"options": {"message": "m", "count": 1}, "input": {}, "type": "echo"})
        ))]
    );
    assert!(cache.sets().is_empty());
}

#[test]
fn test_cache_miss_stores_result() {
    let cache = cached(None);
    let f = with_types(&[("echo", Echo::new("", Shape::default()))]).cache(cache.clone());
    let output = run(
        &f,
        &command(json!({"type": "echo", "cache": "1h", "options": {"message": "m"}})),
        json!({"id": 1}),
        None,
        "event",
        &[],
    )
    .expect("runs");
    let sets = cache.sets();
    assert_eq!(
        sets[0].0,
        cache_key(&obj(
            json!({"type": "echo", "options": {"message": "m", "count": 1}, "input": {"id": 1}})
        ))
    );
    assert_eq!(sets[0].1, output);
    assert_eq!(sets[0].2, 3600);
}

#[test]
fn test_no_cache_setting_skips_cache() {
    let cache = cached(None);
    let f = with_types(&[("echo", Echo::new("", Shape::default()))]).cache(cache.clone());
    run(
        &f,
        &command(json!({"type": "echo", "options": {"message": "m"}})),
        json!({}),
        None,
        "event",
        &[],
    )
    .expect("runs");
    assert!(cache.gets().is_empty() && cache.sets().is_empty());
}

#[test]
fn test_default_key_differs_per_event() {
    // the default key holds the input: a handler may read the event, so two events rendering the
    // same options don't share a result
    let cache = cached(None);
    let f = with_types(&[("echo", Echo::new("", Shape::default()))]).cache(cache.clone());
    let cmd = command(json!({"type": "echo", "cache": "1h", "options": {"message": "same"}}));
    run(&f, &cmd, json!({"id": 1}), None, "event", &[]).expect("runs");
    run(&f, &cmd, json!({"id": 2}), None, "event", &[]).expect("runs");
    let gets = cache.gets();
    assert_ne!(gets[0], gets[1]);
}

#[test]
fn test_default_key_for_stream_uses_whole_stream() {
    let cache = cached(None);
    let f = with_types(&[("echo", Echo::new("", Shape::default()))]).cache(cache.clone());
    run(
        &f,
        &command(json!({"type": "echo", "cache": "1h", "options": {"message": "m"}})),
        json!({"id": 1}),
        Some(json!([{"id": 1}, {"id": 2}])),
        "stream",
        &[],
    )
    .expect("runs");
    assert_eq!(
        cache.gets(),
        [cache_key(&obj(
            json!({"type": "echo", "options": {"message": "m", "count": 1},
            "input": [{"id": 1}, {"id": 2}]})
        ))]
    );
}

#[test]
fn test_narrowed_key_shared_across_events() {
    let cache = cached(None);
    let narrow = Echo::new(
        "",
        Shape {
            narrow_key: true,
            ..Shape::default()
        },
    );
    let f = with_types(&[("narrow", narrow)]).cache(cache.clone());
    let cmd = command(json!({"type": "narrow", "cache": "1h", "options": {"message": "same"}}));
    run(&f, &cmd, json!({"id": 1}), None, "event", &[]).expect("runs");
    run(&f, &cmd, json!({"id": 2}), None, "event", &[]).expect("runs");
    let expected = cache_key(&obj(json!({"type": "narrow", "message": "same"})));
    assert_eq!(cache.gets(), [expected.clone(), expected]);
}

#[test]
fn test_handler_cannot_override_type_in_key() {
    let cache = cached(None);
    let sneaky = Echo::new(
        "",
        Shape {
            sneaky: true,
            ..Shape::default()
        },
    );
    let f = with_types(&[("sneaky", sneaky)]).cache(cache.clone());
    run(
        &f,
        &command(json!({"type": "sneaky", "cache": "1h", "options": {"message": "m"}})),
        json!({}),
        None,
        "event",
        &[],
    )
    .expect("runs");
    assert_eq!(
        cache.gets(),
        [cache_key(&obj(json!({"type": "sneaky", "query": "x"})))]
    );
}

#[test]
fn test_uncacheable_type_ignores_cache() {
    let cache = cached(None);
    let live = Echo::new(
        "",
        Shape {
            uncacheable: true,
            ..Shape::default()
        },
    );
    let f = with_types(&[("live", live.clone())]).cache(cache.clone());
    run(
        &f,
        &command(json!({"type": "live", "cache": "1h", "options": {"message": "m"}})),
        json!({}),
        None,
        "event",
        &[],
    )
    .expect("runs");
    assert!(cache.gets().is_empty() && cache.sets().is_empty());
    assert_eq!(live.calls().len(), 1);
}

#[test]
fn test_defined_resolves_to_custom_type_with_option_override() {
    let echo = Echo::new("", Shape::default());
    let f = with_types(&[("echo", echo.clone())]);
    let predefined = [predefined(
        json!({"name": "greet", "type": "echo", "cache": "1d",
        "options": {"message": "default", "count": 3}}),
    )];
    let cmd = command(json!({"type": "defined", "name": "greet",
        "arguments": {"options": {"message": "hi {{ _event.user }}"}}}));
    let output = run(&f, &cmd, json!({"user": "bob"}), None, "event", &predefined).expect("runs");
    // `arguments.options` replaces the predefined options whole, so count is back to 1
    assert_eq!(
        output.lines().collect::<Vec<_>>(),
        [dumps_json(&json!({"message": "hi bob"}), false)]
    );
    assert_eq!(echo.calls()[0].options["count"], json!(1));
}

#[test]
fn test_predefined_round_trip_does_not_trip_builtin_field_check() {
    // to_command dumps every field (source_options {}, time_range None, ...); the custom type's
    // check judges values, not which fields were set
    let predef = predefined(json!({"name": "greet", "type": "echo", "options": {"message": "m"}}));
    let cmd = predef.to_command(None).expect("converts");
    assert_eq!(cmd.kind, "echo");
    assert_eq!(Json::Object(cmd.options), json!({"message": "m"}));
}

#[test]
fn test_property_transform_enriches_and_filters() {
    let echo = Echo::new("", Shape::default());
    let f = with_types(&[("echo", echo)]);
    let config = logic(json!([
        {"transform": {"type": "event", "method": "property", "property_name": "echoed", "property_type": "list",
            "command": {"type": "echo", "options": {"message": "{{ _event.user }}"}}}},
        {"when": "{{ _event.echoed[0].message == 'noise' }}", "execute": [{"action": "filter"}]},
    ]));
    let result = f.simple(&config, evs(json!([{"user": "noise"}, {"user": "alice"}])));
    let users: Vec<Json> = result
        .events
        .iter()
        .map(|e| js(e)["user"].clone())
        .collect();
    assert_eq!(users, [json!("alice")]);
    assert_eq!(
        js(&result.events[0])["echoed"],
        json!([{"message": "alice"}])
    );
    let t = result.trace.event_traces[1].steps[0]
        .step
        .transform()
        .expect("a transform");
    assert_eq!(t.trace_type, "transform");
    assert_eq!(t.command_type, "echo");
    assert_eq!(
        t.rendered_command.as_deref(),
        Some("echo {\"count\": 1, \"message\": \"alice\"}")
    );
    assert_eq!(t.result_count, Some(1));
    // not a query: no window on the trace
    assert_eq!(t.query_start_time, None);
}

#[test]
fn test_custom_render_summary_is_used() {
    let summarized = Echo::new(
        "",
        Shape {
            summarized: true,
            ..Shape::default()
        },
    );
    let f = with_types(&[("summarized", summarized)]);
    let config = logic(
        json!([{"transform": {"method": "property", "property_name": "p",
        "command": {"type": "summarized", "options": {"message": "{{ _event.user }}"}}}}]),
    );
    let result = f.simple(&config, evs(json!([{"user": "alice"}])));
    assert_eq!(
        result.trace.event_traces[0].steps[0]
            .step
            .transform()
            .expect("a transform")
            .rendered_command
            .as_deref(),
        Some("lookup alice")
    );
}

#[test]
fn test_unregistered_type_errors_and_alerts() {
    let config = logic(
        json!([{"transform": {"method": "property", "property_name": "p",
        "command": {"type": "missing_type"}}}]),
    );
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    // the event still alerts, with the error on its trace
    assert_eq!(result.events.len(), 1);
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "error");
    assert!(
        et.steps[0]
            .step
            .transform()
            .expect("a transform")
            .error
            .as_deref()
            .is_some_and(|e| e.contains("unknown command type: 'missing_type'"))
    );
}
