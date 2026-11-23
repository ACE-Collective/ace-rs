//! `test_commands.py`: 39 cases. Those whose executable ran a `python3 -c` one-liner run [`Echo`]
//! (`super`'s docs say why), with the same rendering, input, caching and scrubbing. ace3 patches
//! `get_cached_result` and `set_cached_result`; here the run's cache is a [`TestCache`], and
//! "called once with these arguments" is "looked up once under these arguments' key". ace3's
//! `execute_command` takes the engine's state as arguments; here it's the engine's method.

use std::sync::Arc;

use chrono::TimeDelta;
use serde_json::{Map as JsonMap, Value as Json, json};

use super::{Fixture, TestCache, TestSource, echo_path, ev, evs, logic, predefined, time, utc, v};
use crate::correlate::cache::cache_key;
use crate::correlate::command::Call;
use crate::correlate::engine::{Engine, HuntRun};
use crate::correlate::expr::Scope;
use crate::correlate::{Command, PredefinedCommand};

fn command(json: Json) -> Command {
    Command::from_value(&v(json)).expect("a valid command")
}

fn args(json: Json) -> JsonMap<String, Json> {
    match json {
        Json::Object(m) => m,
        _ => panic!("an object"),
    }
}

/// `execute_command(cmd, event, events, transform_type, predefined, ...)` once.
fn exec(
    f: &Fixture,
    cmd: &Command,
    event: Json,
    transform_type: &str,
    predefined: &[PredefinedCommand],
) -> Result<String, String> {
    let config = logic(json!([]));
    let event = ev(event);
    let events = vec![event.clone()];
    f.with(|rt| {
        let mut engine = Engine::new(
            rt,
            &config,
            predefined,
            HuntRun::at(utc("2024-06-01T12:00:00+00:00")),
        );
        engine.execute_command(
            cmd,
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

fn no_cache() -> Arc<TestCache> {
    Arc::new(TestCache::default())
}

#[test]
fn test_query_command() {
    let source = TestSource::new(json!([{"host": "web1"}, {"host": "web2"}]));
    let f = Fixture::default()
        .source("test_source", source)
        .cache(no_cache());
    let cmd = command(
        json!({"type": "query", "source": "test_source", "query": "search index=main", "time_range": null}),
    );
    let result = exec(&f, &cmd, json!({}), "event", &[]).expect("runs");
    let lines: Vec<&str> = result.trim().split('\n').collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        serde_json::from_str::<Json>(lines[0]).expect("JSON"),
        json!({"host": "web1"})
    );
}

#[test]
fn test_query_command_forwards_source_options() {
    // source_options reach the QuerySource as written
    let source = TestSource::new(json!([]));
    let f = Fixture::default()
        .source("test_source", source.clone())
        .cache(no_cache());
    let cmd = command(json!({
        "type": "query", "source": "test_source", "query": "where(host='{{ _event.host }}')",
        "source_options": {"log_names": ["Firewall Activity", "DNS Activity"]},
    }));
    exec(&f, &cmd, json!({"host": "web1"}), "event", &[]).expect("runs");
    let calls = source.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        Json::Object(calls[0].source_options.clone()),
        json!({"log_names": ["Firewall Activity", "DNS Activity"]})
    );
}

#[test]
fn test_query_command_omitted_source_options_is_empty_dict() {
    let source = TestSource::new(json!([]));
    let f = Fixture::default()
        .source("test_source", source.clone())
        .cache(no_cache());
    let cmd =
        command(json!({"type": "query", "source": "test_source", "query": "search index=main"}));
    exec(&f, &cmd, json!({}), "event", &[]).expect("runs");
    assert!(source.calls()[0].source_options.is_empty());
}

#[test]
fn test_executable_with_jinja_args() {
    let cmd = command(json!({
        "type": "executable", "path": echo_path(),
        "args": ["print", "{{ _event.user }}", "{{ _event.host }}"],
    }));
    let result = exec(
        &Fixture::default(),
        &cmd,
        json!({"user": "admin", "host": "web1"}),
        "event",
        &[],
    );
    assert_eq!(result.as_deref().map(str::trim), Ok("admin web1"));
}

#[test]
fn test_executable_with_stdin_event() {
    let cmd = command(json!({
        "type": "executable", "path": echo_path(),
        "args": ["stdin"], "stdin": true,
    }));
    let result = exec(
        &Fixture::default(),
        &cmd,
        json!({"user": "admin"}),
        "event",
        &[],
    )
    .expect("runs");
    assert_eq!(
        serde_json::from_str::<Json>(&result).expect("JSON"),
        json!({"user": "admin"})
    );
}

#[test]
fn test_defined_command() {
    let predef = predefined(
        json!({"name": "lookup", "type": "executable", "path": echo_path(), "args": ["print", "default"]}),
    );
    let cmd = command(json!({
        "type": "defined", "name": "lookup",
        "arguments": {"args": ["print", "{{ _event.user }}"]},
    }));
    let result = exec(
        &Fixture::default(),
        &cmd,
        json!({"user": "admin"}),
        "event",
        &[predef],
    );
    assert_eq!(result.as_deref().map(str::trim), Ok("admin"));
}

#[test]
fn test_defined_command_not_found() {
    let cmd = command(json!({"type": "defined", "name": "nonexistent"}));
    let result = exec(&Fixture::default(), &cmd, json!({}), "event", &[]);
    assert!(matches!(result, Err(e) if e.contains("not found")));
}

#[test]
fn test_stream_query_memoization() {
    let source = TestSource::new(json!([{"host": "web1"}]));
    let f = Fixture::default()
        .source("test_source", source.clone())
        .cache(no_cache());
    let cmd =
        command(json!({"type": "query", "source": "test_source", "query": "search index=main"}));
    let config = logic(json!([]));
    let event = ev(json!({}));
    let events: Vec<_> = Vec::new();
    let (r1, r2) = f.with(|rt| {
        let mut engine = Engine::new(
            rt,
            &config,
            &[],
            HuntRun::at(utc("2024-06-01T12:00:00+00:00")),
        );
        let call = Call {
            scope: Scope {
                event: &event,
                events: &events,
            },
            transform_type: "stream",
        };
        (
            engine.execute_command(&cmd, call),
            engine.execute_command(&cmd, call),
        )
    });
    assert_eq!(r1, r2);
    // only called once
    assert_eq!(source.calls().len(), 1);
}

#[test]
fn test_executable_with_jinja_env() {
    let cmd = command(json!({
        "type": "executable", "path": echo_path(),
        "args": ["env", "USER_NAME"], "env": {"USER_NAME": "{{ _event.user }}"},
    }));
    let result = exec(
        &Fixture::default(),
        &cmd,
        json!({"user": "admin"}),
        "event",
        &[],
    );
    assert_eq!(result.as_deref().map(str::trim), Ok("admin"));
}

#[test]
fn test_executable_without_env_does_not_inherit_ace_env() {
    // ace3 sets ACE_TEST_SENTINEL_PASSWORD in its own environment and the script must not see it;
    // a script type sees no environment but the command's `env:`, here none
    let cmd = command(json!({
        "type": "executable", "path": echo_path(),
        "args": ["env-keys"],
    }));
    let result = exec(&Fixture::default(), &cmd, json!({}), "event", &[]).expect("runs");
    let keys: Vec<String> = serde_json::from_str(&result).expect("JSON");
    assert!(!keys.contains(&"ACE_TEST_SENTINEL_PASSWORD".to_owned()));
    assert!(keys.is_empty());
}

#[test]
fn test_executable_with_env_sees_only_allowlist_and_its_own_keys() {
    // ace3's script also sees its allowlist of the process's variables, PATH among them; nothing is
    // executed here, so a script type sees its own keys and nothing else
    let cmd = command(json!({
        "type": "executable", "path": echo_path(),
        "args": ["env-keys"], "env": {"MY_VAR": "test"},
    }));
    let result = exec(&Fixture::default(), &cmd, json!({}), "event", &[]).expect("runs");
    let keys: Vec<String> = serde_json::from_str(&result).expect("JSON");
    assert_eq!(keys, ["MY_VAR"]);
}

/// Four parameters: `env` and `args`, each with `_secrets` and `_config`.
#[test]
fn test_executable_templates_cannot_see_secrets_or_config() {
    for field in ["env", "args"] {
        for name in ["_secrets", "_config"] {
            let template = format!("{{{{ {name} is defined }}}}");
            let cmd = if field == "env" {
                command(json!({"type": "executable", "path": echo_path(),
                    "args": ["env", "PROBE"], "env": {"PROBE": template}}))
            } else {
                command(json!({"type": "executable", "path": echo_path(),
                    "args": ["print", template]}))
            };
            let f = Fixture::default().secrets(&["REAL_KEY"]);
            let result = exec(&f, &cmd, json!({}), "event", &[]);
            assert_eq!(
                result.as_deref().map(str::trim),
                Ok("False"),
                "{field} {name}"
            );
        }
    }
}

/// Two parameters.
#[test]
fn test_executable_env_reading_secrets_fails() {
    // a hunt written against the removed `_secrets` or `_config` fails before its script runs
    for template in [
        "{{ _secrets['vendor.api_key'] }}",
        "{{ _config['vendor']['api_key'] }}",
    ] {
        let cmd = command(json!({"type": "executable", "path": echo_path(),
            "args": ["env", "API_KEY"], "env": {"API_KEY": template}}));
        let result = exec(
            &Fixture::default().secrets(&["REAL_KEY"]),
            &cmd,
            json!({}),
            "event",
            &[],
        );
        assert!(
            matches!(result, Err(e) if e.contains("is undefined")),
            "{template}"
        );
    }
}

#[test]
fn test_executable_stderr_is_sanitized() {
    let cmd = command(json!({"type": "executable", "path": echo_path(),
        "args": ["fail", "1", "REAL_KEY"]}));
    let result = exec(
        &Fixture::default().secrets(&["REAL_KEY"]),
        &cmd,
        json!({}),
        "event",
        &[],
    );
    assert!(matches!(result, Err(e) if !e.contains("REAL_KEY") && e.contains("exited with code")));
}

#[test]
fn test_executable_stdout_is_sanitized() {
    let cmd =
        command(json!({"type": "executable", "path": echo_path(), "args": ["print", "REAL_KEY"]}));
    let result = exec(
        &Fixture::default().secrets(&["REAL_KEY"]),
        &cmd,
        json!({}),
        "event",
        &[],
    )
    .expect("runs");
    assert!(!result.contains("REAL_KEY"));
    assert!(result.contains("***"));
}

/// Two parameters.
#[test]
fn test_query_text_cannot_see_secrets_or_config() {
    for name in ["_secrets", "_config"] {
        let source = TestSource::new(json!([]));
        let f = Fixture::default()
            .source("test_source", source.clone())
            .cache(no_cache())
            .secrets(&["REAL_KEY"]);
        let cmd = command(json!({"type": "query", "source": "test_source",
            "query": format!("search probe={{{{ {name} is defined }}}}")}));
        exec(&f, &cmd, json!({}), "event", &[]).expect("runs");
        assert_eq!(source.calls()[0].query, "search probe=False", "{name}");
    }
}

#[test]
fn test_executable_timeout() {
    let cmd = command(json!({"type": "executable", "path": echo_path(),
        "args": ["slow"], "timeout": "1s"}));
    let result = exec(&Fixture::default(), &cmd, json!({}), "event", &[]);
    assert!(matches!(result, Err(e) if e.contains("timed out")));
}

fn executable_key(args_list: Json, env: Json) -> String {
    cache_key(&args(
        json!({"type": "executable", "path": echo_path(), "args": args_list, "env": env}),
    ))
}

#[test]
fn test_executable_cache_hit() {
    let cache = Arc::new(TestCache {
        answer: Some("cached value".to_owned()),
        ..TestCache::default()
    });
    let f = Fixture::default().cache(cache.clone());
    let cmd = command(
        json!({"type": "executable", "path": echo_path(), "args": ["print", "hello"], "cache": "1h"}),
    );
    assert_eq!(
        exec(&f, &cmd, json!({}), "event", &[]).as_deref(),
        Ok("cached value")
    );
    assert_eq!(
        cache.gets(),
        [executable_key(json!(["print", "hello"]), Json::Null)]
    );
}

#[test]
fn test_executable_cache_miss_stores_result() {
    let cache = no_cache();
    let f = Fixture::default().cache(cache.clone());
    let cmd = command(
        json!({"type": "executable", "path": echo_path(), "args": ["print", "hello"], "cache": "1h"}),
    );
    let result = exec(&f, &cmd, json!({}), "event", &[]).expect("runs");
    assert_eq!(result.trim(), "hello");
    assert_eq!(
        cache.sets(),
        [(
            executable_key(json!(["print", "hello"]), Json::Null),
            result,
            3600
        )]
    );
}

#[test]
fn test_executable_no_cache_skips_cache() {
    let cache = no_cache();
    let f = Fixture::default().cache(cache.clone());
    let cmd =
        command(json!({"type": "executable", "path": echo_path(), "args": ["print", "hello"]}));
    let result = exec(&f, &cmd, json!({}), "event", &[]).expect("runs");
    assert_eq!(result.trim(), "hello");
    assert!(cache.gets().is_empty() && cache.sets().is_empty());
}

#[test]
fn test_executable_cache_key_includes_rendered_args() {
    let cache = no_cache();
    let f = Fixture::default().cache(cache.clone());
    let cmd = command(json!({"type": "executable", "path": echo_path(),
        "args": ["print", "hello", "{{ _event.user }}"], "cache": "1h"}));
    exec(&f, &cmd, json!({"user": "admin"}), "event", &[]).expect("runs");
    assert_eq!(
        cache.gets(),
        [executable_key(
            json!(["print", "hello", "admin"]),
            Json::Null
        )]
    );
}

#[test]
fn test_executable_cache_key_includes_rendered_env() {
    let cache = no_cache();
    let f = Fixture::default().cache(cache.clone());
    let cmd = command(json!({"type": "executable", "path": echo_path(),
        "args": ["env", "MY_VAR"], "env": {"MY_VAR": "{{ _event.val }}"}, "cache": "1h"}));
    exec(&f, &cmd, json!({"val": "test123"}), "event", &[]).expect("runs");
    assert_eq!(
        cache.gets(),
        [executable_key(
            json!(["env", "MY_VAR"]),
            json!({"MY_VAR": "test123"})
        )]
    );
}

#[test]
fn test_query_cache_hit() {
    let source = TestSource::new(json!([{"host": "should-not-run"}]));
    let cache = Arc::new(TestCache {
        answer: Some("cached value".to_owned()),
        ..TestCache::default()
    });
    let f = Fixture::default()
        .source("test_source", source.clone())
        .cache(cache.clone());
    let cmd = command(
        json!({"type": "query", "source": "test_source", "query": "search index=main", "cache": "5m"}),
    );
    assert_eq!(
        exec(&f, &cmd, json!({}), "event", &[]).as_deref(),
        Ok("cached value")
    );
    // a hit short-circuits before the data source is touched
    assert!(source.calls().is_empty());
    assert_eq!(
        cache.gets(),
        [cache_key(&args(
            json!({"type": "query", "source": "test_source", "query": "search index=main"})
        ))]
    );
}

#[test]
fn test_query_cache_key_includes_rendered_query() {
    // the persistent cache keys on the rendered query, not its template
    let source = TestSource::new(json!([{"animal": "dog", "count": "10"}]));
    let cache = no_cache();
    let f = Fixture::default()
        .source("test_source", source)
        .cache(cache.clone());
    let cmd = command(json!({"type": "query", "source": "test_source",
        "query": "search animal=\"{{ _event.animal }}\"", "cache": "5m"}));
    exec(&f, &cmd, json!({"animal": "dog"}), "event", &[]).expect("runs");
    let expected = cache_key(&args(
        json!({"type": "query", "source": "test_source", "query": "search animal=\"dog\""}),
    ));
    assert_eq!(cache.gets(), std::slice::from_ref(&expected));
    let sets = cache.sets();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].0, expected);
}

/// TestResolveTimeRange: `_resolve_time_range(cmd, event, kind, start, end, current_source)` is
/// the engine's, with the hunt's window and its source.
fn resolve(
    f: &Fixture,
    range: Json,
    event: Json,
    transform_type: &str,
    window: (&str, &str),
    current_source: Option<&str>,
) -> Result<(String, String), String> {
    let cmd = command(
        json!({"type": "query", "source": "splunk", "query": "search index=main", "time_range": range}),
    );
    let config = logic(json!([]));
    let mut run = HuntRun::at(utc(window.0));
    run.end = Some(time(window.1));
    run.source_type = current_source.map(str::to_owned);
    f.with(|rt| {
        Engine::new(rt, &config, &[], run)
            .resolve_time_range(&cmd, &ev(event), transform_type)
            .map(|(s, e)| (s.isoformat(), e.isoformat()))
    })
}

const NOW: (&str, &str) = ("2024-06-01T12:00:00+00:00", "2024-06-01T12:00:00+00:00");

fn splunk() -> Fixture {
    Fixture::default().source("splunk", TestSource::new(json!([])))
}

#[test]
fn test_explicit_field_and_format_override_defaults() {
    let r = resolve(
        &splunk(),
        json!({"before": "1h", "after": "1h", "relative_time_field": "custom", "relative_time_format": "iso8601"}),
        json!({"custom": "2024-06-01T00:00:00+00:00", "_time": "2099-01-01T00:00:00+00:00"}),
        "event",
        NOW,
        Some("splunk"),
    );
    // the reference time comes from `custom`, not `_time`
    assert_eq!(
        r,
        Ok((
            "2024-05-31T23:00:00+00:00".to_owned(),
            "2024-06-01T01:00:00+00:00".to_owned()
        ))
    );
}

#[test]
fn test_default_field_and_format_used_when_omitted() {
    let r = resolve(
        &splunk(),
        json!({"before": "30m", "after": "30m"}),
        json!({"_time": "2024-06-01T12:00:00+00:00"}),
        "event",
        NOW,
        Some("splunk"),
    );
    assert_eq!(
        r,
        Ok((
            "2024-06-01T11:30:00+00:00".to_owned(),
            "2024-06-01T12:30:00+00:00".to_owned()
        ))
    );
}

#[test]
fn test_explicit_format_with_default_field() {
    // the default field `_time`, the format overridden to epoch
    let r = resolve(
        &splunk(),
        json!({"before": "1h", "after": "0s", "relative_time_format": "epoch"}),
        json!({"_time": "1717200000"}),
        "event",
        NOW,
        Some("splunk"),
    );
    assert_eq!(
        r,
        Ok((
            "2024-05-31T23:00:00+00:00".to_owned(),
            "2024-06-01T00:00:00+00:00".to_owned()
        ))
    );
}

#[test]
fn test_explicit_field_with_default_format() {
    // the splunk source's default format is iso8601
    let r = resolve(
        &splunk(),
        json!({"before": "0s", "after": "1h", "relative_time_field": "when"}),
        json!({"when": "2024-06-01T00:00:00+00:00"}),
        "event",
        NOW,
        Some("splunk"),
    );
    assert_eq!(
        r,
        Ok((
            "2024-06-01T00:00:00+00:00".to_owned(),
            "2024-06-01T01:00:00+00:00".to_owned()
        ))
    );
}

#[test]
fn test_missing_default_field_raises() {
    let r = resolve(
        &splunk(),
        json!({"before": "30m", "after": "30m"}),
        json!({"host": "web1"}),
        "event",
        NOW,
        Some("splunk"),
    );
    assert!(matches!(r, Err(e) if e.starts_with("KeyError") && e.contains("_time")));
}

#[test]
fn test_no_current_source_falls_back_to_hunt_window() {
    // no source and no field: the hunt's window, before its start and after its end
    let r = resolve(
        &Fixture::default(),
        json!({"before": "1h", "after": "2h"}),
        json!({"host": "web1"}),
        "event",
        ("2024-06-01T12:00:00+00:00", "2024-06-01T18:00:00+00:00"),
        None,
    );
    assert_eq!(
        r,
        Ok((
            "2024-06-01T11:00:00+00:00".to_owned(),
            "2024-06-01T20:00:00+00:00".to_owned()
        ))
    );
}

#[test]
fn test_unknown_current_source_falls_back_to_hunt_window() {
    let r = resolve(
        &Fixture::default(),
        json!({"before": "1h", "after": "2h"}),
        json!({"host": "web1"}),
        "event",
        ("2024-06-01T12:00:00+00:00", "2024-06-01T18:00:00+00:00"),
        Some("not_registered"),
    );
    assert_eq!(
        r,
        Ok((
            "2024-06-01T11:00:00+00:00".to_owned(),
            "2024-06-01T20:00:00+00:00".to_owned()
        ))
    );
}

#[test]
fn test_stream_transform_anchors_to_hunt_window() {
    // a stream transform ignores the event's time, even when it has one
    let r = resolve(
        &splunk(),
        json!({"before": "3h", "after": "1h"}),
        json!({"_time": "2099-01-01T00:00:00+00:00"}),
        "stream",
        ("2024-06-01T00:00:00+00:00", "2024-06-02T00:00:00+00:00"),
        Some("splunk"),
    );
    assert_eq!(
        r,
        Ok((
            "2024-05-31T21:00:00+00:00".to_owned(),
            "2024-06-02T01:00:00+00:00".to_owned()
        ))
    );
}

/// TestQueryRecorder: a run's recorder, seeded through its hunt run.
fn recorded(f: &Fixture, replay: Vec<Json>, host: &str) -> (Result<String, String>, Json) {
    let cmd = command(
        json!({"type": "query", "source": "test_source", "query": "search host={{ _event.host }}", "time_range": null}),
    );
    let config = logic(json!([]));
    let event = ev(json!({"host": host}));
    let events = evs(json!([]));
    let mut run = HuntRun::at(utc("2024-06-01T12:00:00+00:00"));
    run.replay = replay;
    f.with(|rt| {
        let mut engine = Engine::new(rt, &config, &[], run);
        let result = engine.execute_command(
            &cmd,
            Call {
                scope: Scope {
                    event: &event,
                    events: &events,
                },
                transform_type: "event",
            },
        );
        (
            result,
            serde_json::to_value(engine.recorder.export()).expect("JSON"),
        )
    })
}

#[test]
fn test_replay_miss_falls_back_to_live_and_records() {
    let source = TestSource::new(json!([{"host": "web2", "live": true}]));
    let f = Fixture::default()
        .source("test_source", source.clone())
        .cache(no_cache());
    // seeded for another rendered query: a miss, so live, with a warning
    let (result, exported) = recorded(
        &f,
        vec![
            json!({"source": "test_source", "query": "search host=web1", "results": [{"host": "web1"}]}),
        ],
        "web2",
    );
    assert_eq!(
        serde_json::from_str::<Json>(&result.expect("runs")).expect("JSON"),
        json!({"host": "web2", "live": true})
    );
    let calls = source.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].query, "search host=web2");
    // the live result is captured under its rendered query
    let by_query: Vec<&Json> = exported
        .as_array()
        .expect("records")
        .iter()
        .filter(|r| r["query"] == "search host=web2")
        .collect();
    assert_eq!(
        by_query[0]["results"],
        json!([{"host": "web2", "live": true}])
    );
}

#[test]
fn test_pure_capture_records_rendered_query() {
    let source = TestSource::new(json!([{"host": "web3"}]));
    let f = Fixture::default()
        .source("test_source", source.clone())
        .cache(no_cache());
    let (_, exported) = recorded(&f, vec![], "web3");
    assert_eq!(source.calls().len(), 1);
    assert_eq!(
        exported,
        json!([{"source": "test_source", "query": "search host=web3", "results": [{"host": "web3"}]}])
    );
}

/// What a source's call gets as its timeout: the command's.
#[test]
fn a_query_s_timeout_is_its_command_s() {
    let source = TestSource::new(json!([]));
    let f = Fixture::default().source("test_source", source.clone());
    let cmd =
        command(json!({"type": "query", "source": "test_source", "query": "q", "timeout": "45s"}));
    exec(&f, &cmd, json!({}), "event", &[]).expect("runs");
    assert_eq!(source.calls()[0].timeout, TimeDelta::seconds(45));
}

/// Not in ace3 (PLAN.md decision 16): a script command type that failed to build, such as one
/// whose settings the hunter's configuration lacks, fails the step that runs its script.
#[test]
fn a_script_type_that_failed_to_build_fails_its_step() {
    let mut f = Fixture::default();
    f.types
        .scripts_mut()
        .failed("hunts/scripts/echo.py", "echo", "echo needs settings");
    let cmd = command(json!({"type": "executable", "path": echo_path(), "args": ["print", "x"]}));
    let result = exec(&f, &cmd, json!({}), "event", &[]);
    assert_eq!(
        result,
        Err(
            "ValueError: script command type 'echo' failed to load: echo needs settings".to_owned()
        )
    );
    // the example type refuses settings it doesn't take
    let built = crate::correlate::scripts::example::build(&json!({"limits": 3}));
    assert!(built.is_err());
}

/// ace-rs's example script command type (`scripts::example`), registered as a site registers one,
/// runs for an executable whose path ends with its suffix, with the event on stdin.
#[test]
fn the_example_script_type_runs_for_its_path() {
    use crate::correlate::scripts::example;
    let dir = std::path::Path::new(&echo_path())
        .parent()
        .expect("the scripts directory")
        .to_owned();
    let path = dir.join("field_values.py");
    std::fs::write(&path, "").expect("written");
    let mut f = Fixture::default();
    f.types.register_script(
        example::SUFFIX,
        example::NAME,
        example::build(&Json::Null).expect("builds"),
    );
    let cmd = command(json!({
        "type": "executable", "path": path.to_string_lossy(),
        "args": ["--field", "{{ _event.key }}"], "stdin": true,
    }));
    let result = exec(
        &f,
        &cmd,
        json!({"key": "user", "user": "admin"}),
        "event",
        &[],
    );
    assert_eq!(
        result.as_deref(),
        Ok("{\"field\": \"user\", \"count\": 1, \"values\": [\"admin\"]}\n")
    );
}
