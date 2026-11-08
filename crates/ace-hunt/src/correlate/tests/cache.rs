//! `test_cache.py`: 20 cases. ace3 patches `get_redis_connection` with a MagicMock; here the
//! cache is a [`TestCache`] the run is handed, and `caplog` is the run's log lines.

use serde_json::{Map as JsonMap, Value as Json, json};

use super::TestCache;
use crate::correlate::action::LogLine;
use crate::correlate::cache::{Recorder, cache_key, describe, get_cached, set_cached};

// the key of {"query": "test"}: sha256 of '{"query": "test"}', computed with shasum
const QUERY_TEST_KEY: &str =
    "hunt_cache:a59686a9a4c2e8ad9c1ab86ee13b8df3c661b6f11ed3af2a54a0168001b6d5eb";

fn args(json: Json) -> JsonMap<String, Json> {
    match json {
        Json::Object(m) => m,
        _ => panic!("an object"),
    }
}

fn text(logs: &[LogLine]) -> String {
    logs.iter()
        .map(|l| l.message.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// TestCacheKeyGeneration: the cache is shared across processes and restarts in ace3, so the key
/// is the sha256 of the sorted arguments.
#[test]
fn test_key_is_the_sha256_of_the_sorted_arguments() {
    let a = args(json!({"type": "query", "source": "splunk", "query": "index=main"}));
    // sha256 of '{"query": "index=main", "source": "splunk", "type": "query"}', computed with shasum
    assert_eq!(
        cache_key(&a),
        "hunt_cache:f08b50321474848ec395e68bbdfdc27e50e3977f2a50d520083bcd8fc42a19da"
    );
}

#[test]
fn test_different_args_different_keys() {
    assert_ne!(
        cache_key(&args(json!({"query": "a"}))),
        cache_key(&args(json!({"query": "b"})))
    );
}

#[test]
fn test_query_summary_collapses_whitespace() {
    let desc = describe(&args(json!({
        "type": "query", "source": "logscale", "query": "ComputerName=/x/i\n  | foo   bar",
    })));
    assert_eq!(
        desc,
        "type=query source=logscale query='ComputerName=/x/i | foo bar'"
    );
}

#[test]
fn test_query_summary_truncates_long_query() {
    let desc = describe(&args(
        json!({"type": "query", "source": "splunk", "query": "a".repeat(500)}),
    ));
    assert!(desc.ends_with("…'"));
    assert!(desc.chars().count() < 400);
}

#[test]
fn test_executable_summary() {
    let desc = describe(&args(
        json!({"type": "executable", "path": "/bin/foo", "args": ["-c", "x"]}),
    ));
    assert_eq!(desc, "type=executable path=/bin/foo args=['-c', 'x']");
}

#[test]
fn test_executable_summary_omits_env() {
    // env is where a hunt puts the settings it hands a script, and this description is logged
    let desc = describe(&args(json!({
        "type": "executable", "path": "/bin/foo", "args": ["-c", "x"], "env": {"API_KEY": "REAL_KEY"},
    })));
    assert!(!desc.contains("REAL_KEY"));
    assert!(!desc.contains("API_KEY"));
}

#[test]
fn test_unknown_type() {
    assert_eq!(describe(&JsonMap::new()), "type=?");
}

#[test]
fn test_get_cached_hit() {
    let cache = TestCache {
        answer: Some("cached_output".to_owned()),
        ..TestCache::default()
    };
    let mut logs = Vec::new();
    let result = get_cached(&cache, &args(json!({"query": "test"})), &[], &mut logs);
    assert_eq!(result.as_deref(), Some("cached_output"));
    assert_eq!(cache.gets(), [QUERY_TEST_KEY]);
}

#[test]
fn test_get_cached_miss() {
    let cache = TestCache::default();
    let mut logs = Vec::new();
    let result = get_cached(&cache, &args(json!({"query": "test"})), &[], &mut logs);
    assert_eq!(result, None);
    assert!(!text(&logs).contains("cache hit"));
}

#[test]
fn test_set_cached() {
    let cache = TestCache::default();
    let mut logs = Vec::new();
    set_cached(
        &cache,
        &args(json!({"query": "test"})),
        "output",
        3600,
        &[],
        &mut logs,
    );
    assert_eq!(
        cache.sets(),
        [(QUERY_TEST_KEY.to_owned(), "output".to_owned(), 3600)]
    );
}

#[test]
fn test_set_cached_logs_command_identity() {
    let cache = TestCache::default();
    let mut logs = Vec::new();
    set_cached(
        &cache,
        &args(json!({"type": "query", "source": "logscale", "query": "index=main"})),
        "output",
        300,
        &[],
        &mut logs,
    );
    // the log line identifies what was cached (source + query), not just the hash
    let t = text(&logs);
    assert!(t.contains("source=logscale"));
    assert!(t.contains("index=main"));
    assert!(t.contains("for 300s"));
}

#[test]
fn test_set_cached_redacts_secrets() {
    let cache = TestCache::default();
    let mut logs = Vec::new();
    set_cached(
        &cache,
        &args(
            json!({"type": "query", "source": "splunk", "query": "token=SUPERSECRET index=main"}),
        ),
        "output",
        300,
        &["SUPERSECRET".to_owned()],
        &mut logs,
    );
    let t = text(&logs);
    assert!(!t.contains("SUPERSECRET"));
    assert!(t.contains("***"));
}

#[test]
fn test_get_cached_hit_logs_command_identity() {
    let cache = TestCache {
        answer: Some("cached_output".to_owned()),
        ..TestCache::default()
    };
    let mut logs = Vec::new();
    get_cached(
        &cache,
        &args(json!({"type": "query", "source": "logscale", "query": "index=main"})),
        &[],
        &mut logs,
    );
    let t = text(&logs);
    assert!(t.contains("cache hit"));
    assert!(t.contains("source=logscale"));
}

#[test]
fn test_get_handles_redis_error() {
    let cache = TestCache {
        fail: true,
        ..TestCache::default()
    };
    let mut logs = Vec::new();
    assert_eq!(
        get_cached(&cache, &args(json!({"query": "test"})), &[], &mut logs),
        None
    );
}

#[test]
fn test_set_handles_redis_error() {
    let cache = TestCache {
        fail: true,
        ..TestCache::default()
    };
    let mut logs = Vec::new();
    // doesn't fail
    set_cached(
        &cache,
        &args(json!({"query": "test"})),
        "output",
        3600,
        &[],
        &mut logs,
    );
}

/// TestCorrelateQueryRecorder.
#[test]
fn test_capture_export_roundtrip() {
    let mut recorder = Recorder::new(&[]);
    assert!(!recorder.replay_active());
    recorder.record(
        "splunk",
        "search index=main",
        "{\"host\": \"web1\"}\n{\"host\": \"web2\"}",
    );
    assert_eq!(
        serde_json::to_value(recorder.export()).expect("JSON"),
        json!([{
            "source": "splunk",
            "query": "search index=main",
            "results": [{"host": "web1"}, {"host": "web2"}],
        }])
    );
}

#[test]
fn test_replay_lookup_hit_and_miss() {
    let recorder = Recorder::new(&[json!(
        {"source": "splunk", "query": "search index=main", "results": [{"host": "web1"}]}
    )]);
    assert!(recorder.replay_active());
    // a hit is the JSON lines a query's output is
    assert_eq!(
        recorder.lookup("splunk", "search index=main").as_deref(),
        Some("{\"host\": \"web1\"}")
    );
    // a miss on another rendered query or source
    assert_eq!(recorder.lookup("splunk", "search index=other"), None);
    assert_eq!(recorder.lookup("logscale", "search index=main"), None);
}

#[test]
fn test_record_dedup_first_wins() {
    let mut recorder = Recorder::new(&[]);
    recorder.record("splunk", "q", "{\"a\": 1}");
    recorder.record("splunk", "q", "{\"a\": 2}");
    let exported = recorder.export();
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].results, [json!({"a": 1})]);
}

#[test]
fn test_replay_then_export_is_complete() {
    let saved = [
        json!({"source": "splunk", "query": "q1", "results": [{"x": 1}]}),
        json!({"source": "splunk", "query": "q2", "results": [{"y": 2}]}),
    ];
    let mut recorder = Recorder::new(&saved);
    for record in &saved {
        let (s, q) = (
            record["source"].as_str().expect("a source"),
            record["query"].as_str().expect("a query"),
        );
        let output = recorder.lookup(s, q).expect("saved");
        recorder.record(s, q, &output);
    }
    assert_eq!(
        serde_json::to_value(recorder.export()).expect("JSON"),
        json!(saved)
    );
}

#[test]
fn test_empty_replay_is_inactive() {
    assert!(!Recorder::new(&[]).replay_active());
}
