//! A command's `cache:` (`cache.py`) and the validator's record and replay of a correlation's
//! queries (`CorrelateQueryRecorder`).
//!
//! A cached output is kept under ace3's key, `hunt_cache:` and the sha256 of the command's
//! arguments as Python's `json.dumps(sort_keys=True)` writes them, for the cache's time to live.
//! ace3 keeps it in Redis, shared by its hunters and kept across restarts. ace4 has no Redis: the
//! hunter keeps it in its own memory ([`MemoryCache`]), within a bound, so a restart starts it
//! empty and the next run asks the data source again. A cache that fails is a miss, as in ace3.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, TimeDelta, Utc};
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as Json};
use sha2::{Digest, Sha256};

use super::action::{Level, LogLine};
use super::pyjson::{dumps, dumps_json};
use super::trace::sanitize;
use crate::query::extract::py_repr_json;
use crate::render::json::loads;
use crate::value::py_repr;

/// Where cached outputs are kept.
pub trait Cache: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    fn set(&self, key: &str, value: &str, ttl_seconds: i64) -> Result<(), String>;
}

/// `_make_cache_key`.
pub fn cache_key(args: &JsonMap<String, Json>) -> String {
    let text = dumps_json(&Json::Object(args.clone()), true);
    let digest = Sha256::digest(text.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("hunt_cache:{hex}")
}

/// `_describe_command`: what an entry is for, for the log; never an executable's `env`.
pub fn describe(args: &JsonMap<String, Json>) -> String {
    let field = |name: &str| args.get(name).cloned().unwrap_or(Json::Null);
    let text = |v: Json| match v {
        Json::String(s) => s,
        other => crate::query::extract::py_str(&other),
    };
    let kind = args
        .get("type")
        .map(|v| text(v.clone()))
        .unwrap_or_else(|| "?".to_owned());
    if kind == "query" {
        let raw = match field("query") {
            Json::String(s) => s,
            Json::Null => String::new(),
            other => crate::query::extract::py_str(&other),
        };
        let mut query = raw
            .split(crate::render::methods::is_space)
            .filter(|w| !w.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if query.chars().count() > 300 {
            query = query.chars().take(300).collect::<String>() + "…";
        }
        return format!(
            "type=query source={} query={}",
            text(field("source")),
            py_repr(&query)
        );
    }
    if kind == "executable" {
        let a = match field("args") {
            Json::Null => Json::Array(Vec::new()),
            Json::Array(a) if a.is_empty() => Json::Array(Vec::new()),
            other => other,
        };
        return format!(
            "type=executable path={} args={}",
            text(field("path")),
            py_repr_json(&a)
        );
    }
    format!("type={kind}")
}

/// `get_cached_result`: the output, logging a hit; a cache that fails is a miss.
pub fn get_cached(
    cache: &dyn Cache,
    args: &JsonMap<String, Json>,
    secrets: &[String],
    logs: &mut Vec<LogLine>,
) -> Option<String> {
    let key = cache_key(args);
    match cache.get(&key) {
        Ok(Some(value)) => {
            // ace3 logs a hit only for a value that's true, and returns what Redis gave
            if !value.is_empty() {
                let desc = sanitize(&describe(args), secrets);
                logs.push(LogLine::new(
                    Level::Info,
                    format!("cache hit for {key} ({desc})"),
                ));
            }
            Some(value)
        }
        Ok(None) => None,
        Err(e) => {
            logs.push(LogLine::new(
                Level::Warning,
                format!("failed to read from hunt cache: {e}"),
            ));
            None
        }
    }
}

/// `set_cached_result`.
pub fn set_cached(
    cache: &dyn Cache,
    args: &JsonMap<String, Json>,
    value: &str,
    ttl_seconds: i64,
    secrets: &[String],
    logs: &mut Vec<LogLine>,
) {
    let key = cache_key(args);
    match cache.set(&key, value, ttl_seconds) {
        Ok(()) => {
            let desc = sanitize(&describe(args), secrets);
            logs.push(LogLine::new(
                Level::Info,
                format!(
                    "cached result with key {key} ({desc}) for {ttl_seconds}s, {} bytes",
                    value.chars().count()
                ),
            ));
        }
        Err(e) => logs.push(LogLine::new(
            Level::Warning,
            format!("failed to write to hunt cache: {e}"),
        )),
    }
}

/// A cache in memory, as the hunter keeps one: entries expire after their time to live, and past
/// `max_bytes` of outputs the oldest go first.
pub struct MemoryCache {
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    max_bytes: usize,
    inner: Mutex<Entries>,
}

#[derive(Default)]
struct Entries {
    map: HashMap<String, (String, DateTime<Utc>, u64)>,
    bytes: usize,
    order: u64,
}

impl MemoryCache {
    /// A cache of at most `max_bytes` of outputs, expiring them by `clock`.
    pub fn new(
        max_bytes: usize,
        clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    ) -> MemoryCache {
        MemoryCache {
            clock,
            max_bytes,
            inner: Mutex::new(Entries::default()),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|e| e.map.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Cache for MemoryCache {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        let now = (self.clock)();
        let mut entries = self
            .inner
            .lock()
            .map_err(|_| "the cache's lock is poisoned")?;
        match entries.map.get(key) {
            Some((value, expires, _)) if *expires > now => Ok(Some(value.clone())),
            Some(_) => {
                if let Some((value, _, _)) = entries.map.remove(key) {
                    entries.bytes -= value.len();
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }

    fn set(&self, key: &str, value: &str, ttl_seconds: i64) -> Result<(), String> {
        // Redis refuses SETEX with a time to live that isn't positive
        if ttl_seconds <= 0 {
            return Err("ERR invalid expire time in 'setex' command".to_owned());
        }
        if value.len() > self.max_bytes {
            return Err(format!(
                "ace4 limit: an output of {} bytes is past the cache's {} bytes",
                value.len(),
                self.max_bytes
            ));
        }
        let now = (self.clock)();
        let expires = now + TimeDelta::seconds(ttl_seconds.min(10 * 365 * 86_400));
        let mut entries = self
            .inner
            .lock()
            .map_err(|_| "the cache's lock is poisoned")?;
        entries.order += 1;
        let order = entries.order;
        if let Some((old, _, _)) = entries.map.remove(key) {
            entries.bytes -= old.len();
        }
        entries.bytes += value.len();
        entries
            .map
            .insert(key.to_owned(), (value.to_owned(), expires, order));
        // expired ones first, then the oldest, until it fits
        entries.map.retain(|_, (_, e, _)| *e > now);
        entries.bytes = entries.map.values().map(|(v, _, _)| v.len()).sum();
        while entries.bytes > self.max_bytes {
            let Some(oldest) = entries
                .map
                .iter()
                .min_by_key(|(_, (_, _, o))| *o)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some((v, _, _)) = entries.map.remove(&oldest) {
                entries.bytes -= v.len();
            }
        }
        Ok(())
    }
}

/// A cache that keeps nothing, for a run with no cache.
pub struct NoCache;

impl Cache for NoCache {
    fn get(&self, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn set(&self, _: &str, _: &str, _: i64) -> Result<(), String> {
        Ok(())
    }
}

/// One saved query and its rows, as the validator saves and replays them.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RecordedQuery {
    pub source: String,
    pub query: String,
    pub results: Vec<Json>,
}

/// `CorrelateQueryRecorder`: every rendered query a run asked and its output, first answer kept,
/// and the saved answers it replays in place of asking the source.
#[derive(Debug, Default)]
pub struct Recorder {
    replay: HashMap<(String, String), String>,
    captured: Vec<((String, String), String)>,
}

impl Recorder {
    /// A recorder replaying `saved`, ace3's `{source, query, results}` records.
    pub fn new(saved: &[Json]) -> Recorder {
        let mut replay = HashMap::new();
        for record in saved {
            let text = |k: &str| record.get(k).and_then(Json::as_str).unwrap_or_default();
            let rows: Vec<String> = record
                .get("results")
                .and_then(Json::as_array)
                .map(|rows| rows.iter().map(|r| dumps_json(r, false)).collect())
                .unwrap_or_default();
            replay.insert(
                (text("source").to_owned(), text("query").to_owned()),
                rows.join("\n"),
            );
        }
        Recorder {
            replay,
            captured: Vec::new(),
        }
    }

    pub fn replay_active(&self) -> bool {
        !self.replay.is_empty()
    }

    pub fn lookup(&self, source: &str, query: &str) -> Option<String> {
        self.replay
            .get(&(source.to_owned(), query.to_owned()))
            .cloned()
    }

    pub fn record(&mut self, source: &str, query: &str, output: &str) {
        let key = (source.to_owned(), query.to_owned());
        if !self.captured.iter().any(|(k, _)| *k == key) {
            self.captured.push((key, output.to_owned()));
        }
    }

    pub fn export(&self) -> Vec<RecordedQuery> {
        self.captured
            .iter()
            .map(|((source, query), output)| RecordedQuery {
                source: source.clone(),
                query: query.clone(),
                results: output
                    .lines()
                    .filter(|l| !l.trim_matches(crate::render::methods::is_space).is_empty())
                    .filter_map(|l| loads(l).ok().map(|v| v.to_json()))
                    .collect(),
            })
            .collect()
    }
}

/// JSON lines of rows as `"\n".join(json.dumps(row) for row in rows)`.
pub fn json_lines(rows: &[crate::value::Map]) -> String {
    rows.iter()
        .map(|r| dumps(&crate::value::Value::Map(r.clone()), false))
        .collect::<Vec<_>>()
        .join("\n")
}
