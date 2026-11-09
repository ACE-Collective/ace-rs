//! The cases of ace3's `tests/saq/collectors/hunter/correlation/` as Rust tests (PLAN.md 6.6), one
//! module per ace3 file, each test named after the ace3 test it ports, with its inputs and expected
//! outputs; a parametrized case is a loop over its parameters. Where ace3's test leans on Python
//! machinery (a mock patched over a module function, `caplog`, importing a class by name), the test
//! says how it ports the intent: a recording [`TestCache`] for the patched cache functions, the
//! run's [`LogLine`](super::action::LogLine)s for `caplog`, a mock clock for a patched
//! `datetime`, and registration for importing.
//!
//! A case that runs a `type: executable` command ran a Python one-liner (`python3 -c ...`) to see
//! what the engine hands a script and does with what it gives back. ace4 runs no script (PLAN.md
//! decision 16), so such a case runs [`Echo`], a script command type registered for a test path
//! that does what the one-liner did: print its arguments, its stdin or a variable of its `env:`,
//! exit with a code, or outlast its timeout. A case whose executable only had to fail (`/bin/false`)
//! runs as it is: an executable that isn't a script type fails its step the same way.
//! `test_sandbox.py`'s cases test ace3's sandbox runner; [`sandbox`] says which still hold and why
//! the rest don't apply.
//!
//! `test_sources_loader.py` and `test_splunk_source.py` test the hunter's sources, so they're in
//! `ace_app::hunter`'s tests.

mod actions;
mod cache;
mod command_types;
mod commands;
mod engine;
mod expressions;
mod integration;
mod registry;
mod sandbox;
mod schema;
mod timespec;
mod trace;
mod transforms;
mod validation;

use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeDelta, Utc};
use serde_json::{Map as JsonMap, Value as Json};

use super::cache::{Cache, NoCache};
use super::command::CommandTypes;
use super::engine::{Correlated, Engine, HuntRun, Limits, Runtime};
use super::script::{Script, ScriptCall, ScriptExit};
use super::source::{QuerySource, Sources};
use super::time::Time;
use super::{Correlate, PredefinedCommand};
use crate::query::extract::to_loaded;
use crate::render::{Limits as RenderLimits, Renderer};
use crate::value::{Map, Value};

/// A JSON value as Python's `json.loads` would give it.
pub fn v(json: Json) -> Value {
    to_loaded(&json)
}

/// A JSON object as an event.
pub fn ev(json: Json) -> Map {
    match v(json) {
        Value::Map(m) => m,
        other => panic!("not an event: {other:?}"),
    }
}

pub fn evs(json: Json) -> Vec<Map> {
    match json {
        Json::Array(items) => items.into_iter().map(ev).collect(),
        other => panic!("not events: {other:?}"),
    }
}

/// An event as JSON, for comparing.
pub fn js(event: &Map) -> Json {
    Value::Map(event.clone()).to_json()
}

/// `_make_config(logic, timeout)`.
pub fn config(logic: Json, timeout: &str) -> Correlate {
    Correlate::from_value(&v(serde_json::json!({"timeout": timeout, "logic": logic})))
        .unwrap_or_else(|e| panic!("a valid correlate block: {e}"))
}

pub fn logic(logic: Json) -> Correlate {
    config(logic, "15m")
}

pub fn predefined(json: Json) -> PredefinedCommand {
    PredefinedCommand::from_value(&v(json)).unwrap_or_else(|e| panic!("valid: {e}"))
}

pub fn utc(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .expect("a time")
        .with_timezone(&Utc)
}

pub fn time(text: &str) -> Time {
    Time::from(utc(text))
}

/// One call a test source saw.
#[derive(Debug, Clone)]
pub struct SourceCall {
    pub query: String,
    pub start: Time,
    pub end: Time,
    pub timeout: TimeDelta,
    pub source_options: JsonMap<String, Json>,
}

/// ace3's `MockQuerySource` and `_RecordingSource`: answers every query with its rows, and keeps
/// each call. `advance` moves the fixture's clock by that much a call, as `_ClockAdvancingSource`.
pub struct TestSource {
    pub field: Option<&'static str>,
    pub format: Option<&'static str>,
    pub results: Vec<JsonMap<String, Json>>,
    pub calls: Mutex<Vec<SourceCall>>,
    pub clock: Option<(Arc<Mutex<DateTime<Utc>>>, TimeDelta)>,
    pub display: bool,
}

impl TestSource {
    pub fn new(results: Json) -> Arc<TestSource> {
        Arc::new(TestSource::rows(results))
    }

    pub fn rows(results: Json) -> TestSource {
        let results = match results {
            Json::Array(items) => items
                .into_iter()
                .map(|r| match r {
                    Json::Object(m) => m,
                    other => panic!("a row: {other:?}"),
                })
                .collect(),
            other => panic!("rows: {other:?}"),
        };
        TestSource {
            field: Some("_time"),
            format: Some("iso8601"),
            results,
            calls: Mutex::new(Vec::new()),
            clock: None,
            display: false,
        }
    }

    pub fn calls(&self) -> Vec<SourceCall> {
        self.calls.lock().expect("calls").clone()
    }
}

impl QuerySource for TestSource {
    fn default_time_field(&self) -> Option<&str> {
        self.field
    }
    fn default_time_format(&self) -> Option<&str> {
        self.format
    }
    fn execute_query(
        &self,
        query: &str,
        start: Time,
        end: Time,
        timeout: TimeDelta,
        source_options: &JsonMap<String, Json>,
    ) -> Result<Vec<JsonMap<String, Json>>, String> {
        self.calls.lock().expect("calls").push(SourceCall {
            query: query.to_owned(),
            start,
            end,
            timeout,
            source_options: source_options.clone(),
        });
        if let Some((clock, advance)) = &self.clock {
            let mut now = clock.lock().expect("clock");
            *now += *advance;
        }
        Ok(self.results.clone())
    }
    fn format_timespec_for_display(
        &self,
        start: Time,
        end: Time,
    ) -> Result<Option<String>, String> {
        Ok(self
            .display
            .then(|| format!("earliest={} latest={}", start.isoformat(), end.isoformat())))
    }
}

/// The patched `get_cached_result` and `set_cached_result`: answers each lookup with `answer`
/// and keeps each key looked up and each value set.
#[derive(Default)]
pub struct TestCache {
    pub answer: Option<String>,
    pub gets: Mutex<Vec<String>>,
    pub sets: Mutex<Vec<(String, String, i64)>>,
    pub fail: bool,
}

impl Cache for TestCache {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        if self.fail {
            return Err("connection error".to_owned());
        }
        self.gets.lock().expect("gets").push(key.to_owned());
        Ok(self.answer.clone())
    }
    fn set(&self, key: &str, value: &str, ttl: i64) -> Result<(), String> {
        if self.fail {
            return Err("connection error".to_owned());
        }
        self.sets
            .lock()
            .expect("sets")
            .push((key.to_owned(), value.to_owned(), ttl));
        Ok(())
    }
}

impl TestCache {
    pub fn gets(&self) -> Vec<String> {
        self.gets.lock().expect("gets").clone()
    }
    pub fn sets(&self) -> Vec<(String, String, i64)> {
        self.sets.lock().expect("sets").clone()
    }
}

/// What a test run uses: the registered sources and command types, the cache, the secrets and a
/// clock that only moves when a source moves it.
pub struct Fixture {
    pub renderer: Renderer,
    pub sources: Sources,
    pub types: CommandTypes,
    pub cache: Arc<dyn Cache>,
    pub secrets: Vec<String>,
    pub now: Arc<Mutex<DateTime<Utc>>>,
    pub limits: Limits,
}

impl Default for Fixture {
    fn default() -> Fixture {
        Fixture {
            renderer: Renderer::correlation(RenderLimits::default()),
            sources: Sources::new(),
            types: {
                let mut types = CommandTypes::new();
                types.register_script("hunts/scripts/echo.py", "echo", Arc::new(Echo));
                types
            },
            cache: Arc::new(NoCache),
            secrets: Vec::new(),
            now: Arc::new(Mutex::new(utc("2024-06-01T12:00:00+00:00"))),
            limits: Limits::default(),
        }
    }
}

impl Fixture {
    pub fn source(mut self, name: &str, source: Arc<dyn QuerySource>) -> Fixture {
        self.sources.register(name, source);
        self
    }

    pub fn cache(mut self, cache: Arc<dyn Cache>) -> Fixture {
        self.cache = cache;
        self
    }

    pub fn secrets(mut self, secrets: &[&str]) -> Fixture {
        self.secrets = secrets.iter().map(|s| (*s).to_owned()).collect();
        self
    }

    /// Runs `f` with this fixture's runtime.
    pub fn with<R>(&self, f: impl FnOnce(&Runtime<'_>) -> R) -> R {
        let now = self.now.clone();
        let clock = move || *now.lock().expect("clock");
        let stopped = || false;
        let rt = Runtime {
            renderer: &self.renderer,
            sources: &self.sources,
            command_types: &self.types,
            cache: self.cache.as_ref(),
            secrets: &self.secrets,
            clock: &clock,
            stopped: &stopped,
            limits: self.limits,
        };
        f(&rt)
    }

    /// `CorrelationEngine(config, predefined, hunt...).execute(events)`.
    pub fn run(
        &self,
        config: &Correlate,
        predefined: &[PredefinedCommand],
        hunt: HuntRun,
        events: Vec<Map>,
    ) -> Correlated {
        self.with(|rt| {
            Engine::new(rt, config, predefined, hunt)
                .execute(events)
                .unwrap_or_else(|e| panic!("the run failed: {e}"))
        })
    }

    /// A run at the fixture's time with no hunt source.
    pub fn simple(&self, config: &Correlate, events: Vec<Map>) -> Correlated {
        let start = *self.now.lock().expect("clock");
        self.run(config, &[], HuntRun::at(start), events)
    }
}

/// The path of [`Echo`]'s script, a file in a hunt repository made for the tests.
pub fn echo_path() -> String {
    static DIR: std::sync::LazyLock<tempfile::TempDir> = std::sync::LazyLock::new(|| {
        let dir = tempfile::tempdir().expect("a directory");
        let scripts = dir.path().join("hunts/scripts");
        std::fs::create_dir_all(&scripts).expect("made");
        std::fs::write(scripts.join("echo.py"), "").expect("written");
        std::fs::write(scripts.join("data.txt"), "staged data\n").expect("written");
        dir
    });
    DIR.path()
        .join("hunts/scripts/echo.py")
        .to_string_lossy()
        .into_owned()
}

/// A script command type for the tests, registered for [`echo_path`] in every [`Fixture`], standing in for ace3's `python3 -c` one-liners. Its
/// first argument says what it does:
///
/// - `print ARGS...`: prints the rest, joined by spaces;
/// - `stdin`: prints its input;
/// - `env NAME`: prints the variable of the command's `env:`, or fails as a KeyError;
/// - `env-keys`: prints the names of its environment as a JSON list, sorted;
/// - `fail CODE TEXT`: exits with CODE, TEXT on stderr;
/// - `fail-env CODE NAME`: exits with CODE, the variable NAME of its `env:` on stderr;
/// - `read NAME`: prints the staged file beside it, or fails as a FileNotFoundError;
/// - `slow`: runs past its deadline.
pub struct Echo;

impl Script for Echo {
    fn run(&self, call: &ScriptCall<'_>) -> Result<String, ScriptExit> {
        let args = call.argv;
        let rest = |from: usize| args.get(from..).unwrap_or_default().join(" ");
        match args.first().map(String::as_str) {
            Some("print") => Ok(format!("{}\n", rest(1))),
            Some("stdin") => Ok(call.stdin.unwrap_or_default().to_owned()),
            Some("env") => {
                let name = args.get(1).map(String::as_str).unwrap_or_default();
                match call.env.iter().find(|(k, _)| k == name) {
                    Some((_, v)) => Ok(format!("{v}\n")),
                    None => Err(ScriptExit::raised("KeyError", &format!("'{name}'"))),
                }
            }
            Some("env-keys") => {
                let mut keys: Vec<&str> = call.env.iter().map(|(k, _)| k.as_str()).collect();
                keys.sort();
                Ok(format!("{}\n", serde_json::to_string(&keys).expect("JSON")))
            }
            Some("fail") => Err(ScriptExit {
                code: args.get(1).and_then(|c| c.parse().ok()).unwrap_or(1),
                stderr: rest(2),
            }),
            Some("fail-env") => Err(ScriptExit {
                code: args.get(1).and_then(|c| c.parse().ok()).unwrap_or(1),
                stderr: call
                    .env
                    .iter()
                    .find(|(k, _)| Some(k) == args.get(2))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default(),
            }),
            Some("read") => match call.files.read_beside_script(&rest(1)) {
                Some(Ok(bytes)) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
                _ => Err(ScriptExit::raised("FileNotFoundError", &rest(1))),
            },
            Some("slow") => {
                while !call.timed_out() {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                Ok(String::new())
            }
            other => Err(ScriptExit::raised("ValueError", &format!("{other:?}"))),
        }
    }
}

/// A hunt run at `start` on `source_type`.
pub fn hunt(start: DateTime<Utc>, source_type: &str) -> HuntRun {
    let mut run = HuntRun::at(start);
    run.source_type = Some(source_type.to_owned());
    run
}
