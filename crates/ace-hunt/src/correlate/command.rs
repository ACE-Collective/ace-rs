//! A transform's command (`commands.py`, `command_types.py`): a `query` against a
//! [`QuerySource`](super::source::QuerySource), a `defined` command (a predefined one by name, its
//! `arguments` replacing fields), an `executable`, which ace4 doesn't run (the module docs of
//! [`super`] say why), or a custom type an integration registers ([`CommandType`]).
//!
//! A query's text, a custom type's options and an executable's arguments render with the event as
//! `_event` and the stream as `_events`, and nothing else. The output is a string: JSON lines for a
//! query, one row each as Python's `json.dumps` writes it. Within one run a stream transform's query
//! is asked once for each rendered text; a command with `cache:` is kept for that long
//! ([`super::cache`]); and a run seeded with saved results replays them ([`super::cache::Recorder`]).
//!
//! A custom command type is ace3's `CorrelationCommand`, registered by name with
//! [`CommandTypes::register`], as `App::command_type` does for the binary. ace3 builds each from
//! `hunter.correlation.command_types` with its `kwargs`, and hands it the whole configuration in its
//! context; ace4's integration builds its handler with what it needs, so the context has no
//! configuration and no temporary directory, which a handler makes for itself if it needs one.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use chrono::TimeDelta;
use regex::Regex;
use serde_json::{Map as JsonMap, Value as Json};

use super::cache::{get_cached, json_lines, set_cached};
use super::engine::{Engine, EngineError};
use super::expr::{Scope, render};
use super::pyjson::dumps_json;
use super::time::{Time, parse_time_value};
use super::trace::sanitize;
use super::{BUILTIN_COMMAND_TYPES, Command, TimespecError, parse_timespec};
use crate::HuntError;
use crate::value::{Map, Value, py_repr};

/// What a custom command type sees of the call it serves.
pub struct CommandContext<'a> {
    pub command_type: &'a str,
    pub event: &'a Map,
    pub events: &'a [Map],
    /// `event` or `stream`.
    pub transform_type: &'a str,
    pub hunt_start: Time,
    pub hunt_end: Time,
    /// The command's `timeout`, which the handler honours itself: the engine can't interrupt it.
    pub timeout: TimeDelta,
}

/// A custom correlation command type, ace3's `CorrelationCommand`. One instance serves every hunt,
/// so it must be safe to share.
pub trait CommandType: Send + Sync {
    /// Whether it has an options model, ace3's `config_class`; without one it takes no options.
    fn has_options(&self) -> bool {
        false
    }

    /// The rendered options validated as `config_class.model_validate` does, as
    /// `model_dump(mode="json")` gives them, or the ValidationError
    /// (`crate::validate` validates as pydantic does).
    fn validate_options(&self, options: &Value) -> Result<Json, HuntError> {
        Ok(options.to_json())
    }

    /// False: never cached, and hunt validation reports a `cache:` on it.
    fn cacheable(&self) -> bool {
        true
    }

    /// False: the options pass as written, for a type whose values hold `{{ }}` of their own.
    fn render_options(&self) -> bool {
        true
    }

    /// Does the work: the output, JSON lines for a stream transform or a `list` property, JSON for
    /// a `dict`, else any text; `""` for no data. An error is a step error.
    fn execute(&self, context: &CommandContext<'_>, options: &Json) -> Result<String, String>;

    /// What identifies a call for `cache:`, which the engine adds the type to. The default holds
    /// the input, the event or the stream, since the handler can read it.
    fn cache_key(&self, context: &CommandContext<'_>, options: &Json) -> JsonMap<String, Json> {
        let input = if context.transform_type == "stream" {
            Json::Array(
                context
                    .events
                    .iter()
                    .map(|e| Value::Map(e.clone()).to_json())
                    .collect(),
            )
        } else {
            Value::Map(context.event.clone()).to_json()
        };
        let mut key = JsonMap::new();
        key.insert("options".to_owned(), options.clone());
        key.insert("input".to_owned(), input);
        key
    }

    /// The trace's one line for the call; never a credential, and the engine sanitizes it too.
    fn render_summary(&self, context: &CommandContext<'_>, options: &Json) -> Option<String> {
        Some(format!(
            "{} {}",
            context.command_type,
            dumps_json(options, true)
        ))
    }
}

static NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]*\z").expect("a valid pattern"));

/// The registered custom command types, and the ones that failed to build, with why.
#[derive(Clone, Default)]
pub struct CommandTypes {
    types: BTreeMap<String, Arc<dyn CommandType>>,
    errors: BTreeMap<String, String>,
}

impl CommandTypes {
    pub fn new() -> CommandTypes {
        CommandTypes::default()
    }

    /// `register_command_type`: refused for a built-in type's name or a name that isn't
    /// `^[a-z][a-z0-9_]*$`; true when it replaced one, which ace3 warns of.
    pub fn register(&mut self, name: &str, handler: Arc<dyn CommandType>) -> Result<bool, String> {
        if BUILTIN_COMMAND_TYPES.contains(&name) {
            return Err(format!(
                "{} is a built-in correlation command type and cannot be registered",
                py_repr(name)
            ));
        }
        if !NAME.is_match(name) {
            return Err(format!(
                "invalid correlation command type name {}: must match ^[a-z][a-z0-9_]*$",
                py_repr(name)
            ));
        }
        self.errors.remove(name);
        Ok(self.types.insert(name.to_owned(), handler).is_some())
    }

    /// A type that failed to build: hunts that use it fail per step with this, and validation
    /// reports it.
    pub fn failed(&mut self, name: &str, error: &str) {
        self.errors.insert(name.to_owned(), error.to_owned());
    }

    /// `get_command_type`.
    pub fn get(&self, name: &str) -> Result<&Arc<dyn CommandType>, String> {
        if let Some(handler) = self.types.get(name) {
            return Ok(handler);
        }
        Err(match self.errors.get(name) {
            Some(error) => format!(
                "ValueError: correlation command type {} failed to load: {error}",
                py_repr(name)
            ),
            None => format!("ValueError: unknown command type: {}", py_repr(name)),
        })
    }

    pub fn names(&self) -> Vec<&str> {
        self.types.keys().map(String::as_str).collect()
    }

    pub fn load_errors(&self) -> &BTreeMap<String, String> {
        &self.errors
    }

    pub fn clear(&mut self) {
        self.types.clear();
        self.errors.clear();
    }
}

/// Why an executable command doesn't run in ace4.
pub const EXECUTABLE_WAITS: &str = "RuntimeError: executable commands don't run in ace4: how a hunt's scripts run waits for the owner's decision (PLAN.md 6.6)";

/// A timespec as a duration, or ace3's ValueError or OverflowError.
pub fn timespec(text: &str) -> Result<TimeDelta, String> {
    match parse_timespec(text) {
        Ok(seconds) => i64::try_from(seconds)
            .ok()
            .and_then(TimeDelta::try_seconds)
            .ok_or_else(|| format!("OverflowError: {text}")),
        Err(TimespecError::Invalid(m)) => Err(format!("ValueError: {m}")),
        Err(TimespecError::Overflow(m)) => Err(format!("OverflowError: {m}")),
    }
}

/// Whether Python takes a value as true, for an optional string field.
fn set(field: &Option<String>) -> Option<&str> {
    field.as_deref().filter(|s| !s.is_empty())
}

/// Every string in an options value rendered, through its mappings and lists.
fn render_options(engine: &Engine<'_>, value: &Value, scope: Scope<'_>) -> Result<Value, String> {
    Ok(match value {
        Value::Str(s) => Value::Str(render(engine.rt.renderer, s, scope)?),
        Value::Map(m) => {
            let mut out = Map::new();
            for (k, v) in m.iter() {
                out.insert(k.clone(), render_options(engine, v, scope)?);
            }
            Value::Map(out)
        }
        Value::Seq(items) => Value::Seq(
            items
                .iter()
                .map(|v| render_options(engine, v, scope))
                .collect::<Result<_, _>>()?,
        ),
        other => other.clone(),
    })
}

/// A command's place in a run: its event and stream, and the kind of transform.
#[derive(Clone, Copy)]
pub struct Call<'a> {
    pub scope: Scope<'a>,
    pub transform_type: &'a str,
}

/// A custom command ready to run: its handler, its rendered and validated options, and its
/// context's timeout.
pub struct Prepared {
    pub handler: Arc<dyn CommandType>,
    pub options: Json,
    pub timeout: TimeDelta,
}

impl Engine<'_> {
    /// `execute_command`: the command's output, or why it failed, which is a step error.
    pub fn execute_command(&mut self, command: &Command, call: Call<'_>) -> Result<String, String> {
        self.check_stop().map_err(|e| e.to_string())?;
        let output = match command.kind.as_str() {
            "defined" => {
                let name = command.name.clone().unwrap_or_default();
                let predefined =
                    self.predefined
                        .iter()
                        .find(|p| p.name == name)
                        .ok_or_else(|| {
                            format!(
                                "ValueError: predefined command not found: {}",
                                py_repr(&name)
                            )
                        })?;
                let resolved = predefined
                    .to_command(command.arguments.as_ref())
                    .map_err(|e| format!("ValidationError: {e}"))?;
                return self.execute_command(&resolved, call);
            }
            "query" => self.execute_query(command, call)?,
            "executable" => return Err(EXECUTABLE_WAITS.to_owned()),
            _ => self.execute_custom(command, call)?,
        };
        Ok(output)
    }

    fn execute_query(&mut self, command: &Command, call: Call<'_>) -> Result<String, String> {
        let source_name = command.source.clone().unwrap_or_default();
        let query = render(
            self.rt.renderer,
            command.query.as_deref().unwrap_or_default(),
            call.scope,
        )?;
        let stream_key = format!("query:{source_name}:{query}");
        if call.transform_type == "stream"
            && let Some(cached) = self.stream_cache.get(&stream_key)
        {
            return Ok(cached.clone());
        }
        let mut cache_args = JsonMap::new();
        cache_args.insert("type".to_owned(), Json::from("query"));
        cache_args.insert("source".to_owned(), Json::from(source_name.clone()));
        cache_args.insert("query".to_owned(), Json::from(query.clone()));
        if set(&command.cache).is_some()
            && let Some(cached) =
                get_cached(self.rt.cache, &cache_args, self.rt.secrets, &mut self.logs)
        {
            return Ok(cached);
        }
        let mut output = self.recorder.lookup(&source_name, &query);
        if output.is_none() && self.recorder.replay_active() {
            let shown: String = query.chars().take(120).collect();
            self.log_warning(format!(
                "no saved correlate result for query against {source_name}; running live: {shown}"
            ));
        }
        let output = match output.take() {
            Some(o) => o,
            None => {
                let (start, end) =
                    self.resolve_time_range(command, call.scope.event, call.transform_type)?;
                let timeout = timespec(&command.timeout)?;
                let source = self.rt.sources.get(&source_name)?.clone();
                let rows =
                    source.execute_query(&query, start, end, timeout, &command.source_options)?;
                let rows: Vec<Map> = rows
                    .iter()
                    .map(
                        |r| match crate::query::extract::to_loaded(&Json::Object(r.clone())) {
                            Value::Map(m) => m,
                            _ => Map::new(),
                        },
                    )
                    .collect();
                json_lines(&rows)
            }
        };
        self.recorder.record(&source_name, &query, &output);
        if let Some(cache) = set(&command.cache) {
            let ttl = timespec(cache)?.num_seconds();
            set_cached(
                self.rt.cache,
                &cache_args,
                &output,
                ttl,
                self.rt.secrets,
                &mut self.logs,
            );
        }
        if call.transform_type == "stream" {
            self.stream_cache.insert(stream_key, output.clone());
        }
        Ok(output)
    }

    /// `_resolve_time_range`: an event transform with a time field is anchored to the event's
    /// time, `before` and `after` around it; anything else to the hunt's window, `before` before
    /// its start and `after` after its end. The field and its format are the command's, or else the
    /// current source's defaults. An event without the field fails.
    pub fn resolve_time_range(
        &self,
        command: &Command,
        event: &Map,
        transform_type: &str,
    ) -> Result<(Time, Time), String> {
        let range = command.time_range.as_ref();
        let delta = |v: Option<&Option<String>>| -> Result<TimeDelta, String> {
            match v.and_then(|v| set(v)) {
                Some(t) => timespec(t),
                None => Ok(TimeDelta::zero()),
            }
        };
        let before = delta(range.map(|r| &r.before))?;
        let after = delta(range.map(|r| &r.after))?;
        let (field, format) = self.time_field_and_format(command);
        if transform_type == "event"
            && let Some(field) = field
        {
            let Some(value) = event.get(&field) else {
                return Err(format!(
                    "KeyError: 'event missing time field {field} required by query time_range (source={})'",
                    self.current_source.as_deref().unwrap_or("None")
                ));
            };
            let reference = parse_time_value(value, format.as_deref())?;
            return Ok((reference.minus(before)?, reference.plus(after)?));
        }
        Ok((self.hunt_start.minus(before)?, self.hunt_end.plus(after)?))
    }

    /// `_resolve_time_field_and_format`.
    fn time_field_and_format(&self, command: &Command) -> (Option<String>, Option<String>) {
        let range = command.time_range.as_ref();
        let field = range.and_then(|r| r.relative_time_field.clone());
        let format = range.and_then(|r| r.relative_time_format.clone());
        if field.is_some() && format.is_some() {
            return (field, format);
        }
        let source = self
            .current_source
            .as_deref()
            .and_then(|s| self.rt.sources.get(s).ok());
        let default_field = source.and_then(|s| s.default_time_field().map(str::to_owned));
        let default_format = source.and_then(|s| s.default_time_format().map(str::to_owned));
        (field.or(default_field), format.or(default_format))
    }

    /// `prepare_custom_command`: the handler, the options rendered then validated, the timeout.
    pub fn prepare_custom(&self, command: &Command, call: Call<'_>) -> Result<Prepared, String> {
        let handler = self.rt.command_types.get(&command.kind)?.clone();
        let raw = crate::query::extract::to_loaded(&Json::Object(command.options.clone()));
        let rendered = if handler.render_options() {
            render_options(self, &raw, call.scope)?
        } else {
            raw
        };
        let options = if handler.has_options() {
            handler
                .validate_options(&rendered)
                .map_err(|e| format!("ValidationError: {e}"))?
        } else {
            match &rendered {
                Value::Map(m) if !m.is_empty() => {
                    let mut keys: Vec<String> = m.iter().map(|(k, _)| k.key_text()).collect();
                    keys.sort();
                    let keys: Vec<String> = keys.iter().map(|k| py_repr(k)).collect();
                    return Err(format!(
                        "ValueError: command type {} does not take options, got [{}]",
                        command.kind,
                        keys.join(", ")
                    ));
                }
                _ => Json::Object(JsonMap::new()),
            }
        };
        Ok(Prepared {
            handler,
            options,
            timeout: timespec(&command.timeout)?,
        })
    }

    pub fn context<'c>(
        &self,
        command: &'c Command,
        call: Call<'c>,
        timeout: TimeDelta,
    ) -> CommandContext<'c> {
        CommandContext {
            command_type: &command.kind,
            event: call.scope.event,
            events: call.scope.events,
            transform_type: call.transform_type,
            hunt_start: self.hunt_start,
            hunt_end: self.hunt_end,
            timeout,
        }
    }

    fn execute_custom(&mut self, command: &Command, call: Call<'_>) -> Result<String, String> {
        let prepared = self.prepare_custom(command, call)?;
        let context = self.context(command, call, prepared.timeout);
        let mut cache_args = None;
        if set(&command.cache).is_some() && prepared.handler.cacheable() {
            let mut args = prepared.handler.cache_key(&context, &prepared.options);
            args.insert("type".to_owned(), Json::from(command.kind.clone()));
            if let Some(cached) = get_cached(self.rt.cache, &args, self.rt.secrets, &mut self.logs)
            {
                return Ok(cached);
            }
            cache_args = Some(args);
        }
        let output = prepared.handler.execute(&context, &prepared.options)?;
        let output = sanitize(&output, self.rt.secrets);
        if let (Some(args), Some(cache)) = (cache_args, set(&command.cache)) {
            let ttl = timespec(cache)?.num_seconds();
            set_cached(
                self.rt.cache,
                &args,
                &output,
                ttl,
                self.rt.secrets,
                &mut self.logs,
            );
        }
        Ok(output)
    }

    /// `_render_command_summary`: the query or the path and arguments as rendered, never an
    /// executable's `env`; `defined:<name>`; a custom type's own summary; None on any failure.
    pub fn command_summary(&self, command: &Command, call: Call<'_>) -> Option<String> {
        match command.kind.as_str() {
            "query" => command
                .query
                .as_deref()
                .filter(|q| !q.is_empty())
                .and_then(|q| render(self.rt.renderer, q, call.scope).ok()),
            "executable" => {
                let path = command.path.as_deref().filter(|p| !p.is_empty())?;
                let mut args = Vec::new();
                for arg in command.args.iter().flatten() {
                    args.push(render(self.rt.renderer, arg, call.scope).ok()?);
                }
                Some(
                    format!("{path} {}", args.join(" "))
                        .trim_matches(crate::render::methods::is_space)
                        .to_owned(),
                )
            }
            "defined" => command
                .name
                .as_deref()
                .filter(|n| !n.is_empty())
                .map(|n| format!("defined:{n}")),
            _ => {
                let prepared = self.prepare_custom(command, call).ok()?;
                let context = self.context(command, call, prepared.timeout);
                prepared.handler.render_summary(&context, &prepared.options)
            }
        }
    }

    /// `_resolve_command_source`: the source a command queries, through a `defined` one.
    pub fn command_source(&self, command: &Command) -> Option<String> {
        match command.kind.as_str() {
            "query" => command.source.clone(),
            "defined" => {
                let name = command.name.as_deref().filter(|n| !n.is_empty())?;
                self.predefined
                    .iter()
                    .find(|p| p.name == name && p.kind == "query")
                    .and_then(|p| p.source.clone())
            }
            _ => None,
        }
    }

    /// `_effective_query_command`: the query a command runs, through a `defined` one, whose
    /// `arguments` failing to validate ends the run, as ace3's exception does there.
    pub fn effective_query(&self, command: &Command) -> Result<Option<Command>, EngineError> {
        match command.kind.as_str() {
            "query" => Ok(Some(command.clone())),
            "defined" => {
                let Some(name) = command.name.as_deref().filter(|n| !n.is_empty()) else {
                    return Ok(None);
                };
                let Some(predefined) = self
                    .predefined
                    .iter()
                    .find(|p| p.name == name && p.kind == "query")
                else {
                    return Ok(None);
                };
                predefined
                    .to_command(command.arguments.as_ref())
                    .map(Some)
                    .map_err(|e| EngineError::Raised(format!("ValidationError: {e}")))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn check_stop(&self) -> Result<(), EngineError> {
        if (self.rt.stopped)() {
            Err(EngineError::Stopped)
        } else {
            Ok(())
        }
    }
}
