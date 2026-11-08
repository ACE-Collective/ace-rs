//! Correlation hunts (PLAN.md 6.6): a hunt's `correlate` block and its predefined `commands`, as
//! ace3's correlation schema validates them at load (`saq/collectors/hunter/correlation/schema.py`,
//! this module, 6.2), and the engine that runs them over a search's rows ([`engine`]).
//!
//! A step is `when`, `transform` or `action`, decided by which key it has, as ace3's
//! `StepConfig.dispatch_step_type` does. That dispatch is a pydantic before validator, which shapes
//! the errors a bad step gets: the first problem in a step ends it, a step nested in a condition's
//! branch reports its errors at its outermost step's location, and a branch that isn't a list
//! fails the whole hunt with Python's TypeError, as in ace3.
//!
//! The engine's parts are ace3's: [`expr`] its expressions, [`transform`] what a transform does
//! with a command's output, [`action`] its actions, [`command`] its commands (a query against a
//! [`source::QuerySource`], a predefined command, or a custom type an integration registers), with
//! [`cache`] their cache and the validator's record and replay, [`trace`] the record of a run, and
//! [`check`] the checks hunt validation adds. [`time`] reads times as ace3 does and [`pyjson`]
//! writes JSON as Python does.
//!
//! **`type: executable` doesn't run.** ace3 runs a hunt's executable, which in the signatures is a
//! Python script under `hunts/scripts/`, in a Landlock sandbox (`saq/sandbox/`). ace4 has no Python
//! and no sandbox runner, and how such a command runs waits for the owner: a sandbox runner with an
//! interpreter for hunt scripts, or the scripts' work as built-in command types (PLAN.md 6.6). Until
//! then an executable step fails as a step error, so its event falls through to an alert, as ace3's
//! does where Landlock is missing. A hunt that names one loads and validates.

pub mod action;
pub mod cache;
pub mod check;
pub mod command;
pub mod engine;
pub mod expr;
pub mod pyjson;
pub mod source;
pub mod time;
pub mod trace;
pub mod transform;

#[cfg(test)]
mod tests;

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as Json};

use crate::HuntError;
use crate::model::{all, optional};
use crate::validate::{
    Errors, Loc, Obj, V, any_dict, boolean, child, dict, key, list, opt_boolean, opt_string,
    opt_string_list, push, raw_dict, string, value_error,
};
use crate::value::{Value, py_repr};

/// The `correlate` block.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Correlate {
    pub timeout: String,
    pub logic: Vec<Step>,
}

/// One step of the logic.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Step {
    pub step: StepKind,
    pub description: Option<String>,
    pub debug: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum StepKind {
    Condition(Condition),
    Transform(Box<Transform>),
    Action(Action),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Condition {
    pub when: Expression,
    pub execute: Vec<Step>,
    #[serde(rename = "else")]
    pub otherwise: Option<Vec<Step>>,
}

/// A condition's expression. A plain string is a Jinja expression.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Expression {
    #[serde(rename = "type")]
    pub kind: String,
    /// The value, or the sub-expressions of `and`, `or` and `not`, as written: ace3 types it `Any`.
    pub value: Json,
    pub property: Option<String>,
    pub case_sensitive: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Transform {
    #[serde(rename = "type")]
    pub kind: String,
    pub method: String,
    pub property_name: Option<String>,
    pub property_type: String,
    pub merge_time_spec: Option<MergeTimeSpec>,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MergeTimeSpec {
    pub l_field: String,
    pub l_format: String,
    pub r_field: String,
    pub r_format: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub kind: String,
    pub queue: Option<String>,
    pub analysis_mode: Option<String>,
    pub log_level: String,
    pub log_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CommandTimeRange {
    pub before: Option<String>,
    pub after: Option<String>,
    pub relative_time_field: Option<String>,
    pub relative_time_format: Option<String>,
}

/// A transform's command: `query`, `executable`, `defined` (a predefined command by name), or a
/// custom type an integration registers.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Command {
    #[serde(rename = "type")]
    pub kind: String,
    pub timeout: String,
    pub cache: Option<String>,
    pub source: Option<String>,
    pub query: Option<String>,
    pub time_range: Option<CommandTimeRange>,
    pub source_options: JsonMap<String, Json>,
    /// An executable's path, made absolute against the file that named it as ace3 does.
    pub path: Option<String>,
    pub stdin: Option<bool>,
    pub args: Option<Vec<String>>,
    #[serde(serialize_with = "string_pairs")]
    pub env: Option<Vec<(String, String)>>,
    pub files: Option<Vec<String>>,
    pub name: Option<String>,
    pub arguments: Option<JsonMap<String, Json>>,
    pub options: JsonMap<String, Json>,
}

/// One of a hunt file's top-level `commands`, which a `defined` command names.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PredefinedCommand {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    pub timeout: String,
    pub cache: Option<String>,
    pub source: Option<String>,
    pub query: Option<String>,
    pub time_range: Option<CommandTimeRange>,
    pub source_options: JsonMap<String, Json>,
    pub path: Option<String>,
    pub stdin: Option<bool>,
    pub args: Option<Vec<String>>,
    #[serde(serialize_with = "string_pairs")]
    pub env: Option<Vec<(String, String)>>,
    pub files: Option<Vec<String>>,
    pub options: JsonMap<String, Json>,
}

fn string_pairs<S: serde::Serializer>(
    value: &Option<Vec<(String, String)>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    match value {
        None => serializer.serialize_none(),
        Some(pairs) => {
            let mut map = serializer.serialize_map(Some(pairs.len()))?;
            for (k, v) in pairs {
                map.serialize_entry(k, v)?;
            }
            map.end()
        }
    }
}

/// The command types ace3's core implements; any other `type` is a custom command type.
pub const BUILTIN_COMMAND_TYPES: [&str; 3] = ["query", "executable", "defined"];

impl Correlate {
    pub fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Correlate> {
        let Some(mut o) = Obj::new(v, loc, "CorrelateConfig", errs) else {
            return Ok(None);
        };
        let timeout = o.default(errs, "timeout", "15m".to_owned(), string)?;
        let logic = o.required(errs, "logic", |v, l, e| list(v, l, e, Step::validate))?;
        if !o.finish(errs) {
            return Ok(None);
        }
        let Some((timeout, logic)) = all!(timeout, logic) else {
            return Ok(None);
        };
        // validate_timeout
        if let Err(error) = parse_timespec(&timeout) {
            return match error {
                TimespecError::Invalid(message) => {
                    value_error(errs, loc, &message);
                    Ok(None)
                }
                TimespecError::Overflow(message) => {
                    Err(HuntError::python("OverflowError", message))
                }
            };
        }
        Ok(Some(Correlate { timeout, logic }))
    }
}

/// Why a timespec doesn't parse.
pub enum TimespecError {
    /// ace3's ValueError.
    Invalid(String),
    /// Python's OverflowError, from a timedelta past 999999999 days.
    Overflow(String),
}

static TIMESPEC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(\d+)\s*([smhdwy])").expect("a valid pattern"));

/// `saq.util.timespec.parse_timespec`: units summed, such as `1d 12h` or `8h30m30s`, in seconds.
pub fn parse_timespec(value: &str) -> Result<i128, TimespecError> {
    let mut seconds: i128 = 0;
    let mut any = false;
    for capture in TIMESPEC.captures_iter(value) {
        any = true;
        let digits: String = capture[1]
            .chars()
            .map(|c| c.to_digit(10).map_or('0', |d| char::from(b'0' + d as u8)))
            .collect();
        let count: i128 = digits.parse().unwrap_or(i128::MAX / 1_000_000_000);
        let unit = match capture[2].to_ascii_lowercase().as_str() {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            "w" => 604_800,
            _ => 365 * 86_400,
        };
        seconds = seconds.saturating_add(count.saturating_mul(unit));
    }
    if !any {
        return Err(TimespecError::Invalid(format!(
            "invalid timespec: {}",
            py_repr(value)
        )));
    }
    let days = seconds / 86_400;
    if days > 999_999_999 {
        return Err(TimespecError::Overflow(format!(
            "days={days}; must have magnitude <= 999999999"
        )));
    }
    Ok(seconds)
}

/// A Python list of strings as `repr` writes it, such as `['when', 'action']`.
fn py_list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| py_repr(s)).collect();
    format!("[{}]", quoted.join(", "))
}

/// Whether `name` is a key of `v`, for a mapping's string keys.
fn has(v: &crate::value::Map, name: &str) -> bool {
    v.contains(name)
}

impl Step {
    pub fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Step> {
        let Value::Map(data) = v else {
            push(
                errs,
                loc,
                "model_type",
                "Input should be a valid dictionary or instance of StepConfig",
            );
            return Ok(None);
        };
        // dispatch_step_type, the before validator: its first problem ends the step
        let present: Vec<String> = ["when", "transform", "action"]
            .into_iter()
            .filter(|k| has(data, k))
            .map(str::to_owned)
            .collect();
        if present.len() > 1 {
            value_error(
                errs,
                loc,
                &format!(
                    "step must contain exactly one of 'when', 'transform', or 'action'; got {}",
                    py_list(&present)
                ),
            );
            return Ok(None);
        }
        let Some(which) = present.first() else {
            value_error(
                errs,
                loc,
                "step must contain 'when', 'transform', or 'action' key",
            );
            return Ok(None);
        };
        let allowed: &[&str] = if which == "when" {
            &["debug", "description", "else", "execute", "when"]
        } else {
            &["action", "debug", "description", "transform"]
        };
        let mut extras: Vec<String> = Vec::new();
        for (k, _) in data.iter() {
            match k {
                Value::Str(s) if allowed.contains(&s.as_str()) => {}
                Value::Str(s) => extras.push(s.clone()),
                other => {
                    return Err(HuntError::python(
                        "TypeError",
                        format!(
                            "'<' not supported between instances of '{}' and 'str'",
                            other.type_name()
                        ),
                    ));
                }
            }
        }
        if !extras.is_empty() {
            extras.sort();
            let allowed: Vec<String> = allowed.iter().map(|s| (*s).to_owned()).collect();
            value_error(
                errs,
                loc,
                &format!(
                    "step has unexpected keys {}; allowed: {}",
                    py_list(&extras),
                    py_list(&allowed)
                ),
            );
            return Ok(None);
        }

        // the inner models are validated here, and their errors are this step's, at its location
        let mut inner = Errors::new();
        let step = match which.as_str() {
            "when" => Condition::from_dispatch(data, loc, &mut inner)?,
            "transform" => Transform::validate(
                data.get("transform").unwrap_or(&Value::Null),
                loc,
                &mut inner,
            )?
            .map(|t| StepKind::Transform(Box::new(t))),
            _ => Action::validate(data.get("action").unwrap_or(&Value::Null), loc, &mut inner)?
                .map(StepKind::Action),
        };
        let Some(step) = step else {
            errs.append(&mut inner);
            return Ok(None);
        };
        let start = errs.len();
        let description = optional_text(data.get("description"), &key(loc, "description"), errs)?;
        let debug = optional_text(data.get("debug"), &key(loc, "debug"), errs)?;
        if errs.len() > start {
            return Ok(None);
        }
        Ok(Some(Step {
            step,
            description: description.flatten(),
            debug: debug.flatten(),
        }))
    }
}

fn optional_text(v: Option<&Value>, loc: &[Loc], errs: &mut Errors) -> V<Option<String>> {
    match v {
        None => Ok(Some(None)),
        Some(v) => opt_string(v, loc, errs),
    }
}

impl Condition {
    /// The `when` step dispatch builds: each branch's steps validated in turn, the first bad one
    /// ending the step, and then ConditionConfig over them.
    fn from_dispatch(data: &crate::value::Map, loc: &[Loc], inner: &mut Errors) -> V<StepKind> {
        let empty = Value::Seq(Vec::new());
        let branch = |value: &Value, inner: &mut Errors| -> V<Vec<Step>> {
            let mut steps = Vec::new();
            for item in value
                .py_iter()
                .map_err(|m| HuntError::python("TypeError", m))?
            {
                match Step::validate(&item, loc, inner)? {
                    Some(step) => steps.push(step),
                    None => return Ok(None),
                }
            }
            Ok(Some(steps))
        };
        let Some(execute) = branch(data.get("execute").unwrap_or(&empty), inner)? else {
            return Ok(None);
        };
        let otherwise = match data.get("else") {
            None => None,
            Some(value) => match branch(value, inner)? {
                Some(steps) => Some(steps),
                None => return Ok(None),
            },
        };
        // ConditionConfig.model_validate: `when` is ExpressionConfig or a string
        let when = data.get("when").unwrap_or(&Value::Null);
        let when_loc = key(loc, "when");
        let expression = match when {
            Value::Str(s) => Expression {
                kind: "jinja".to_owned(),
                value: Json::String(s.clone()),
                property: None,
                case_sensitive: true,
            },
            other => {
                let tag = "function-after[validate_expression(), ExpressionConfig]";
                let mut union = Errors::new();
                match Expression::validate(
                    other,
                    &child(&when_loc, Loc::Key(tag.to_owned())),
                    &mut union,
                )? {
                    Some(expression) => expression,
                    None => {
                        inner.append(&mut union);
                        push(
                            inner,
                            &key(&when_loc, "str"),
                            "string_type",
                            "Input should be a valid string",
                        );
                        return Ok(None);
                    }
                }
            }
        };
        Ok(Some(StepKind::Condition(Condition {
            when: expression,
            execute,
            otherwise,
        })))
    }
}

impl Expression {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Expression> {
        let shorthand;
        let v = match v {
            Value::Str(s) => {
                let mut map = crate::value::Map::new();
                map.insert(Value::str("type"), Value::str("jinja"));
                map.insert(Value::str("value"), Value::Str(s.clone()));
                shorthand = Value::Map(map);
                &shorthand
            }
            other => other,
        };
        let Some(mut o) = Obj::new(v, loc, "ExpressionConfig", errs) else {
            return Ok(None);
        };
        let kind = o.default(errs, "type", "jinja".to_owned(), string)?;
        let value = o.required(errs, "value", |v, _, _| Ok(Some(v.clone())))?;
        let property = o.default(errs, "property", None, opt_string)?;
        let case_sensitive = o.default(errs, "case_sensitive", true, boolean)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        let Some((kind, value, property, case_sensitive)) =
            all!(kind, value, property, case_sensitive)
        else {
            return Ok(None);
        };
        let message = if ["equals", "glob", "regex"].contains(&kind.as_str()) && property.is_none()
        {
            Some(format!(
                "'property' is required for expression type '{kind}'"
            ))
        } else if kind == "not" && matches!(value, Value::Seq(_)) {
            Some("'not' expression value must not be a list".to_owned())
        } else if (kind == "and" || kind == "or") && !matches!(value, Value::Seq(_)) {
            Some(format!("'{kind}' expression value must be a list"))
        } else {
            None
        };
        if let Some(message) = message {
            value_error(errs, loc, &message);
            return Ok(None);
        }
        Ok(Some(Expression {
            kind,
            value: value.to_json(),
            property,
            case_sensitive,
        }))
    }
}

impl Transform {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Transform> {
        let Some(mut o) = Obj::new(v, loc, "TransformConfig", errs) else {
            return Ok(None);
        };
        let kind = o.default(errs, "type", "event".to_owned(), string)?;
        let method = o.default(errs, "method", "property".to_owned(), string)?;
        let property_name = o.default(errs, "property_name", None, opt_string)?;
        let property_type = o.default(errs, "property_type", "str".to_owned(), string)?;
        let merge_time_spec = o.default(
            errs,
            "merge_time_spec",
            None,
            optional(MergeTimeSpec::validate),
        )?;
        let command = o.required(errs, "command", Command::validate)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        let Some((kind, method, property_name, property_type, merge_time_spec, command)) = all!(
            kind,
            method,
            property_name,
            property_type,
            merge_time_spec,
            command
        ) else {
            return Ok(None);
        };
        let message = if method == "property" && kind != "event" {
            Some("'property' method is only valid for event transforms".to_owned())
        } else if (method == "merge" || method == "mutate") && kind != "stream" {
            Some(format!(
                "'{method}' method is only valid for stream transforms"
            ))
        } else if method == "property" && property_name.is_none() {
            Some("'property_name' is required for property method".to_owned())
        } else if method == "merge" && merge_time_spec.is_none() {
            Some("'merge_time_spec' is required for merge method".to_owned())
        } else {
            None
        };
        if let Some(message) = message {
            value_error(errs, loc, &message);
            return Ok(None);
        }
        Ok(Some(Transform {
            kind,
            method,
            property_name,
            property_type,
            merge_time_spec,
            command,
        }))
    }
}

impl MergeTimeSpec {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<MergeTimeSpec> {
        let Some(mut o) = Obj::new(v, loc, "MergeTimeSpecConfig", errs) else {
            return Ok(None);
        };
        let l_field = o.required(errs, "l_field", string)?;
        let l_format = o.required(errs, "l_format", string)?;
        let r_field = o.required(errs, "r_field", string)?;
        let r_format = o.required(errs, "r_format", string)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        Ok(all!(l_field, l_format, r_field, r_format).map(
            |(l_field, l_format, r_field, r_format)| MergeTimeSpec {
                l_field,
                l_format,
                r_field,
                r_format,
            },
        ))
    }
}

impl Action {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Action> {
        let shorthand;
        let v = match v {
            Value::Str(s) => {
                let mut map = crate::value::Map::new();
                map.insert(Value::str("type"), Value::Str(s.clone()));
                shorthand = Value::Map(map);
                &shorthand
            }
            other => other,
        };
        let Some(mut o) = Obj::new(v, loc, "ActionConfig", errs) else {
            return Ok(None);
        };
        let kind = o.required(errs, "type", string)?;
        let queue = o.default(errs, "queue", None, opt_string)?;
        let analysis_mode = o.default(errs, "analysis_mode", None, opt_string)?;
        let log_level = o.default(errs, "log_level", "INFO".to_owned(), string)?;
        let log_message = o.default(errs, "log_message", None, opt_string)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        let Some((kind, queue, analysis_mode, log_level, log_message)) =
            all!(kind, queue, analysis_mode, log_level, log_message)
        else {
            return Ok(None);
        };
        if !["filter", "stop", "discard", "alert", "log"].contains(&kind.as_str()) {
            value_error(
                errs,
                loc,
                &format!("invalid action type: {}", py_repr(&kind)),
            );
            return Ok(None);
        }
        Ok(Some(Action {
            kind,
            queue,
            analysis_mode,
            log_level,
            log_message,
        }))
    }
}

impl CommandTimeRange {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<CommandTimeRange> {
        let Some(mut o) = Obj::new(v, loc, "TimeRangeConfig", errs) else {
            return Ok(None);
        };
        let before = o.default(errs, "before", None, opt_string)?;
        let after = o.default(errs, "after", None, opt_string)?;
        let relative_time_field = o.default(errs, "relative_time_field", None, opt_string)?;
        let relative_time_format = o.default(errs, "relative_time_format", None, opt_string)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        Ok(
            all!(before, after, relative_time_field, relative_time_format).map(
                |(before, after, relative_time_field, relative_time_format)| CommandTimeRange {
                    before,
                    after,
                    relative_time_field,
                    relative_time_format,
                },
            ),
        )
    }
}

/// The fields a command shares with a predefined one, validated in their order.
struct CommandFields {
    kind: String,
    timeout: String,
    cache: Option<String>,
    source: Option<String>,
    query: Option<String>,
    time_range: Option<CommandTimeRange>,
    source_options: JsonMap<String, Json>,
    path: Option<String>,
    stdin: Option<bool>,
    args: Option<Vec<String>>,
    env: Option<Vec<(String, String)>>,
    files: Option<Vec<String>>,
}

/// Validates `type` through `files`; `before` runs first, for PredefinedCommandConfig's `name`
/// and `description`, which come before them.
fn command_fields(o: &mut Obj<'_>, errs: &mut Errors) -> Result<Option<CommandFields>, HuntError> {
    let kind = o.required(errs, "type", string)?;
    let timeout = o.default(errs, "timeout", "10m".to_owned(), string)?;
    let cache = o.default(errs, "cache", None, opt_string)?;
    let source = o.default(errs, "source", None, opt_string)?;
    let query = o.default(errs, "query", None, opt_string)?;
    let time_range = o.default(
        errs,
        "time_range",
        None,
        optional(CommandTimeRange::validate),
    )?;
    let source_options = o.default(errs, "source_options", JsonMap::new(), any_dict)?;
    let path = o.default(errs, "path", None, opt_string)?;
    let stdin = o.default(errs, "stdin", None, opt_boolean)?;
    let args = o.default(errs, "args", None, opt_string_list)?;
    let env = o.default(errs, "env", None, optional(|v, l, e| dict(v, l, e, string)))?;
    let files = o.default(errs, "files", None, opt_string_list)?;
    Ok(all!(
        kind,
        timeout,
        cache,
        source,
        query,
        time_range,
        source_options,
        path,
        stdin,
        args,
        env,
        files
    )
    .map(
        |(
            kind,
            timeout,
            cache,
            source,
            query,
            time_range,
            source_options,
            path,
            stdin,
            args,
            env,
            files,
        )| {
            CommandFields {
                kind,
                timeout,
                cache,
                source,
                query,
                time_range,
                source_options,
                path,
                stdin,
                args,
                env,
                files,
            }
        },
    ))
}

/// `_validate_options_placement`: `options` only on a custom type, and none of the built-in
/// types' fields on one.
fn check_options(
    kind: &str,
    options: &JsonMap<String, Json>,
    present: &[(&str, bool)],
) -> Result<(), String> {
    if BUILTIN_COMMAND_TYPES.contains(&kind) {
        if !options.is_empty() {
            let hint = if kind == "query" {
                " (did you mean 'source_options'?)"
            } else {
                ""
            };
            return Err(format!(
                "'options' is only valid for custom command types, not '{kind}'{hint}"
            ));
        }
        return Ok(());
    }
    let present: Vec<String> = present
        .iter()
        .filter(|(_, set)| *set)
        .map(|(name, _)| (*name).to_owned())
        .collect();
    if !present.is_empty() {
        return Err(format!(
            "custom command type '{kind}' does not accept {}; put its settings under 'options'",
            py_list(&present)
        ));
    }
    Ok(())
}

/// Whether a field counts as set for `_validate_options_placement`: not None, `{}` or `[]`.
fn set_fields(f: &CommandFields) -> Vec<(&'static str, bool)> {
    vec![
        ("source", f.source.is_some()),
        ("query", f.query.is_some()),
        ("time_range", f.time_range.is_some()),
        ("source_options", !f.source_options.is_empty()),
        ("path", f.path.is_some()),
        ("stdin", f.stdin.is_some()),
        ("args", f.args.as_ref().is_some_and(|a| !a.is_empty())),
        ("env", f.env.as_ref().is_some_and(|e| !e.is_empty())),
        ("files", f.files.as_ref().is_some_and(|x| !x.is_empty())),
    ]
}

impl Command {
    fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Command> {
        let Some(mut o) = Obj::new(v, loc, "CommandConfig", errs) else {
            return Ok(None);
        };
        let fields = command_fields(&mut o, errs)?;
        let name = o.default(errs, "name", None, opt_string)?;
        let arguments = o.default(errs, "arguments", None, optional(raw_dict))?;
        let options = o.default(errs, "options", JsonMap::new(), any_dict)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        let Some((f, name, arguments, options)) = all!(fields, name, arguments, options) else {
            return Ok(None);
        };
        let message = if f.kind == "query" && f.source.is_none() {
            Err("'source' is required for query commands".to_owned())
        } else if f.kind == "executable" && f.path.is_none() {
            Err("'path' is required for executable commands".to_owned())
        } else if f.kind == "defined" && name.is_none() {
            Err("'name' is required for defined commands".to_owned())
        } else {
            let mut present = set_fields(&f);
            present.push(("name", name.is_some()));
            present.push((
                "arguments",
                arguments.as_ref().is_some_and(|a| !a.is_empty()),
            ));
            check_options(&f.kind, &options, &present)
        };
        if let Err(message) = message {
            value_error(errs, loc, &message);
            return Ok(None);
        }
        Ok(Some(Command {
            kind: f.kind,
            timeout: f.timeout,
            cache: f.cache,
            source: f.source,
            query: f.query,
            time_range: f.time_range,
            source_options: f.source_options,
            path: f.path,
            stdin: f.stdin,
            args: f.args,
            env: f.env,
            files: f.files,
            name,
            arguments,
            options,
        }))
    }
}

impl PredefinedCommand {
    /// Validates one of `commands` as PredefinedCommandConfig, whose errors ace3 raises as a
    /// ValidationError of its own.
    pub fn validate(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<PredefinedCommand> {
        let Some(mut o) = Obj::new(v, loc, "PredefinedCommandConfig", errs) else {
            return Ok(None);
        };
        let name = o.required(errs, "name", string)?;
        let description = o.default(errs, "description", None, opt_string)?;
        let fields = command_fields(&mut o, errs)?;
        let options = o.default(errs, "options", JsonMap::new(), any_dict)?;
        if !o.finish(errs) {
            return Ok(None);
        }
        let Some((name, description, f, options)) = all!(name, description, fields, options) else {
            return Ok(None);
        };
        if let Err(message) = check_options(&f.kind, &options, &set_fields(&f)) {
            value_error(errs, loc, &message);
            return Ok(None);
        }
        Ok(Some(PredefinedCommand {
            name,
            description,
            kind: f.kind,
            timeout: f.timeout,
            cache: f.cache,
            source: f.source,
            query: f.query,
            time_range: f.time_range,
            source_options: f.source_options,
            path: f.path,
            stdin: f.stdin,
            args: f.args,
            env: f.env,
            files: f.files,
            options,
        }))
    }
}

impl PredefinedCommand {
    /// `to_command_config(overrides)`: the command with its fields as `model_dump` gives them,
    /// `overrides` (a `defined` command's `arguments`) replacing whole fields, validated as a
    /// CommandConfig.
    pub fn to_command(
        &self,
        overrides: Option<&JsonMap<String, Json>>,
    ) -> Result<Command, HuntError> {
        let mut data = crate::value::Map::new();
        let s = |v: &Option<String>| v.as_ref().map_or(Value::Null, |s| Value::Str(s.clone()));
        let strings = |v: &Option<Vec<String>>| {
            v.as_ref().map_or(Value::Null, |l| {
                Value::Seq(l.iter().map(|s| Value::Str(s.clone())).collect())
            })
        };
        let json = |map: &JsonMap<String, Json>| {
            crate::query::extract::to_loaded(&Json::Object(map.clone()))
        };
        data.insert(Value::str("type"), Value::Str(self.kind.clone()));
        data.insert(Value::str("timeout"), Value::Str(self.timeout.clone()));
        data.insert(Value::str("cache"), s(&self.cache));
        data.insert(Value::str("source"), s(&self.source));
        data.insert(Value::str("query"), s(&self.query));
        data.insert(
            Value::str("time_range"),
            match &self.time_range {
                None => Value::Null,
                Some(t) => {
                    let mut m = crate::value::Map::new();
                    m.insert(Value::str("before"), s(&t.before));
                    m.insert(Value::str("after"), s(&t.after));
                    m.insert(Value::str("relative_time_field"), s(&t.relative_time_field));
                    m.insert(
                        Value::str("relative_time_format"),
                        s(&t.relative_time_format),
                    );
                    Value::Map(m)
                }
            },
        );
        data.insert(Value::str("source_options"), json(&self.source_options));
        data.insert(Value::str("path"), s(&self.path));
        data.insert(
            Value::str("stdin"),
            self.stdin.map_or(Value::Null, Value::Bool),
        );
        data.insert(Value::str("args"), strings(&self.args));
        data.insert(
            Value::str("env"),
            match &self.env {
                None => Value::Null,
                Some(pairs) => {
                    let mut m = crate::value::Map::new();
                    for (k, v) in pairs {
                        m.insert(Value::Str(k.clone()), Value::Str(v.clone()));
                    }
                    Value::Map(m)
                }
            },
        );
        data.insert(Value::str("files"), strings(&self.files));
        data.insert(Value::str("options"), json(&self.options));
        for (k, v) in overrides.into_iter().flatten() {
            data.insert(Value::Str(k.clone()), crate::query::extract::to_loaded(v));
        }
        let mut errs = Errors::new();
        match Command::validate(&Value::Map(data), &[], &mut errs)? {
            Some(command) if errs.is_empty() => Ok(command),
            _ => Err(HuntError::Validation {
                title: "CommandConfig".to_owned(),
                errors: errs,
            }),
        }
    }
}

/// `iter_correlate_commands`: every transform's command in the logic, in document order, into a
/// condition's branches.
pub fn commands(steps: &[Step]) -> Vec<&Command> {
    let mut out = Vec::new();
    for step in steps {
        match &step.step {
            StepKind::Transform(t) => out.push(&t.command),
            StepKind::Condition(c) => {
                out.extend(commands(&c.execute));
                if let Some(otherwise) = &c.otherwise {
                    out.extend(commands(otherwise));
                }
            }
            StepKind::Action(_) => {}
        }
    }
    out
}

/// `collect_correlate_steps` (`query_hunter.py`): each transform that sets a named property, with
/// its step's description, in document order, for the provenance of a correlated alert's
/// observables.
pub fn property_steps(steps: &[Step]) -> Vec<(Option<&str>, &str)> {
    let mut out = Vec::new();
    for step in steps {
        match &step.step {
            StepKind::Transform(t) => {
                if t.method == "property"
                    && let Some(name) = t.property_name.as_deref().filter(|n| !n.is_empty())
                {
                    out.push((step.description.as_deref(), name));
                }
            }
            StepKind::Condition(c) => {
                out.extend(property_steps(&c.execute));
                if let Some(otherwise) = &c.otherwise {
                    out.extend(property_steps(otherwise));
                }
            }
            StepKind::Action(_) => {}
        }
    }
    out
}

impl Correlate {
    /// Validates a `correlate` block as `CorrelateConfig.model_validate` does.
    pub fn from_value(v: &Value) -> Result<Correlate, HuntError> {
        let mut errs = Errors::new();
        match Correlate::validate(v, &[], &mut errs)? {
            Some(c) if errs.is_empty() => Ok(c),
            _ => Err(HuntError::Validation {
                title: "CorrelateConfig".to_owned(),
                errors: errs,
            }),
        }
    }
}

impl PredefinedCommand {
    /// Validates one predefined command as `PredefinedCommandConfig.model_validate` does.
    pub fn from_value(v: &Value) -> Result<PredefinedCommand, HuntError> {
        let mut errs = Errors::new();
        match PredefinedCommand::validate(v, &[], &mut errs)? {
            Some(c) if errs.is_empty() => Ok(c),
            _ => Err(HuntError::Validation {
                title: "PredefinedCommandConfig".to_owned(),
                errors: errs,
            }),
        }
    }
}

impl Command {
    /// Validates a command as `CommandConfig.model_validate` does.
    pub fn from_value(v: &Value) -> Result<Command, HuntError> {
        let mut errs = Errors::new();
        match Command::validate(v, &[], &mut errs)? {
            Some(c) if errs.is_empty() => Ok(c),
            _ => Err(HuntError::Validation {
                title: "CommandConfig".to_owned(),
                errors: errs,
            }),
        }
    }
}

impl Step {
    /// Validates a step as `StepConfig.model_validate` does.
    pub fn from_value(v: &Value) -> Result<Step, HuntError> {
        let mut errs = Errors::new();
        match Step::validate(v, &[], &mut errs)? {
            Some(c) if errs.is_empty() => Ok(c),
            _ => Err(HuntError::Validation {
                title: "StepConfig".to_owned(),
                errors: errs,
            }),
        }
    }
}

impl Expression {
    /// Validates an expression as `ExpressionConfig.model_validate` does, a string as a Jinja one.
    pub fn from_value(v: &Value) -> Result<Expression, HuntError> {
        let mut errs = Errors::new();
        match Expression::validate(v, &[], &mut errs)? {
            Some(c) if errs.is_empty() => Ok(c),
            _ => Err(HuntError::Validation {
                title: "ExpressionConfig".to_owned(),
                errors: errs,
            }),
        }
    }
}

impl Action {
    /// Validates an action as `ActionConfig.model_validate` does, a string as its type.
    pub fn from_value(v: &Value) -> Result<Action, HuntError> {
        let mut errs = Errors::new();
        match Action::validate(v, &[], &mut errs)? {
            Some(c) if errs.is_empty() => Ok(c),
            _ => Err(HuntError::Validation {
                title: "ActionConfig".to_owned(),
                errors: errs,
            }),
        }
    }
}

impl Transform {
    /// Validates a transform as `TransformConfig.model_validate` does.
    pub fn from_value(v: &Value) -> Result<Transform, HuntError> {
        let mut errs = Errors::new();
        match Transform::validate(v, &[], &mut errs)? {
            Some(c) if errs.is_empty() => Ok(c),
            _ => Err(HuntError::Validation {
                title: "TransformConfig".to_owned(),
                errors: errs,
            }),
        }
    }
}

#[cfg(test)]
mod timespec_tests {
    use super::*;

    #[test]
    fn timespecs_parse_as_ace3s() {
        assert!(matches!(parse_timespec("1d 12h"), Ok(129_600)));
        assert!(matches!(parse_timespec("8h30m30s"), Ok(30_630)));
        assert!(matches!(parse_timespec("2Y"), Ok(63_072_000)));
        assert!(
            matches!(parse_timespec("soon"), Err(TimespecError::Invalid(m)) if m == "invalid timespec: 'soon'")
        );
    }
}
