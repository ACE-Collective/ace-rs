//! What hunt validation checks of a correlation beyond its schema (`validation.py`), which the
//! `hunt` router's validation runs and loading doesn't: a template that reads `_secrets` or
//! `_config`, which no correlation template has, and a custom command type that isn't registered,
//! failed to build, is cached when it can't be, or has options its model refuses.

use serde_json::{Map as JsonMap, Value as Json};

use super::command::CommandTypes;
use super::{
    Action, BUILTIN_COMMAND_TYPES, Command, CommandTimeRange, Correlate, Expression, MergeTimeSpec,
    PredefinedCommand, Step, StepKind, Transform, commands,
};
use crate::HuntError;
use crate::query::extract::to_loaded;
use crate::validate::Loc;
use crate::value::{Value, py_repr};

/// The names hunt templates once had and no longer do.
const REMOVED: [&str; 2] = ["_config", "_secrets"];

fn is_template(value: &str) -> bool {
    value.contains("{{") || value.contains("{%")
}

/// `_iter_strings`: every string a model holds, in its fields' order, but `description` and
/// `source_options`, which are never rendered.
#[derive(Default)]
struct Strings<'a>(Vec<&'a str>);

impl<'a> Strings<'a> {
    fn s(&mut self, v: &'a str) {
        self.0.push(v);
    }
    fn o(&mut self, v: &'a Option<String>) {
        if let Some(v) = v {
            self.0.push(v);
        }
    }
    fn json(&mut self, v: &'a Json) {
        match v {
            Json::String(s) => self.0.push(s),
            Json::Array(items) => items.iter().for_each(|i| self.json(i)),
            Json::Object(map) => map.values().for_each(|i| self.json(i)),
            _ => {}
        }
    }
    fn map(&mut self, m: &'a JsonMap<String, Json>) {
        m.values().for_each(|v| self.json(v));
    }
    fn list(&mut self, l: &'a Option<Vec<String>>) {
        l.iter().flatten().for_each(|s| self.0.push(s));
    }
    fn env(&mut self, e: &'a Option<Vec<(String, String)>>) {
        e.iter().flatten().for_each(|(_, v)| self.0.push(v));
    }
    fn range(&mut self, r: &'a Option<CommandTimeRange>) {
        if let Some(r) = r {
            self.o(&r.before);
            self.o(&r.after);
            self.o(&r.relative_time_field);
            self.o(&r.relative_time_format);
        }
    }
    fn merge(&mut self, m: &'a Option<MergeTimeSpec>) {
        if let Some(m) = m {
            self.s(&m.l_field);
            self.s(&m.l_format);
            self.s(&m.r_field);
            self.s(&m.r_format);
        }
    }
    fn correlate(&mut self, c: &'a Correlate) {
        self.s(&c.timeout);
        self.steps(&c.logic);
    }
    fn steps(&mut self, steps: &'a [Step]) {
        for step in steps {
            match &step.step {
                StepKind::Condition(c) => {
                    self.expression(&c.when);
                    self.steps(&c.execute);
                    if let Some(o) = &c.otherwise {
                        self.steps(o);
                    }
                }
                StepKind::Transform(t) => self.transform(t),
                StepKind::Action(a) => self.action(a),
            }
            self.o(&step.debug);
        }
    }
    fn expression(&mut self, e: &'a Expression) {
        self.s(&e.kind);
        self.json(&e.value);
        self.o(&e.property);
    }
    fn transform(&mut self, t: &'a Transform) {
        self.s(&t.kind);
        self.s(&t.method);
        self.o(&t.property_name);
        self.s(&t.property_type);
        self.merge(&t.merge_time_spec);
        self.command(&t.command);
    }
    fn action(&mut self, a: &'a Action) {
        self.s(&a.kind);
        self.o(&a.queue);
        self.o(&a.analysis_mode);
        self.s(&a.log_level);
        self.o(&a.log_message);
    }
    fn command(&mut self, c: &'a Command) {
        self.s(&c.kind);
        self.s(&c.timeout);
        self.o(&c.cache);
        self.o(&c.source);
        self.o(&c.query);
        self.range(&c.time_range);
        self.o(&c.path);
        self.list(&c.args);
        self.env(&c.env);
        self.list(&c.files);
        self.o(&c.name);
        if let Some(a) = &c.arguments {
            self.map(a);
        }
        self.map(&c.options);
    }
    fn predefined(&mut self, c: &'a PredefinedCommand) {
        self.s(&c.name);
        self.s(&c.kind);
        self.s(&c.timeout);
        self.o(&c.cache);
        self.o(&c.source);
        self.o(&c.query);
        self.range(&c.time_range);
        self.o(&c.path);
        self.list(&c.args);
        self.env(&c.env);
        self.list(&c.files);
        self.map(&c.options);
    }
}

/// The variables a template reads that it doesn't set, or None when it doesn't parse.
fn undeclared(template: &str) -> Option<Vec<String>> {
    let mut env = minijinja::Environment::empty();
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Lenient);
    let t = env.template_from_str(template).ok()?;
    Some(t.undeclared_variables(false).into_iter().collect())
}

/// `check_templates_for_removed_names`: one error per template that reads `_secrets` or
/// `_config`, each once.
pub fn removed_names(
    correlate: Option<&Correlate>,
    predefined: Option<&[PredefinedCommand]>,
) -> Vec<String> {
    let mut sources: Vec<(String, Strings<'_>)> = Vec::new();
    if let Some(c) = correlate {
        let mut s = Strings::default();
        s.correlate(c);
        sources.push(("correlate".to_owned(), s));
    }
    for c in predefined.into_iter().flatten() {
        let mut s = Strings::default();
        s.predefined(c);
        sources.push((format!("predefined command {}", py_repr(&c.name)), s));
    }
    let mut errors: Vec<String> = Vec::new();
    for (label, strings) in &sources {
        for value in &strings.0 {
            if !is_template(value) {
                continue;
            }
            let Some(names) = undeclared(value) else {
                continue;
            };
            let removed: Vec<&str> = REMOVED
                .into_iter()
                .filter(|n| names.iter().any(|m| m == n))
                .collect();
            if removed.is_empty() {
                continue;
            }
            let error = format!(
                "{label}: template {} references {}. Hunts have no access to secrets or configuration; a command that needs a credential must be a custom command type that reads it from its integration's configuration.",
                py_repr(value),
                removed.join(", ")
            );
            if !errors.contains(&error) {
                errors.push(error);
            }
        }
    }
    errors
}

/// The value at an error's location in the options, or the last container on the way.
fn input_at<'a>(options: &'a Value, loc: &[Loc]) -> &'a Value {
    let mut at = options;
    for part in loc {
        let next = match (at, part) {
            (Value::Map(m), Loc::Key(k)) => m.get(k),
            (Value::Seq(items), Loc::Index(i)) => items.get(*i),
            _ => None,
        };
        match next {
            Some(v) => at = v,
            None => break,
        }
    }
    at
}

/// `_check_custom_command`: the problems with one custom-typed command on this node.
fn check_custom(
    label: &str,
    kind: &str,
    cache: Option<&str>,
    options: &JsonMap<String, Json>,
    types: &CommandTypes,
) -> Vec<String> {
    let handler = match types.get(kind) {
        Ok(h) => h,
        Err(_) => {
            if let Some(error) = types.load_errors().get(kind) {
                return vec![format!(
                    "{label}: command type {} failed to load on this node: {error}",
                    py_repr(kind)
                )];
            }
            let mut known: Vec<&str> = BUILTIN_COMMAND_TYPES.to_vec();
            known.extend(types.names());
            known.sort_unstable();
            known.dedup();
            return vec![format!(
                "{label}: unknown command type {} (known types: {})",
                py_repr(kind),
                known.join(", ")
            )];
        }
    };
    let mut errors = Vec::new();
    if cache.is_some_and(|c| !c.is_empty()) && !handler.cacheable() {
        errors.push(format!(
            "{label}: command type {} is not cacheable; remove 'cache'",
            py_repr(kind)
        ));
    }
    if !handler.has_options() {
        if !options.is_empty() {
            let mut keys: Vec<&String> = options.keys().collect();
            keys.sort();
            let keys: Vec<String> = keys.iter().map(|k| py_repr(k)).collect();
            errors.push(format!(
                "{label}: command type {} takes no options, got [{}]",
                py_repr(kind),
                keys.join(", ")
            ));
        }
        return errors;
    }
    let raw = to_loaded(&Json::Object(options.clone()));
    if let Err(HuntError::Validation { errors: found, .. }) = handler.validate_options(&raw) {
        for error in found {
            // a template is judged once it has rendered against an event, at run time
            if handler.render_options()
                && let Value::Str(s) = input_at(&raw, &error.loc)
                && is_template(s)
                && !error.loc.is_empty()
            {
                continue;
            }
            let location: Vec<String> = error
                .loc
                .iter()
                .map(|l| match l.to_json() {
                    Json::String(s) => s,
                    other => other.to_string(),
                })
                .collect();
            let location = if location.is_empty() {
                "options".to_owned()
            } else {
                location.join(".")
            };
            errors.push(format!("{label}: options.{location}: {}", error.msg));
        }
    }
    errors
}

/// `check_custom_command_types`: one error per problem with a custom command type, a `defined`
/// command checked as what it resolves to with its `arguments`, each problem once.
pub fn custom_command_types(
    correlate: Option<&Correlate>,
    predefined: Option<&[PredefinedCommand]>,
    types: &CommandTypes,
) -> Vec<String> {
    let predefined = predefined.unwrap_or_default();
    let mut errors: Vec<String> = Vec::new();
    for c in predefined {
        if !BUILTIN_COMMAND_TYPES.contains(&c.kind.as_str()) {
            errors.extend(check_custom(
                &format!("predefined command {}", py_repr(&c.name)),
                &c.kind,
                c.cache.as_deref(),
                &c.options,
                types,
            ));
        }
    }
    if let Some(correlate) = correlate {
        for command in commands(&correlate.logic) {
            if command.kind == "defined" {
                let name = command.name.clone().unwrap_or_default();
                // a dict by name: the last of a name wins
                let Some(p) = predefined.iter().rev().find(|p| p.name == name) else {
                    continue;
                };
                let arguments = command.arguments.as_ref().filter(|a| !a.is_empty());
                if BUILTIN_COMMAND_TYPES.contains(&p.kind.as_str()) || arguments.is_none() {
                    continue;
                }
                let label = format!("defined command {}", py_repr(&name));
                match p.to_command(arguments) {
                    Ok(effective) => errors.extend(check_custom(
                        &label,
                        &effective.kind,
                        effective.cache.as_deref(),
                        &effective.options,
                        types,
                    )),
                    Err(e) => errors.push(format!("{label}: {e}")),
                }
            } else if !BUILTIN_COMMAND_TYPES.contains(&command.kind.as_str()) {
                errors.extend(check_custom(
                    &format!("command {}", py_repr(&command.kind)),
                    &command.kind,
                    command.cache.as_deref(),
                    &command.options,
                    types,
                ));
            }
        }
    }
    let mut unique = Vec::new();
    for e in errors {
        if !unique.contains(&e) {
            unique.push(e);
        }
    }
    unique
}
