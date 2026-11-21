//! `field_values`, ace4's own example of a script command type (PLAN.md decision 16). No hunt of
//! ace4's runs it; it shows a site how one is written and registered (`ace_app::App::hunt_script`,
//! as `ace-site-example` registers this one), and the tests of the mechanism use it.
//!
//! It stands for a script `hunts/scripts/field_values.py` that a hunt runs as `type: executable`
//! with `stdin: true`: it reads the events as JSON lines on stdin and prints, as JSON, how many have
//! the field `--field` names and that field's distinct values, as Python's `str()` writes them, in
//! the order first seen, at most `--limit` of them. Its settings in the hunter's configuration
//! (`scripts.field_values`) may set the default limit, which is otherwise 100.

use std::sync::Arc;

use serde::Deserialize;

use super::argparse::{Kind, Opt, int, parse};
use super::{dict, loads, no_attribute, print_json, py_str, raised, s, strings, strip};
use crate::correlate::script::{Script, ScriptCall, ScriptExit};
use crate::value::Value;

/// The script's path, as a hunt's command would name it.
pub const SUFFIX: &str = "hunts/scripts/field_values.py";
/// The type's name.
pub const NAME: &str = "field_values";
/// The limit when neither `--limit` nor the settings give one.
pub const DEFAULT_LIMIT: i64 = 100;

const PROG: &str = "field_values.py";
const OPTS: [Opt; 2] = [
    Opt::new("--field", Kind::One).short("-f").required(),
    Opt::new("--limit", Kind::One),
];

/// The type's settings, `scripts.field_values` in the hunter's configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The limit when a command gives no `--limit`.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// The type.
pub struct FieldValues {
    pub settings: Settings,
}

/// Builds the type with its settings (`Value::Null` for none), or why it can't be built.
pub fn build(settings: &serde_json::Value) -> Result<Arc<dyn Script>, String> {
    let settings = if settings.is_null() {
        Settings::default()
    } else {
        serde_json::from_value(settings.clone()).map_err(|e| format!("{NAME}'s settings: {e}"))?
    };
    Ok(Arc::new(FieldValues { settings }))
}

impl Script for FieldValues {
    fn run(&self, call: &ScriptCall<'_>) -> Result<String, ScriptExit> {
        let args = parse(PROG, &OPTS, call.argv)?;
        let field = args.one("--field").unwrap_or_default();
        let limit = match args.one("--limit") {
            Some(text) => int(PROG, "--limit", text)?,
            None => self.settings.limit.unwrap_or(DEFAULT_LIMIT),
        };
        let mut count: i128 = 0;
        let mut values: Vec<String> = Vec::new();
        for line in call.stdin.unwrap_or_default().lines() {
            let line = strip(line);
            if line.is_empty() {
                continue;
            }
            let event = loads(line).map_err(|e| raised("json.JSONDecodeError", &e.message))?;
            let Value::Map(event) = &event else {
                return Err(no_attribute(&event, "get"));
            };
            if let Some(value) = event.get(field) {
                count += 1;
                let text = py_str(value);
                if !values.contains(&text)
                    && i64::try_from(values.len()).unwrap_or(i64::MAX) < limit
                {
                    values.push(text);
                }
            }
        }
        Ok(print_json(&Value::Map(dict([
            ("field", s(field)),
            ("count", Value::Int(count)),
            ("values", strings(values)),
        ]))))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use chrono::NaiveDate;
    use serde_json::json;

    use super::*;
    use crate::correlate::script::Staged;

    fn run(settings: serde_json::Value, argv: &[&str], stdin: &str) -> Result<String, ScriptExit> {
        let argv: Vec<String> = argv.iter().map(|a| (*a).to_owned()).collect();
        build(&settings).expect("builds").run(&ScriptCall {
            argv: &argv,
            stdin: Some(stdin),
            env: &[],
            files: &Staged::default(),
            deadline: Instant::now() + Duration::from_secs(60),
            today: NaiveDate::from_ymd_opt(2026, 11, 21).expect("a date"),
        })
    }

    const EVENTS: &str =
        "{\"host\": \"a\", \"n\": 1}\n\n{\"host\": \"b\"}\n{\"n\": 2}\n{\"host\": \"a\"}\n";

    #[test]
    fn it_counts_a_field_and_lists_its_distinct_values() {
        assert_eq!(
            run(serde_json::Value::Null, &["--field", "host"], EVENTS).expect("runs"),
            "{\"field\": \"host\", \"count\": 3, \"values\": [\"a\", \"b\"]}\n"
        );
        assert_eq!(
            run(
                serde_json::Value::Null,
                &["-f", "n", "--limit", "1"],
                EVENTS
            )
            .expect("runs"),
            "{\"field\": \"n\", \"count\": 2, \"values\": [\"1\"]}\n"
        );
        // the settings' limit, when the command gives none
        assert_eq!(
            run(json!({"limit": 0}), &["--field", "host"], EVENTS).expect("runs"),
            "{\"field\": \"host\", \"count\": 3, \"values\": []}\n"
        );
    }

    #[test]
    fn it_fails_as_the_script_would() {
        let usage = run(serde_json::Value::Null, &[], EVENTS).expect_err("no --field");
        assert_eq!(usage.code, 2, "argparse's usage error: {}", usage.stderr);
        let bad = run(
            serde_json::Value::Null,
            &["-f", "x", "--limit", "many"],
            EVENTS,
        )
        .expect_err("not an int");
        assert!(bad.stderr.contains("invalid int value"), "{}", bad.stderr);
        let broken = run(serde_json::Value::Null, &["-f", "x"], "{not json").expect_err("broken");
        assert_eq!(broken.code, 1);
        let list = run(serde_json::Value::Null, &["-f", "x"], "[1]").expect_err("a list");
        assert!(list.stderr.contains("AttributeError"), "{}", list.stderr);
    }

    #[test]
    fn its_settings_are_checked_when_it_is_built() {
        assert!(build(&json!({})).is_ok());
        let refused = build(&json!({"lmit": 3})).err().expect("refused");
        assert!(refused.starts_with("field_values's settings"), "{refused}");
    }
}
