//! What a script command type (PLAN.md decision 16) is written with: Python's `argparse` as a
//! script's parser reads its arguments ([`argparse`]), `json.loads` and `json.dumps` as a script
//! reads and prints JSON, and Python's `str()`, `repr()` and `str.strip()` of a loaded value. A site
//! writes its types with these and registers each with `ace_app::App::hunt_script` under its
//! script's path; ace4 has no site's scripts (owner, 2026-11-21). [`example`] is ace4's own, a small
//! type no hunt of ace4's runs, which `ace-site-example` registers and the tests of the mechanism
//! use.
//!
//! A type writes what its script prints: JSON as Python's `json.dumps` writes it, with the
//! script's keys in the script's order. It holds only its script's logic, never detection content
//! (decision 16): content comes from the signatures checkout at run time, as the files a command
//! stages, or from the hunter's configuration (`scripts.<name>`).

pub mod argparse;
pub mod example;

use super::pyjson;
use super::script::ScriptExit;
use crate::value::{Map, Value, py_repr};

/// `print(json.dumps(value))`.
pub fn print_json(value: &Value) -> String {
    let mut out = pyjson::dumps(value, false);
    out.push('\n');
    out
}

/// A string value.
pub fn s(text: impl Into<String>) -> Value {
    Value::Str(text.into())
}

/// A list of strings.
pub fn strings<I: IntoIterator<Item = S>, S: Into<String>>(items: I) -> Value {
    Value::Seq(items.into_iter().map(|i| Value::Str(i.into())).collect())
}

/// Sets `key` in `map`, keeping its place if it's there, as `d[key] = value` does.
pub fn set(map: &mut Map, key: &str, value: Value) {
    map.insert(Value::Str(key.to_owned()), value);
}

/// A dict from pairs, in order.
pub fn dict<const N: usize>(pairs: [(&str, Value); N]) -> Map {
    let mut map = Map::new();
    for (k, v) in pairs {
        set(&mut map, k, v);
    }
    map
}

/// `str.strip()`, by Python's whitespace.
pub fn strip(text: &str) -> &str {
    text.trim_matches(crate::render::methods::is_space)
}

/// Python's `str()` of a loaded value.
pub fn py_str(value: &Value) -> String {
    match value {
        Value::Str(s) => s.clone(),
        other => py_repr_value(other),
    }
}

/// Python's `repr()` of a loaded value.
pub fn py_repr_value(value: &Value) -> String {
    match value {
        Value::Str(s) | Value::Date(s) | Value::DateTime(s) => py_repr(s),
        Value::Seq(items) => format!(
            "[{}]",
            items
                .iter()
                .map(py_repr_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Map(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{}: {}", py_repr_value(k), py_repr_value(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        other => other.key_text(),
    }
}

/// `json.loads` of text, as a loaded value.
pub fn loads(text: &str) -> Result<Value, ace_pycompat::PyErr> {
    ace_pycompat::json::loads(text).map(|v| from_pycompat(&v))
}

/// `json.loads` of bytes, which reads UTF-8, UTF-16 or UTF-32 as Python detects it.
pub fn loads_bytes(bytes: &[u8]) -> Result<Value, ace_pycompat::PyErr> {
    ace_pycompat::json::loads_bytes(bytes).map(|v| from_pycompat(&v))
}

fn from_pycompat(value: &ace_pycompat::json::Value) -> Value {
    use ace_pycompat::json::Value as P;
    match value {
        P::Null => Value::Null,
        P::Bool(b) => Value::Bool(*b),
        P::Int(text) => text
            .parse::<i128>()
            .map(Value::Int)
            .unwrap_or_else(|_| Value::Float(text.parse().unwrap_or(f64::INFINITY))),
        P::Float(f) => Value::Float(*f),
        P::Str(s) => Value::Str(s.as_str().to_owned()),
        P::Array(items) => Value::Seq(items.iter().map(from_pycompat).collect()),
        P::Object(members) => {
            let mut map = Map::new();
            for (k, v) in members {
                map.insert(Value::Str(k.as_str().to_owned()), from_pycompat(v));
            }
            Value::Map(map)
        }
    }
}

/// An uncaught exception's exit, `Traceback ...` and its last line.
pub fn raised(kind: &str, message: &str) -> ScriptExit {
    ScriptExit::raised(kind, message)
}

/// `AttributeError: '<type>' object has no attribute '<name>'`.
pub fn no_attribute(value: &Value, name: &str) -> ScriptExit {
    raised(
        "AttributeError",
        &format!("'{}' object has no attribute '{name}'", value.type_name()),
    )
}

/// `value == number` in Python, for a JSON value.
pub fn equals_int(value: &Value, number: i128) -> bool {
    match value {
        Value::Bool(b) => i128::from(*b) == number,
        Value::Int(i) => *i == number,
        Value::Float(f) => *f == number as f64,
        _ => false,
    }
}
