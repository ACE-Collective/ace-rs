//! `json.dumps` as Python writes it by default: `", "` and `": "` between items, every character
//! past ASCII escaped, NaN and the infinities as `NaN` and `Infinity`, and a dict's keys in their
//! order unless `sort_keys`. A correlation's command output is JSON lines written this way, and its
//! cache keys hash it, so a key is the one ace3 computes for the same arguments.

use serde_json::Value as Json;

use crate::render::json::quote;
use crate::render::py::float_repr;
use crate::value::{Map, Value};

/// `json.dumps(value, sort_keys=sort_keys)` of a loaded value.
pub fn dumps(value: &Value, sort_keys: bool) -> String {
    let mut out = String::new();
    loaded(value, sort_keys, &mut out);
    out
}

/// `json.dumps(value, sort_keys=sort_keys)` of a JSON value.
pub fn dumps_json(value: &Json, sort_keys: bool) -> String {
    let mut out = String::new();
    json(value, sort_keys, &mut out);
    out
}

/// `json.dumps` of a mapping.
pub fn dumps_map(map: &Map, sort_keys: bool) -> String {
    let mut out = String::new();
    object(map, sort_keys, &mut out);
    out
}

fn float(f: f64, out: &mut String) {
    if f.is_nan() {
        out.push_str("NaN");
    } else if f.is_infinite() {
        out.push_str(if f > 0.0 { "Infinity" } else { "-Infinity" });
    } else {
        out.push_str(&float_repr(f));
    }
}

/// A key as `json.dumps` writes a non-string one.
fn key_text(key: &Value) -> String {
    match key {
        Value::Str(s) => s.clone(),
        Value::Bool(true) => "true".to_owned(),
        Value::Bool(false) => "false".to_owned(),
        Value::Null => "null".to_owned(),
        Value::Float(f) => {
            let mut s = String::new();
            float(*f, &mut s);
            s
        }
        other => other.key_text(),
    }
}

fn loaded(value: &Value, sort_keys: bool, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(f) => float(*f, out),
        Value::Str(s) | Value::Date(s) | Value::DateTime(s) => quote(s, out),
        Value::Seq(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                loaded(item, sort_keys, out);
            }
            out.push(']');
        }
        Value::Map(map) => object(map, sort_keys, out),
    }
}

fn object(map: &Map, sort_keys: bool, out: &mut String) {
    let mut entries: Vec<(String, &Value)> = map.iter().map(|(k, v)| (key_text(k), v)).collect();
    if sort_keys {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
    }
    out.push('{');
    for (i, (k, v)) in entries.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        quote(k, out);
        out.push_str(": ");
        loaded(v, sort_keys, out);
    }
    out.push('}');
}

fn json(value: &Json, sort_keys: bool, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => out.push_str(&i.to_string()),
            (None, Some(u)) => out.push_str(&u.to_string()),
            _ => float(n.as_f64().unwrap_or(f64::NAN), out),
        },
        Json::String(s) => quote(s, out),
        Json::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                json(item, sort_keys, out);
            }
            out.push(']');
        }
        Json::Object(map) => {
            let mut entries: Vec<(&String, &Json)> = map.iter().collect();
            if sort_keys {
                entries.sort_by(|a, b| a.0.cmp(b.0));
            }
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                quote(k, out);
                out.push_str(": ");
                json(v, sort_keys, out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_is_written_as_python_writes_it() {
        let mut ordered = Map::new();
        ordered.insert(
            Value::str("b"),
            crate::query::extract::to_loaded(&json!([1, 2.5, "\u{e9}"])),
        );
        ordered.insert(Value::str("a"), Value::Null);
        assert_eq!(
            dumps_map(&ordered, false),
            "{\"b\": [1, 2.5, \"\\u00e9\"], \"a\": null}"
        );
        assert_eq!(
            dumps_json(&json!({"b": 1, "a": true}), true),
            r#"{"a": true, "b": 1}"#
        );
        let mut m = Map::new();
        m.insert(Value::Int(1), Value::Float(f64::NAN));
        assert_eq!(dumps_map(&m, false), r#"{"1": NaN}"#);
    }
}
