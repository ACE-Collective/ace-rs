//! What urlfinderlib does with `json.loads`, on `ace-pycompat`'s port.

use ace_pycompat::json::{self, Value};

use crate::py::{PyErr, PyResult};

/// `_json_strings`' parse: the document's strings, keys included, in the order its stack takes
/// them, or None where `json.loads` raises ValueError or RecursionError.
pub fn strings(text: &str) -> PyResult<Option<Vec<String>>> {
    let document = match json::loads(text) {
        Ok(document) => document,
        Err(e)
            if e.is_instance("builtins", "ValueError")
                || e.is_instance("builtins", "RecursionError") =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let mut strings = Vec::new();
    let mut stack = vec![&document];
    while let Some(value) = stack.pop() {
        match value {
            Value::Str(s) => strings.push(s.as_str().to_owned()),
            Value::Object(members) => {
                strings.extend(members.iter().map(|(k, _)| k.as_str().to_owned()));
                stack.extend(members.iter().map(|(_, v)| v));
            }
            Value::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
    Ok(Some(strings))
}

/// `except (json.JSONDecodeError, UnicodeDecodeError)` as `decode_mandrillapp` has it.
fn caught(e: &PyErr) -> bool {
    e.is_instance("json.decoder", "JSONDecodeError")
        || e.is_instance("builtins", "UnicodeDecodeError")
}

/// `json.loads(bytes)`, None for what `decode_mandrillapp` catches.
pub fn loads_bytes(bytes: &[u8]) -> PyResult<Option<Value>> {
    match json::loads_bytes(bytes) {
        Ok(value) => Ok(Some(value)),
        Err(e) if caught(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `json.loads(value)` of a JSON string, None for what `decode_mandrillapp` catches.
pub fn loads_value_str(value: &Value) -> PyResult<Option<Value>> {
    let Some(s) = value.as_json_str() else {
        // json.loads of anything but str or bytes: TypeError, caught
        return Ok(None);
    };
    match json::loads_str(s) {
        Ok(value) => Ok(Some(value)),
        Err(e) if caught(&e) => Ok(None),
        Err(e) => Err(e),
    }
}
