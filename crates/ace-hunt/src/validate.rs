//! Validating loaded values into the hunt model as pydantic v2 does in its default (lax) mode,
//! collecting every error with the type, location and message pydantic gives it.
//!
//! A model's fields are validated in pydantic's order, each error at its location; keys the model
//! doesn't know are `extra_forbidden`, after the fields' errors, where ace3's model forbids extra
//! keys, as each of the hunt models does. A model's own checks (pydantic's after validators) run
//! only when its fields are valid, and fail as `value_error` at the model's location. A string
//! field takes only a string; a boolean takes pydantic's words for one (`yes`, `off`, `1`, ...) and
//! 0 or 1; an integer takes a whole float and a string of digits.

use serde_json::Value as Json;

use crate::HuntError;
use crate::value::{Map, Value};

/// One part of an error's location: a field or key, or a list index.
#[derive(Debug, Clone, PartialEq)]
pub enum Loc {
    Key(String),
    Index(usize),
    /// A dict key that isn't a string, such as an integer, as pydantic writes it.
    Value(Json),
}

impl Loc {
    pub fn to_json(&self) -> Json {
        match self {
            Loc::Key(k) => Json::String(k.clone()),
            Loc::Index(i) => Json::from(*i),
            Loc::Value(v) => v.clone(),
        }
    }

    /// A dict key in a location, as pydantic writes one: an integer stays one, anything else is
    /// its str().
    pub fn of_key(key: &Value) -> Loc {
        match key {
            Value::Str(s) => Loc::Key(s.clone()),
            Value::Int(i) => Loc::Value(crate::value::int_json(*i)),
            Value::Bool(b) => Loc::Value(Json::from(u8::from(*b))),
            other => Loc::Key(other.key_text()),
        }
    }
}

/// One of pydantic's errors.
#[derive(Debug, Clone, PartialEq)]
pub struct LineError {
    /// pydantic's error type, such as `missing` or `string_type`.
    pub kind: String,
    pub loc: Vec<Loc>,
    pub msg: String,
}

/// The result of validating a value: None when it failed and its errors were recorded, or
/// Err for an exception that isn't a validation error, which ends validation as it does in ace3.
pub type V<T> = Result<Option<T>, HuntError>;

/// Where errors are collected.
pub type Errors = Vec<LineError>;

pub fn push(errs: &mut Errors, loc: &[Loc], kind: &str, msg: impl Into<String>) {
    errs.push(LineError {
        kind: kind.to_owned(),
        loc: loc.to_vec(),
        msg: msg.into(),
    });
}

pub fn value_error(errs: &mut Errors, loc: &[Loc], msg: &str) {
    push(errs, loc, "value_error", format!("Value error, {msg}"));
}

pub fn child(loc: &[Loc], part: Loc) -> Vec<Loc> {
    let mut out = loc.to_vec();
    out.push(part);
    out
}

pub fn key(loc: &[Loc], name: &str) -> Vec<Loc> {
    child(loc, Loc::Key(name.to_owned()))
}

/// A `str` field.
pub fn string(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<String> {
    match v {
        Value::Str(s) => Ok(Some(s.clone())),
        _ => {
            push(errs, loc, "string_type", "Input should be a valid string");
            Ok(None)
        }
    }
}

/// An `Optional[str]` field.
pub fn opt_string(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Option<String>> {
    match v {
        Value::Null => Ok(Some(None)),
        other => Ok(string(other, loc, errs)?.map(Some)),
    }
}

/// A `bool` field.
pub fn boolean(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<bool> {
    let parsed = match v {
        Value::Bool(b) => Some(*b),
        Value::Int(0) => Some(false),
        Value::Int(1) => Some(true),
        Value::Float(f) if *f == 0.0 => Some(false),
        Value::Float(f) if *f == 1.0 => Some(true),
        Value::Str(s) => match s.to_lowercase().as_str() {
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            _ => None,
        },
        _ => None,
    };
    if parsed.is_none() {
        let (kind, msg) = match v {
            Value::Str(_) | Value::Int(_) => (
                "bool_parsing",
                "Input should be a valid boolean, unable to interpret input",
            ),
            _ => ("bool_type", "Input should be a valid boolean"),
        };
        push(errs, loc, kind, msg);
    }
    Ok(parsed)
}

/// An `Optional[bool]` field.
pub fn opt_boolean(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Option<bool>> {
    match v {
        Value::Null => Ok(Some(None)),
        other => Ok(boolean(other, loc, errs)?.map(Some)),
    }
}

/// An `int` field.
pub fn integer(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<i128> {
    let parse_failed = "Input should be a valid integer, unable to parse string as an integer";
    match v {
        Value::Int(i) => Ok(Some(*i)),
        Value::Bool(b) => Ok(Some(i128::from(*b))),
        Value::Float(f) if !f.is_finite() => {
            push(
                errs,
                loc,
                "finite_number",
                "Input should be a finite number",
            );
            Ok(None)
        }
        Value::Float(f) if f.fract() != 0.0 => {
            push(
                errs,
                loc,
                "int_from_float",
                "Input should be a valid integer, got a number with a fractional part",
            );
            Ok(None)
        }
        Value::Float(f) => Ok(Some(*f as i128)),
        Value::Str(s) => match parse_int_str(s) {
            Some(i) => Ok(Some(i)),
            None => {
                push(errs, loc, "int_parsing", parse_failed);
                Ok(None)
            }
        },
        _ => {
            push(errs, loc, "int_type", "Input should be a valid integer");
            Ok(None)
        }
    }
}

/// A string as pydantic reads an integer from it: surrounding whitespace, a sign, digits with
/// single underscores between them, and a fraction of zeros.
fn parse_int_str(s: &str) -> Option<i128> {
    let s = s.trim();
    let (whole, fraction) = s.split_once('.').unwrap_or((s, ""));
    if !fraction.chars().all(|c| c == '0') {
        return None;
    }
    let (sign, digits) = match whole.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, whole.strip_prefix('+').unwrap_or(whole)),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    digits
        .replace('_', "")
        .parse::<i128>()
        .ok()
        .map(|i| sign * i)
}

/// An `Optional[int]` field.
pub fn opt_integer(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Option<i128>> {
    match v {
        Value::Null => Ok(Some(None)),
        other => Ok(integer(other, loc, errs)?.map(Some)),
    }
}

/// A `list[...]` field: every item validated, each error at its index.
pub fn list<T>(
    v: &Value,
    loc: &[Loc],
    errs: &mut Errors,
    mut item: impl FnMut(&Value, &[Loc], &mut Errors) -> V<T>,
) -> V<Vec<T>> {
    let Value::Seq(items) = v else {
        push(errs, loc, "list_type", "Input should be a valid list");
        return Ok(None);
    };
    let mut out = Vec::with_capacity(items.len());
    let mut ok = true;
    for (i, value) in items.iter().enumerate() {
        match item(value, &child(loc, Loc::Index(i)), errs)? {
            Some(v) => out.push(v),
            None => ok = false,
        }
    }
    Ok(ok.then_some(out))
}

/// A `list[str]` field.
pub fn string_list(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Vec<String>> {
    list(v, loc, errs, string)
}

/// An `Optional[list[str]]` field.
pub fn opt_string_list(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<Option<Vec<String>>> {
    match v {
        Value::Null => Ok(Some(None)),
        other => Ok(string_list(other, loc, errs)?.map(Some)),
    }
}

/// A `dict[str, ...]` field, its values validated by `value`.
pub fn dict<T>(
    v: &Value,
    loc: &[Loc],
    errs: &mut Errors,
    mut value: impl FnMut(&Value, &[Loc], &mut Errors) -> V<T>,
) -> V<Vec<(String, T)>> {
    let Value::Map(map) = v else {
        push(errs, loc, "dict_type", "Input should be a valid dictionary");
        return Ok(None);
    };
    let mut out = Vec::with_capacity(map.len());
    let mut ok = true;
    for (k, item) in map.iter() {
        let key_loc = child(loc, Loc::of_key(k));
        let name = match k {
            Value::Str(s) => Some(s.clone()),
            _ => {
                push(
                    errs,
                    &child(&key_loc, Loc::Key("[key]".to_owned())),
                    "string_type",
                    "Input should be a valid string",
                );
                ok = false;
                None
            }
        };
        let validated = value(item, &key_loc, errs)?;
        match (name, validated) {
            (Some(name), Some(v)) => out.push((name, v)),
            _ => ok = false,
        }
    }
    Ok(ok.then_some(out))
}

/// A `dict[str, Any]` field, as JSON.
pub fn any_dict(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<serde_json::Map<String, Json>> {
    Ok(dict(v, loc, errs, |item, _, _| Ok(Some(item.to_json())))?
        .map(|pairs| pairs.into_iter().collect()))
}

/// A plain `dict` field, any keys, as JSON.
pub fn raw_dict(v: &Value, loc: &[Loc], errs: &mut Errors) -> V<serde_json::Map<String, Json>> {
    match v {
        Value::Map(_) => match v.to_json() {
            Json::Object(map) => Ok(Some(map)),
            _ => Ok(None),
        },
        _ => {
            push(errs, loc, "dict_type", "Input should be a valid dictionary");
            Ok(None)
        }
    }
}

/// A model's input: its fields taken one at a time, and the rest refused once they're done.
pub struct Obj<'a> {
    map: &'a Map,
    loc: Vec<Loc>,
    used: Vec<bool>,
    start: usize,
}

/// A field's value, if the input had one.
pub enum Field<T> {
    Missing,
    Invalid,
    Valid(T),
}

impl<'a> Obj<'a> {
    /// Starts validating `v` as the model `name`; a value that isn't a mapping is `model_type`.
    pub fn new(v: &'a Value, loc: &[Loc], name: &str, errs: &mut Errors) -> Option<Obj<'a>> {
        match v {
            Value::Map(map) => Some(Obj {
                map,
                loc: loc.to_vec(),
                used: vec![false; map.len()],
                start: errs.len(),
            }),
            _ => {
                push(
                    errs,
                    loc,
                    "model_type",
                    format!("Input should be a valid dictionary or instance of {name}"),
                );
                None
            }
        }
    }

    pub fn loc(&self) -> &[Loc] {
        &self.loc
    }

    /// The input's value for a field, marking it known.
    pub fn take(&mut self, name: &str) -> Option<&'a Value> {
        for (i, (k, v)) in self.map.iter().enumerate() {
            if matches!(k, Value::Str(s) if s == name) {
                self.used[i] = true;
                return Some(v);
            }
        }
        None
    }

    /// Validates a field with `f`.
    pub fn field<T>(
        &mut self,
        errs: &mut Errors,
        name: &str,
        f: impl FnOnce(&Value, &[Loc], &mut Errors) -> V<T>,
    ) -> Result<Field<T>, HuntError> {
        let Some(value) = self.take(name) else {
            return Ok(Field::Missing);
        };
        Ok(match f(value, &key(&self.loc, name), errs)? {
            Some(v) => Field::Valid(v),
            None => Field::Invalid,
        })
    }

    /// A required field: a missing one is `missing`.
    pub fn required<T>(
        &mut self,
        errs: &mut Errors,
        name: &str,
        f: impl FnOnce(&Value, &[Loc], &mut Errors) -> V<T>,
    ) -> Result<Option<T>, HuntError> {
        Ok(match self.field(errs, name, f)? {
            Field::Valid(v) => Some(v),
            Field::Invalid => None,
            Field::Missing => {
                push(errs, &key(&self.loc, name), "missing", "Field required");
                None
            }
        })
    }

    /// A field with a default.
    pub fn default<T>(
        &mut self,
        errs: &mut Errors,
        name: &str,
        default: T,
        f: impl FnOnce(&Value, &[Loc], &mut Errors) -> V<T>,
    ) -> Result<Option<T>, HuntError> {
        Ok(match self.field(errs, name, f)? {
            Field::Valid(v) => Some(v),
            Field::Invalid => None,
            Field::Missing => Some(default),
        })
    }

    /// Refuses the keys no field took, and says whether the model's fields are valid.
    pub fn finish(self, errs: &mut Errors) -> bool {
        for (i, (k, _)) in self.map.iter().enumerate() {
            if !self.used[i] {
                push(
                    errs,
                    &child(&self.loc, Loc::of_key(k)),
                    "extra_forbidden",
                    "Extra inputs are not permitted",
                );
            }
        }
        errs.len() == self.start
    }
}

/// pydantic's message for a value outside an enum's members.
pub fn enum_message(members: &[&str]) -> String {
    let quoted: Vec<String> = members.iter().map(|m| format!("'{m}'")).collect();
    match quoted.split_last() {
        Some((last, rest)) if !rest.is_empty() => {
            format!("Input should be {} or {last}", rest.join(", "))
        }
        _ => format!("Input should be {}", quoted.join("")),
    }
}

/// A string field that must be one of `members`.
pub fn one_of(v: &Value, loc: &[Loc], errs: &mut Errors, members: &[&str]) -> V<String> {
    match v {
        Value::Str(s) if members.contains(&s.as_str()) => Ok(Some(s.clone())),
        _ => {
            push(errs, loc, "enum", enum_message(members));
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_parse_from_strings_as_pydantic_does() {
        assert_eq!(parse_int_str("  5 "), Some(5));
        assert_eq!(parse_int_str("5.0"), Some(5));
        assert_eq!(parse_int_str("1_000"), Some(1000));
        assert_eq!(parse_int_str("+3"), Some(3));
        assert_eq!(parse_int_str("5.5"), None);
        assert_eq!(parse_int_str("0x10"), None);
        assert_eq!(parse_int_str("abc"), None);
    }

    #[test]
    fn enum_messages_read_as_pydantic_writes_them() {
        assert_eq!(
            enum_message(&["base64", "ascii_hex"]),
            "Input should be 'base64' or 'ascii_hex'"
        );
        assert_eq!(
            enum_message(&["a", "b", "c"]),
            "Input should be 'a', 'b' or 'c'"
        );
    }
}
