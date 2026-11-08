//! A YAML value as PyYAML's SafeLoader builds it, with the parts of Python's semantics the loader
//! and the validation lean on: equality where `1 == 1.0 == True`, a type's name, a string's
//! `repr`, and what iterating a value gives.

use serde_json::{Map as JsonMap, Number, Value as Json};

/// A value from a hunt file.
#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    /// A plain scalar PyYAML resolves as a date, kept as its text.
    Date(String),
    /// A plain scalar PyYAML resolves as a datetime, kept as its text.
    DateTime(String),
    Seq(Vec<Value>),
    Map(Map),
}

/// A mapping in the order its keys first appeared, as a Python dict keeps them.
#[derive(Debug, Clone, Default)]
pub struct Map(Vec<(Value, Value)>);

impl Map {
    pub fn new() -> Map {
        Map(Vec::new())
    }

    /// Sets `key`, keeping the position of an equal key already there, as a dict does.
    pub fn insert(&mut self, key: Value, value: Value) {
        match self.0.iter_mut().find(|(k, _)| py_eq(k, &key)) {
            Some(entry) => entry.1 = value,
            None => self.0.push((key, value)),
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
            .map(|(_, v)| v)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.0
            .iter_mut()
            .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
            .map(|(_, v)| v)
    }

    pub fn get_value(&self, key: &Value) -> Option<&Value> {
        self.0.iter().find(|(k, _)| py_eq(k, key)).map(|(_, v)| v)
    }

    pub fn get_value_mut(&mut self, key: &Value) -> Option<&mut Value> {
        self.0
            .iter_mut()
            .find(|(k, _)| py_eq(k, key))
            .map(|(_, v)| v)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let index = self
            .0
            .iter()
            .position(|(k, _)| matches!(k, Value::Str(s) if s == key))?;
        Some(self.0.remove(index).1)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Value, &Value)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Value {
    pub fn str(text: &str) -> Value {
        Value::Str(text.to_owned())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&Map> {
        match self {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }

    /// The name of the value's Python type, as an AttributeError or TypeError names it.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "NoneType",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::Date(_) => "datetime.date",
            Value::DateTime(_) => "datetime.datetime",
            Value::Seq(_) => "list",
            Value::Map(_) => "dict",
        }
    }

    /// Python's truth value.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Date(_) | Value::DateTime(_) => true,
            Value::Seq(items) => !items.is_empty(),
            Value::Map(map) => !map.is_empty(),
        }
    }

    /// What `for item in value` gives: a list's items, a dict's keys, a string's characters, or
    /// Python's TypeError for anything else.
    pub fn py_iter(&self) -> Result<Vec<Value>, String> {
        match self {
            Value::Seq(items) => Ok(items.clone()),
            Value::Map(map) => Ok(map.iter().map(|(k, _)| k.clone()).collect()),
            Value::Str(s) => Ok(s.chars().map(|c| Value::Str(c.to_string())).collect()),
            other => Err(format!("'{}' object is not iterable", other.type_name())),
        }
    }

    /// How many nodes the value holds, counting itself.
    pub fn nodes(&self) -> usize {
        match self {
            Value::Seq(items) => 1 + items.iter().map(Value::nodes).sum::<usize>(),
            Value::Map(map) => {
                1 + map
                    .iter()
                    .map(|(k, v)| k.nodes() + v.nodes())
                    .sum::<usize>()
            }
            _ => 1,
        }
    }

    /// The bytes of text the value holds.
    pub fn text_bytes(&self) -> usize {
        match self {
            Value::Str(s) | Value::Date(s) | Value::DateTime(s) => s.len(),
            Value::Seq(items) => items.iter().map(Value::text_bytes).sum(),
            Value::Map(map) => map
                .iter()
                .map(|(k, v)| k.text_bytes() + v.text_bytes())
                .sum(),
            _ => 8,
        }
    }

    /// The value as pydantic's `model_dump(mode="json")` writes a field typed `Any`.
    pub fn to_json(&self) -> Json {
        match self {
            Value::Null => Json::Null,
            Value::Bool(b) => Json::Bool(*b),
            Value::Int(i) => int_json(*i),
            Value::Float(f) => Number::from_f64(*f).map_or(Json::Null, Json::Number),
            Value::Str(s) => Json::String(s.clone()),
            Value::Date(s) => Json::String(s.clone()),
            Value::DateTime(s) => Json::String(datetime_iso(s)),
            Value::Seq(items) => Json::Array(items.iter().map(Value::to_json).collect()),
            Value::Map(map) => {
                let mut out = JsonMap::new();
                for (k, v) in map.iter() {
                    out.insert(k.key_text(), v.to_json());
                }
                Json::Object(out)
            }
        }
    }

    /// A dict key as JSON writes it: Python's str() of anything but a string.
    pub fn key_text(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Null => "None".to_owned(),
            Value::Bool(true) => "True".to_owned(),
            Value::Bool(false) => "False".to_owned(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => py_float_repr(*f),
            Value::Date(s) => s.clone(),
            Value::DateTime(s) => datetime_iso(s),
            Value::Seq(_) | Value::Map(_) => "<unhashable>".to_owned(),
        }
    }
}

pub fn int_json(i: i128) -> Json {
    if let Ok(small) = i64::try_from(i) {
        Json::Number(small.into())
    } else if let Ok(unsigned) = u64::try_from(i) {
        Json::Number(unsigned.into())
    } else {
        Number::from_f64(i as f64).map_or(Json::Null, Json::Number)
    }
}

/// Python's equality between two loaded values.
pub fn py_eq(a: &Value, b: &Value) -> bool {
    use Value::*;
    match (a, b) {
        (Null, Null) => true,
        (Str(x), Str(y)) => x == y,
        (Date(x), Date(y)) | (DateTime(x), DateTime(y)) => x == y,
        (Seq(x), Seq(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q)),
        (Map(x), Map(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get_value(k).is_some_and(|w| py_eq(v, w)))
        }
        _ => match (number(a), number(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        },
    }
}

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

/// Python's `repr` of a string.
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if !is_printable(c) => {
                let n = c as u32;
                if n < 0x100 {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n < 0x10000 {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python's `str.isprintable()` for one character: not a control, format, separator other than
/// the space, surrogate, private-use or noncharacter. Python also counts unassigned code points
/// as unprintable, which needs Unicode's tables; this doesn't, so a character Unicode hasn't
/// assigned prints as itself here where Python escapes it.
pub fn is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    let n = c as u32;
    !(c.is_control()
        || c.is_whitespace()
        || matches!(n,
            0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2 | 0x180e
            | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f | 0xfeff
            | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x1343f | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f
            | 0xe000..=0xf8ff | 0xf0000..=0xffffd | 0x100000..=0x10fffd
            | 0xfdd0..=0xfdef | 0xfffe..=0xffff))
}

/// Python's `repr` of a float.
pub fn py_float_repr(f: f64) -> String {
    crate::render::py::float_repr(f)
}

/// A YAML timestamp in the form Python's `datetime.isoformat()` writes it.
fn datetime_iso(text: &str) -> String {
    // 2001-12-14t21:59:43.10-05:00, 2001-12-14 21:59:43.10 -5, 2001-12-15 2:59:43.10
    let text = text.trim();
    let (date, rest) = text.split_at(text.len().min(10));
    let rest = rest.trim_start_matches(['T', 't', ' ', '\t']);
    let time_end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == ':' || c == '.'))
        .unwrap_or(rest.len());
    let (time, zone) = rest.split_at(time_end);
    let (hms, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut parts = hms.split(':');
    let hour: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minute = parts.next().unwrap_or("00");
    let second = parts.next().unwrap_or("00");
    let mut out = format!("{date}T{hour:02}:{minute}:{second}");
    if !fraction.is_empty() {
        let mut micro: String = fraction.chars().take(6).collect();
        while micro.len() < 6 {
            micro.push('0');
        }
        if micro != "000000" {
            out.push('.');
            out.push_str(&micro);
        }
    }
    let zone = zone.trim();
    if zone == "Z" {
        out.push_str("+00:00");
    } else if !zone.is_empty() {
        let sign = &zone[..1];
        let (h, m) = zone[1..].split_once(':').unwrap_or((&zone[1..], "00"));
        let h: u32 = h.parse().unwrap_or(0);
        out.push_str(&format!("{sign}{h:02}:{m}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_follows_python() {
        assert!(py_eq(&Value::Int(1), &Value::Bool(true)));
        assert!(py_eq(&Value::Int(1), &Value::Float(1.0)));
        assert!(!py_eq(&Value::str("1"), &Value::Int(1)));
    }

    #[test]
    fn repr_follows_python() {
        assert_eq!(py_repr("soon"), "'soon'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("a\nb"), "'a\\nb'");
    }

    #[test]
    fn a_datetime_is_written_as_isoformat() {
        assert_eq!(
            datetime_iso("2001-12-14t21:59:43.10-05:00"),
            "2001-12-14T21:59:43.100000-05:00"
        );
        assert_eq!(datetime_iso("2001-12-15 2:59:43"), "2001-12-15T02:59:43");
    }
}
