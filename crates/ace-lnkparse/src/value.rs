//! The Python values `get_json` returns, and the two ways ace3 writes them as JSON.

/// An aware `datetime` in UTC (`tzinfo=timezone.utc`), the only kind LnkParse3 makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub microsecond: u32,
}

impl DateTime {
    /// `strftime('%Y-%m-%dT%H:%M:%S.%f%z')`, as ace3's `_JSONEncoder` writes it.
    pub fn ace3_format(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}+0000",
            self.year, self.month, self.day, self.hour, self.minute, self.second, self.microsecond
        )
    }

    /// `replace(microsecond=0).isoformat()`, as the module's `_datetime_to_str` writes it.
    pub fn isoformat_seconds(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// A value of the tree `get_json` returns. LnkParse3 only makes these types: no `bool`, `float`
/// or `bytes`, and every `int` fits an `i64` (the largest is the file's computed `size`, at most
/// the input length plus a few 32-bit sizes).
#[derive(Debug, Clone, PartialEq)]
pub enum PyValue {
    None,
    Int(i64),
    Str(String),
    DateTime(DateTime),
    List(Vec<PyValue>),
    Dict(Dict),
}

/// A `dict`, in insertion order, each key once.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Dict(Vec<(String, PyValue)>);

impl Dict {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// `d[key] = value`: a key already there keeps its place.
    pub fn set(&mut self, key: &str, value: PyValue) {
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }

    pub fn get(&self, key: &str) -> Option<&PyValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub(crate) fn get_mut(&mut self, key: &str) -> Option<&mut PyValue> {
        self.0.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &PyValue)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for PyValue {
    fn from(s: &str) -> Self {
        PyValue::Str(s.to_owned())
    }
}

impl From<String> for PyValue {
    fn from(s: String) -> Self {
        PyValue::Str(s)
    }
}

impl From<Option<String>> for PyValue {
    fn from(s: Option<String>) -> Self {
        s.map_or(PyValue::None, PyValue::Str)
    }
}

impl From<Option<DateTime>> for PyValue {
    fn from(d: Option<DateTime>) -> Self {
        d.map_or(PyValue::None, PyValue::DateTime)
    }
}

impl From<Dict> for PyValue {
    fn from(d: Dict) -> Self {
        PyValue::Dict(d)
    }
}

macro_rules! from_int {
    ($($t:ty),*) => {$(
        impl From<$t> for PyValue {
            fn from(v: $t) -> Self {
                PyValue::Int(i64::from(v))
            }
        }
    )*};
}
from_int!(u8, u16, u32, i16, i32, i64);

/// The value as ace3 stores it in the analysis details: `json` with `_JSONEncoder`, which turns a
/// datetime into `strftime('%Y-%m-%dT%H:%M:%S.%f%z')`. Dict order is kept.
pub fn to_ace3_json(v: &PyValue) -> serde_json::Value {
    use serde_json::Value;
    match v {
        PyValue::None => Value::Null,
        PyValue::Int(i) => Value::from(*i),
        PyValue::Str(s) => Value::String(s.clone()),
        PyValue::DateTime(d) => Value::String(d.ace3_format()),
        PyValue::List(l) => Value::Array(l.iter().map(to_ace3_json).collect()),
        PyValue::Dict(d) => Value::Object(
            d.iter()
                .map(|(k, v)| (k.to_owned(), to_ace3_json(v)))
                .collect(),
        ),
    }
}

/// The text of `json.dump(info, fp, indent=4, default=_datetime_to_str, sort_keys=True)`.
///
/// It can't fail on a tree LnkParse3 makes: every key is a `str` and every leaf serializes, a
/// datetime through `_datetime_to_str`. (Only `bytes` or another unserializable leaf would make
/// json raise, and LnkParse3 returns none.)
pub fn dump_lnkparser_json(v: &PyValue) -> String {
    let mut out = String::new();
    dump(v, 0, &mut out);
    out
}

fn newline_indent(level: usize, out: &mut String) {
    out.push('\n');
    for _ in 0..level * 4 {
        out.push(' ');
    }
}

fn dump(v: &PyValue, level: usize, out: &mut String) {
    match v {
        PyValue::None => out.push_str("null"),
        PyValue::Int(i) => out.push_str(&i.to_string()),
        PyValue::Str(s) => encode_ascii(s, out),
        PyValue::DateTime(d) => encode_ascii(&d.isoformat_seconds(), out),
        PyValue::List(l) => {
            if l.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in l.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_indent(level + 1, out);
                dump(item, level + 1, out);
            }
            newline_indent(level, out);
            out.push(']');
        }
        PyValue::Dict(d) => {
            if d.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut items: Vec<(&str, &PyValue)> = d.iter().collect();
            items.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (k, item)) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline_indent(level + 1, out);
                encode_ascii(k, out);
                out.push_str(": ");
                dump(item, level + 1, out);
            }
            newline_indent(level, out);
            out.push('}');
        }
    }
}

/// `json.encoder.py_encode_basestring_ascii`.
fn encode_ascii(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_shape() {
        let mut d = Dict::new();
        d.set("b", PyValue::List(vec![PyValue::Int(1), PyValue::None]));
        d.set("a", PyValue::Dict(Dict::new()));
        d.set("c", PyValue::List(vec![]));
        d.set("d", "\u{e9}\u{1F600}\"\u{7f}".into());
        assert_eq!(
            dump_lnkparser_json(&PyValue::Dict(d)),
            "{\n    \"a\": {},\n    \"b\": [\n        1,\n        null\n    ],\n    \"c\": [],\n    \"d\": \"\\u00e9\\ud83d\\ude00\\\"\\u007f\"\n}"
        );
    }
}
