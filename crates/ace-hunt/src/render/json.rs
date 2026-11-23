//! JSON in and out as Python's `json` module does it: what ace3's `fromjson` filter (`json.loads`)
//! and Jinja's `tojson` (`json.dumps(sort_keys=True)`, made safe for HTML) give, and how the
//! comparison's inputs are read, keeping each object's key order as a dict does.

use minijinja::value::Value;
use minijinja::{Error, ErrorKind};

use super::budget;
use super::py::{self, Kind, float_repr, kind, type_error, type_name};
use crate::value::{Map, Value as Loaded};

/// Why text isn't JSON, as `json.JSONDecodeError` would say.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodeError(pub String);

const MAX_DEPTH: usize = 512;

/// `json.loads(text)`: NaN and the infinities included, an object's keys in their order with a
/// repeated key's last value in its first place, and integers as large as 128 bits hold.
pub fn loads(text: &str) -> Result<Loaded, DecodeError> {
    let mut p = Parser {
        s: text.as_bytes(),
        text,
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(DecodeError(format!("Extra data: char {}", p.i)));
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    text: &'a str,
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn err<T>(&self, what: &str) -> Result<T, DecodeError> {
        Err(DecodeError(format!("{what}: char {}", self.i)))
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.s[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Loaded, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError("maximum recursion depth exceeded".to_owned()));
        }
        let Some(&c) = self.s.get(self.i) else {
            return self.err("Expecting value");
        };
        match c {
            b'{' => {
                self.i += 1;
                let mut map = Map::new();
                self.ws();
                if self.eat("}") {
                    return Ok(Loaded::Map(map));
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return self.err("Expecting property name enclosed in double quotes");
                    }
                    let key = self.string()?;
                    self.ws();
                    if !self.eat(":") {
                        return self.err("Expecting ':' delimiter");
                    }
                    self.ws();
                    let v = self.value(depth + 1)?;
                    map.insert(Loaded::Str(key), v);
                    self.ws();
                    if self.eat("}") {
                        return Ok(Loaded::Map(map));
                    }
                    if !self.eat(",") {
                        return self.err("Expecting ',' delimiter");
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat("]") {
                    return Ok(Loaded::Seq(items));
                }
                loop {
                    self.ws();
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    if self.eat("]") {
                        return Ok(Loaded::Seq(items));
                    }
                    if !self.eat(",") {
                        return self.err("Expecting ',' delimiter");
                    }
                }
            }
            b'"' => Ok(Loaded::Str(self.string()?)),
            b'n' if self.eat("null") => Ok(Loaded::Null),
            b't' if self.eat("true") => Ok(Loaded::Bool(true)),
            b'f' if self.eat("false") => Ok(Loaded::Bool(false)),
            b'N' if self.eat("NaN") => Ok(Loaded::Float(f64::NAN)),
            b'I' if self.eat("Infinity") => Ok(Loaded::Float(f64::INFINITY)),
            b'-' if self.eat("-Infinity") => Ok(Loaded::Float(f64::NEG_INFINITY)),
            b'-' | b'0'..=b'9' => self.number(),
            _ => self.err("Expecting value"),
        }
    }

    fn number(&mut self) -> Result<Loaded, DecodeError> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let from = p.i;
            while p.i < p.s.len() && p.s[p.i].is_ascii_digit() {
                p.i += 1;
            }
            p.i - from
        };
        if self.s[self.i] == b'-' {
            self.i += 1;
        }
        match self.s.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                digits(self);
            }
            _ => {
                self.i = start;
                return self.err("Expecting value");
            }
        }
        let mut is_float = false;
        if self.s.get(self.i) == Some(&b'.')
            && self.s.get(self.i + 1).is_some_and(u8::is_ascii_digit)
        {
            self.i += 1;
            digits(self);
            is_float = true;
        }
        if matches!(self.s.get(self.i), Some(b'e' | b'E')) {
            let mark = self.i;
            self.i += 1;
            if matches!(self.s.get(self.i), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                self.i = mark;
            } else {
                is_float = true;
            }
        }
        let text = &self.text[start..self.i];
        if is_float {
            text.parse::<f64>()
                .map(Loaded::Float)
                .map_err(|_| DecodeError("bad number".to_owned()))
        } else {
            text.parse::<i128>()
                .map(Loaded::Int)
                .map_err(|_| DecodeError("integer past 128 bits (ace-rs limit)".to_owned()))
        }
    }

    fn hex4(&mut self) -> Result<u32, DecodeError> {
        let Some(h) = self.text.get(self.i..self.i + 4) else {
            return self.err("Invalid \\uXXXX escape");
        };
        let v = u32::from_str_radix(h, 16).or_else(|_| self.err("Invalid \\uXXXX escape"))?;
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return self.err("Invalid \\uXXXX escape");
        }
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        self.i += 1;
        let mut out = String::new();
        loop {
            let Some(&c) = self.s.get(self.i) else {
                return self.err("Unterminated string starting at");
            };
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let Some(&e) = self.s.get(self.i) else {
                        return self.err("Unterminated string starting at");
                    };
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\x08'),
                        b'f' => out.push('\x0c'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut u = self.hex4()?;
                            if (0xd800..0xdc00).contains(&u)
                                && self.text[self.i..].starts_with("\\u")
                            {
                                let mark = self.i;
                                self.i += 2;
                                let low = self.hex4()?;
                                if (0xdc00..0xe000).contains(&low) {
                                    u = 0x10000 + ((u - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    self.i = mark;
                                }
                            }
                            // Python keeps a lone surrogate in a str; Rust can't hold one
                            out.push(char::from_u32(u).unwrap_or('\u{fffd}'));
                        }
                        _ => {
                            self.i -= 1;
                            return self.err("Invalid \\escape");
                        }
                    }
                }
                0..=0x1f => return self.err("Invalid control character at"),
                _ => {
                    let rest = &self.text[self.i..];
                    let ch = rest.chars().next().unwrap_or('\u{fffd}');
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
        }
    }
}

/// `json.dumps(value, sort_keys=True, indent=indent)`, with `<`, `>`, `&` and `'` escaped as
/// Jinja's `htmlsafe_json_dumps` does.
pub fn dumps_html_safe(value: &Value, indent: Option<&str>) -> Result<String, Error> {
    let mut out = String::new();
    dump(value, indent, 0, &mut out)?;
    Ok(out
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        .replace('\'', "\\u0027"))
}

fn not_serializable(v: &Value) -> Error {
    type_error(format!(
        "Object of type {} is not JSON serializable",
        type_name(v)
    ))
}

pub fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if c.is_ascii() && (c as u32) >= 0x20 => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn float_json(f: f64) -> String {
    if f.is_nan() {
        "NaN".to_owned()
    } else if f.is_infinite() {
        if f > 0.0 { "Infinity" } else { "-Infinity" }.to_owned()
    } else {
        float_repr(f)
    }
}

fn dump(v: &Value, indent: Option<&str>, level: usize, out: &mut String) -> Result<(), Error> {
    if level > MAX_DEPTH {
        return Err(Error::new(
            ErrorKind::InvalidOperation,
            "ValueError: Circular reference detected",
        ));
    }
    budget::string(out.len())?;
    let (open_sep, item_sep, close_sep) = match indent {
        Some(unit) => (
            format!("\n{}", unit.repeat(level + 1)),
            format!(",\n{}", unit.repeat(level + 1)),
            format!("\n{}", unit.repeat(level)),
        ),
        None => (String::new(), ", ".to_owned(), String::new()),
    };
    match kind(v) {
        Kind::None => out.push_str("null"),
        Kind::Bool(b) => out.push_str(if b { "true" } else { "false" }),
        Kind::Int(i) => out.push_str(&i.to_string()),
        Kind::Float(f) => out.push_str(&float_json(f)),
        Kind::Str(s) => quote(s, out),
        Kind::List(_) | Kind::Tuple(_) | Kind::Seq => {
            let items = py::iterate(v)?;
            if items.is_empty() {
                out.push_str("[]");
                return Ok(());
            }
            out.push('[');
            out.push_str(&open_sep);
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(&item_sep);
                }
                dump(item, indent, level + 1, out)?;
            }
            out.push_str(&close_sep);
            out.push(']');
        }
        Kind::Dict(d) => {
            let mut entries = d.entries();
            if entries.is_empty() {
                out.push_str("{}");
                return Ok(());
            }
            for (k, _) in &entries {
                if !matches!(
                    kind(k),
                    Kind::Str(_) | Kind::Int(_) | Kind::Float(_) | Kind::Bool(_) | Kind::None
                ) {
                    return Err(type_error(format!(
                        "keys must be str, int, float, bool or None, not {}",
                        type_name(k)
                    )));
                }
            }
            let mut keys: Vec<Value> = entries.iter().map(|(k, _)| k.clone()).collect();
            super::methods::sort_values(&mut keys, |k| Ok(k.clone()))?;
            let mut sorted = Vec::with_capacity(entries.len());
            for key in keys {
                let at = entries
                    .iter()
                    .position(|(k, _)| py::same_object(k, &key) || py::eq(k, &key))
                    .unwrap_or(0);
                sorted.push(entries.remove(at));
            }
            out.push('{');
            out.push_str(&open_sep);
            for (i, (k, value)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push_str(&item_sep);
                }
                let key = match kind(k) {
                    Kind::Str(s) => s.to_owned(),
                    Kind::Int(i) => i.to_string(),
                    Kind::Float(f) => float_json(f),
                    Kind::Bool(b) => if b { "true" } else { "false" }.to_owned(),
                    _ => "null".to_owned(),
                };
                quote(&key, out);
                out.push_str(": ");
                dump(value, indent, level + 1, out)?;
            }
            out.push_str(&close_sep);
            out.push('}');
        }
        _ => return Err(not_serializable(v)),
    }
    Ok(())
}

/// Reads a comparison's inputs, written by Python's `json.dump`.
pub fn read(text: &str) -> Result<Loaded, String> {
    loads(text).map_err(|e| e.0)
}

/// The template value of what `loads` read.
pub fn to_template(v: &Loaded) -> Value {
    py::to_template(v)
}
