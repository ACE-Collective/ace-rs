//! Python's values and conversions as the deobfuscator leans on them: it's untyped, and what a macro
//! does often depends on `str(x)`, `float(x)` or the exception a wrong type raises.

use std::rc::Rc;

use super::lark::Node;
use super::sheet::CellRef;
use crate::py::{is_space, repr_str};

/// A Python exception on its way up, or the pass's clock running out, which nothing catches.
#[derive(Debug, Clone)]
pub enum Raised {
    Exception {
        kind: &'static str,
        message: String,
    },
    Timeout,
    /// Its output or memory limit: the module treats it as it treats the timer.
    Limit,
}

pub type R<T> = Result<T, Raised>;

pub fn raise<T>(kind: &'static str, message: impl Into<String>) -> R<T> {
    Err(Raised::Exception {
        kind,
        message: message.into(),
    })
}

pub fn attr_error<T>(of: &str, attr: &str) -> R<T> {
    raise(
        "AttributeError",
        format!("'{of}' object has no attribute '{attr}'"),
    )
}

pub fn unbound<T>(name: &str) -> R<T> {
    raise(
        "UnboundLocalError",
        format!("cannot access local variable '{name}' where it is not associated with a value"),
    )
}

pub fn index_error<T>() -> R<T> {
    raise("IndexError", "list index out of range")
}

pub fn memory_error<T>() -> R<T> {
    raise("MemoryError", "")
}

#[derive(Clone, Default)]
pub enum Value {
    #[default]
    None,
    Str(Rc<str>),
    Int(i128),
    Float(f64),
    Bool(bool),
    List(Rc<Vec<Value>>),
    Tuple(Rc<Vec<Value>>),
    Cell(CellRef),
    Node(Node),
    /// What `str()` of an object with no `__str__` is. Python's has its address in it.
    Object(Rc<str>),
}

/// `str(float)`.
pub fn float_str(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_owned();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0" } else { "0.0" }.to_owned();
    }
    let digits = format!("{:e}", f.abs());
    let (mantissa, exponent) = digits.split_once('e').unwrap_or((&digits, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let sign = if f < 0.0 { "-" } else { "" };
    let plain: String = mantissa.chars().filter(|c| *c != '.').collect();
    if (-4..16).contains(&exponent) {
        if exponent >= 0 {
            let point = exponent as usize + 1;
            if plain.len() <= point {
                format!("{sign}{plain}{}.0", "0".repeat(point - plain.len()))
            } else {
                format!("{sign}{}.{}", &plain[..point], &plain[point..])
            }
        } else {
            format!("{sign}0.{}{plain}", "0".repeat((-exponent - 1) as usize))
        }
    } else {
        let tail = if plain.len() > 1 {
            format!("{}.{}", &plain[..1], &plain[1..])
        } else {
            plain.clone()
        };
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{sign}{tail}e{exp_sign}{:02}", exponent.abs())
    }
}

/// `float(text)`, or None for its ValueError.
pub fn parse_float(text: &str) -> Option<f64> {
    let t = text.trim_matches(is_space);
    if t.is_empty() {
        return None;
    }
    let (sign, body) = match t.as_bytes()[0] {
        b'-' => (-1.0, &t[1..]),
        b'+' => (1.0, &t[1..]),
        _ => (1.0, t),
    };
    let lower = body.to_ascii_lowercase();
    if lower == "inf" || lower == "infinity" {
        return Some(sign * f64::INFINITY);
    }
    if lower == "nan" {
        return Some(if sign < 0.0 { -f64::NAN } else { f64::NAN });
    }
    let mut cleaned = String::with_capacity(body.len());
    let bytes = body.as_bytes();
    let mut digits = 0;
    let mut seen_point = false;
    let mut seen_exp = false;
    let mut at = 0;
    while at < bytes.len() {
        let c = bytes[at];
        match c {
            b'0'..=b'9' => {
                digits += 1;
                cleaned.push(c as char);
            }
            b'_' => {
                let before = at > 0 && bytes[at - 1].is_ascii_digit();
                let after = bytes.get(at + 1).is_some_and(u8::is_ascii_digit);
                if !before || !after {
                    return None;
                }
            }
            b'.' if !seen_point && !seen_exp => {
                seen_point = true;
                cleaned.push('.');
            }
            b'e' | b'E' if !seen_exp && digits > 0 => {
                seen_exp = true;
                cleaned.push('e');
                if matches!(bytes.get(at + 1), Some(b'+' | b'-')) {
                    at += 1;
                    cleaned.push(bytes[at] as char);
                }
                if !bytes.get(at + 1).is_some_and(u8::is_ascii_digit) {
                    return None;
                }
            }
            _ => return None,
        }
        at += 1;
    }
    if digits == 0 {
        return None;
    }
    cleaned.parse::<f64>().ok().map(|f| sign * f)
}

/// `int(text)`, or None for its ValueError. Past i128 it saturates: nothing a macro does with a number
/// that size depends on its digits.
pub fn parse_int(text: &str) -> Option<i128> {
    let t = text.trim_matches(is_space);
    let (negative, body) = match t.as_bytes().first()? {
        b'-' => (true, &t[1..]),
        b'+' => (false, &t[1..]),
        _ => (false, t),
    };
    if body.is_empty() || body.starts_with('_') || body.ends_with('_') || body.contains("__") {
        return None;
    }
    let mut total: i128 = 0;
    for c in body.bytes() {
        match c {
            b'0'..=b'9' => {
                total = total
                    .saturating_mul(10)
                    .saturating_add(i128::from(c - b'0'));
            }
            b'_' => {}
            _ => return None,
        }
    }
    Some(if negative { -total } else { total })
}

/// `float.is_integer` then `str(int(f))`.
pub fn integer_float_str(f: f64) -> String {
    if f == 0.0 {
        return "0".to_owned();
    }
    format!("{f:.0}")
}

/// `round(f, digits)` of Python 3.
pub fn py_round(f: f64, digits: i128) -> f64 {
    if !f.is_finite() || digits > 323 {
        return f;
    }
    if digits < -308 {
        return 0.0f64.copysign(f);
    }
    if digits >= 0 {
        format!("{:.*}", digits as usize, f).parse().unwrap_or(f)
    } else {
        let scale = 10f64.powi((-digits) as i32);
        ((f / scale).round_ties_even() * scale).copysign(f)
    }
}

impl Value {
    pub fn str(text: &str) -> Value {
        Value::Str(Rc::from(text))
    }

    pub fn string(text: String) -> Value {
        Value::Str(Rc::from(text))
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Value::None => "NoneType",
            Value::Str(_) => "str",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Bool(_) => "bool",
            Value::List(_) => "list",
            Value::Tuple(_) => "tuple",
            Value::Cell(_) => "Cell",
            Value::Node(Node::Token(_)) => "Token",
            Value::Node(Node::Tree(_)) => "Tree",
            Value::Node(Node::EmptyList) => "list",
            Value::Object(_) => "EvalResult",
        }
    }

    /// `str(x)`.
    pub fn to_py_str(&self) -> String {
        match self {
            Value::None => "None".to_owned(),
            Value::Str(s) => s.to_string(),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => float_str(*f),
            Value::Bool(true) => "True".to_owned(),
            Value::Bool(false) => "False".to_owned(),
            Value::Cell(cell) => cell.borrow().to_py_str(),
            Value::Node(Node::Token(token)) => token.text.clone(),
            Value::Object(text) => text.to_string(),
            _ => self.repr(),
        }
    }

    /// `repr(x)`.
    pub fn repr(&self) -> String {
        match self {
            Value::Str(s) => repr_str(s),
            Value::List(items) => {
                let inner: Vec<String> = items.iter().map(Value::repr).collect();
                format!("[{}]", inner.join(", "))
            }
            Value::Tuple(items) => {
                let inner: Vec<String> = items.iter().map(Value::repr).collect();
                if inner.len() == 1 {
                    format!("({},)", inner[0])
                } else {
                    format!("({})", inner.join(", "))
                }
            }
            Value::Cell(_) => "<XLMMacroDeobfuscator.boundsheet.Cell object>".to_owned(),
            Value::Node(node) => node.repr(),
            _ => self.to_py_str(),
        }
    }

    pub fn is_str(&self, text: &str) -> bool {
        match self {
            Value::Str(s) => &**s == text,
            Value::Node(Node::Token(token)) => token.text == text,
            _ => false,
        }
    }

    /// The text of a str, or a Token, which is one.
    pub fn as_text(&self) -> Option<String> {
        match self {
            Value::Str(s) => Some(s.to_string()),
            Value::Node(Node::Token(token)) => Some(token.text.clone()),
            _ => None,
        }
    }

    /// `float(x)`.
    pub fn to_float(&self) -> R<f64> {
        match self {
            Value::Int(i) => Ok(*i as f64),
            Value::Float(f) => Ok(*f),
            Value::Bool(b) => Ok(f64::from(u8::from(*b))),
            Value::Str(_) | Value::Node(Node::Token(_)) => {
                let text = self.as_text().unwrap_or_default();
                match parse_float(&text) {
                    Some(f) => Ok(f),
                    None => raise(
                        "ValueError",
                        format!("could not convert string to float: {}", repr_str(&text)),
                    ),
                }
            }
            other => raise(
                "TypeError",
                format!(
                    "float() argument must be a string or a real number, not '{}'",
                    other.type_name()
                ),
            ),
        }
    }

    /// `int(x)`.
    pub fn to_int(&self) -> R<i128> {
        match self {
            Value::Int(i) => Ok(*i),
            Value::Bool(b) => Ok(i128::from(*b)),
            Value::Float(f) => float_to_int(*f),
            Value::Str(_) | Value::Node(Node::Token(_)) => {
                let text = self.as_text().unwrap_or_default();
                match parse_int(&text) {
                    Some(i) => Ok(i),
                    None => raise(
                        "ValueError",
                        format!(
                            "invalid literal for int() with base 10: {}",
                            repr_str(&text)
                        ),
                    ),
                }
            }
            other => raise(
                "TypeError",
                format!(
                    "int() argument must be a string, a bytes-like object or a real number, not '{}'",
                    other.type_name()
                ),
            ),
        }
    }

    /// `EvalResult.is_float`.
    pub fn is_float(&self) -> bool {
        self.to_float().is_ok()
    }

    /// `EvalResult.is_int`, where a float that's no integer raises what `int()` raises.
    pub fn is_int(&self) -> R<bool> {
        match self.to_int() {
            Ok(_) => Ok(true),
            Err(Raised::Exception { kind, message }) if kind == "OverflowError" => {
                Err(Raised::Exception { kind, message })
            }
            Err(Raised::Exception { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// `strtobool` for what doesn't raise.
    pub fn strtobool(&self) -> Option<bool> {
        let text = self.as_text()?;
        match py_lower(&text).as_str() {
            "y" | "yes" | "t" | "true" | "on" | "1" => Some(true),
            "n" | "no" | "f" | "false" | "off" | "0" => Some(false),
            _ => None,
        }
    }

    /// Python's truth of a value.
    pub fn truthy(&self) -> bool {
        match self {
            Value::None => false,
            Value::Str(s) => !s.is_empty(),
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Bool(b) => *b,
            Value::List(items) | Value::Tuple(items) => !items.is_empty(),
            Value::Node(Node::Token(token)) => !token.text.is_empty(),
            Value::Node(Node::EmptyList) => false,
            _ => true,
        }
    }
}

pub fn float_to_int(f: f64) -> R<i128> {
    if f.is_nan() {
        return raise("ValueError", "cannot convert float NaN to integer");
    }
    if f.is_infinite() {
        return raise("OverflowError", "cannot convert float infinity to integer");
    }
    Ok(f.trunc() as i128)
}

/// `str.lower()`, which for the rare characters whose lower case Rust words differently goes by Rust.
pub fn py_lower(text: &str) -> String {
    text.to_lowercase()
}

/// `str.strip('"')`.
pub fn strip_quotes(text: &str) -> &str {
    text.trim_matches('"')
}

/// `EvalResult.unwrap_str_literal`.
pub fn unwrap_str_literal(value: &str) -> String {
    let count = value.chars().count();
    if count > 1 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].replace("\"\"", "\"")
    } else {
        value.to_owned()
    }
}

/// `EvalResult.wrap_str_literal`.
pub fn wrap_str_literal(data: &Value, must_wrap: bool) -> R<String> {
    if let Some(text) = data.as_text() {
        if parse_float(&text).is_some()
            || (text.chars().count() > 1
                && text.starts_with('"')
                && text.ends_with('"')
                && !must_wrap)
        {
            return Ok(text);
        }
        return Ok(format!("\"{}\"", text.replace('"', "\"\"")));
    }
    match data {
        Value::Int(_) | Value::Float(_) | Value::Bool(_) => Ok(data.to_py_str()),
        Value::None => raise("TypeError", "object of type 'NoneType' has no len()"),
        Value::List(items) | Value::Tuple(items) if items.len() <= 1 => {
            attr_error(data.type_name(), "replace")
        }
        Value::List(_) | Value::Tuple(_) => attr_error(data.type_name(), "startswith"),
        Value::Node(Node::EmptyList) => attr_error("list", "replace"),
        Value::Cell(_) => raise("TypeError", "object of type 'Cell' has no len()"),
        Value::Node(_) => attr_error("Tree", "replace"),
        Value::Object(_) => raise("TypeError", "object of type 'EvalResult' has no len()"),
        _ => raise("TypeError", "bad value"),
    }
}

/// `datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f")`, as seconds from the epoch in UTC, which is the
/// containers' zone, and `%f` read as a fraction.
pub fn parse_datetime(text: &str) -> Option<f64> {
    let (date, time) = text.split_once(' ')?;
    let mut parts = date.split('-');
    let year = parts.next().filter(|p| p.len() == 4)?;
    let year: i64 = digits(year)?;
    let month: i64 = number(parts.next()?, 1, 12, 2)?;
    let day: i64 = number(parts.next()?, 1, 31, 2)?;
    if parts.next().is_some() || year == 0 {
        return None;
    }
    let (clock, fraction) = time.split_once('.')?;
    let seconds = clock_seconds(clock)?;
    if fraction.is_empty() || fraction.len() > 6 || !fraction.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let micro: f64 = format!("0.{fraction}").parse().ok()?;
    if day > days_in_month(year, month) {
        return None;
    }
    Some((days_from_civil(year, month, day) * 86400) as f64 + seconds as f64 + micro)
}

/// `datetime.strptime(text, "%H:%M:%S")`: seconds into the day.
pub fn parse_time(text: &str) -> Option<i64> {
    clock_seconds(text)
}

fn clock_seconds(clock: &str) -> Option<i64> {
    let mut parts = clock.split(':');
    let hour = number(parts.next()?, 0, 23, 2)?;
    let minute = number(parts.next()?, 0, 59, 2)?;
    let second = number(parts.next()?, 0, 61, 2)?;
    if parts.next().is_some() {
        return None;
    }
    Some(hour * 3600 + minute * 60 + second)
}

fn digits(text: &str) -> Option<i64> {
    if text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn number(text: &str, low: i64, high: i64, width: usize) -> Option<i64> {
    if text.len() > width {
        return None;
    }
    digits(text).filter(|n| (low..=high).contains(n))
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `str(datetime.fromtimestamp(seconds))` in UTC.
pub fn datetime_str(seconds: f64) -> String {
    let micros = (seconds * 1e6).round_ties_even() as i128;
    let total = micros.div_euclid(1_000_000);
    let micro = micros.rem_euclid(1_000_000);
    let days = total.div_euclid(86400) as i64;
    let rest = total.rem_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let mut out = format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    );
    if micro != 0 {
        out.push_str(&format!(".{micro:06}"));
    }
    out
}

/// Excel's serial date for now, as `excel_date(datetime.now() + timedelta(seconds))`.
pub fn excel_date(unix_seconds: f64) -> f64 {
    // days from 1899-12-30 to 1970-01-01
    let whole = unix_seconds.floor();
    let days = (whole / 86400.0).floor();
    let seconds = whole - days * 86400.0;
    days + 25569.0 + seconds / 86400.0
}
