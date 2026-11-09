//! `json.loads` as Python 3.14 runs it: `json.decoder.JSONDecoder` over the C scanner
//! (`Modules/_json.c`), ported line by line, error positions and messages included.
//!
//! Python's `str` can hold lone surrogates, which a JSON `\ud800` escape makes and which a Rust
//! `String` can't. [`JsonStr`] keeps the text with them dropped, as every caller re-encodes with
//! `errors="ignore"`, and keeps the code points too when there were any, so dict keys compare as
//! Python compares them and [`loads_str`] can parse such a string again exactly. `loads_bytes` takes
//! `bytes`: Python detects UTF-8, UTF-16 or UTF-32 and decodes with `surrogatepass`.
//!
//! Numbers keep Python's types: an int as its decimal text (Python refuses one of more than 4300
//! digits with `ValueError`, as `sys.get_int_max_str_digits()` says), a float as `f64`, with
//! [`float_repr`] for Python's `repr`. `NaN`, `Infinity` and `-Infinity` are floats.
//!
//! The parser keeps its own stack, so deep nesting can't overflow Rust's. Python's C scanner
//! raises `RecursionError` when the C stack is nearly used up, which on ace3's main thread (8 MiB
//! stack) happens at about 47,450 nested arrays or objects; the exact depth varied between 47,446
//! and 47,453 between runs. Here the container at depth [`MAX_DEPTH`] raises it, with Python's
//! message. Within a few levels of that depth an unterminated document can raise RecursionError
//! "while calling a Python object" in Python, where this raises the JSONDecodeError.

use std::collections::HashMap;

use crate::PyErr;
use crate::pystr::unicode_decode_error;

/// The nesting depth of arrays and objects at which `json.loads` raises `RecursionError`.
pub const MAX_DEPTH: usize = 47_450;

/// `sys.get_int_max_str_digits()`'s default.
pub const INT_MAX_STR_DIGITS: usize = 4300;

/// A Python `str` from a JSON document.
#[derive(Debug, Clone, Default)]
pub struct JsonStr {
    text: String,
    /// Every code point, lone surrogates included, when there were any.
    code_points: Option<Box<[u32]>>,
}

impl JsonStr {
    /// The string without its lone surrogates, which is `s.encode("utf-8", errors="ignore")`.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether Python's string holds lone surrogates that [`as_str`](Self::as_str) drops.
    pub fn has_surrogates(&self) -> bool {
        self.code_points.is_some()
    }

    /// Python's string, as code points.
    pub fn code_points(&self) -> Vec<u32> {
        match &self.code_points {
            Some(cps) => cps.to_vec(),
            None => self.text.chars().map(|c| c as u32).collect(),
        }
    }

    /// `len(s)` in Python.
    pub fn py_len(&self) -> usize {
        match &self.code_points {
            Some(cps) => cps.len(),
            None => self.text.chars().count(),
        }
    }

    fn from_code_points(cps: &[u32]) -> Self {
        let mut text = String::with_capacity(cps.len());
        let mut surrogates = false;
        for &cp in cps {
            match char::from_u32(cp) {
                Some(c) => text.push(c),
                None => surrogates = true,
            }
        }
        Self {
            text,
            code_points: surrogates.then(|| cps.into()),
        }
    }
}

impl PartialEq for JsonStr {
    fn eq(&self, other: &Self) -> bool {
        match (&self.code_points, &other.code_points) {
            (None, None) => self.text == other.text,
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for JsonStr {}

impl PartialEq<str> for JsonStr {
    fn eq(&self, other: &str) -> bool {
        self.code_points.is_none() && self.text == other
    }
}

/// A value `json.loads` returns.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `None`.
    Null,
    /// `True` or `False`.
    Bool(bool),
    /// An `int`, as `str(value)` gives it.
    Int(String),
    /// A `float`.
    Float(f64),
    /// A `str`.
    Str(JsonStr),
    /// A `list`.
    Array(Vec<Value>),
    /// A `dict`, in its insertion order, each key once.
    Object(Vec<(JsonStr, Value)>),
}

impl Drop for Value {
    /// Drops nested arrays and objects without recursing, so a deep document can't overflow the
    /// stack. (Clone, PartialEq and Debug still recurse.)
    fn drop(&mut self) {
        let mut pending: Vec<Value> = match self {
            Value::Array(items) if !items.is_empty() => std::mem::take(items),
            Value::Object(members) if !members.is_empty() => std::mem::take(members)
                .into_iter()
                .map(|(_, v)| v)
                .collect(),
            _ => return,
        };
        while let Some(mut v) = pending.pop() {
            match &mut v {
                Value::Array(items) => pending.append(items),
                Value::Object(members) => {
                    pending.extend(std::mem::take(members).into_iter().map(|(_, v)| v))
                }
                _ => {}
            }
        }
    }
}

impl Value {
    /// `type(value).__name__`.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "NoneType",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::Array(_) => "list",
            Value::Object(_) => "dict",
        }
    }

    /// `value[key]` for a dict: `None` when it isn't a dict or hasn't the key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, for a `str`.
    pub fn as_json_str(&self) -> Option<&JsonStr> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The string without lone surrogates, for a `str`.
    pub fn as_str(&self) -> Option<&str> {
        self.as_json_str().map(JsonStr::as_str)
    }
}

/// `repr(f)` for a Python float.
pub fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_owned();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    let mut out = String::new();
    if f.is_sign_negative() {
        out.push('-');
    }
    let f = f.abs();
    if f == 0.0 {
        out.push_str("0.0");
        return out;
    }
    // Rust's `{:e}` gives the shortest digits that round-trip, as Python's repr uses.
    let sci = format!("{f:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1;
    if (-4 < decpt) && decpt <= 16 {
        let n = digits.len() as i32;
        if decpt <= 0 {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', (-decpt) as usize));
            out.push_str(&digits);
        } else if decpt >= n {
            out.push_str(&digits);
            out.extend(std::iter::repeat_n('0', (decpt - n) as usize));
            out.push_str(".0");
        } else {
            out.push_str(&digits[..decpt as usize]);
            out.push('.');
            out.push_str(&digits[decpt as usize..]);
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exp.unsigned_abs()));
    }
    out
}

/// `json.loads(text)` for a `str`.
pub fn loads(text: &str) -> Result<Value, PyErr> {
    let cps: Vec<u32> = text.chars().map(|c| c as u32).collect();
    loads_code_points(&cps)
}

/// `json.loads(s)` for a `str` that may hold lone surrogates, such as a string an earlier
/// `json.loads` returned.
pub fn loads_str(s: &JsonStr) -> Result<Value, PyErr> {
    match &s.code_points {
        Some(cps) => loads_code_points(cps),
        None => loads(&s.text),
    }
}

/// `json.loads(s)` for a `str` given as code points.
pub fn loads_code_points(cps: &[u32]) -> Result<Value, PyErr> {
    if cps.first() == Some(&0xFEFF) {
        return Err(decode_error(
            "Unexpected UTF-8 BOM (decode using utf-8-sig)",
            cps,
            0,
        ));
    }
    decode(cps)
}

/// `json.loads(b)` for `bytes`.
pub fn loads_bytes(b: &[u8]) -> Result<Value, PyErr> {
    let cps = decode_bytes(b)?;
    decode(&cps)
}

fn decode_error(msg: &str, doc: &[u32], pos: usize) -> PyErr {
    let before = &doc[..pos.min(doc.len())];
    let lineno = before.iter().filter(|&&c| c == '\n' as u32).count() + 1;
    let colno = match before.iter().rposition(|&c| c == '\n' as u32) {
        Some(i) => pos - i,
        None => pos + 1,
    };
    PyErr::new(
        "json.decoder",
        "JSONDecodeError",
        format!("{msg}: line {lineno} column {colno} (char {pos})"),
    )
}

#[inline]
fn is_ws(c: u32) -> bool {
    c == ' ' as u32 || c == '\t' as u32 || c == '\n' as u32 || c == '\r' as u32
}

fn skip_ws(s: &[u32], mut idx: usize) -> usize {
    while idx < s.len() && is_ws(s[idx]) {
        idx += 1;
    }
    idx
}

/// JSONDecoder.decode.
fn decode(s: &[u32]) -> Result<Value, PyErr> {
    let idx = skip_ws(s, 0);
    let (value, end) = match scan(s, idx) {
        Ok(v) => v,
        Err(Fail::Stop(at)) => return Err(decode_error("Expecting value", s, at)),
        Err(Fail::Py(e)) => return Err(e),
    };
    let end = skip_ws(s, end);
    if end != s.len() {
        return Err(decode_error("Extra data", s, end));
    }
    Ok(value)
}

enum Fail {
    /// StopIteration(idx): no value where one was expected.
    Stop(usize),
    Py(PyErr),
}

impl From<PyErr> for Fail {
    fn from(e: PyErr) -> Self {
        Fail::Py(e)
    }
}

enum Frame {
    Array(Vec<Value>),
    Object {
        members: Vec<(JsonStr, Value)>,
        index: HashMap<String, usize>,
        key: JsonStr,
    },
}

fn insert(
    members: &mut Vec<(JsonStr, Value)>,
    index: &mut HashMap<String, usize>,
    key: JsonStr,
    value: Value,
) {
    if key.code_points.is_none() {
        if let Some(&i) = index.get(&key.text) {
            members[i].1 = value;
            return;
        }
        index.insert(key.text.clone(), members.len());
    } else if let Some(m) = members.iter_mut().find(|(k, _)| *k == key) {
        m.1 = value;
        return;
    }
    members.push((key, value));
}

fn recursion_error(what: &str) -> Fail {
    Fail::Py(PyErr::builtin(
        "RecursionError",
        format!("Stack overflow (used 8160 kB) while decoding a JSON {what} from a unicode string"),
    ))
}

/// Reads a key and its ':' at `idx`, which _parse_object_unicode expects to be the key's quote.
/// Returns the key and the index of the value.
fn read_key(s: &[u32], idx: usize) -> Result<(JsonStr, usize), Fail> {
    if idx >= s.len() || s[idx] != '"' as u32 {
        return Err(
            decode_error("Expecting property name enclosed in double quotes", s, idx).into(),
        );
    }
    let (key, next) = scanstring(s, idx + 1)?;
    let mut idx = skip_ws(s, next);
    if idx >= s.len() || s[idx] != ':' as u32 {
        return Err(decode_error("Expecting ':' delimiter", s, idx).into());
    }
    idx += 1;
    Ok((key, skip_ws(s, idx)))
}

/// scan_once_unicode, with the recursion into arrays and objects on an explicit stack.
fn scan(s: &[u32], start: usize) -> Result<(Value, usize), Fail> {
    let len = s.len();
    let mut stack: Vec<Frame> = Vec::new();
    let mut idx = start;
    'value: loop {
        if idx >= len {
            return Err(Fail::Stop(idx));
        }
        let at = |i: usize, c: char| i < len && s[i] == c as u32;
        let (mut value, mut next) = match char::from_u32(s[idx]).unwrap_or('\0') {
            '"' => {
                let (v, n) = scanstring(s, idx + 1)?;
                (Value::Str(v), n)
            }
            '{' => {
                if stack.len() + 1 >= MAX_DEPTH {
                    return Err(recursion_error("object"));
                }
                let i = skip_ws(s, idx + 1);
                if i < len && s[i] == '}' as u32 {
                    (Value::Object(Vec::new()), i + 1)
                } else {
                    let (key, i) = read_key(s, i)?;
                    stack.push(Frame::Object {
                        members: Vec::new(),
                        index: HashMap::new(),
                        key,
                    });
                    idx = i;
                    continue 'value;
                }
            }
            '[' => {
                if stack.len() + 1 >= MAX_DEPTH {
                    return Err(recursion_error("array"));
                }
                let i = skip_ws(s, idx + 1);
                if i < len && s[i] == ']' as u32 {
                    (Value::Array(Vec::new()), i + 1)
                } else {
                    stack.push(Frame::Array(Vec::new()));
                    idx = i;
                    continue 'value;
                }
            }
            'n' if idx + 3 < len && at(idx + 1, 'u') && at(idx + 2, 'l') && at(idx + 3, 'l') => {
                (Value::Null, idx + 4)
            }
            't' if idx + 3 < len && at(idx + 1, 'r') && at(idx + 2, 'u') && at(idx + 3, 'e') => {
                (Value::Bool(true), idx + 4)
            }
            'f' if idx + 4 < len
                && at(idx + 1, 'a')
                && at(idx + 2, 'l')
                && at(idx + 3, 's')
                && at(idx + 4, 'e') =>
            {
                (Value::Bool(false), idx + 5)
            }
            'N' if idx + 2 < len && at(idx + 1, 'a') && at(idx + 2, 'N') => {
                (Value::Float(f64::NAN), idx + 3)
            }
            'I' if idx + 7 < len && matches_ascii(s, idx + 1, "nfinity") => {
                (Value::Float(f64::INFINITY), idx + 8)
            }
            '-' if idx + 8 < len && matches_ascii(s, idx + 1, "Infinity") => {
                (Value::Float(f64::NEG_INFINITY), idx + 9)
            }
            _ => match_number(s, idx)?,
        };
        // Hand the value to the arrays and objects it closes.
        loop {
            match stack.last_mut() {
                None => return Ok((value, next)),
                Some(Frame::Array(items)) => {
                    items.push(value);
                    let mut i = skip_ws(s, next);
                    if i < len && s[i] == ']' as u32 {
                        let Some(Frame::Array(items)) = stack.pop() else {
                            unreachable!()
                        };
                        value = Value::Array(items);
                        next = i + 1;
                        continue;
                    }
                    if i >= len || s[i] != ',' as u32 {
                        return Err(decode_error("Expecting ',' delimiter", s, i).into());
                    }
                    let comma = i;
                    i = skip_ws(s, i + 1);
                    if i < len && s[i] == ']' as u32 {
                        return Err(decode_error(
                            "Illegal trailing comma before end of array",
                            s,
                            comma,
                        )
                        .into());
                    }
                    idx = i;
                    continue 'value;
                }
                Some(Frame::Object {
                    members,
                    index,
                    key,
                }) => {
                    insert(members, index, std::mem::take(key), value);
                    let mut i = skip_ws(s, next);
                    if i < len && s[i] == '}' as u32 {
                        let Some(Frame::Object { members, .. }) = stack.pop() else {
                            unreachable!()
                        };
                        value = Value::Object(members);
                        next = i + 1;
                        continue;
                    }
                    if i >= len || s[i] != ',' as u32 {
                        return Err(decode_error("Expecting ',' delimiter", s, i).into());
                    }
                    let comma = i;
                    i = skip_ws(s, i + 1);
                    if i < len && s[i] == '}' as u32 {
                        return Err(decode_error(
                            "Illegal trailing comma before end of object",
                            s,
                            comma,
                        )
                        .into());
                    }
                    let (k, i) = read_key(s, i)?;
                    *key = k;
                    idx = i;
                    continue 'value;
                }
            }
        }
    }
}

fn matches_ascii(s: &[u32], from: usize, word: &str) -> bool {
    word.bytes()
        .enumerate()
        .all(|(i, b)| s.get(from + i) == Some(&(b as u32)))
}

#[inline]
fn is_digit(c: u32) -> bool {
    ('0' as u32..='9' as u32).contains(&c)
}

/// _match_number_unicode.
fn match_number(s: &[u32], start: usize) -> Result<(Value, usize), Fail> {
    let len = s.len();
    let end_idx = len - 1;
    let mut idx = start;
    let mut is_float = false;
    if s[idx] == '-' as u32 {
        idx += 1;
        if idx > end_idx {
            return Err(Fail::Stop(start));
        }
    }
    if ('1' as u32..='9' as u32).contains(&s[idx]) {
        idx += 1;
        while idx <= end_idx && is_digit(s[idx]) {
            idx += 1;
        }
    } else if s[idx] == '0' as u32 {
        idx += 1;
    } else {
        return Err(Fail::Stop(start));
    }
    if idx < end_idx && s[idx] == '.' as u32 && is_digit(s[idx + 1]) {
        is_float = true;
        idx += 2;
        while idx <= end_idx && is_digit(s[idx]) {
            idx += 1;
        }
    }
    if idx < end_idx && (s[idx] == 'e' as u32 || s[idx] == 'E' as u32) {
        let e_start = idx;
        idx += 1;
        if idx < end_idx && (s[idx] == '-' as u32 || s[idx] == '+' as u32) {
            idx += 1;
        }
        while idx <= end_idx && is_digit(s[idx]) {
            idx += 1;
        }
        if is_digit(s[idx - 1]) {
            is_float = true;
        } else {
            idx = e_start;
        }
    }
    let text: String = s[start..idx].iter().map(|&c| c as u8 as char).collect();
    if is_float {
        // Python's float() of the text; Rust's parse rounds the same way and overflows to inf.
        let f: f64 = text.parse().unwrap_or(f64::NAN);
        return Ok((Value::Float(f), idx));
    }
    let digits = text.strip_prefix('-').unwrap_or(&text);
    if digits.len() > INT_MAX_STR_DIGITS {
        return Err(PyErr::value_error(format!(
            "Exceeds the limit ({INT_MAX_STR_DIGITS} digits) for integer string conversion: value has {} digits; use sys.set_int_max_str_digits() to increase the limit",
            digits.len()
        ))
        .into());
    }
    let text = if text == "-0" { "0".to_owned() } else { text };
    Ok((Value::Int(text), idx))
}

fn hex_digit(c: u32) -> Option<u32> {
    char::from_u32(c).and_then(|c| c.to_digit(16))
}

/// scanstring_unicode with strict=True. `end` is the index after the opening quote.
fn scanstring(s: &[u32], mut end: usize) -> Result<(JsonStr, usize), Fail> {
    let len = s.len();
    let begin = end - 1;
    let mut chunks: Vec<u32> = Vec::new();
    loop {
        let mut next = end;
        let mut c = 0;
        while next < len {
            c = s[next];
            if c == '"' as u32 || c == '\\' as u32 {
                break;
            }
            if c <= 0x1f {
                return Err(decode_error("Invalid control character at", s, next).into());
            }
            next += 1;
        }
        if next < len && c == '"' as u32 {
            chunks.extend_from_slice(&s[end..next]);
            return Ok((JsonStr::from_code_points(&chunks), next + 1));
        }
        if next >= len {
            return Err(decode_error("Unterminated string starting at", s, begin).into());
        }
        // A backslash.
        chunks.extend_from_slice(&s[end..next]);
        next += 1;
        if next == len {
            return Err(decode_error("Unterminated string starting at", s, begin).into());
        }
        let mut ch = s[next];
        if ch != 'u' as u32 {
            end = next + 1;
            ch = match char::from_u32(ch) {
                Some('"') => '"' as u32,
                Some('\\') => '\\' as u32,
                Some('/') => '/' as u32,
                Some('b') => 8,
                Some('f') => 12,
                Some('n') => 10,
                Some('r') => 13,
                Some('t') => 9,
                _ => return Err(decode_error("Invalid \\escape", s, end - 2).into()),
            };
        } else {
            next += 1;
            end = next + 4;
            if end > len {
                return Err(decode_error("Invalid \\uXXXX escape", s, next - 1).into());
            }
            ch = 0;
            while next < end {
                let Some(d) = hex_digit(s[next]) else {
                    return Err(decode_error("Invalid \\uXXXX escape", s, end - 5).into());
                };
                ch = (ch << 4) | d;
                next += 1;
            }
            if (0xD800..=0xDBFF).contains(&ch)
                && end + 6 < len
                && s[next] == '\\' as u32
                && s[next + 1] == 'u' as u32
            {
                next += 2;
                let mut c2 = 0;
                end += 6;
                while next < end {
                    let Some(d) = hex_digit(s[next]) else {
                        return Err(decode_error("Invalid \\uXXXX escape", s, end - 5).into());
                    };
                    c2 = (c2 << 4) | d;
                    next += 1;
                }
                if (0xDC00..=0xDFFF).contains(&c2) {
                    ch = 0x10000 + (((ch - 0xD800) << 10) | (c2 - 0xDC00));
                } else {
                    end -= 6;
                }
            }
        }
        chunks.push(ch);
    }
}

/// `b.decode(json.detect_encoding(b), "surrogatepass")`, as code points.
fn decode_bytes(b: &[u8]) -> Result<Vec<u32>, PyErr> {
    if b.starts_with(&[0, 0, 0xFE, 0xFF]) {
        return decode_utf32(b, 4, true);
    }
    if b.starts_with(&[0xFF, 0xFE, 0, 0]) {
        return decode_utf32(b, 4, false);
    }
    if b.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(b, 2, true);
    }
    if b.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(b, 2, false);
    }
    if let Some(rest) = b.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return decode_utf8(rest);
    }
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] != 0 {
                decode_utf16(b, 0, true)
            } else {
                decode_utf32(b, 0, true)
            };
        }
        if b[1] == 0 {
            return if b[2] != 0 || b[3] != 0 {
                decode_utf16(b, 0, false)
            } else {
                decode_utf32(b, 0, false)
            };
        }
    } else if b.len() == 2 {
        if b[0] == 0 {
            return decode_utf16(b, 0, true);
        }
        if b[1] == 0 {
            return decode_utf16(b, 0, false);
        }
    }
    decode_utf8(b)
}

/// UTF-8 with `surrogatepass`: an encoded surrogate decodes to itself.
fn decode_utf8(b: &[u8]) -> Result<Vec<u32>, PyErr> {
    let mut out = Vec::with_capacity(b.len());
    let mut pos = 0;
    while pos < b.len() {
        match std::str::from_utf8(&b[pos..]) {
            Ok(s) => {
                out.extend(s.chars().map(|c| c as u32));
                break;
            }
            Err(e) => {
                let valid = pos + e.valid_up_to();
                let prefix = std::str::from_utf8(&b[pos..valid]).unwrap_or("");
                out.extend(prefix.chars().map(|c| c as u32));
                let p = valid;
                if p + 3 <= b.len()
                    && b[p] & 0xF0 == 0xE0
                    && b[p + 1] & 0xC0 == 0x80
                    && b[p + 2] & 0xC0 == 0x80
                {
                    let cp = ((b[p] as u32 & 0x0F) << 12)
                        | ((b[p + 1] as u32 & 0x3F) << 6)
                        | (b[p + 2] as u32 & 0x3F);
                    if (0xD800..=0xDFFF).contains(&cp) {
                        out.push(cp);
                        pos = p + 3;
                        continue;
                    }
                }
                let (end, reason) = match e.error_len() {
                    None => (b.len(), "unexpected end of data"),
                    Some(n) => {
                        let first = b[p];
                        let reason = if (0x80..=0xC1).contains(&first) || first >= 0xF5 {
                            "invalid start byte"
                        } else {
                            "invalid continuation byte"
                        };
                        (p + n, reason)
                    }
                };
                return Err(unicode_decode_error(
                    "utf-8", b, p as i64, end as i64, reason,
                ));
            }
        }
    }
    Ok(out)
}

/// UTF-16 with `surrogatepass`, from `start` (after a BOM). Positions count from the start of `b`.
fn decode_utf16(b: &[u8], start: usize, be: bool) -> Result<Vec<u32>, PyErr> {
    let name = if be { "utf-16-be" } else { "utf-16-le" };
    let unit = |i: usize| -> u32 {
        if be {
            u32::from(b[i]) << 8 | u32::from(b[i + 1])
        } else {
            u32::from(b[i + 1]) << 8 | u32::from(b[i])
        }
    };
    let mut out = Vec::with_capacity((b.len() - start) / 2);
    let mut i = start;
    while i + 2 <= b.len() {
        let u = unit(i);
        if (0xD800..=0xDBFF).contains(&u) && i + 4 <= b.len() {
            let u2 = unit(i + 2);
            if (0xDC00..=0xDFFF).contains(&u2) {
                out.push(0x10000 + (((u - 0xD800) << 10) | (u2 - 0xDC00)));
                i += 4;
                continue;
            }
        }
        out.push(u);
        i += 2;
    }
    if i < b.len() {
        return Err(unicode_decode_error(
            name,
            b,
            i as i64,
            b.len() as i64,
            "truncated data",
        ));
    }
    Ok(out)
}

/// UTF-32 with `surrogatepass`, from `start` (after a BOM). Positions count from the start of `b`.
fn decode_utf32(b: &[u8], start: usize, be: bool) -> Result<Vec<u32>, PyErr> {
    let name = if be { "utf-32-be" } else { "utf-32-le" };
    let mut out = Vec::with_capacity((b.len() - start) / 4);
    let mut i = start;
    while i + 4 <= b.len() {
        let w = [b[i], b[i + 1], b[i + 2], b[i + 3]];
        let cp = if be {
            u32::from_be_bytes(w)
        } else {
            u32::from_le_bytes(w)
        };
        if cp > 0x10FFFF {
            return Err(unicode_decode_error(
                name,
                b,
                i as i64,
                i as i64 + 4,
                "code point not in range(0x110000)",
            ));
        }
        out.push(cp);
        i += 4;
    }
    if i < b.len() {
        return Err(unicode_decode_error(
            name,
            b,
            i as i64,
            b.len() as i64,
            "truncated data",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value as J, json};

    use super::*;

    /// The value as cases_json.py's `tag` writes Python's.
    fn tag(v: &Value) -> J {
        match v {
            Value::Null => json!(["None"]),
            Value::Bool(b) => json!(["bool", b]),
            Value::Int(t) => json!(["int", t]),
            Value::Float(f) => json!(["float", float_repr(*f)]),
            Value::Str(s) => json!(["str", s.code_points()]),
            Value::Array(items) => json!(["list", items.iter().map(tag).collect::<Vec<_>>()]),
            Value::Object(members) => json!([
                "dict",
                members
                    .iter()
                    .map(|(k, v)| json!([k.code_points(), tag(v)]))
                    .collect::<Vec<_>>()
            ]),
        }
    }

    fn outcome(r: Result<Value, PyErr>) -> J {
        match r {
            Ok(v) => json!({ "ok": tag(&v) }),
            Err(e) => json!({"err": {"module": e.module, "kind": e.kind, "message": e.message}}),
        }
    }

    fn hex(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn loads_matches_python() {
        let data: J = crate::testdata::load("json", include_str!("../tests/data/json.json"));
        let mut bad = Vec::new();
        let mut n = 0;
        for case in data["texts"].as_array().unwrap() {
            n += 1;
            // Texts are given as code points, since they may hold lone surrogates.
            let cps: Vec<u32> = case["cps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_u64().unwrap() as u32)
                .collect();
            let got = if cps.iter().all(|&c| char::from_u32(c).is_some()) {
                let text: String = cps.iter().filter_map(|&c| char::from_u32(c)).collect();
                outcome(loads(&text))
            } else {
                outcome(loads_code_points(&cps))
            };
            if got != case["want"] {
                bad.push(format!(
                    "text {:?}\n got  {got}\n want {}",
                    cps.iter()
                        .map(|&c| char::from_u32(c).unwrap_or('?'))
                        .collect::<String>()
                        .chars()
                        .take(200)
                        .collect::<String>(),
                    case["want"]
                ));
            }
        }
        for case in data["bytes"].as_array().unwrap() {
            n += 1;
            let b = hex(case["b"].as_str().unwrap());
            let got = outcome(loads_bytes(&b));
            if got != case["want"] {
                bad.push(format!("bytes {b:?}\n got  {got}\n want {}", case["want"]));
            }
        }
        assert!(n > 700, "{n} cases");
        assert!(
            bad.is_empty(),
            "{} of {n} differ:\n{}",
            bad.len(),
            bad.iter().take(6).cloned().collect::<Vec<_>>().join("\n")
        );
    }

    #[test]
    fn floats_repr_as_python() {
        let data: J = crate::testdata::load("json", include_str!("../tests/data/json.json"));
        let mut n = 0;
        for case in data["floats"].as_array().unwrap() {
            let bits = case[0].as_str().unwrap();
            let f = f64::from_bits(u64::from_str_radix(bits, 16).unwrap());
            assert_eq!(float_repr(f), case[1].as_str().unwrap(), "{bits}");
            n += 1;
        }
        assert!(n > 500);
    }

    #[test]
    fn deep_nesting_raises_recursion_error_without_overflowing() {
        let ok = "[".repeat(MAX_DEPTH - 1) + &"]".repeat(MAX_DEPTH - 1);
        assert!(loads(&ok).is_ok());
        let deep = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        let e = loads(&deep).unwrap_err();
        assert_eq!(e.kind, "RecursionError");
        assert_eq!(
            e.message,
            "Stack overflow (used 8160 kB) while decoding a JSON array from a unicode string"
        );
        let deep = "{\"a\":".repeat(MAX_DEPTH) + "1" + &"}".repeat(MAX_DEPTH);
        assert!(loads(&deep).unwrap_err().message.contains("JSON object"));
        let mixed: String = (0..MAX_DEPTH)
            .map(|i| if i % 2 == 0 { "[" } else { "{\"k\":" })
            .collect();
        assert_eq!(loads(&mixed).unwrap_err().kind, "RecursionError");
        // A million levels raise as quickly, without recursing.
        assert_eq!(
            loads(&"[".repeat(1_000_000)).unwrap_err().kind,
            "RecursionError"
        );
    }

    #[test]
    fn duplicate_keys_keep_their_first_position() {
        let v = loads(r#"{"a":1,"b":2,"a":3}"#).unwrap();
        assert_eq!(v.get("a"), Some(&Value::Int("3".into())));
        let Value::Object(m) = &v else { panic!() };
        assert_eq!(m[0].0.as_str(), "a");
        assert_eq!(m.len(), 2);
        let v = loads(r#"{"a\ud800":1,"a":2}"#).unwrap();
        assert_eq!(v.get("a"), Some(&Value::Int("2".into())));
        let Value::Object(m) = &v else { panic!() };
        assert_eq!(m.len(), 2);
        assert!(m[0].0.has_surrogates());
    }

    #[test]
    fn a_megabyte_is_quick() {
        let item = r#"{"url": "https://example.com/a?b=cé", "n": [1, 2.5, -3e10, true, null]}"#;
        let doc = format!("[{}]", vec![item; 14_000].join(","));
        assert!(doc.len() > 1_000_000);
        let t = std::time::Instant::now();
        let v = loads(&doc).unwrap();
        assert!(matches!(v, Value::Array(ref a) if a.len() == 14_000));
        assert!(t.elapsed().as_secs_f64() < 2.0, "{:?}", t.elapsed());
    }
}
