//! An entry's attributes as ace3 stores them: each value formatted by the server's schema as
//! Python's ldap3 2.9.1 formats it (`ldap3/protocol/formatters/standard.py` and `formatters.py`,
//! with `get_info=ALL` and `check_names=True`), then written by ace3's `CaseInsensitiveDictEncoder`
//! (`saq/ldap.py`), which writes bytes as their Python repr without `b'` and `'` and anything else
//! it can't encode, a `datetime` or a `timedelta`, as `str()` of it.
//!
//! The formatter of an attribute is found as ldap3 finds it: by its name as a key of ldap3's
//! table, by its OID from the schema, then by its syntax; with none, a value is
//! UTF-8 text, or bytes when it isn't UTF-8. An attribute the schema says is `SINGLE-VALUE` is one
//! value, and any other a list. ldap3 also looks an attribute up by the names its own OID table
//! gives the schema's OID, which reaches only the table's two name keys, so it isn't ported.

use std::collections::HashMap;

use chrono::{DateTime, Duration, FixedOffset, NaiveDate, TimeZone, Utc};
use serde_json::{Map, Value};

/// One `attributeTypes` definition, as ldap3's `AttributeTypeInfo` keeps what's used here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeType {
    pub oid: String,
    pub syntax: Option<String>,
    pub single_value: bool,
}

/// The server's schema: its attribute types by every name each has, without regard to case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schema {
    types: HashMap<String, AttributeType>,
}

impl Schema {
    /// The schema the `attributeTypes` values define. A value that doesn't parse is skipped.
    pub fn from_attribute_types<'a>(definitions: impl IntoIterator<Item = &'a str>) -> Schema {
        let mut types = HashMap::new();
        for definition in definitions {
            if let Some((names, attribute)) = parse_attribute_type(definition) {
                for name in names {
                    types.insert(name.to_lowercase(), attribute.clone());
                }
            }
        }
        Schema { types }
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    fn get(&self, name: &str) -> Option<&AttributeType> {
        self.types.get(&name.to_lowercase())
    }

    /// One attribute's values, formatted and encoded as ace3 stores them.
    pub fn format(&self, name: &str, values: &[Vec<u8>]) -> Value {
        if values.is_empty() {
            return Value::Array(Vec::new());
        }
        let attribute = self.get(name);
        let formatter = find_formatter(attribute, name);
        let mut formatted: Vec<Value> = values.iter().map(|v| formatter(v).to_json()).collect();
        if attribute.is_some_and(|a| a.single_value) {
            formatted.swap_remove(0)
        } else {
            Value::Array(formatted)
        }
    }

    /// An entry's attributes in the order the server sent them, by the names it gave them.
    pub fn entry(&self, attributes: &[(String, Vec<Vec<u8>>)]) -> Map<String, Value> {
        let mut map = Map::new();
        for (name, values) in attributes {
            // a later attribute of the same name replaces the earlier, as a dict does
            map.insert(name.clone(), self.format(name, values));
        }
        map
    }
}

/// RFC 4512's AttributeTypeDescription, as far as ldap3 reads it: the OID, the names, the syntax
/// without its length bound or quotes, and SINGLE-VALUE.
fn parse_attribute_type(definition: &str) -> Option<(Vec<String>, AttributeType)> {
    let tokens = tokenize(definition);
    let mut iter = tokens.iter().peekable();
    if iter.next().map(String::as_str) != Some("(") {
        return None;
    }
    let oid = iter.next()?.clone();
    let mut names = Vec::new();
    let mut syntax = None;
    let mut single_value = false;
    while let Some(token) = iter.next() {
        match token.to_uppercase().as_str() {
            "NAME" => {
                if iter.peek().map(|t| t.as_str()) == Some("(") {
                    iter.next();
                    for t in iter.by_ref() {
                        if t == ")" {
                            break;
                        }
                        names.push(t.clone());
                    }
                } else if let Some(name) = iter.next() {
                    names.push(name.clone());
                }
            }
            "SYNTAX" => {
                if let Some(value) = iter.next() {
                    let value = value.split('{').next().unwrap_or(value);
                    syntax = Some(value.trim_matches('\'').to_owned());
                }
            }
            "SINGLE-VALUE" => single_value = true,
            _ => {}
        }
    }
    Some((
        names,
        AttributeType {
            oid,
            syntax,
            single_value,
        },
    ))
}

/// The definition's tokens: parentheses, quoted strings without their quotes, and words.
fn tokenize(definition: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = definition.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            '(' | ')' => {
                tokens.push(c.to_string());
                chars.next();
            }
            '\'' => {
                chars.next();
                let mut word = String::new();
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    word.push(c);
                }
                tokens.push(word);
            }
            c if c.is_whitespace() => {
                chars.next();
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == '(' || c == ')' {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                tokens.push(word);
            }
        }
    }
    tokens
}

/// A Python value a formatter returns, before ace3's encoder writes it.
#[derive(Debug, Clone, PartialEq)]
pub enum Py {
    Str(String),
    Bytes(Vec<u8>),
    Int(i128),
    Bool(bool),
    /// `str()` of a `datetime` or a `timedelta`.
    Text(String),
}

impl Py {
    fn to_json(&self) -> Value {
        match self {
            Py::Str(s) | Py::Text(s) => Value::String(s.clone()),
            Py::Bytes(b) => Value::String(bytes_repr(b)),
            Py::Int(i) => i64::try_from(*i)
                .map(Value::from)
                .or_else(|_| u64::try_from(*i).map(Value::from))
                // past 64 bits, which no LDAP integer syntax reaches in practice
                .unwrap_or_else(|_| Value::String(i.to_string())),
            Py::Bool(b) => Value::Bool(*b),
        }
    }
}

/// `str(b)[2:-1]`: a bytes value's Python repr without its `b` and quotes.
pub fn bytes_repr(bytes: &[u8]) -> String {
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if b == quote => {
                out.push('\\');
                out.push(char::from(b));
            }
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

type Formatter = fn(&[u8]) -> Py;

/// ldap3's `standard_formatter` for an OID or one of its two name keys.
fn standard(key: &str) -> Option<Formatter> {
    const DS: &str = "1.3.6.1.4.1.1466.115.121.1.";
    if let Some(n) = key.strip_prefix(DS) {
        return Some(match n {
            "1" | "2" | "4" | "5" | "8" | "9" | "10" | "13" | "18" | "19" | "20" | "21" | "23"
            | "25" | "28" | "29" | "40" | "42" | "43" | "45" | "46" | "47" | "48" | "49" | "55"
            | "56" => format_binary,
            "3" | "6" | "11" | "12" | "14" | "15" | "16" | "17" | "22" | "26" | "30" | "31"
            | "32" | "33" | "34" | "35" | "36" | "37" | "38" | "39" | "41" | "44" | "50" | "51"
            | "52" | "54" | "57" | "58" => format_unicode,
            "7" => format_boolean,
            "24" | "53" => format_time,
            "27" => format_integer,
            _ => return None,
        });
    }
    Some(match key {
        "1.2.840.113556.1.4.903" | "1.2.840.113556.1.4.907" | "1.2.840.113556.1.4.1221" => {
            format_binary
        }
        "1.2.840.113556.1.4.904" | "1.2.840.113556.1.4.905" | "1.2.840.113556.1.4.1362" => {
            format_unicode
        }
        "1.2.840.113556.1.4.906" => format_integer,
        "1.3.6.1.1.16.1" | "1.3.6.1.1.16.4" | "2.16.840.1.113719.1.1.4.1.501" => format_uuid,
        "2.16.840.1.113719.1.1.5.1.0"
        | "2.16.840.1.113719.1.1.5.1.12"
        | "2.16.840.1.113719.1.1.5.1.13"
        | "2.16.840.1.113719.1.1.5.1.16" => format_binary,
        "2.16.840.1.113719.1.1.5.1.6"
        | "2.16.840.1.113719.1.1.5.1.14"
        | "2.16.840.1.113719.1.1.5.1.15"
        | "2.16.840.1.113719.1.1.5.1.17"
        | "2.16.840.1.113719.1.1.5.1.23"
        | "2.16.840.1.113719.1.1.5.1.25" => format_unicode,
        "2.16.840.1.113719.1.1.5.1.19" => format_time,
        "2.16.840.1.113719.1.1.5.1.22" => format_integer,
        "supportedldapversion" => format_integer,
        "octetstring" => format_binary,
        "1.2.840.113556.1.4.2" => format_uuid_le,
        "1.2.840.113556.1.4.13"
        | "1.2.840.113556.1.4.26"
        | "1.2.840.113556.1.4.49"
        | "1.2.840.113556.1.4.51"
        | "1.2.840.113556.1.4.52"
        | "1.2.840.113556.1.4.96"
        | "1.2.840.113556.1.4.159"
        | "1.2.840.113556.1.4.662"
        | "1.2.840.113556.1.4.1696" => format_ad_timestamp,
        "1.2.840.113556.1.4.60"
        | "1.2.840.113556.1.4.61"
        | "1.2.840.113556.1.4.74"
        | "1.2.840.113556.1.4.78" => format_ad_timedelta,
        "1.2.840.113556.1.4.146" => format_sid,
        "1.3.6.1.4.1.42.2.27.8.1.17" => format_time_with_0_year,
        _ => return None,
    })
}

/// `find_attribute_helpers`: the attribute's name (as the server gave it), its OID, then its
/// syntax; `format_unicode` with none.
fn find_formatter(attribute: Option<&AttributeType>, name: &str) -> Formatter {
    standard(name)
        .or_else(|| attribute.and_then(|a| standard(&a.oid)))
        .or_else(|| {
            attribute
                .and_then(|a| a.syntax.as_deref())
                .and_then(standard)
        })
        .unwrap_or(format_unicode)
}

fn format_unicode(raw: &[u8]) -> Py {
    match std::str::from_utf8(raw) {
        Ok(text) => Py::Str(text.to_owned()),
        Err(_) => Py::Bytes(raw.to_vec()),
    }
}

fn format_binary(raw: &[u8]) -> Py {
    Py::Bytes(raw.to_vec())
}

/// Python's `int()` of bytes: ASCII white space around an optional sign and digits, single
/// underscores between digits.
pub fn py_int(raw: &[u8]) -> Option<i128> {
    let text = std::str::from_utf8(raw).ok()?;
    let text = text.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b' || c == '\x0c');
    let (negative, digits) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let value: i128 = digits.replace('_', "").parse().ok()?;
    Some(if negative { -value } else { value })
}

fn format_integer(raw: &[u8]) -> Py {
    match py_int(raw) {
        Some(value) => Py::Int(value),
        None => Py::Bytes(raw.to_vec()),
    }
}

fn format_boolean(raw: &[u8]) -> Py {
    match raw {
        b"TRUE" | b"true" | b"True" => Py::Bool(true),
        b"FALSE" | b"false" | b"False" => Py::Bool(false),
        _ => Py::Bytes(raw.to_vec()),
    }
}

fn uuid_text(bytes: &[u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

fn format_uuid(raw: &[u8]) -> Py {
    match <[u8; 16]>::try_from(raw) {
        Ok(bytes) => Py::Str(uuid_text(&bytes)),
        Err(_) => format_unicode(raw),
    }
}

fn format_uuid_le(raw: &[u8]) -> Py {
    match <[u8; 16]>::try_from(raw) {
        Ok(mut bytes) => {
            bytes[0..4].reverse();
            bytes[4..6].reverse();
            bytes[6..8].reverse();
            Py::Str(format!("{{{}}}", uuid_text(&bytes)))
        }
        Err(_) => format_unicode(raw),
    }
}

fn format_sid(raw: &[u8]) -> Py {
    if raw.starts_with(b"S-1-") {
        return Py::Bytes(raw.to_vec());
    }
    let (Some(&revision), Some(&count)) = (raw.first(), raw.get(1)) else {
        return Py::Bytes(raw.to_vec());
    };
    let slice = |from: usize, to: usize| {
        raw.get(from.min(raw.len())..to.min(raw.len()))
            .unwrap_or(&[])
    };
    let authority = slice(2, 8)
        .iter()
        .fold(0u64, |n, b| (n << 8) | u64::from(*b));
    let authority = if authority >= 1 << 32 {
        format!("{authority:#x}")
    } else {
        authority.to_string()
    };
    let mut text = format!("S-{revision}-{authority}");
    for i in 0..usize::from(count) {
        let part = slice(8 + i * 4, 12 + i * 4)
            .iter()
            .rev()
            .fold(0u64, |n, b| (n << 8) | u64::from(*b));
        text.push_str(&format!("-{part}"));
    }
    Py::Str(text)
}

/// Python's `str(datetime)` of an aware time: microseconds only when there are any, and the
/// offset as `+HH:MM`.
fn datetime_text(time: DateTime<FixedOffset>) -> String {
    let mut text = time.format("%Y-%m-%d %H:%M:%S").to_string();
    let micros = time.timestamp_subsec_micros();
    if micros != 0 {
        text.push_str(&format!(".{micros:06}"));
    }
    let seconds = time.offset().local_minus_utc();
    let sign = if seconds < 0 { '-' } else { '+' };
    let seconds = seconds.abs();
    text.push_str(&format!(
        "{sign}{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60
    ));
    if seconds % 60 != 0 {
        text.push_str(&format!(":{:02}", seconds % 60));
    }
    text
}

/// `datetime.max` in UTC.
const MAX_TIME: &str = "9999-12-31 23:59:59.999999+00:00";

/// `datetime.fromtimestamp(seconds, tz=utc)`: the seconds rounded to microseconds half to even,
/// as CPython's `_PyTime_ObjectToTimeval` rounds them. None past `datetime`'s range.
fn from_timestamp(seconds: f64) -> Option<DateTime<Utc>> {
    if !seconds.is_finite() {
        return None;
    }
    let mut whole = seconds.trunc();
    let mut micros = ((seconds - whole) * 1e6).round_ties_even();
    if micros >= 1e6 {
        micros -= 1e6;
        whole += 1.0;
    } else if micros < 0.0 {
        micros += 1e6;
        whole -= 1.0;
    }
    let time = DateTime::from_timestamp(whole as i64, (micros as u32) * 1000)?;
    let year = chrono::Datelike::year(&time);
    (1..=9999).contains(&year).then_some(time)
}

fn ad_time(raw: &[u8]) -> Option<Result<DateTime<Utc>, &'static str>> {
    if raw == b"9223372036854775807" {
        return Some(Err(MAX_TIME));
    }
    let timestamp = py_int(raw)?.abs();
    // timestamp / 10000000.0: the int becomes a float first
    let seconds = timestamp as f64 / 10_000_000.0 - 11_644_473_600.0;
    from_timestamp(seconds).map(Ok)
}

fn format_ad_timestamp(raw: &[u8]) -> Py {
    match ad_time(raw) {
        Some(Ok(time)) => Py::Text(datetime_text(time.fixed_offset())),
        Some(Err(max)) => Py::Text(max.to_owned()),
        None => Py::Bytes(raw.to_vec()),
    }
}

/// Python's `str(timedelta)`.
fn timedelta_text(delta: Duration) -> String {
    let micros = delta.num_microseconds().unwrap_or(i64::MAX);
    let days = micros.div_euclid(86_400_000_000);
    let rest = micros.rem_euclid(86_400_000_000);
    let (seconds, micro) = (rest / 1_000_000, rest % 1_000_000);
    let mut text = String::new();
    if days != 0 {
        let plural = if days.abs() == 1 { "" } else { "s" };
        text.push_str(&format!("{days} day{plural}, "));
    }
    text.push_str(&format!(
        "{}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    ));
    if micro != 0 {
        text.push_str(&format!(".{micro:06}"));
    }
    text
}

fn format_ad_timedelta(raw: &[u8]) -> Py {
    if raw == b"-9223372036854775808" {
        return Py::Text("999999999 days, 23:59:59.999999".to_owned());
    }
    let epoch = Utc
        .with_ymd_and_hms(1601, 1, 1, 0, 0, 0)
        .single()
        .expect("a valid time");
    match ad_time(raw) {
        Some(Ok(time)) => Py::Text(timedelta_text(time - epoch)),
        // ldap3 subtracts whatever it got, and a bytes value fails there; it's kept as it came
        _ => Py::Bytes(raw.to_vec()),
    }
}

/// ldap3's `format_time`: RFC 4517's GeneralizedTime, with a fraction of an hour or a minute.
fn format_time(raw: &[u8]) -> Py {
    parse_generalized(raw)
        .map(|t| Py::Text(datetime_text(t)))
        .unwrap_or_else(|| Py::Bytes(raw.to_vec()))
}

fn format_time_with_0_year(raw: &[u8]) -> Py {
    if raw.starts_with(b"0000") {
        return Py::Bytes(raw.to_vec());
    }
    format_time(raw)
}

fn parse_generalized(raw: &[u8]) -> Option<DateTime<FixedOffset>> {
    let text = std::str::from_utf8(raw).ok()?;
    let re = regex::Regex::new(
        r"^(?P<Year>[0-9]{4})(?P<Month>0[1-9]|1[0-2])(?P<Day>0[1-9]|[12][0-9]|3[01])(?P<Hour>[01][0-9]|2[0-3])(?:(?P<Minute>[0-5][0-9])(?P<Second>[0-5][0-9]|60)?)?(?:[.,](?P<Fraction>[0-9]+))?(?:Z|(?:(?P<Offset>[+-])(?P<OffHour>[01][0-9]|2[0-3])(?P<OffMinute>[0-5][0-9])?))$",
    )
    .expect("a valid pattern");
    let caps = re.captures(text)?;
    let number = |name: &str| {
        caps.name(name)
            .map(|m| m.as_str().parse::<i64>().unwrap_or(0))
    };
    let mut offset = number("OffHour").unwrap_or(0) * 3600 + number("OffMinute").unwrap_or(0) * 60;
    if caps.name("Offset").map(|m| m.as_str()) == Some("-") {
        offset = -offset;
    }
    let mut fraction: f64 = format!("0.{}", caps.name("Fraction").map_or("0", |m| m.as_str()))
        .parse()
        .ok()?;
    let minute = match number("Minute") {
        None => {
            fraction *= 60.0;
            let minute = fraction as i64;
            fraction -= minute as f64;
            minute
        }
        Some(minute) => minute,
    };
    let second = match number("Second") {
        None => {
            fraction *= 60.0;
            let second = fraction as i64;
            fraction -= second as f64;
            second
        }
        // Python's datetime has no leap second
        Some(60) => 59,
        Some(second) => second,
    };
    let micros = (fraction * 1_000_000.0) as u32;
    let date = NaiveDate::from_ymd_opt(
        number("Year")? as i32,
        number("Month")? as u32,
        number("Day")? as u32,
    )?;
    let naive =
        date.and_hms_micro_opt(number("Hour")? as u32, minute as u32, second as u32, micros)?;
    let zone = FixedOffset::east_opt(i32::try_from(offset).ok()?)?;
    zone.from_local_datetime(&naive).single()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_are_written_as_their_python_repr() {
        assert_eq!(
            bytes_repr(b"\x89PNG\r\n'\\\x00\x7f\xff\""),
            "\\x89PNG\\r\\n\\'\\\\\\x00\\x7f\\xff\""
        );
        assert_eq!(bytes_repr(b"it's"), "it's");
        assert_eq!(bytes_repr(b"a\"b"), "a\"b");
    }

    #[test]
    fn integers_read_as_python_s_int_reads_bytes() {
        assert_eq!(py_int(b" 7 "), Some(7));
        assert_eq!(py_int(b"1_000"), Some(1000));
        assert_eq!(py_int(b"-3"), Some(-3));
        assert_eq!(py_int(b"1__0"), None);
        assert_eq!(py_int(b"abc"), None);
        assert_eq!(py_int(b""), None);
    }

    #[test]
    fn times_and_deltas_are_written_as_python_s_str() {
        assert_eq!(
            format_ad_timestamp(b"134065000001234567"),
            Py::Text("2025-11-01 19:46:40.123455+00:00".into())
        );
        assert_eq!(
            format_ad_timestamp(b"0"),
            Py::Text("1601-01-01 00:00:00+00:00".into())
        );
        assert_eq!(
            format_ad_timedelta(b"-36288000000000"),
            Py::Text("42 days, 0:00:00".into())
        );
        assert_eq!(
            format_time(b"202601011230,5+0130"),
            Py::Text("2026-01-01 12:30:30+01:30".into())
        );
        assert_eq!(
            format_time(b"20261301000000Z"),
            Py::Bytes(b"20261301000000Z".to_vec())
        );
    }
}
