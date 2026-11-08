//! Times as ace3's correlation reads and compares them (`commands._parse_time_value`): an epoch in
//! seconds, milliseconds or nanoseconds, ISO 8601 as Python's `datetime.fromisoformat` reads it, or
//! a `strptime` format. A Python datetime is aware or naive, and the two don't compare; [`Time`]
//! keeps that apart, with an aware time's own offset, which `strftime` writes its fields in.

use std::cmp::Ordering;

use chrono::{
    DateTime, Datelike, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, TimeDelta, Timelike, Utc,
};

use crate::render::py::float_repr;
use crate::value::Value;

/// A Python datetime: aware, with its offset, or naive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Time {
    Aware(DateTime<FixedOffset>),
    Naive(NaiveDateTime),
}

impl From<DateTime<Utc>> for Time {
    fn from(t: DateTime<Utc>) -> Time {
        Time::Aware(t.fixed_offset())
    }
}

impl Time {
    /// `self + delta`, or Python's OverflowError past year 9999 or before year 1.
    pub fn plus(self, delta: TimeDelta) -> Result<Time, String> {
        let overflow = || "OverflowError: date value out of range".to_owned();
        let out = match self {
            Time::Aware(t) => Time::Aware(t.checked_add_signed(delta).ok_or_else(overflow)?),
            Time::Naive(t) => Time::Naive(t.checked_add_signed(delta).ok_or_else(overflow)?),
        };
        if !(1..=9999).contains(&out.local().year()) {
            return Err(overflow());
        }
        Ok(out)
    }

    pub fn minus(self, delta: TimeDelta) -> Result<Time, String> {
        self.plus(-delta)
    }

    /// The fields as the time's own clock reads them.
    pub fn local(&self) -> NaiveDateTime {
        match self {
            Time::Aware(t) => t.naive_local(),
            Time::Naive(t) => *t,
        }
    }

    /// The instant, taking a naive time as UTC, as ace4's hunter's container runs in UTC and
    /// Python's `astimezone` takes a naive time as the system's local time.
    pub fn utc(&self) -> DateTime<Utc> {
        match self {
            Time::Aware(t) => t.with_timezone(&Utc),
            Time::Naive(t) => t.and_utc(),
        }
    }

    /// Python's comparison: by instant between aware times, by fields between naive ones, and a
    /// TypeError between the two.
    pub fn py_cmp(&self, other: &Time) -> Result<Ordering, String> {
        match (self, other) {
            (Time::Aware(a), Time::Aware(b)) => Ok(a.cmp(b)),
            (Time::Naive(a), Time::Naive(b)) => Ok(a.cmp(b)),
            _ => Err("TypeError: can't compare offset-naive and offset-aware datetimes".to_owned()),
        }
    }

    /// `strftime(format)` over the time's own fields.
    pub fn strftime(&self, format: &str) -> String {
        self.local().format(format).to_string()
    }

    /// `isoformat()`: `2024-06-01T12:00:00+00:00`, microseconds when there are any.
    pub fn isoformat(&self) -> String {
        let local = self.local();
        let mut out = local.format("%Y-%m-%dT%H:%M:%S").to_string();
        let micros = local.and_utc().timestamp_subsec_micros();
        if micros != 0 {
            out.push_str(&format!(".{micros:06}"));
        }
        if let Time::Aware(t) = self {
            out.push_str(&offset_text(t.offset().local_minus_utc()));
        }
        out
    }
}

impl Time {
    /// The time as ace3 saves one in a root's details, `EVENT_TIME_FORMAT_JSON_TZ`
    /// (`%Y-%m-%dT%H:%M:%S.%f%z`): `2026-11-01T10:53:00.000000+0000`, no offset for a naive time.
    pub fn details_format(&self) -> String {
        let local = self.local();
        let mut out = local.format("%Y-%m-%dT%H:%M:%S").to_string();
        out.push_str(&format!(
            ".{:06}",
            local.and_utc().timestamp_subsec_micros()
        ));
        if let Time::Aware(t) = self {
            let seconds = t.offset().local_minus_utc();
            let sign = if seconds < 0 { '-' } else { '+' };
            let s = seconds.unsigned_abs();
            out.push_str(&format!("{sign}{:02}{:02}", s / 3600, s / 60 % 60));
            if s % 60 != 0 {
                out.push_str(&format!("{:02}", s % 60));
            }
        }
        out
    }
}

/// An offset as Python's `isoformat` writes it: `+05:30`, with seconds when it has any.
fn offset_text(seconds: i32) -> String {
    let sign = if seconds < 0 { '-' } else { '+' };
    let s = seconds.unsigned_abs();
    let (h, m, sec) = (s / 3600, s / 60 % 60, s % 60);
    if sec == 0 {
        format!("{sign}{h:02}:{m:02}")
    } else {
        format!("{sign}{h:02}:{m:02}:{sec:02}")
    }
}

/// `_parse_time_value(value, format)`.
pub fn parse_time_value(value: &Value, format: Option<&str>) -> Result<Time, String> {
    match format {
        Some("epoch") => from_timestamp(py_float(value)?),
        Some("epoch_ms") => from_timestamp(py_float(value)? / 1000.0),
        Some("epoch_ns") => from_timestamp(py_float(value)? / 1_000_000_000.0),
        Some(f) if !f.is_empty() && f != "iso8601" => strptime(&str_of(value), f),
        _ => fromisoformat(&str_of(value)),
    }
}

fn str_of(value: &Value) -> String {
    crate::render::py::str_of(&crate::render::py::to_template(value))
}

/// Python's `float(value)`.
pub fn py_float(value: &Value) -> Result<f64, String> {
    match value {
        Value::Bool(b) => Ok(f64::from(u8::from(*b))),
        Value::Int(i) => Ok(*i as f64),
        Value::Float(f) => Ok(*f),
        Value::Str(s) => parse_float(s).ok_or_else(|| {
            format!(
                "ValueError: could not convert string to float: {}",
                crate::value::py_repr(s)
            )
        }),
        Value::Null => Err(
            "TypeError: float() argument must be a string or a real number, not 'NoneType'"
                .to_owned(),
        ),
        other => Err(format!(
            "TypeError: float() argument must be a string or a real number, not '{}'",
            other.type_name()
        )),
    }
}

/// A string as Python's `float()` reads it: whitespace around it, `_` between digits, `inf`,
/// `infinity` and `nan` in any case.
fn parse_float(text: &str) -> Option<f64> {
    let t = text.trim_matches(crate::render::methods::is_space);
    let bytes = t.as_bytes();
    let mut cleaned = String::with_capacity(t.len());
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'_' {
            let digit = |j: Option<&u8>| j.is_some_and(u8::is_ascii_digit);
            if !(i > 0 && digit(bytes.get(i - 1)) && digit(bytes.get(i + 1))) {
                return None;
            }
            continue;
        }
        cleaned.push(char::from(b));
    }
    if !t.is_ascii() {
        return None;
    }
    let body = cleaned.trim_start_matches(['+', '-']);
    let lower = body.to_ascii_lowercase();
    if lower == "inf" || lower == "infinity" || lower == "nan" {
        return cleaned.parse().ok().or_else(|| {
            let negative = cleaned.starts_with('-');
            Some(match (lower.as_str(), negative) {
                ("nan", _) => f64::NAN,
                (_, true) => f64::NEG_INFINITY,
                _ => f64::INFINITY,
            })
        });
    }
    // only digits, a point, an exponent and signs: Rust also reads forms Python doesn't
    if !body
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
        || body.is_empty()
    {
        return None;
    }
    cleaned.parse().ok()
}

/// `datetime.fromtimestamp(t, tz=timezone.utc)`, rounding to the microsecond as Python does.
pub fn from_timestamp(t: f64) -> Result<Time, String> {
    if t.is_nan() {
        return Err("ValueError: Invalid value NaN (not a number)".to_owned());
    }
    if t.is_infinite() {
        return Err("OverflowError: cannot convert float infinity to integer".to_owned());
    }
    let mut whole = t.trunc();
    let frac = t - whole;
    let mut us = round_half_even(frac * 1e6);
    if us >= 1_000_000.0 {
        whole += 1.0;
        us -= 1_000_000.0;
    } else if us < 0.0 {
        whole -= 1.0;
        us += 1_000_000.0;
    }
    let out_of_range = || {
        format!(
            "ValueError: year is out of range for timestamp {}",
            float_repr(t)
        )
    };
    if whole.abs() > 1e15 {
        return Err(out_of_range());
    }
    let time = DateTime::<Utc>::from_timestamp(whole as i64, (us as u32) * 1000)
        .ok_or_else(out_of_range)?;
    if !(1..=9999).contains(&time.year()) {
        return Err(out_of_range());
    }
    Ok(Time::from(time))
}

fn round_half_even(x: f64) -> f64 {
    let r = x.round();
    if (x - x.trunc()).abs() == 0.5 && r % 2.0 != 0.0 {
        r - x.signum()
    } else {
        r
    }
}

fn invalid_iso(text: &str) -> String {
    format!(
        "ValueError: Invalid isoformat string: {}",
        crate::value::py_repr(text)
    )
}

/// `datetime.fromisoformat(text)` as Python 3.11 and later read it: a date (`2024-06-01` or
/// `20240601`), then any one character and a time (`HH`, `HH:MM`, `HH:MM:SS` with a fraction after
/// `.` or `,`, or the same without colons), and an offset (`Z`, `+HH`, `+HH:MM`, `+HHMM`, with
/// seconds). ISO week dates (`2024-W22-6`) and a time of `24:00` aren't read.
pub fn fromisoformat(text: &str) -> Result<Time, String> {
    let err = || invalid_iso(text);
    let chars: Vec<char> = text.chars().collect();
    let digits = |s: &[char]| s.iter().all(char::is_ascii_digit);
    let num = |s: &[char]| -> u32 { s.iter().collect::<String>().parse().unwrap_or(0) };
    let (date, rest) = if chars.len() >= 10 && chars[4] == '-' && chars[7] == '-' {
        if !(digits(&chars[0..4]) && digits(&chars[5..7]) && digits(&chars[8..10])) {
            return Err(err());
        }
        (
            (num(&chars[0..4]), num(&chars[5..7]), num(&chars[8..10])),
            &chars[10..],
        )
    } else if chars.len() >= 8 && digits(&chars[0..8]) {
        (
            (num(&chars[0..4]), num(&chars[4..6]), num(&chars[6..8])),
            &chars[8..],
        )
    } else {
        return Err(err());
    };
    let day = NaiveDate::from_ymd_opt(date.0 as i32, date.1, date.2).ok_or_else(|| {
        if date.1 == 0 || date.1 > 12 {
            "ValueError: month must be in 1..12".to_owned()
        } else {
            "ValueError: day is out of range for month".to_owned()
        }
    })?;
    if date.0 == 0 {
        return Err("ValueError: year 0 is out of range".to_owned());
    }
    if rest.is_empty() {
        return Ok(Time::Naive(day.and_time(NaiveTime::MIN)));
    }
    // the separator, any one character, then the time
    let time = &rest[1..];
    if time.is_empty() {
        return Err(err());
    }
    let tz_at = time
        .iter()
        .position(|c| matches!(c, '+' | '-' | 'Z'))
        .unwrap_or(time.len());
    let (clock, zone) = time.split_at(tz_at);
    let (h, m, s, us) = parse_clock(clock).ok_or_else(err)?;
    let naive = day.and_time(NaiveTime::from_hms_micro_opt(h, m, s, us).ok_or_else(|| {
        if h > 23 {
            "ValueError: hour must be in 0..23".to_owned()
        } else if m > 59 {
            "ValueError: minute must be in 0..59".to_owned()
        } else {
            "ValueError: second must be in 0..59".to_owned()
        }
    })?);
    if zone.is_empty() {
        return Ok(Time::Naive(naive));
    }
    let offset = parse_zone(zone).ok_or_else(err)?;
    let offset = FixedOffset::east_opt(offset).ok_or_else(err)?;
    Ok(Time::Aware(
        naive.and_local_timezone(offset).single().ok_or_else(err)?,
    ))
}

/// `HH[:MM[:SS[.f]]]` or `HH[MM[SS[.f]]]`, a fraction's digits past six dropped.
fn parse_clock(clock: &[char]) -> Option<(u32, u32, u32, u32)> {
    let (main, fraction) = match clock.iter().position(|c| matches!(c, '.' | ',')) {
        Some(p) => (&clock[..p], Some(&clock[p + 1..])),
        None => (clock, None),
    };
    let two = |s: &[char]| -> Option<u32> {
        (s.len() == 2 && s.iter().all(char::is_ascii_digit))
            .then(|| s.iter().collect::<String>().parse().ok())
            .flatten()
    };
    let fields: Vec<u32> = if main.contains(&':') {
        main.split(|c| *c == ':').map(two).collect::<Option<_>>()?
    } else if main.len() % 2 == 0 {
        main.chunks(2).map(two).collect::<Option<_>>()?
    } else {
        return None;
    };
    if fields.is_empty() || fields.len() > 3 {
        return None;
    }
    let mut us = 0;
    if let Some(fraction) = fraction {
        if fields.len() != 3 || fraction.is_empty() || !fraction.iter().all(char::is_ascii_digit) {
            return None;
        }
        let kept: String = fraction.iter().take(6).collect();
        let n: u32 = kept.parse().ok()?;
        us = n * 10u32.pow(6 - kept.len() as u32);
    }
    let field = |i: usize| fields.get(i).copied().unwrap_or(0);
    Some((field(0), field(1), field(2), us))
}

/// `Z`, or a sign and `HH[:MM[:SS[.f]]]`, in seconds east.
fn parse_zone(zone: &[char]) -> Option<i32> {
    if zone == ['Z'] {
        return Some(0);
    }
    let sign = match zone.first()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let (h, m, s, _) = parse_clock(&zone[1..])?;
    if h > 23 || m > 59 || s > 59 {
        return None;
    }
    Some(sign * (h * 3600 + m * 60 + s) as i32)
}

/// `datetime.strptime(text, format)`, with chrono's reading of the format, which is Python's for
/// the directives a time needs (`%Y %m %d %H %M %S %f %z %b`, ...). A format with only a date gives
/// midnight, as Python's does.
pub fn strptime(text: &str, format: &str) -> Result<Time, String> {
    let err = || {
        format!(
            "ValueError: time data {} does not match format {}",
            crate::value::py_repr(text),
            crate::value::py_repr(format)
        )
    };
    if format.contains("%z") || format.contains("%:z") {
        return DateTime::parse_from_str(text, format)
            .map(Time::Aware)
            .map_err(|_| err());
    }
    match NaiveDateTime::parse_from_str(text, format) {
        Ok(t) => Ok(Time::Naive(t)),
        Err(_) => NaiveDate::parse_from_str(text, format)
            .map(|d| Time::Naive(d.and_time(NaiveTime::MIN)))
            .map_err(|_| err()),
    }
}

/// A time's fields, for display: `HH:MM:SS`.
pub fn clock_text(t: &DateTime<Utc>) -> String {
    format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aware(text: &str) -> Time {
        Time::Aware(DateTime::parse_from_rfc3339(text).expect("a time"))
    }

    #[test]
    fn iso_times_read_as_python_reads_them() {
        assert_eq!(
            fromisoformat("2024-06-01T00:00:00+00:00"),
            Ok(aware("2024-06-01T00:00:00+00:00"))
        );
        assert_eq!(
            fromisoformat("2024-06-01T00:00:00Z"),
            Ok(aware("2024-06-01T00:00:00+00:00"))
        );
        assert_eq!(
            fromisoformat("2024-06-01 00:00:00.123+0530"),
            Ok(aware("2024-06-01T00:00:00.123+05:30"))
        );
        assert_eq!(
            fromisoformat("20240601T000000").map(|t| t.isoformat()),
            Ok("2024-06-01T00:00:00".to_owned())
        );
        assert_eq!(
            fromisoformat("2024-06-01").map(|t| t.isoformat()),
            Ok("2024-06-01T00:00:00".to_owned())
        );
        assert_eq!(
            fromisoformat("2024-06-01T12:30").map(|t| t.isoformat()),
            Ok("2024-06-01T12:30:00".to_owned())
        );
        assert_eq!(
            fromisoformat("2024-06-01T12:30:15.1234567-04:00").map(|t| t.isoformat()),
            Ok("2024-06-01T12:30:15.123456-04:00".to_owned())
        );
        assert!(fromisoformat("1717200000").is_err());
        assert!(fromisoformat("not a time").is_err());
        assert!(fromisoformat("2024-13-01").is_err());
    }

    #[test]
    fn epochs_round_to_the_microsecond_as_python_does() {
        assert_eq!(
            parse_time_value(&Value::str("1717200000"), Some("epoch")).map(|t| t.isoformat()),
            Ok("2024-06-01T00:00:00+00:00".to_owned())
        );
        assert_eq!(
            parse_time_value(&Value::str("1717200000123"), Some("epoch_ms")).map(|t| t.isoformat()),
            Ok("2024-06-01T00:00:00.123000+00:00".to_owned())
        );
        assert_eq!(
            parse_time_value(&Value::Int(-1), Some("epoch")).map(|t| t.isoformat()),
            Ok("1969-12-31T23:59:59+00:00".to_owned())
        );
        assert_eq!(
            parse_time_value(&Value::str(" 1_000 "), Some("epoch")).map(|t| t.isoformat()),
            Ok("1970-01-01T00:16:40+00:00".to_owned())
        );
        assert!(parse_time_value(&Value::str("not-a-timestamp"), Some("epoch")).is_err());
        assert!(parse_time_value(&Value::str("nan"), Some("epoch")).is_err());
        assert!(parse_time_value(&Value::str("1e20"), Some("epoch")).is_err());
    }

    #[test]
    fn aware_and_naive_times_do_not_compare() {
        let a = aware("2024-06-01T00:00:00+00:00");
        let n = fromisoformat("2024-06-01T00:00:00").expect("a time");
        assert!(a.py_cmp(&n).is_err());
        assert_eq!(
            a.py_cmp(&aware("2024-06-01T02:00:00+02:00")),
            Ok(Ordering::Equal)
        );
    }

    #[test]
    fn strptime_reads_a_format() {
        assert_eq!(
            strptime("06/01/2024 10:00", "%m/%d/%Y %H:%M").map(|t| t.isoformat()),
            Ok("2024-06-01T10:00:00".to_owned())
        );
        assert_eq!(
            strptime("2024-06-01", "%Y-%m-%d").map(|t| t.isoformat()),
            Ok("2024-06-01T00:00:00".to_owned())
        );
        assert!(strptime("x", "%Y").is_err());
    }
}
