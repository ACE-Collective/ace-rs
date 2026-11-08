//! The query as the module sends it, and the observables it takes from the rows that come back:
//! `BaseAPIAnalyzer.build_target_query` and `extract_result_observables`
//! (`saq/modules/api_analysis.py`), `SplunkQueryObject.queue` (`saq/splunk.py`) and the shared
//! extraction in `saq/query/extraction.py`, for the mapping options the port reads.

use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

use ace_results::{NewObservable, ObservableKind};
use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value};

/// One field of a row to turn into observables, as an entry of ace3's `observable_mapping`.
/// ace3's other options (several fields, value templates, files, relationships, display values
/// and the rest) aren't ported; a mapping that uses one fails to load.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservableMapping {
    /// The row's field. A multivalue field gives an observable per value.
    pub field: String,
    /// The observable type the values become.
    #[serde(rename = "type")]
    pub kind: ObservableKind,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub directives: Vec<String>,
    /// Gives each observable the row's `_time`.
    #[serde(default)]
    pub time: bool,
    /// Values to skip, as regular expressions that match the whole value.
    #[serde(default)]
    pub ignored_values: Vec<String>,
    /// The label the alert view shows in place of the type's name, such as `Source IP`.
    #[serde(default)]
    pub display_type: Option<String>,
}

/// A mapping with its patterns compiled.
pub(crate) struct Mapping {
    pub(crate) spec: ObservableMapping,
    ignored: Vec<Regex>,
}

impl Mapping {
    pub(crate) fn new(spec: &ObservableMapping) -> Result<Mapping, String> {
        Ok(Mapping {
            spec: spec.clone(),
            ignored: whole_value_patterns(&spec.ignored_values)?,
        })
    }
}

/// Patterns that match a whole value, as Python's `re.fullmatch`.
pub(crate) fn whole_value_patterns(patterns: &[String]) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|p| {
            Regex::new(&format!(r"\A(?:{p})\z"))
                .map_err(|e| format!("ignored value pattern {p:?}: {e}"))
        })
        .collect()
}

/// ace3's query tokens other than `<O_VALUE>` and `<O_TYPE>`, which the port doesn't fill.
static UNFILLED_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<(?:O_[A-Z0-9_]+|observable\.[^>]+|[A-Z0-9_]*TIMESPEC[A-Z0-9_]*)>")
        .expect("a valid pattern")
});

/// The first token in `query` the port doesn't fill, such as `<O_TIMESPEC>`.
pub(crate) fn unfilled_token(query: &str) -> Option<&str> {
    UNFILLED_TOKEN
        .find_iter(query)
        .map(|m| m.as_str())
        .find(|token| !matches!(*token, "<O_VALUE>" | "<O_TYPE>"))
}

/// The query with the observable in it: `<O_TYPE>` is its type and `<O_VALUE>` its value, with
/// backslashes and quotes escaped (`SplunkAPIAnalyzer._escape_value`).
pub(crate) fn fill_query(query: &str, kind: ObservableKind, value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\'', "\\'");
    query
        .replace("<O_TYPE>", kind.as_str())
        .replace("<O_VALUE>", &escaped)
}

/// The search splunkd runs: the query with `search ` in front, unless it starts with a
/// generating command (`|`). A query that already starts with `search` loses it first, as
/// `SplunkQueryObject.queue` does it.
pub(crate) fn search_text(query: &str) -> String {
    let trimmed = query.trim_start();
    if trimmed.starts_with('|') {
        return query.to_owned();
    }
    let rest = match trimmed.get(.."search".len()) {
        Some(head) if head.eq_ignore_ascii_case("search") => &trimmed["search".len()..],
        _ => query,
    };
    format!("search {rest}")
}

/// The columns of a `| table` command, so the rows show in that order
/// (`SplunkAPIAnalyzer.process_query_results`).
pub(crate) fn table_columns(query: &str) -> Option<Vec<String>> {
    // Python's `$` also matches before a final newline
    static TABLE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\|\s*table\s+(.+?)(?:\||\n?\z)").expect("a valid pattern")
    });
    let columns = TABLE.captures(query)?.get(1)?.as_str();
    Some(
        columns
            .split_whitespace()
            .map(|c| c.trim().trim_end_matches(',').to_owned())
            .collect(),
    )
}

/// A duration in ace3's `DD:HH:MM:SS` form, read from the right, so `30` is 30 seconds and
/// `1:00:00` an hour (`saq.util.time.create_timedelta`).
pub(crate) fn parse_timespec(text: &str) -> Result<Duration, String> {
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() > 4 {
        return Err(format!("{text:?} has more parts than DD:HH:MM:SS"));
    }
    let mut seconds: u64 = 0;
    for (part, unit) in parts.iter().rev().zip([1, 60, 3600, 86400]) {
        let value: u64 = part
            .trim()
            .parse()
            .map_err(|_| format!("{text:?} isn't DD:HH:MM:SS"))?;
        seconds += value * unit;
    }
    Ok(Duration::from_secs(seconds))
}

/// A row's `_time`, read as UTC from its first 19 characters, or `now` when it has none
/// (`saq.splunk.extract_event_timestamp`).
pub(crate) fn event_time(row: &Map<String, Value>, now: DateTime<Utc>) -> DateTime<Utc> {
    row.get("_time")
        .and_then(Value::as_str)
        .and_then(|t| t.get(..19))
        .and_then(|t| NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S").ok())
        .map(|t| t.and_utc())
        .unwrap_or(now)
}

/// Whether a field counts as absent: null, blank text, or an empty list or object.
fn is_blank(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// A field's values as text, one per value of a multivalue field.
fn values(value: &Value) -> Vec<String> {
    let one = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    };
    match value {
        Value::Array(items) => items.iter().filter_map(one).collect(),
        other => one(other).into_iter().collect(),
    }
}

/// Whether ace3 would make an observable of this type from the value. Only IP addresses are
/// checked.
fn valid_value(kind: ObservableKind, value: &str) -> bool {
    !kind.is_subtype_of(ObservableKind::Ip) || value.trim().parse::<IpAddr>().is_ok()
}

/// The observables a row's mapped fields give, added to `out` in mapping order. One with the
/// type, value and time of an observable already there is merged into it, as ace3's analysis
/// keeps one of each.
pub(crate) fn add_observables(
    row: &Map<String, Value>,
    mappings: &[Mapping],
    ignored: &[Regex],
    now: DateTime<Utc>,
    out: &mut Vec<NewObservable>,
) {
    let time = event_time(row, now);
    for mapping in mappings {
        let spec = &mapping.spec;
        let Some(value) = row.get(&spec.field).filter(|v| !is_blank(v)) else {
            continue;
        };
        for value in values(value) {
            if value.is_empty()
                || ignored.iter().any(|p| p.is_match(&value))
                || mapping.ignored.iter().any(|p| p.is_match(&value))
            {
                continue;
            }
            if !valid_value(spec.kind, &value) {
                tracing::warn!(
                    "unable to create observable {} with value {value}",
                    spec.kind
                );
                continue;
            }
            let time = spec.time.then_some(time);
            let index = match out
                .iter()
                .position(|o| o.kind == spec.kind && o.value == value && o.time == time)
            {
                Some(index) => index,
                None => {
                    let mut observable = NewObservable::new(spec.kind, value);
                    observable.time = time;
                    out.push(observable);
                    out.len() - 1
                }
            };
            let observable = &mut out[index];
            for tag in &spec.tags {
                if !observable.tags.contains(tag) {
                    observable.tags.push(tag.clone());
                }
            }
            for directive in &spec.directives {
                if !observable.directives.contains(directive) {
                    observable.directives.push(directive.clone());
                }
            }
            // ace3's mapping sets it on the one observable, so the last mapping with one names it
            if let Some(display_type) = &spec.display_type {
                observable.display_type = Some(display_type.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_observable_fills_the_query_escaped() {
        let query = r#"index=x hostname="<O_VALUE>" type=<O_TYPE>"#;
        assert_eq!(
            fill_query(query, ObservableKind::Fqdn, r#"a"b\c'd"#),
            r#"index=x hostname="a\"b\\c\'d" type=fqdn"#
        );
    }

    #[test]
    fn unfilled_tokens_are_found() {
        assert_eq!(unfilled_token("x=<O_VALUE> <O_TYPE>"), None);
        assert_eq!(
            unfilled_token("x=<O_VALUE> <O_TIMESPEC>"),
            Some("<O_TIMESPEC>")
        );
        assert_eq!(unfilled_token("x=<O_VALUE1>"), Some("<O_VALUE1>"));
        assert_eq!(
            unfilled_token("x=<observable.value>"),
            Some("<observable.value>")
        );
        assert_eq!(unfilled_token("x <TIMESPEC>"), Some("<TIMESPEC>"));
        assert_eq!(unfilled_token("x | where a<b> c"), None);
    }

    #[test]
    fn the_search_starts_with_search() {
        assert_eq!(search_text("index=x\n"), "search index=x\n");
        assert_eq!(search_text("search index=x"), "search  index=x");
        assert_eq!(search_text("  | tstats count"), "  | tstats count");
    }

    #[test]
    fn table_columns_come_from_the_query() {
        assert_eq!(
            table_columns("index=x | table a, b c | sort a"),
            Some(vec!["a".into(), "b".into(), "c".into()])
        );
        assert_eq!(
            table_columns("index=x | TABLE a b\n"),
            Some(vec!["a".into(), "b".into()])
        );
        assert_eq!(table_columns("index=x | stats count"), None);
    }

    #[test]
    fn timespecs_read_from_the_right() {
        assert_eq!(parse_timespec("30"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_timespec("01:00"), Ok(Duration::from_secs(60)));
        assert_eq!(
            parse_timespec("00:24:00:00"),
            Ok(Duration::from_secs(86400))
        );
        assert_eq!(parse_timespec("1:00:00:01"), Ok(Duration::from_secs(86401)));
        assert!(parse_timespec("1:2:3:4:5").is_err());
        assert!(parse_timespec("soon").is_err());
    }

    #[test]
    fn rows_give_observables_once_each() {
        let mappings: Vec<Mapping> = [
            json!({"field": "src_ip", "type": "ip", "tags": ["proxy"], "display_type": "Source IP"}),
            json!({"field": "user", "type": "email_address", "ignored_values": ["-"]}),
            json!({"field": "dest", "type": "fqdn", "time": true}),
            json!({"field": "dest_ip", "type": "ip", "display_type": "Destination IP"}),
        ]
        .iter()
        .map(|m| {
            Mapping::new(&serde_json::from_value(m.clone()).expect("a mapping")).expect("compiles")
        })
        .collect();
        let rows = [
            json!({"_time": "2026-10-30T14:02:11.000+00:00", "src_ip": "192.0.2.10", "user": "-", "dest": ["a.example.com", "b.example.com"]}),
            json!({"_time": "2026-10-30T14:05:00.000+00:00", "src_ip": "192.0.2.10", "user": "alice@example.com", "dest": "a.example.com", "dest_ip": "192.0.2.10"}),
            json!({"src_ip": "not an address", "user": "  "}),
        ];
        let now = DateTime::from_timestamp(1_767_225_600, 0).expect("a time");
        let mut out = Vec::new();
        for row in &rows {
            add_observables(
                row.as_object().expect("an object"),
                &mappings,
                &[],
                now,
                &mut out,
            );
        }
        let seen: Vec<String> = out
            .iter()
            .map(|o| {
                format!(
                    "{}:{} {:?} {:?} {:?}",
                    o.kind,
                    o.value,
                    o.time.map(|t| t.to_rfc3339()),
                    o.tags,
                    o.display_type,
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                // the second row's dest_ip is the same address, and its mapping's label is the last
                r#"ip:192.0.2.10 None ["proxy"] Some("Destination IP")"#,
                r#"fqdn:a.example.com Some("2026-10-30T14:02:11+00:00") [] None"#,
                r#"fqdn:b.example.com Some("2026-10-30T14:02:11+00:00") [] None"#,
                r#"email_address:alice@example.com None [] None"#,
                r#"fqdn:a.example.com Some("2026-10-30T14:05:00+00:00") [] None"#,
            ]
        );
    }
}
