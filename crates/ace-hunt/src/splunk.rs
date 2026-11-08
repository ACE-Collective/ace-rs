//! What a Splunk hunt sends: ace3's `SplunkHunt` (`saq/collectors/hunter/splunk_hunter.py`) and
//! the parts of its Splunk client that shape a search (`saq/splunk.py`): the query with its
//! includes and `auto_append`, the `<TIMESPEC>` tokens, the search splunkd runs with its time
//! range, the form that creates the job, and the link to the search in Splunk's web UI. The client
//! that sends them is `ace_mod_splunk::search`.

use std::path::Path;
use std::sync::LazyLock;

use chrono::{DateTime, NaiveDateTime, SecondsFormat, TimeDelta, Utc};
use chrono_tz::Tz;
use regex::Regex;
use serde_json::{Map as JsonMap, Value as Json};

use crate::loader::Hunt;
use crate::query::schedule::timedelta;

/// A Splunk instance a hunt names in `splunk_config`, ace3's `splunk_config_<name>` section, for
/// what shapes a search: the host the web UI link names and the timezone searches are written in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub host: String,
    pub timezone: Tz,
}

/// A hunt's Splunk settings.
pub fn splunk_config(hunt: &Hunt) -> &str {
    setting(hunt, "splunk_config").unwrap_or("default")
}

pub fn user_context(hunt: &Hunt) -> Option<&str> {
    setting(hunt, "splunk_user_context")
}

pub fn app_context(hunt: &Hunt) -> Option<&str> {
    setting(hunt, "splunk_app_context")
}

fn setting<'a>(hunt: &'a Hunt, name: &str) -> Option<&'a str> {
    hunt.config.settings.get(name).and_then(Json::as_str)
}

/// `SplunkHunt.query`: the query or its file's text, with `query_prefix` and `query_suffix`, and
/// each `<include:PATH>` replaced by that file's text without its comment lines. A relative path
/// is read from `home`, ace3's working directory. A missing file stops the replacing, as in ace3.
pub fn query(hunt: &Hunt, home: &Path) -> Result<String, String> {
    let config = &hunt.config;
    let mut result = match (&config.query, &hunt.query_file) {
        (Some(query), _) => query.clone(),
        (None, Some(text)) => text.clone(),
        (None, None) => {
            return Err(format!(
                "no query specified for hunt Hunt({}[splunk])",
                config.name
            ));
        }
    };
    if let Some(prefix) = config.query_prefix.as_deref().filter(|p| !p.is_empty()) {
        result = format!("{prefix}\n{result}");
    }
    if let Some(suffix) = config.query_suffix.as_deref().filter(|s| !s.is_empty()) {
        result = format!("{}\n{suffix}", result.trim_end_matches(char::is_whitespace));
    }
    static INCLUDE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"<include:([^>]+)>").expect("valid"));
    static COMMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?m)^\s*#.*$").expect("valid"));
    // each include is read once, so a file that includes itself can't loop
    for _ in 0..256 {
        let Some(m) = INCLUDE.captures(&result) else {
            break;
        };
        let whole = m[0].to_owned();
        let path = home.join(&m[1]);
        let Ok(text) = std::fs::read_to_string(&path) else {
            break;
        };
        let text = COMMENT.replace_all(text.trim_matches(char::is_whitespace), "");
        result = result.replace(&whole, &text);
    }
    Ok(result)
}

/// `formatted_query`: the query with `auto_append` after a space, unless it ends with it.
pub fn formatted(query: &str, auto_append: &str) -> String {
    if query.ends_with(auto_append) {
        query.to_owned()
    } else {
        format!("{query} {auto_append}")
    }
}

/// `formatted_query_timeless`: the same with no space, for the link.
pub fn formatted_timeless(query: &str, auto_append: &str) -> String {
    if query.ends_with(auto_append) {
        query.to_owned()
    } else {
        format!("{query}{auto_append}")
    }
}

/// One search, as `SplunkHunt.execute_query` builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Search {
    /// The query with its `<TIMESPEC>` tokens filled, when it has any: ace3's `resolved_query`.
    pub resolved: Option<String>,
    /// What the hunt's details record as its query: the resolved query, or the formatted one.
    pub query: String,
    /// The form that creates the job, in ace3's order: `search`, `max_count`, `exec_mode` and the
    /// time range.
    pub form: Vec<(String, String)>,
    /// The search in Splunk's web UI.
    pub link: String,
}

const SPLUNK_TIME: &str = "%m/%d/%Y:%H:%M:%S";

fn wall(time: DateTime<Utc>, tz: Tz) -> String {
    time.with_timezone(&tz).format(SPLUNK_TIME).to_string()
}

/// `datetime.isoformat(sep='T', timespec='auto')` in the instance's timezone.
fn iso(time: DateTime<Utc>, tz: Tz) -> String {
    let local = time.with_timezone(&tz);
    let seconds = if local.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    local.to_rfc3339_opts(seconds, false)
}

/// The search for a hunt's window, as `execute_query` and the client's `queue` and
/// `encoded_query_link` build it.
pub fn search(
    hunt: &Hunt,
    query: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    instance: &Instance,
) -> Result<Search, String> {
    let config = &hunt.config;
    let tz = instance.timezone;
    let formatted_query = formatted(query, &config.auto_append);
    static TOKEN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"<(TIMESPEC\w*)>").expect("valid"));
    let tokens: Vec<String> = TOKEN
        .captures_iter(&formatted_query)
        .map(|c| c[1].to_owned())
        .collect();
    let prefix = if config.use_index_time { "_index_" } else { "" };
    let (text, resolved, search_start, search_end, embed) = if tokens.is_empty() {
        (formatted_query.clone(), None, start, end, true)
    } else {
        let mut ranges: Vec<(String, DateTime<Utc>, DateTime<Utc>)> = Vec::new();
        for (name, range) in config.time_ranges.iter().flatten() {
            let before = range
                .duration_before
                .as_deref()
                .ok_or_else(|| format!("hunt {}: {name} has no duration_before", config.name))?;
            ranges.push((name.clone(), end - timedelta(before)?, end));
        }
        if tokens.iter().any(|t| t == "TIMESPEC") && !ranges.iter().any(|(n, _, _)| n == "TIMESPEC")
        {
            ranges.push(("TIMESPEC".to_owned(), start, end));
        }
        if let Some(token) = tokens
            .iter()
            .find(|t| !ranges.iter().any(|(n, _, _)| n == *t))
        {
            return Err(format!(
                "hunt {}: query contains <{token}> but no time range configured for it",
                config.name
            ));
        }
        let mut text = formatted_query.clone();
        for (name, s, e) in &ranges {
            let spec = format!(
                "{prefix}earliest={} {prefix}latest={}",
                wall(*s, tz),
                wall(*e, tz)
            );
            text = text.replace(&format!("<{name}>"), &spec);
        }
        let s = ranges.iter().map(|r| r.1).min().unwrap_or(start);
        let e = ranges.iter().map(|r| r.2).max().unwrap_or(end);
        (text.clone(), Some(text), s, e, false)
    };

    let link = if resolved.is_some() {
        link(
            &instance.host,
            app_context(hunt),
            &text,
            search_start,
            search_end,
            tz,
            false,
        )
    } else {
        link(
            &instance.host,
            app_context(hunt),
            &formatted_timeless(query, &config.auto_append),
            search_start,
            search_end,
            tz,
            config.use_index_time,
        )
    };

    // SplunkQueryObject.queue
    let mut job = text.clone();
    let trimmed = job.trim_start().to_owned();
    if !trimmed.starts_with('|') {
        let starts_with_search = trimmed
            .get(..6)
            .is_some_and(|h| h.eq_ignore_ascii_case("search"));
        if embed {
            if starts_with_search {
                job = trimmed[6..].to_owned();
            }
            job = format!("{prefix}latest={} {job}", wall(search_end, tz));
            job = format!("{prefix}earliest={} {job}", wall(search_start, tz));
        } else if starts_with_search {
            job = trimmed[6..].trim_start().to_owned();
        }
        job = format!("search {job}");
    }
    let max_count = config
        .max_result_count
        .map(|n| n.to_string())
        .unwrap_or_else(|| "None".to_owned());
    let mut form = vec![
        ("search".to_owned(), job),
        ("max_count".to_owned(), max_count),
        ("exec_mode".to_owned(), "normal".to_owned()),
    ];
    let (earliest, latest) = if config.use_index_time {
        ("index_earliest", "index_latest")
    } else {
        ("earliest_time", "latest_time")
    };
    form.push((earliest.to_owned(), iso(search_start, tz)));
    form.push((latest.to_owned(), iso(search_end, tz)));

    Ok(Search {
        query: resolved.clone().unwrap_or(formatted_query),
        resolved,
        form,
        link,
    })
}

/// The job a correlation's Splunk query creates (`SplunkQuerySource.execute_query`, which calls
/// `SplunkClient.query`): the query with its window put in front, in the times' own offsets as
/// they are, a `search` before it unless it's a generating command, 1000 rows at most, and the
/// window again as the job's `earliest_time` and `latest_time`. ace3's hunts write their window in
/// the instance's timezone; its correlation doesn't.
pub fn correlation_form(
    query: &str,
    start: crate::correlate::time::Time,
    end: crate::correlate::time::Time,
) -> Vec<(String, String)> {
    let mut job = query.to_owned();
    let trimmed = query.trim_start_matches(crate::render::methods::is_space);
    if !trimmed.starts_with('|') {
        if trimmed.to_lowercase().starts_with("search") {
            job = trimmed.chars().skip(6).collect();
        }
        job = format!("latest={} {job}", end.strftime("%m/%d/%Y:%H:%M:%S"));
        job = format!("earliest={} {job}", start.strftime("%m/%d/%Y:%H:%M:%S"));
        job = format!("search {job}");
    }
    vec![
        ("search".to_owned(), job),
        ("max_count".to_owned(), "1000".to_owned()),
        ("exec_mode".to_owned(), "normal".to_owned()),
        ("earliest_time".to_owned(), start.isoformat()),
        ("latest_time".to_owned(), end.isoformat()),
    ]
}

/// `SplunkQuerySource.format_timespec_for_display`: the window as `earliest=` and `latest=` in the
/// instance's timezone, a naive time taken as UTC.
pub fn correlation_timespec(
    start: crate::correlate::time::Time,
    end: crate::correlate::time::Time,
    tz: Tz,
) -> String {
    let f = |t: crate::correlate::time::Time| {
        t.utc()
            .with_timezone(&tz)
            .format("%m/%d/%Y:%H:%M:%S")
            .to_string()
    };
    format!("earliest={} latest={}", f(start), f(end))
}

/// `strip_spl_comments`: the ```comment``` blocks out, a double-quoted string kept as it is.
pub fn strip_comments(query: &str) -> String {
    static COMMENT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?s)"(?:\\.|[^"\\])*"|(\s*)```.*?```(\s*)"#).expect("valid")
    });
    let out = COMMENT.replace_all(query, |c: &regex::Captures<'_>| {
        let (Some(before), Some(after)) = (c.get(1), c.get(2)) else {
            return c[0].to_owned();
        };
        let (before, after) = (before.as_str(), after.as_str());
        if let Some((_, tail)) = after.rsplit_once('\n') {
            format!("\n{tail}")
        } else if let Some((_, tail)) = before.rsplit_once('\n') {
            format!("\n{tail}")
        } else {
            " ".to_owned()
        }
    });
    out.trim_matches(char::is_whitespace).to_owned()
}

/// Python's `time.mktime(t.timetuple())` of a time in `tz`, on a host whose local time is UTC, as
/// ace3's containers' is: the wall clock read as UTC, an hour earlier when the time is in daylight
/// saving, since the tuple's `tm_isdst` says so and C's `mktime` honours it.
fn mktime(time: DateTime<Utc>, tz: Tz) -> i64 {
    use chrono_tz::OffsetComponents;
    let local = time.with_timezone(&tz);
    let wall: NaiveDateTime = local.naive_local();
    wall.and_utc().timestamp() - local.offset().dst_offset().num_seconds()
}

/// `encode_splunk_query_link`.
pub fn link(
    host: &str,
    app: Option<&str>,
    query: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    tz: Tz,
    use_index_time: bool,
) -> String {
    let mut query = strip_comments(query);
    let generating = query.starts_with('|');
    let lower = query.trim_start().to_lowercase();
    if !generating && !lower.starts_with("search") {
        query = format!("search {query}");
    }
    if use_index_time && !generating {
        static SEARCH: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"(?i)^\s*search\s+").expect("valid"));
        let replacement = format!(
            "search _index_earliest={} _index_latest={} ",
            wall(start, tz),
            wall(end, tz)
        );
        query = SEARCH
            .replace(&query, regex::NoExpand(&replacement))
            .into_owned();
    }
    let month = TimeDelta::days(30);
    let (earliest, latest) = if use_index_time {
        (mktime(start - month, tz), mktime(end + month, tz))
    } else {
        (mktime(start, tz), mktime(end, tz))
    };
    let path = match app {
        None | Some("-") => "en-US/app/search/search".to_owned(),
        Some(app) => format!("en-US/app/{app}/search"),
    };
    let params = urlencode(&[
        ("q", query.as_str()),
        ("earliest", &earliest.to_string()),
        ("latest", &latest.to_string()),
    ]);
    format!("https://{host}/{path}?{params}")
}

/// Python's `urllib.parse.quote_plus`: letters, digits and `_.-~` kept, a space as `+`.
pub fn quote_plus(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Python's `urllib.parse.urlencode` of pairs.
pub fn urlencode<K: AsRef<str>, V: AsRef<str>>(pairs: &[(K, V)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k.as_ref()), quote_plus(v.as_ref())))
        .collect::<Vec<_>>()
        .join("&")
}

/// `saq.splunk.extract_event_timestamp`: a row's `_time`, its first 19 characters read as UTC, or
/// `now` when it has none or it doesn't read.
pub fn event_time(row: &JsonMap<String, Json>, now: DateTime<Utc>) -> DateTime<Utc> {
    row.get("_time")
        .and_then(Json::as_str)
        .and_then(|t| t.get(..19).or(Some(t)))
        .and_then(|t| NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S").ok())
        .map(|t| t.and_utc())
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_go_and_quoted_text_stays() {
        assert_eq!(strip_comments("a ```x``` b"), "a b");
        assert_eq!(strip_comments("a\n  ```x```\n  b"), "a\n  b");
        assert_eq!(strip_comments(r#"a "```x```" b"#), r#"a "```x```" b"#);
        assert_eq!(strip_comments("a ```open"), "a ```open");
    }

    #[test]
    fn forms_encode_as_python_s_urlencode() {
        assert_eq!(quote_plus("a b*`~/"), "a+b%2A%60~%2F");
        assert_eq!(urlencode(&[("q", "x=1"), ("n", "2")]), "q=x%3D1&n=2");
    }
}
