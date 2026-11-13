//! The link from a run to the site's own log search: ace3's `saq/svs/log_search.py` and its
//! `svs.log_search_url` check. ACE builds the link from the overlay's template and never queries it.

use chrono::{DateTime, Utc};

/// The names a template may use: ace3's `SVS_LOG_SEARCH_FIELDS`.
pub const FIELDS: [&str; 5] = ["run_uuid", "marker", "test_guid", "earliest", "latest"];

/// A piece of a template.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    Text(String),
    Field(&'static str),
}

/// `svs.log_search_url`, checked as ace3's configuration checks it: an http or https URL, since it becomes
/// a link, whose `{name}` fields are only `FIELDS`, with no conversion or format spec, and whose braces are
/// otherwise written `{{` and `}}`, as Python's `str.format` reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSearchTemplate {
    template: String,
    pieces: Vec<Piece>,
}

/// What a run's search is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSearch<'a> {
    pub run_uuid: &'a str,
    pub marker: &'a str,
    pub test_guid: &'a str,
    pub times: RunTimes,
}

/// The times of a run that its search window is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunTimes {
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub attribution_ends_at: Option<DateTime<Utc>>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
}

impl LogSearchTemplate {
    /// The template, None for none (unset or empty), or why it's refused.
    pub fn parse(template: Option<&str>) -> Result<Option<Self>, String> {
        let Some(template) = template.filter(|template| !template.is_empty()) else {
            return Ok(None);
        };
        let lower = template.to_lowercase();
        if !(lower.starts_with("https://") || lower.starts_with("http://")) {
            return Err("svs.log_search_url must be an http or https URL".to_owned());
        }
        let invalid = |why: &str| format!("svs.log_search_url is not a valid template: {why}");
        let refused = |name: &str| {
            format!(
                "svs.log_search_url may only use {{{}}} (braces themselves are written {{{{ and }}}}), \
                 not {{{name}}}",
                FIELDS.join("}, {")
            )
        };
        let mut pieces = Vec::new();
        let mut text = String::new();
        let mut chars = template.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '{' if chars.peek() == Some(&'{') => {
                    chars.next();
                    text.push('{');
                }
                '}' if chars.peek() == Some(&'}') => {
                    chars.next();
                    text.push('}');
                }
                '}' => return Err(invalid("Single '}' encountered in format string")),
                '{' => {
                    let mut field = String::new();
                    let mut closed = false;
                    for c in chars.by_ref() {
                        if c == '}' {
                            closed = true;
                            break;
                        }
                        if c == '{' {
                            return Err(invalid("unexpected '{' in field name"));
                        }
                        field.push(c);
                    }
                    if !closed {
                        return Err(invalid("expected '}' before end of string"));
                    }
                    // a conversion (!r) or a format spec (:>12) is refused, whatever the name
                    let name = field.split(['!', ':']).next().unwrap_or_default();
                    let known = FIELDS.iter().find(|known| **known == field);
                    match known {
                        Some(known) => {
                            if !text.is_empty() {
                                pieces.push(Piece::Text(std::mem::take(&mut text)));
                            }
                            pieces.push(Piece::Field(known));
                        }
                        None => return Err(refused(name)),
                    }
                }
                c => text.push(c),
            }
        }
        if !text.is_empty() {
            pieces.push(Piece::Text(text));
        }
        Ok(Some(LogSearchTemplate {
            template: template.to_owned(),
            pieces,
        }))
    }

    /// The template as the overlay wrote it.
    pub fn as_str(&self) -> &str {
        &self.template
    }

    /// The link for a run at `now`, each value URL-encoded: ace3's `log_search_url`.
    pub fn url(&self, run: &RunSearch<'_>, now: DateTime<Utc>) -> String {
        let (earliest, latest) = log_search_window(&run.times, now);
        let mut url = String::new();
        for piece in &self.pieces {
            match piece {
                Piece::Text(text) => url.push_str(text),
                Piece::Field(name) => {
                    let value = match *name {
                        "run_uuid" => run.run_uuid.to_owned(),
                        "marker" => run.marker.to_owned(),
                        "test_guid" => run.test_guid.to_owned(),
                        "earliest" => earliest.timestamp().to_string(),
                        _ => latest.timestamp().to_string(),
                    };
                    url.push_str(&ace_pycompat::parse::quote(&value, ""));
                }
            }
        }
        url
    }
}

/// Where a search for a run's records starts and ends: its start (its registration while it hasn't
/// started) to the end of its attribution window (when it was canceled or closed if it never got one), or
/// now when that's still to come. ace3's `log_search_window`.
pub fn log_search_window(run: &RunTimes, now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
    let earliest = run.started_at.unwrap_or(run.created_at);
    let end = run
        .attribution_ends_at
        .or(run.canceled_at)
        .or(run.closed_at);
    let latest = match end {
        Some(end) if end < now => end,
        _ => now,
    };
    (earliest, latest.max(earliest))
}

/// ace3's tests/saq/svs/test_log_search.py.
#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 15, 12, 0, 0).unwrap()
    }

    #[test]
    fn accepted() {
        for template in [
            "https://logs.example/?q=svs_run%3D{run_uuid}",
            "http://logs.example/{marker}/{test_guid}?from={earliest}&to={latest}",
            "https://logs.example/?q={{literal}}",
        ] {
            let parsed = LogSearchTemplate::parse(Some(template))
                .unwrap_or_else(|why| panic!("{template}: {why}"))
                .expect("a template");
            assert_eq!(parsed.as_str(), template);
        }
    }

    #[test]
    fn refused() {
        for template in [
            "https://logs.example/{run}", // not one of the names
            "https://logs.example/{0}",   // positional
            "https://logs.example/{}",
            "https://logs.example/{run_uuid!r}",   // a conversion
            "https://logs.example/{earliest:>12}", // a format spec
            "https://logs.example/{run_uuid.hex}", // an attribute
            "https://logs.example/{",              // not a template
            "javascript:alert({run_uuid})",        // it becomes a link
        ] {
            assert!(
                LogSearchTemplate::parse(Some(template)).is_err(),
                "{template}"
            );
        }
    }

    #[test]
    fn unset() {
        assert_eq!(LogSearchTemplate::parse(None), Ok(None));
        assert_eq!(LogSearchTemplate::parse(Some("")), Ok(None));
    }

    fn run(started: Option<i64>, ends: Option<i64>, canceled: Option<i64>) -> RunTimes {
        let at = |hours: i64| now() + Duration::hours(hours);
        RunTimes {
            created_at: at(-10),
            started_at: started.map(at),
            attribution_ends_at: ends.map(at),
            canceled_at: canceled.map(at),
            closed_at: None,
        }
    }

    #[test]
    fn the_window() {
        let at = |hours: i64| now() + Duration::hours(hours);
        // registered, not started: from its registration until now
        assert_eq!(
            log_search_window(&run(None, None, None), now()),
            (at(-10), now())
        );
        // inside its attribution window: until now
        assert_eq!(
            log_search_window(&run(Some(-9), Some(1), None), now()),
            (at(-9), now())
        );
        // past it: until it ended
        assert_eq!(
            log_search_window(&run(Some(-9), Some(-1), None), now()),
            (at(-9), at(-1))
        );
        // canceled before it started
        assert_eq!(
            log_search_window(&run(None, None, Some(-8)), now()),
            (at(-10), at(-8))
        );
    }

    /// What the run page links to: each value URL-encoded, the braces written twice as one.
    #[test]
    fn the_link() {
        let template = LogSearchTemplate::parse(Some(
            "https://logs.example/?q=svs_run%3D{run_uuid}&m={marker}&from={earliest}&to={latest}&x={{y}}",
        ))
        .expect("good")
        .expect("a template");
        let search = RunSearch {
            run_uuid: "a b/c",
            marker: "svs-x",
            test_guid: "g",
            times: run(Some(-9), Some(-1), None),
        };
        assert_eq!(
            template.url(&search, now()),
            format!(
                "https://logs.example/?q=svs_run%3Da%20b%2Fc&m=svs-x&from={}&to={}&x={{y}}",
                (now() - Duration::hours(9)).timestamp(),
                (now() - Duration::hours(1)).timestamp()
            )
        );
    }
}
