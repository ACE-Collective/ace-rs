//! The running half of a hunt type (PLAN.md decision 40, docs/decisions/0005-site-hunt-types.md):
//! how a hunt's query runs over its window, as ace3's `QueryHunt` subclasses say with
//! `execute_query`, `extract_event_timestamp`, `formatted_query`, `search_link` and `tool_instance`.
//!
//! [`crate::HuntType`] is what a hunt of the type is made of and checked against when it loads;
//! [`HuntSearch`] is what runs it. `ace hunter` (`ace_app::hunter`) finds a hunt's search by its
//! type, asks it for the rows, and hands what ran to [`crate::query::process`]. Splunk's is
//! `ace_app::hunter::splunk`; a site adds its own with `ace_app::App::hunt_search`.
//!
//! A search is async, and must end on [`Stop`] at once, so a stopping hunter leaves the window to
//! its next start. Every wait it makes is bounded (PLAN.md 2.21): the hunt's `query_timeout` is in
//! [`SearchLimits`].

use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map as JsonMap, Value as Json};

use crate::query::schedule::Window;
use crate::{Hunt, HuntConfig, HuntError};

/// A boxed future a search returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Ends when the hunter stops.
pub type Stop = BoxFuture<'static, ()>;

/// The bounds of one search.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchLimits {
    /// Between two reads of a search job's status, the hunter's `poll_seconds`.
    pub poll: Duration,
    /// The hunt's `query_timeout`, 30 minutes when it has none.
    pub query_timeout: Duration,
}

/// What a search sent, as the hunt's submissions and the hunter's log name it.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Ran {
    /// The query as it ran, ace3's `formatted_query`, with its time range where the type writes it
    /// into the query.
    pub query: String,
    /// The search in the vendor's console, ace3's `search_link`.
    pub link: Option<String>,
    /// ace3's `search_id`.
    pub search_id: Option<String>,
    /// Where the hunt searched, ace3's `tool_instance`, such as the Splunk host.
    pub tool_instance: String,
    /// The type's own record of what it sent, such as Splunk's job form, for the log.
    pub sent: Option<Json>,
}

/// What a search came back with: what ran, when it got that far, and the rows or why there are
/// none. A search that fails after it built its query still says what ran.
#[derive(Debug, Clone)]
pub struct Searched {
    pub ran: Option<Ran>,
    pub rows: Result<Vec<JsonMap<String, Json>>, String>,
}

impl Searched {
    /// A search that failed before it ran anything.
    pub fn failed(error: impl Into<String>) -> Searched {
        Searched {
            ran: None,
            rows: Err(error.into()),
        }
    }
}

/// How a hunt type's hunts run.
pub trait HuntSearch: Send + Sync {
    /// What the type's hunt class checks when the hunter loads a hunt of the type, beyond its
    /// [`crate::HuntType`]'s checks: Splunk looks up the instance a hunt names. Nothing by default.
    fn on_load(&self, config: &HuntConfig) -> Result<(), HuntError> {
        let _ = config;
        Ok(())
    }

    /// Runs `hunt`'s query over `window`'s `start` to `end` within `limits`, ending at once on
    /// `stop` with an error that says it stopped. `home` is where the hunt's `<include:PATH>`s
    /// are read from, ace3's working directory.
    fn search<'a>(
        &'a self,
        hunt: &'a Hunt,
        home: &'a Path,
        window: &'a Window,
        limits: SearchLimits,
        stop: Stop,
    ) -> BoxFuture<'a, Searched>;

    /// ace3's `extract_event_timestamp` for one row of `hunt`'s search: None when the row has no
    /// time the type reads, so the submission takes the query's time. `hunt` is the hunt whose rows
    /// these are, for a type whose hunts name the field their time is in (a site's mail_filter hunts'
    /// `timestamp_field`), since one search serves every hunt of its type, several at once.
    fn event_time(
        &self,
        hunt: &HuntConfig,
        row: &JsonMap<String, Json>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>>;
}

/// ace3's `QueryHunt.query`: the hunt's query or its query file's text, with `query_prefix` before
/// it on a line of its own and `query_suffix` after it, trailing whitespace taken off first. A type
/// adds what its own class adds, such as Splunk's includes (`crate::splunk::query`).
pub fn query(hunt: &Hunt) -> Result<String, String> {
    let config = &hunt.config;
    let mut result = match (&config.query, &hunt.query_file) {
        (Some(query), _) => query.clone(),
        (None, Some(text)) => text.clone(),
        (None, None) => {
            return Err(format!(
                "no query specified for hunt Hunt({}[{}])",
                config.name, config.kind
            ));
        }
    };
    if let Some(prefix) = config.query_prefix.as_deref().filter(|p| !p.is_empty()) {
        result = format!("{prefix}\n{result}");
    }
    if let Some(suffix) = config.query_suffix.as_deref().filter(|s| !s.is_empty()) {
        result = format!("{}\n{suffix}", result.trim_end_matches(char::is_whitespace));
    }
    Ok(result)
}

/// The words a search that stopped ends with, which the hunter reads as a stop, not a failure.
pub const STOPPED: &str = "the search stopped because the hunter is stopping";

/// A [`crate::HuntType`] whose loading adds its search's own check, as ace3's hunt class checks
/// what it needs when it is made: what `ace hunter` loads a type's hunts with.
pub struct Checked<'a> {
    pub kind: &'a dyn crate::HuntType,
    pub search: &'a dyn HuntSearch,
}

impl crate::HuntType for Checked<'_> {
    fn name(&self) -> &str {
        self.kind.name()
    }

    fn model(&self) -> &str {
        self.kind.model()
    }

    fn auto_append(&self) -> &str {
        self.kind.auto_append()
    }

    fn settings(
        &self,
        o: &mut crate::validate::Obj<'_>,
        errs: &mut crate::validate::Errors,
    ) -> Result<Option<JsonMap<String, Json>>, HuntError> {
        self.kind.settings(o, errs)
    }

    fn check(&self, config: &HuntConfig) -> Result<(), String> {
        self.kind.check(config)
    }

    fn on_load(&self, config: &HuntConfig) -> Result<(), HuntError> {
        self.kind.on_load(config)?;
        self.search.on_load(config)
    }
}
