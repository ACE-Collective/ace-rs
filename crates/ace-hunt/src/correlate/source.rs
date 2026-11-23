//! Where a correlation's `query` commands run (`registry.py`): a [`QuerySource`] by the name a
//! command's `source` gives, such as `splunk`. ace3 registers its sources from
//! `hunter.correlation.query_sources`, importing each class; ace-rs's hunter builds them from the
//! overlay's `query_sources:`, each of a type the binary has (`ace_app::App::query_source_type`,
//! PLAN.md decision 40), and `ace serve`, validating a hunt, builds them without their credentials
//! and refuses to run a query on them, so a query there fails as a step error unless its results are
//! replayed.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::TimeDelta;
use serde_json::{Map as JsonMap, Value as Json};

use super::time::Time;

/// A data source correlation queries run against.
pub trait QuerySource: Send + Sync {
    /// The field of this source's events that holds their time, which an event transform's time
    /// range is anchored to when the hunt doesn't name one; None for a source without one.
    fn default_time_field(&self) -> Option<&str>;

    /// How that field's time is written: `epoch`, `epoch_ms`, `epoch_ns`, `iso8601` or a
    /// `strptime` format.
    fn default_time_format(&self) -> Option<&str>;

    /// Runs `query` over `start` to `end` within `timeout`, with the command's `source_options`
    /// (empty when it has none, and a source ignores keys it doesn't know). An error is a step
    /// error.
    fn execute_query(
        &self,
        query: &str,
        start: Time,
        end: Time,
        timeout: TimeDelta,
        source_options: &JsonMap<String, Json>,
    ) -> Result<Vec<JsonMap<String, Json>>, String>;

    /// The bounds as this source's query language writes them, for the trace, or None for a
    /// source that takes them as parameters.
    fn format_timespec_for_display(
        &self,
        _start: Time,
        _end: Time,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }
}

/// The registered sources, by name.
#[derive(Clone, Default)]
pub struct Sources {
    sources: BTreeMap<String, Arc<dyn QuerySource>>,
}

impl Sources {
    pub fn new() -> Sources {
        Sources::default()
    }

    /// `register_query_source`: true when it replaced one of that name, which ace3 warns of.
    pub fn register(&mut self, name: &str, source: Arc<dyn QuerySource>) -> bool {
        self.sources.insert(name.to_owned(), source).is_some()
    }

    /// `get_query_source`.
    pub fn get(&self, name: &str) -> Result<&Arc<dyn QuerySource>, String> {
        self.sources.get(name).ok_or_else(|| {
            format!(
                "ValueError: query source not registered: {}",
                crate::value::py_repr(name)
            )
        })
    }

    /// `get_registered_sources`.
    pub fn names(&self) -> Vec<&str> {
        self.sources.keys().map(String::as_str).collect()
    }

    /// `clear_query_sources`.
    pub fn clear(&mut self) {
        self.sources.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}
