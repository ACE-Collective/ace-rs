//! `splunk_api_analysis`: one Splunk search about an observable, and the rows it found (ace3's
//! `SplunkAPIAnalysis`, `saq/modules/splunk.py`, with the keys `BaseAPIAnalysis` gives it in
//! `saq/modules/api_analysis.py`).
//!
//! The keys keep ace3's names and times keep ace3's form (`format_iso8601`, such as
//! `2026-11-02T18:06:05.296-00:00`), so the analysis template ports as is. ace3's `gui_link`, a
//! Splunk web link set only for a query with `<O_TIMESPEC>`, has no counterpart yet: the module
//! doesn't fill `<O_TIMESPEC>`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::envelope::AnalysisType;

/// The details of a `splunk_api_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SplunkApiAnalysis {
    /// The search, with the observable filled in, before the module adds `search `.
    pub query: Option<String>,
    /// The rows the search returned, as Splunk's JSON output gives them: each field's value is
    /// a string, or a list of strings for a multivalue field. Null when the search failed or
    /// timed out, and the result's `error` then says why, such as `timed out`, as ace3's
    /// `Analysis.error` (its `query_error` until 41d44392).
    pub query_results: Option<Vec<Map<String, Value>>>,
    /// The question the search answers, from the settings.
    pub question: Option<String>,
    /// The summary's prefix, from the settings.
    pub query_summary: Option<String>,
    /// When the analysis started, in seconds since the epoch.
    pub query_start: Option<f64>,
    /// The Splunk job's id.
    pub search_id: Option<String>,
    /// The job's last `dispatchState`, such as `RUNNING` or `DONE`.
    pub dispatch_state: Option<String>,
    /// When the job was submitted.
    pub start_time: Option<String>,
    /// When the module first saw the job running.
    pub running_start_time: Option<String>,
    /// When the module read the job's results.
    pub end_time: Option<String>,
    /// The columns of a `| table` command in the query, in order, so the rows show that way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_columns: Option<Vec<String>>,
}

impl AnalysisType for SplunkApiAnalysis {
    const NAME: &'static str = "splunk_api_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "splunk_api";
}

/// One click a clicker search found: ace3's `ClickerEvent` as its analysis keeps it, each mapped
/// field as the row gave it (a string, a list for a multivalue field, or null when unmapped).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClickerEvent {
    /// `<source>:<search name>`, such as `splunk:url_clicks`.
    pub source: String,
    /// A Splunk web link to the search.
    pub portal_url: Option<String>,
    pub timestamp: Value,
    pub user: Value,
    pub action_type: Value,
    pub url: Value,
    /// The observable's value, which the search was about.
    pub searched_value: String,
    pub network_message_id: Value,
}

/// `splunk_clicker_detection_analysis`: who clicked a URL or visited a domain, by the clicker
/// searches an analyst configured (ace3's `SplunkClickerDetectionAnalysis`,
/// `saq/modules/clicker_detection.py` and `saq/clicker_detection/`), with the keys
/// `SplunkAPIAnalysis` gives it. Its searches run one after another, so the job keys are reset
/// after each and are null at the end, and `query` and `query_results` stay null: the events are
/// in `clicker_events`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SplunkClickerDetectionAnalysis {
    pub query: Option<String>,
    /// Null. Each failed search's `<name>: <error>`, joined by `; `, is the result's `error`.
    pub query_results: Option<Vec<Map<String, Value>>>,
    pub question: Option<String>,
    pub query_summary: Option<String>,
    /// When the analysis started, in seconds since the epoch.
    pub query_start: Option<f64>,
    /// A Splunk web link to the last search.
    pub gui_link: Option<String>,
    pub gui_link_label: Option<String>,
    pub search_id: Option<String>,
    pub dispatch_state: Option<String>,
    pub start_time: Option<String>,
    pub running_start_time: Option<String>,
    pub end_time: Option<String>,
    /// The searches that applied, by name, in order.
    pub clicker_plan: Option<Vec<String>>,
    /// How many of them have run.
    pub clicker_index: Option<usize>,
    /// The clicker config's source, such as `splunk`.
    pub clicker_source: Option<String>,
    pub clicker_events: Option<Vec<ClickerEvent>>,
    /// How many values the searches matched: the URL and its child URLs, or the domain.
    pub matched_url_count: Option<usize>,
}

impl AnalysisType for SplunkClickerDetectionAnalysis {
    const NAME: &'static str = "splunk_clicker_detection_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "clicker_detection_splunk";
}
