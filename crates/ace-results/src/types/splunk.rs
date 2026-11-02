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
    /// timed out.
    pub query_results: Option<Vec<Map<String, Value>>>,
    /// Why there are no rows, such as `timed out`.
    pub query_error: Option<String>,
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
