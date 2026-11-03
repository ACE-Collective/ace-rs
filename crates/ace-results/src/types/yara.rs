//! `yara_scan_results`: the YARA rules a file matched (ace3's `YaraScanResults_v3_4`,
//! `saq/modules/file_analysis/yara.py`).
//!
//! The lists keep ace3's shapes, so the analysis template ports as is: `strings` and `context`
//! are arrays of `[offset, identifier, value, ...]`. The matched bytes stay bytes, written as
//! `{"base64": ...}`, where ace3 turns them into text.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::bytes::Bytes;
use crate::envelope::AnalysisType;

/// The details of a `yara_scan_results` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct YaraScanResults {
    /// One entry per rule that matched and the filter kept, in the ruleset's order.
    pub scan_results: Vec<ScanResult>,
}

impl AnalysisType for YaraScanResults {
    const NAME: &'static str = "yara_scan_results";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "yara_scanner_v3_4";
}

/// One rule that matched.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanResult {
    pub rule: String,
    /// The rule's namespace: its subdirectory of the signature directory.
    pub namespace: String,
    /// The rule's meta block, as written.
    pub meta: Map<String, Value>,
    pub tags: Vec<String>,
    /// The commit of the repository the rule came from, when it came from one.
    pub commit: Option<String>,
    /// The key of the ruleset the rule came from, the sha256 of its bytes, when the module
    /// scanned with a ruleset the core built (PLAN.md 2.26).
    #[serde(default)]
    pub ruleset: Option<String>,
    /// The file scanned, by its path inside the alert.
    pub target: String,
    /// Every pattern occurrence: `[offset, identifier, matched bytes]`.
    pub strings: Vec<(u64, String, Bytes)>,
    /// The same occurrences with the bytes around them as `hexdump -C` prints them:
    /// `[offset, identifier, matched bytes, hexdump]`.
    pub context: Vec<(u64, String, Bytes, String)>,
    /// The bytes around each occurrence, aligned with `context`.
    pub match_context: Vec<MatchContext>,
}

/// The bytes around one pattern occurrence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchContext {
    pub data: Bytes,
    /// Where the occurrence starts in `data`.
    pub match_offset: u64,
    pub match_length: u64,
}
