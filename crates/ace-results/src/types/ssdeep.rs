//! `ssdeep_analysis`: the known files a file matches by its fuzzy hash (ace3's `SsdeepAnalysis`,
//! `saq/modules/file_analysis/ssdeep.py`), which `ace-mod-files` writes (PLAN.md 7.5 batch 10).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// One known file a file matched, in an `ssdeep_analysis`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SsdeepMatch {
    /// The known file's name in the list of hashes.
    pub file: String,
    /// ssdeep's score, 0 to 100.
    pub score: u32,
}

/// The details of an `ssdeep_analysis` result (ace3's `SsdeepAnalysis`, `ssdeep.py`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SsdeepAnalysis {
    /// The known files it matched at or above the threshold, in the list's order.
    pub matches: Vec<SsdeepMatch>,
}

impl AnalysisType for SsdeepAnalysis {
    const NAME: &'static str = "ssdeep_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "ssdeep";
}
