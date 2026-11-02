//! A sample analysis type for the integration tests, using each kind of field a real type would.

use std::collections::BTreeMap;

use ace_results::{AnalysisType, Bytes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A sample analysis type.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleAnalysis {
    /// A required string.
    pub subject: String,
    /// Bytes stay bytes.
    pub raw_subject: Bytes,
    pub attachment_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default)]
    pub headers: Vec<SampleHeader>,
    pub verdict: SampleVerdict,
    #[serde(default)]
    pub counts: BTreeMap<String, u64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleHeader {
    pub name: String,
    pub value: Bytes,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SampleVerdict {
    Clean,
    Suspicious,
}

impl AnalysisType for SampleAnalysis {
    const NAME: &'static str = "sample_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "sample_module";
}
