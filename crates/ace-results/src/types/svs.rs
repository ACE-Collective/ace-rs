//! The result of SVS's sample capture (PLAN.md 7.10 batch 2), which `ace-mod-svs` never stores.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// `svs_yara_sample_capture`: ace3's `YaraSampleCapture` creates no analysis. It keeps the files YARA rules
/// matched on an alert graded TP or FP as SVS samples, which its task's `svs-capture` write lands, and its
/// tasks end with that write and no result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct YaraSampleCaptureAnalysis {}

impl AnalysisType for YaraSampleCaptureAnalysis {
    const NAME: &'static str = "svs_yara_sample_capture";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "svs_yara_sample_capture";
}
