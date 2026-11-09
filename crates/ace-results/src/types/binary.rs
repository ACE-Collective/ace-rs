//! `binary_file_analysis`: an RTF file, or an EPS file in a Word document, that ace3's
//! `BinaryFileAnalyzer` (`saq/modules/file_analysis/binary.py`) looked for NUL bytes in. Its
//! details are empty: what it found is the file's tag and directive. `ace-mod-files` writes it
//! (PLAN.md 7.5 batch 2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `binary_file_analysis` result, which ace3 leaves empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BinaryFileAnalysis {}

impl AnalysisType for BinaryFileAnalysis {
    const NAME: &'static str = "binary_file_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "binary_file_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_are_empty() {
        let read: BinaryFileAnalysis = serde_json::from_value(json!({})).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), json!({}));
        assert!(serde_json::from_value::<BinaryFileAnalysis>(json!({"x": 1})).is_err());
    }
}
