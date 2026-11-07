//! `pcode_analysis`: what pcodedmp disassembled in a file (ace3's `PCodeAnalysis`,
//! `saq/modules/file_analysis/vbs.py`). `ace-mod-xlm` writes it (PLAN.md 4.12).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `pcode_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PCodeAnalysis {
    /// The lines in the disassembly's file.
    pub line_count: u64,
}

impl AnalysisType for PCodeAnalysis {
    const NAME: &'static str = "pcode_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "pcodedmp";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({"line_count": 12});
        let read: PCodeAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(serde_json::from_value::<PCodeAnalysis>(json!({"line_count": 1, "x": 1})).is_err());
    }
}
