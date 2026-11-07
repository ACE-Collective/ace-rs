//! `xlm_deobfuscator_analysis`: what XLMMacroDeobfuscator found in a file's Excel 4.0 macros (ace3's
//! `XLMMacroDeobfuscatorAnalysis`, `saq/modules/file_analysis/xlm.py`). The Python pool writes it
//! (PLAN.md 4.7).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `xlm_deobfuscator_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct XlmDeobfuscatorAnalysis {
    /// The cells the pass with no emulation listed.
    pub cell_count: u64,
}

impl AnalysisType for XlmDeobfuscatorAnalysis {
    const NAME: &'static str = "xlm_deobfuscator_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "xlmdeobfuscator";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({"cell_count": 3});
        let read: XlmDeobfuscatorAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(
            serde_json::from_value::<XlmDeobfuscatorAnalysis>(json!({"cell_count": 1, "x": 1}))
                .is_err()
        );
    }
}
