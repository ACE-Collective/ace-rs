//! The results of PLAN.md 7.5 batch 6's modules, which `ace-mod-scripts` writes: ace3's
//! `MicrosoftScriptEncodingAnalysis` (`saq/modules/file_analysis/mse.py`), `ExtractedRTFAnalysis`
//! and `NoWhiteSpaceAnalysis` (`rtf.py`) and `VBScriptAnalysis` (`vbs.py`), with ace3's keys.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `microsoft_script_encoding_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MicrosoftScriptEncodingAnalysis {
    /// The decoded script's path in the alert, or null when the decoder wrote nothing.
    pub analysis_output: Option<String>,
}

impl AnalysisType for MicrosoftScriptEncodingAnalysis {
    const NAME: &'static str = "microsoft_script_encoding_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "microsoft_script_encoding_analysis";
}

/// The details of an `extracted_rtf_analysis` result, which ace3 leaves empty: what it found is
/// on the file, as detections.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtractedRtfAnalysis {}

impl AnalysisType for ExtractedRtfAnalysis {
    const NAME: &'static str = "extracted_rtf_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "extracted_rtf_analyzer";
}

/// The details of a `vbscript_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VbScriptAnalysis {
    /// How many runs of 5 or more hex digits the file has, outside comment lines.
    pub total_hex_strings: u64,
    /// The longest run's length.
    pub largest_hex_string: u64,
    /// Hex digits in those lines as a percentage of the file's size.
    pub percentage_of_hex_strings: f64,
}

impl AnalysisType for VbScriptAnalysis {
    const NAME: &'static str = "vbscript_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "vbscript_analyzer";
}

/// The details of a `no_white_space_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoWhiteSpaceAnalysis {
    /// How many whitespace bytes the copy left out.
    pub count: u64,
}

impl AnalysisType for NoWhiteSpaceAnalysis {
    const NAME: &'static str = "no_white_space_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "nowhitespace_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn round_trip<T: Serialize + for<'de> Deserialize<'de>>(details: Value) {
        let read: T = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        let mut unknown = details;
        unknown["extra"] = json!(1);
        assert!(serde_json::from_value::<T>(unknown).is_err());
    }

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        round_trip::<MicrosoftScriptEncodingAnalysis>(
            json!({"analysis_output": "a.vbe.decrypted.vbs"}),
        );
        round_trip::<MicrosoftScriptEncodingAnalysis>(json!({"analysis_output": null}));
        round_trip::<ExtractedRtfAnalysis>(json!({}));
        round_trip::<VbScriptAnalysis>(json!({
            "total_hex_strings": 2,
            "largest_hex_string": 64,
            "percentage_of_hex_strings": 15.625,
        }));
        round_trip::<NoWhiteSpaceAnalysis>(json!({"count": 4}));
    }
}
