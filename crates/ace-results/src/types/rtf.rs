//! `rtf_ole_object_analysis`: the objects in an RTF file (ace3's `RTFOLEObjectAnalysis`,
//! `saq/modules/file_analysis/rtf.py`). The Python pool writes it (PLAN.md 4.5).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `rtf_ole_object_analysis` result. What rtfobj reported, as ace3 keeps it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RtfOleObjectAnalysis {
    /// rtfobj's report, with the file and its objects named by their paths in the alert.
    pub stdout: String,
    /// The traceback, when rtfobj raised.
    pub stderr: String,
    /// 0, or 1 when rtfobj raised. What it wrote before that is still in `extracted_files`.
    pub return_code: i32,
    /// The objects' paths in the alert. rtfobj's names only hold word characters, `.`, `-` and
    /// spaces, so these are text.
    pub extracted_files: Vec<String>,
}

impl AnalysisType for RtfOleObjectAnalysis {
    const NAME: &'static str = "rtf_ole_object_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "rtfole";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "stdout": "report",
            "stderr": "",
            "return_code": 0,
            "extracted_files": ["a.rtf.rtfobj/a.rtf_payload.exe"],
        });
        let read: RtfOleObjectAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);

        let mut unknown = details;
        unknown["extra"] = json!(1);
        assert!(serde_json::from_value::<RtfOleObjectAnalysis>(unknown).is_err());
    }
}
