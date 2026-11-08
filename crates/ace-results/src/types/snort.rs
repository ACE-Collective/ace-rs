//! `snort_signature_analysis`: the rule an IDS alert's snort or suricata signature names (ace3's
//! `SnortSignatureAnalysis_v1`, `saq/modules/snort.py`). `ace-mod-snort` writes it (PLAN.md 7.4).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `snort_signature_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnortSignatureAnalysis {
    /// `<sid> rev <rev>`, when the rule was found.
    pub signature_id: Option<String>,
    /// The rule's line, or ace3's `unknown signature (rules not updating?)` when it wasn't found.
    pub signature: Option<String>,
}

impl AnalysisType for SnortSignatureAnalysis {
    const NAME: &'static str = "snort_signature_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "snort_signature_analysis_v1";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({"signature_id": "1 rev 2", "signature": "alert ip any any -> any any (sid:1; rev:2;)"});
        let read: SnortSignatureAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(
            serde_json::from_value::<SnortSignatureAnalysis>(
                json!({"signature": null, "signature_id": null, "x": 1})
            )
            .is_err()
        );
    }
}
