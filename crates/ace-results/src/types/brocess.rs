//! The results of the modules that read brocess, ace3's database of what its email modules have
//! seen before (PLAN.md 7.4). `ace-mod-brocess` writes them.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// `email_conversation_frequency_analysis`: how often brocess has seen an email conversation's
/// sender, and the sender write to its recipient (ace3's `EmailConversationFrequencyAnalysis`,
/// `saq/modules/email/fa.py`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailConversationFrequencyAnalysis {
    /// Emails seen from the sender before.
    pub source_count: Option<i64>,
    /// Emails seen from the sender to the recipient before. Null when the sender is new.
    pub dest_count: Option<i64>,
}

impl AnalysisType for EmailConversationFrequencyAnalysis {
    const NAME: &'static str = "email_conversation_frequency_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "email_conversation_frequency_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({"source_count": 10, "dest_count": null});
        let read: EmailConversationFrequencyAnalysis =
            serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(
            serde_json::from_value::<EmailConversationFrequencyAnalysis>(
                json!({"source_count": 1, "dest_count": 1, "x": 1})
            )
            .is_err()
        );
    }
}
