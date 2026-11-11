//! The tagging and detection modules' types (PLAN.md 7.6): `observable_detection_analysis`
//! (ace3's `ObservableDetectionAnalysis`, `saq/modules/observable_detection.py`),
//! `user_defined_tagging_analysis` (`UserDefinedTaggingAnalysis`) and `site_tag_analysis`
//! (`SiteTagAnalysis`, both `saq/modules/tag.py`). `ace-mod-tag` writes them. The core's
//! `observable_modifier` hook writes `observable_modifier_analysis` (ace3's `ObservableModifierAnalysis`,
//! `saq/modules/util/observable_modifier.py`), `ace_core::hooks`.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `observable_detection_analysis` result: whether the observable is on the
/// list of observables enabled for detection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservableDetectionAnalysis {
    pub for_detection: bool,
}

impl AnalysisType for ObservableDetectionAnalysis {
    const NAME: &'static str = "observable_detection_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "observable_detection";
}

/// The details of a `user_defined_tagging_analysis` result: the tags analysts mapped to the
/// observable's type and value, in the order they were added to it, a tag it had already among them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserDefinedTaggingAnalysis {
    pub tags_added: Vec<String>,
}

impl AnalysisType for UserDefinedTaggingAnalysis {
    const NAME: &'static str = "user_defined_tagging_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "user_defined_tagging";
}

/// The details of a `site_tag_analysis` result: the tags of each site tag row that matched the
/// observable, in the rows' order, a tag two rows give listed twice, as ace3 lists it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteTagAnalysis {
    pub tags_added: Vec<String>,
}

impl AnalysisType for SiteTagAnalysis {
    const NAME: &'static str = "site_tag_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "site_tagger";
}

/// The details of an `observable_modifier_analysis` result: each observable modifier rule that matched
/// the observable, in the order they matched, with what its actions did.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservableModifierAnalysis {
    pub matched_rules: Vec<MatchedRule>,
}

/// One rule's match, ace3's `{"name", "uuid", "actions_applied"}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MatchedRule {
    pub name: String,
    pub uuid: String,
    /// Each action that did something, by its name in the rule (`add_tags`, `ignore`, ...), with what
    /// it did: the tags, the modules, the display value, or `true` for `ignore`.
    pub actions_applied: BTreeMap<String, serde_json::Value>,
}

impl ObservableModifierAnalysis {
    /// Whether a rule's `ignore` matched.
    pub fn ignores(&self) -> bool {
        self.matched_rules
            .iter()
            .any(|m| m.actions_applied.contains_key("ignore"))
    }
}

impl AnalysisType for ObservableModifierAnalysis {
    const NAME: &'static str = "observable_modifier_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "observable_modifier";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let detection = json!({"for_detection": true});
        let read: ObservableDetectionAnalysis =
            serde_json::from_value(detection.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), detection);
        let tags = json!({"tags_added": ["a", "a", "b"]});
        let read: UserDefinedTaggingAnalysis = serde_json::from_value(tags.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), tags);
        let read: SiteTagAnalysis = serde_json::from_value(tags.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), tags);
        assert!(
            serde_json::from_value::<ObservableDetectionAnalysis>(
                json!({"for_detection": false, "x": 1})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<SiteTagAnalysis>(json!({"tags_added": [], "x": 1})).is_err()
        );
        let modifier = json!({"matched_rules": [{"name": "r", "uuid": "u",
            "actions_applied": {"add_tags": ["a"], "ignore": true}}]});
        let read: ObservableModifierAnalysis =
            serde_json::from_value(modifier.clone()).expect("reads");
        assert!(read.ignores());
        assert_eq!(serde_json::to_value(&read).expect("writes"), modifier);
    }
}
