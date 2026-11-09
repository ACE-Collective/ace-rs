//! `dhash_image_analysis`: an image's difference hash against the analysts' reference images
//! (ace3's `DHashImageAnalysis`, `saq/modules/dhash.py`). `ace-mod-files` writes it, on
//! `ace-dhash` (PLAN.md 7.5 batch 2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `dhash_image_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DHashImageAnalysis {
    /// How alike the image is to each reference image.
    pub scores: Vec<DHashScore>,
}

/// One reference image's score.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DHashScore {
    /// The reference image's file name.
    pub image_file: String,
    /// The percent of the 512 hash bits that are the same.
    pub score: f64,
    /// The reference image's threshold, in percent, from its `.score` file.
    pub threshold: f64,
}

impl AnalysisType for DHashImageAnalysis {
    const NAME: &'static str = "dhash_image_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "dhash";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details =
            json!({"scores": [{"image_file": "logo.png", "score": 96.875, "threshold": 90.0}]});
        let read: DHashImageAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(
            serde_json::from_value::<DHashImageAnalysis>(json!({"scores": [], "x": 1})).is_err()
        );
    }
}
