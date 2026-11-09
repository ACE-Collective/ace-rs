//! `file_hash_analysis`: a file's hashes (ace3's `FileHashAnalysis`,
//! `saq/modules/file_analysis/hash.py`). `ace-mod-files` writes it (PLAN.md 7.5 batch 2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `file_hash_analysis` result: lowercase hex digests of the file's bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FileHashAnalysis {
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
}

impl AnalysisType for FileHashAnalysis {
    const NAME: &'static str = "file_hash_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "file_hash_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({"md5": "a", "sha1": "b", "sha256": "c"});
        let read: FileHashAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(serde_json::from_value::<FileHashAnalysis>(json!({"md5": null, "x": 1})).is_err());
    }
}
