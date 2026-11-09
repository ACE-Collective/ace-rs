//! `ioc_extraction_analysis`: the indicators found in a file's text (ace3's
//! `IOCExtractionAnalysis`, `saq/modules/file_analysis/ioc_extraction.py`). `ace-mod-urls` writes
//! it (PLAN.md 7.5).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `ioc_extraction_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IocExtractionAnalysis {
    /// The values found, by observable type, each once.
    pub iocs: BTreeMap<String, Vec<String>>,
    /// How many there are in `iocs`.
    pub total_count: u64,
    /// The values left out, as `[type, value, the ignore pattern that matched]`, sorted.
    pub ignored: Vec<[String; 3]>,
}

impl AnalysisType for IocExtractionAnalysis {
    const NAME: &'static str = "ioc_extraction_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "ioc_extraction";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "iocs": {"ip": ["10.1.2.3"], "url": ["https://a.example.com/x"]},
            "total_count": 2,
            "ignored": [["md5", "aAbB", "(?=.*[a-f])(?=.*[A-F])"]],
        });
        let read: IocExtractionAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(
            serde_json::from_value::<IocExtractionAnalysis>(json!({"iocs": {}, "x": 1})).is_err()
        );
    }
}
