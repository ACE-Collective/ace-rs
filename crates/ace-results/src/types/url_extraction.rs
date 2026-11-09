//! `url_extraction_analysis`: the URLs found in a file (ace3's `URLExtractionAnalysis`,
//! `saq/modules/file_analysis/url_extraction.py`). `ace-mod-urls` writes it (PLAN.md 7.5).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `url_extraction_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UrlExtractionAnalysis {
    /// Every URL found, the most interesting first: those of the rarest domains, images last. Only
    /// the first `max_extracted_urls` became observables.
    pub urls: Vec<String>,
    /// The same URLs by registrable domain, with `no_tld` for a host the suffix list doesn't know,
    /// such as an IP address.
    pub urls_grouped_by_domain: BTreeMap<String, Vec<String>>,
}

impl AnalysisType for UrlExtractionAnalysis {
    const NAME: &'static str = "url_extraction_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "url_extraction";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "urls": ["https://a.example.com/x", "http://10.0.0.1/y"],
            "urls_grouped_by_domain": {
                "example.com": ["https://a.example.com/x"], "no_tld": ["http://10.0.0.1/y"],
            },
        });
        let read: UrlExtractionAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(
            serde_json::from_value::<UrlExtractionAnalysis>(json!({"urls": [], "x": 1})).is_err()
        );
    }
}
