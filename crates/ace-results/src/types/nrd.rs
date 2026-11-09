//! `nrd_analysis`: a domain found in the newly registered domains list (ace3's `NRDAnalysis`,
//! `saq/modules/nrd.py`). `ace-mod-nrd` writes it (PLAN.md 7.4).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `nrd_analysis` result, in ace3's order. There's a result only for a hit.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NrdAnalysis {
    /// True: the value or a parent of it is in the list.
    pub is_nrd: Option<bool>,
    /// When the hit was found, as Python's `isoformat()` of a UTC time.
    pub matched_at: Option<String>,
    /// The registration date RDAP gave, as Python's `isoformat(" ")`.
    pub datetime_created: Option<String>,
    /// Whole days from the registration to the hit.
    pub age_created_in_days: Option<String>,
    /// `rdap` when RDAP gave the date; ace3's WHOIS fallback isn't ported.
    pub lookup_protocol: Option<String>,
    /// Why the registration date couldn't be found, when the hit is kept unverified.
    pub lookup_error: Option<String>,
}

impl AnalysisType for NrdAnalysis {
    const NAME: &'static str = "nrd_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "nrd_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "is_nrd": true, "matched_at": "2026-11-08T23:04:22.383457+00:00",
            "datetime_created": "2026-11-01 12:30:00+00:00", "age_created_in_days": "7",
            "lookup_protocol": "rdap", "lookup_error": null,
        });
        let read: NrdAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(serde_json::from_value::<NrdAnalysis>(json!({"is_nrd": true, "x": 1})).is_err());
    }
}
