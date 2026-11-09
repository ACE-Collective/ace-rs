//! `lnk_parse_analysis`: a Windows shortcut parsed by LnkParse3 (ace3's `LnkParseAnalysis`,
//! `saq/modules/file_analysis/lnk_parser.py`). `ace-mod-files` writes it, on `ace-lnkparse`
//! (PLAN.md 7.5 batch 2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of a `lnk_parse_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LnkParseAnalysis {
    /// The exception LnkParse3 raised, as Python's `str()` gives it.
    pub error: Option<String>,
    /// LnkParse3's `get_json(get_all=True)`: the header, the link target's shell items, the link
    /// info, the string data and the extra blocks, with datetimes as ace3 writes them. `{}` when
    /// the parse raised.
    pub info: serde_json::Value,
}

impl AnalysisType for LnkParseAnalysis {
    const NAME: &'static str = "lnk_parse_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "lnk_parser";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({"error": null, "info": {"data": {"icon_location": "x"}}});
        let read: LnkParseAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(
            serde_json::from_value::<LnkParseAnalysis>(json!({"error": null, "info": {}, "x": 1}))
                .is_err()
        );
    }
}
