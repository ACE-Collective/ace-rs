//! `olevba_analysis`: the VBA macros in an Office document (ace3's `OLEVBA_Analysis_v1_2`,
//! `saq/modules/file_analysis/olevba.py`), which `ace-mod-oletools` writes.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bytes::TextOrBytes;
use crate::envelope::AnalysisType;

/// The details of an `olevba_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OlevbaAnalysis {
    /// The kind of file oletools found, such as `OLE` or `OpenXML`. Null when it couldn't open it.
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub macros: Vec<OlevbaMacro>,
    /// What oletools' scan found, by lowercase kind. As in ace3, each count is 1, because its loop
    /// looks up the kind before lowercasing it and so starts the count again each time.
    pub keyword_summary: BTreeMap<String, u64>,
}

/// One macro module. The names come out of the hostile file, so they may not be text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OlevbaMacro {
    /// The OLE file the macro is in: the file's path in the alert, or a part's name inside it. Null
    /// for a PowerPoint 97 storage, which olevba gives no name.
    pub file_name: Option<TextOrBytes>,
    pub stream_path: TextOrBytes,
    pub vba_filename: TextOrBytes,
    pub vba_code: String,
    /// The sha256 of the file holding the macro.
    pub local_path: crate::file::Sha256,
}

impl AnalysisType for OlevbaAnalysis {
    const NAME: &'static str = "olevba_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "olevba_v1_2";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_name_that_isnt_text_stays_bytes() {
        let sha256 = "0".repeat(64);
        let details = json!({
            "type": "OLE",
            "macros": [{
                "file_name": "a.doc",
                "stream_path": {"base64": "/w=="},
                "vba_filename": "m.bas",
                "vba_code": "Sub X()",
                "local_path": sha256,
            }],
            "keyword_summary": {"autoexec": 1},
        });
        let read: OlevbaAnalysis = serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(
            read.macros[0].stream_path,
            TextOrBytes::Bytes(crate::bytes::Bytes::new(vec![0xff]))
        );
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
    }

    #[test]
    fn a_file_oletools_couldnt_open_has_a_null_type() {
        let read: OlevbaAnalysis =
            serde_json::from_value(json!({"type": null, "macros": [], "keyword_summary": {}}))
                .expect("reads");
        assert_eq!(read.kind, None);
    }
}
