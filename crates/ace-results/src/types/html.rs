//! The results of PLAN.md 7.5 batch 4's modules, which `ace-mod-html` writes: ace3's
//! `HTMLDataURLAnalysis` and `MHTMLAnalysis` (`saq/modules/file_analysis/html.py`), `HARAnalysis`
//! (`har.py`) and `HTMLJavaScriptExtractionAnalysis` (`html_js_extraction.py`).
//!
//! ace3 writes a DOM snapshot beside each script it extracts, `<script>.dom.json`, a file that
//! isn't an observable, which its JavaScript deobfuscator reads. ace4 keeps no file outside the
//! tree, so the snapshots ride in the result: `dom_snapshots`, which ace3's details don't have.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `html_data_url_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HtmlDataUrlAnalysis {
    /// How many `data:<type>;base64,` URLs became files.
    pub count: u64,
}

impl AnalysisType for HtmlDataUrlAnalysis {
    const NAME: &'static str = "html_data_url_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "html_data_url_extraction";
}

/// The details of an `mhtml_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MhtmlAnalysis {
    /// The sha256 of each part written out, in the order of the parts.
    pub extracted_files: Vec<String>,
}

impl AnalysisType for MhtmlAnalysis {
    const NAME: &'static str = "mhtml_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "mhtml";
}

/// One element of a DOM snapshot: what the JavaScript deobfuscator answers a document lookup
/// with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DomElement {
    pub tag: String,
    /// The attributes, a multi-valued one such as `class` joined with spaces, each cut to 16 KiB
    /// of characters.
    pub attrs: BTreeMap<String, String>,
    /// The element's first own string, stripped, cut to 4 KiB of characters; absent when empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// A document's elements and attributes, as ace3's `build_dom_snapshot` writes them to a
/// `.dom.json` sidecar.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DomSnapshot {
    pub version: u32,
    /// Whether an element, an attribute or a text was left out or cut.
    pub truncated: bool,
    pub elements: Vec<DomElement>,
    /// The address the document was loaded from, when it was downloaded from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// One snapshot and the files whose sidecar it is: ace3 writes it to `<file>.dom.json` for each.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DomSnapshotFile {
    /// The files' paths inside the alert: scripts, and for `html_js_extraction` the document
    /// itself when it loads an external script.
    pub files: Vec<String>,
    pub snapshot: DomSnapshot,
}

/// The details of an `html_javascript_extraction_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HtmlJavaScriptExtractionAnalysis {
    /// The inline scripts written out, by their paths inside the alert.
    pub extracted_files: Vec<String>,
    /// The external scripts' sources that are URLs.
    pub extracted_urls: Vec<String>,
    /// The external scripts' sources that aren't.
    pub extracted_uri_paths: Vec<String>,
    /// The event handlers written out, by their paths inside the alert.
    pub inline_handlers: Vec<String>,
    /// Scripts and handlers found, duplicates included.
    pub script_count: u64,
    pub duplicate_count: u64,
    /// The names of the `.dom.json` sidecars written.
    pub dom_snapshot_files: Vec<String>,
    /// ace4's: the snapshots themselves, which ace3 writes as files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dom_snapshots: Vec<DomSnapshotFile>,
}

impl AnalysisType for HtmlJavaScriptExtractionAnalysis {
    const NAME: &'static str = "html_javascript_extraction_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "html_js_extraction";
}

/// One response of an HTTP archive written out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HarResponse {
    pub url: String,
    /// The response's `status` as the archive has it, whatever its type.
    pub status: serde_json::Value,
    pub mime_type: String,
    /// The file's path inside the alert.
    pub file_path: String,
    /// The archive records a larger size than the body it kept.
    pub truncated: bool,
    /// For a script: the page whose DOM snapshot it runs against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded_by: Option<String>,
}

/// The details of a `har_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HarAnalysis {
    /// The exporting tool's name and version.
    pub creator: Option<String>,
    pub entry_count: u64,
    pub responses: Vec<HarResponse>,
    /// Responses past `max_extracted_files`. Why nothing was extracted, when nothing was, is the
    /// result's `error` (ace3's `Analysis.error`).
    pub skipped_count: u64,
    /// ace4's: the snapshots ace3 writes as files beside the scripts a page loads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dom_snapshots: Vec<DomSnapshotFile>,
}

impl AnalysisType for HarAnalysis {
    const NAME: &'static str = "har_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "har_extraction";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({
            "extracted_files": ["page_js_inline_0_0123abcd.js"], "extracted_urls": ["https://x.example/a.js"],
            "extracted_uri_paths": ["/b.js"], "inline_handlers": [], "script_count": 3, "duplicate_count": 0,
            "dom_snapshot_files": ["page_js_inline_0_0123abcd.js.dom.json"],
            "dom_snapshots": [{"files": ["page_js_inline_0_0123abcd.js"], "snapshot": {
                "version": 1, "truncated": false, "elements": [{"tag": "a", "attrs": {"href": "x"}, "text": "t"}],
            }}],
        });
        let read: HtmlJavaScriptExtractionAnalysis =
            serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        let har = json!({
            "creator": "Firefox 140", "entry_count": 2, "skipped_count": 0,
            "responses": [{"url": "https://x.example/", "status": 200, "mime_type": "text/html",
                "file_path": "s.har.extracted/000_x.example.html", "truncated": false}],
        });
        let read: HarAnalysis = serde_json::from_value(har.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), har);
        for (value, ok) in [
            (json!({"count": 1}), true),
            (json!({"count": 1, "x": 1}), false),
        ] {
            assert_eq!(
                serde_json::from_value::<HtmlDataUrlAnalysis>(value).is_ok(),
                ok
            );
        }
        assert!(
            serde_json::from_value::<MhtmlAnalysis>(json!({"extracted_files": [], "x": 1}))
                .is_err()
        );
    }
}
