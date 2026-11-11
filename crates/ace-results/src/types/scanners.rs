//! The results of PLAN.md 7.7's modules, which `ace-mod-scanners` writes from what a scanner image
//! brought back, with ace3's keys: `JavaScriptDeobfuscationAnalysis`
//! (`saq/modules/file_analysis/js.py`) and `PhishkitAnalysis` (`saq/modules/phishkit.py`).
//!
//! The fields ace3 copies from the scanner's own JSON (the deobfuscator's `report.json`, phishkit's
//! `metrics.json` and the manager's `proxy.json`) keep whatever JSON they held, as ace3 stores it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::envelope::AnalysisType;

/// The details of a `javascript_deobfuscation_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JavaScriptDeobfuscationAnalysis {
    /// The files added, by their paths in the alert: the reconstructed trace, `deobfuscated-<name>`,
    /// then each Blob the script made, `<name>.<blob file>`.
    pub extracted_files: Vec<String>,
    /// What the scanner wrote to stdout, which is the harness's JSON report, and to stderr.
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// The scanner's exit code: -1 when it was stopped at its timeout.
    pub exit_code: Option<i64>,
    /// The report's `event_count` and `secondary_script_count`.
    pub event_count: i64,
    pub secondary_script_count: i64,
    /// The report's `error`, or why the scan couldn't run.
    pub error: Option<Value>,
    /// `compile` when the source never parsed, `runtime` when it failed while it ran.
    pub error_type: Option<Value>,
    /// The webcrack static pass's status and error.
    pub webcrack_status: Option<Value>,
    pub webcrack_error: Option<Value>,
    /// Whether a DOM snapshot backed the script's document lookups.
    pub dom_snapshot: bool,
    /// The document whose snapshot it ran against, by its path in the alert, when that isn't the
    /// script's own: the script was fetched from a URL found in that document.
    pub dom_snapshot_source: Option<String>,
}

impl AnalysisType for JavaScriptDeobfuscationAnalysis {
    const NAME: &'static str = "javascript_deobfuscation_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "javascript_deobfuscation";
}

/// The details of a `phishkit_analysis` result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PhishkitAnalysis {
    /// The scanner's exit code: 143 when it flushed what it had on SIGTERM at its timeout.
    pub exit_code: Option<i64>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    /// Where the scan's files were kept. ace3's is a temporary directory on its node; ace4's is the
    /// scan's directory in the alert, `phishkit/<job_id>`.
    pub output_dir: Option<String>,
    /// The scan's id: ace3's Celery task id, and here a UUID made from the module and the observable.
    pub job_id: Option<String>,
    /// `url` or `file`.
    pub scan_type: Option<String>,
    /// `successfully scanned <observable>`, or `partial scan of <observable>: scanner timed out`.
    pub scan_result: Option<String>,
    /// The files added, by their paths in the alert, `phishkit/<job_id>/<path>`.
    pub output_files: Vec<String>,
    pub error: Option<String>,
    /// The scanner's `metrics.json`: bytes downloaded, domains, the document's URL and so on.
    pub metrics: Option<Value>,
    /// Whether the scan went through a proxy, as ace3's manager writes it to `proxy.json`.
    pub proxy_status: Option<Value>,
}

impl AnalysisType for PhishkitAnalysis {
    const NAME: &'static str = "phishkit_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "phishkit_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let js = json!({
            "extracted_files": ["deobfuscated-a.js"], "stdout": "{}", "stderr": "", "exit_code": 0,
            "event_count": 3, "secondary_script_count": 0, "error": null, "error_type": null,
            "webcrack_status": "applied", "webcrack_error": null, "dom_snapshot": true,
            "dom_snapshot_source": null,
        });
        let read: JavaScriptDeobfuscationAnalysis =
            serde_json::from_value(js.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), js);
        let pk = json!({
            "exit_code": 0, "stdout": "", "stderr": "", "output_dir": "phishkit/x", "job_id": "x",
            "scan_type": "url", "scan_result": "successfully scanned url:https://a.example/",
            "output_files": ["phishkit/x/dom.html"], "error": null,
            "metrics": {"total_bytes_downloaded": 10}, "proxy_status": {"configured": false},
        });
        let read: PhishkitAnalysis = serde_json::from_value(pk.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), pk);
        let mut extra = pk;
        extra["x"] = json!(1);
        assert!(serde_json::from_value::<PhishkitAnalysis>(extra).is_err());
    }
}
