//! The results of PLAN.md 7.5 batch 9's modules, which `ace-mod-emailarchive` writes: ace3's
//! `EmailArchiveResults` and `EncryptedArchiveAnalysis` (`saq/modules/email/archive.py`),
//! `URLEmailPivotAnalysis_v2` (`saq/modules/email/correlation.py`) and `MessageIDAnalysisV2`
//! (`saq/modules/email/message_id.py`), with ace3's keys.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// Where the email archive keeps an email, by the SHA-256 of its bytes, as ace3 names its file
/// (`get_archive_path_by_hash`) under its `archive_dir` without the node's hostname: one bucket
/// holds every node's archive here. It's a name, not a path on a disk: the archive is rows in
/// Postgres and an encrypted object in the bucket's `email_archive` pool.
pub fn archive_path(sha256: &str) -> String {
    let sha256 = sha256.to_ascii_lowercase();
    format!(
        "archive/email/{}/{sha256}.gz.e",
        &sha256[..2.min(sha256.len())]
    )
}

/// The details of an `email_archive_results` result: an email the archiver archived.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailArchiveResults {
    /// ace3 has this key and never sets it.
    pub message_id: Option<String>,
    /// The archive's row for the email, which the core gives it when the archive lands.
    pub archive_id: Option<i64>,
    /// Where the archive keeps it (`archive_path`).
    pub archive_path: Option<String>,
    /// The SHA-256 of the email's bytes, in lower-case hex.
    pub hash: Option<String>,
}

impl AnalysisType for EmailArchiveResults {
    const NAME: &'static str = "email_archive_results";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "email_archiver";
}

/// The details of an `encrypted_archive_analysis` result: an archived email file (`.gz.e`) in the
/// alert, opened.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EncryptedArchiveAnalysis {
    /// The decrypted email's path in the alert.
    pub decrypted_file: Option<String>,
}

impl AnalysisType for EncryptedArchiveAnalysis {
    const NAME: &'static str = "encrypted_archive_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "encrypted_archive_analyzer";
}

/// The details of a `url_email_pivot_analysis_v2` result: how many archived emails held a URL.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UrlEmailPivotAnalysis {
    pub count: Option<i64>,
    /// ace3 has this key and never sets it: the code that listed the emails is commented out.
    pub emails: Option<serde_json::Value>,
}

impl AnalysisType for UrlEmailPivotAnalysis {
    const NAME: &'static str = "url_email_pivot_analysis_v2";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "url_email_pivot_analyzer";
}

/// The details of a `message_id_analysis_v2` result: an email pulled out of the archive by its
/// Message-ID, which the result adds as a file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageIdAnalysis {
    /// ace3 sets this only when adding the file fails after the analysis exists, which ace4's
    /// result can't do.
    pub error: Option<String>,
    /// ace3 has this key and never sets it.
    pub extracted_email: Option<String>,
}

impl AnalysisType for MessageIdAnalysis {
    const NAME: &'static str = "message_id_analysis_v2";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "message_id_analyzer_v2";
}

#[cfg(test)]
mod tests {
    use super::archive_path;

    #[test]
    fn an_archive_path_is_named_by_the_hash_lowercased() {
        assert_eq!(archive_path("ABCDEF"), "archive/email/ab/abcdef.gz.e");
    }
}
