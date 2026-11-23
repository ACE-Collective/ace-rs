//! The results of PLAN.md 7.5 batch 9's modules, which `ace-mod-emailarchive` writes: ace3's
//! `EmailArchiveResults` (`saq/modules/email/archive.py`) and `MessageIDAnalysisV2`
//! (`saq/modules/email/message_id.py`), with ace3's keys.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `email_archive_results` result: an email the archiver archived.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailArchiveResults {
    /// ace3 has this key and never sets it.
    pub message_id: Option<String>,
    /// The SHA-256 of the email's bytes, in lower-case hex: how ace3's archive names it (its digest
    /// in the `email_archive` pool) and how the email logger's entry names it.
    pub hash: Option<String>,
}

impl AnalysisType for EmailArchiveResults {
    const NAME: &'static str = "email_archive_results";
    const VERSION: u32 = 2;
    const MODULE: &'static str = "email_archiver";
}

/// The details of a `message_id_analysis_v2` result: an email pulled out of the archive by its
/// Message-ID, which the result adds as a file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageIdAnalysis {
    /// ace3 has this key and never sets it. ace3 marks the analysis failed (`Analysis.error`) only
    /// when adding the file fails after the analysis exists, which ace-rs's result can't do.
    pub extracted_email: Option<String>,
}

impl AnalysisType for MessageIdAnalysis {
    const NAME: &'static str = "message_id_analysis_v2";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "message_id_analyzer_v2";
}
