//! The results of PLAN.md 7.5 batch 8's modules that walk an email's tree, which `ace-mod-emailtree`
//! writes: ace3's `LureURLAnalysis` (`saq/modules/email/lure.py`) and `MailboxEmailAnalysis`
//! (`saq/modules/email/mailbox.py`), with ace3's keys.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// `lure_url_analysis`: which of an email's URLs it lures its recipient to, and the runners-up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LureUrlAnalysis {
    /// The best candidate, when its score reaches the module's `min_primary_score`.
    pub primary: Option<LureCandidate>,
    /// The best candidates, best first, at most the module's `max_candidates`, the primary among
    /// them.
    pub candidates: Vec<LureCandidate>,
    /// The email carries another email, which has a result of its own.
    pub has_inner_email: bool,
    /// The email's decoded subject, or its subject.
    pub subject: Option<String>,
}

/// One URL the email carries, with its score and why.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LureCandidate {
    pub url: String,
    pub score: i64,
    /// Where it was found: `body`, `attachment` or `qr`, sorted.
    pub sources: Vec<String>,
    /// The text of the link to it in the body, cut at 100 characters.
    pub anchor_text: Option<String>,
    /// The candidate URLs in its query string, such as a click tracker's destination.
    pub carries: Vec<String>,
    /// Each signal that applied, in the order they're scored.
    pub reasons: Vec<String>,
    /// For each reason, the values in it the alert page shows in bold.
    pub highlights: Vec<Vec<String>>,
}

impl AnalysisType for LureUrlAnalysis {
    const NAME: &'static str = "lure_url_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "lure_url_analyzer";
}

/// `mailbox_email_analysis`: ace3's, which holds nothing. The module's work is on the root, which it
/// names after the email's subject and gives the email's details, and on the email's Message-ID,
/// which it tracks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailboxEmailAnalysis {}

impl AnalysisType for MailboxEmailAnalysis {
    const NAME: &'static str = "mailbox_email_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "mailbox_email_analyzer";
}
