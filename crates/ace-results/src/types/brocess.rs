//! The results of the modules that read brocess, ace3's database of what its email modules have
//! seen before (PLAN.md 7.4). `ace-mod-brocess` writes them.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// `email_conversation_frequency_analysis`: how often brocess has seen an email conversation's
/// sender, and the sender write to its recipient (ace3's `EmailConversationFrequencyAnalysis`,
/// `saq/modules/email/fa.py`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailConversationFrequencyAnalysis {
    /// Emails seen from the sender before.
    pub source_count: Option<i64>,
    /// Emails seen from the sender to the recipient before. Null when the sender is new.
    pub dest_count: Option<i64>,
}

impl AnalysisType for EmailConversationFrequencyAnalysis {
    const NAME: &'static str = "email_conversation_frequency_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "email_conversation_frequency_analyzer";
}

/// `email_logging_analysis`: ace3's `EmailLoggingAnalysis` (`saq/modules/email/logging.py`), which
/// the email logger never stores. It works after the rest of the root and writes to brocess and
/// fluent-bit, so its tasks end with writes and no result.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailLoggingAnalysis {}

impl AnalysisType for EmailLoggingAnalysis {
    const NAME: &'static str = "email_logging_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "email_logger";
}

/// `email_thread_analysis`: the conversation a Message-ID belongs to, as a timeline, with the
/// look-alike domain pairs in it (ace3's `EmailThreadAnalysis`, `saq/modules/email/thread.py`).
/// Display only: it tags and detects nothing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailThreadAnalysis {
    /// The Message-ID, `<...>`.
    pub anchor_message_id: Option<String>,
    pub normalized_subject: Option<String>,
    /// How many threads were joined into the conversation.
    pub thread_count: u32,
    /// `headers` or `self`: whether reply headers grouped it or same-subject threads were joined.
    pub thread_method: Option<String>,
    /// The domains that joined same-subject threads.
    pub link_domains: Vec<String>,
    /// How many messages each joined thread has, largest first.
    pub thread_message_counts: Vec<u32>,
    /// A cap trimmed the conversation.
    pub truncated: bool,
    pub messages: Vec<ThreadMessage>,
    pub lookalikes: Vec<Lookalike>,
    /// Addresses recorded before the store kept which message each was on.
    pub unattributed_participants: Vec<String>,
    /// Message-IDs In-Reply-To headers name that the store has no record of.
    pub missing_parent_message_ids: Vec<String>,
}

impl AnalysisType for EmailThreadAnalysis {
    const NAME: &'static str = "email_thread_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "email_thread_analyzer";
}

impl EmailThreadAnalysis {
    /// `_build_findings` (`saq/modules/email/thread.py`): the facts that decide an alert, as the
    /// markdown ace3 adds to the analysis as a summary detail. ace4's results have no summary
    /// details, so the analysis view draws them from the details.
    pub fn findings(&self) -> Option<String> {
        let analysis = self;
        if analysis.lookalikes.is_empty() {
            return None;
        }
        let mut lines: Vec<String> = Vec::new();
        for entry in &analysis.lookalikes {
            lines.push(format!(
                "**{}** (looks like {})",
                entry.domain, entry.counterpart
            ));
            lines.push(String::new());
            let roles = entry.roles.join(", ");
            if entry.ever_sent {
                lines.push(format!(
                    "- Sent mail into this conversation - seen as {roles}."
                ));
            } else if entry.ever_reply_to {
                lines.push(format!(
                    "- Never sent mail into this conversation, but replies were directed to it (Reply-To) - seen as {roles}."
                ));
            } else {
                lines.push(format!(
                    "- Never sent mail into this conversation - only ever {roles}. No mail was received from this domain here."
                ));
            }
            if !entry.shared_reply_to.is_empty() {
                lines.push(format!(
                    "- Messages from **both** domains direct replies to {} - check whether one sender runs both domains before treating this as impersonation.",
                    entry.shared_reply_to.join(", ")
                ));
            } else if !entry.reply_to_addresses.is_empty() {
                lines.push(format!(
                    "- Replies are directed to {}, from one side of the pair only - replies leave this conversation for the look-a-like domain. This is not the shared-operator pattern.",
                    entry.reply_to_addresses.join(", ")
                ));
            }
            let mut presence = format!(
                "- Present on {} of {} recorded messages",
                entry.message_count, entry.total_messages
            );
            if let Some(on) = entry.introduced_on.as_deref().filter(|d| !d.is_empty()) {
                presence.push_str(&format!("; first recorded appearance {on} UTC"));
                if let Some(by) = entry
                    .introduced_by_address
                    .as_deref()
                    .filter(|a| !a.is_empty())
                {
                    presence.push_str(&format!(" on a message from {by}"));
                }
            }
            lines.push(presence + ".");
            if entry.likely_inherited {
                lines.push("- That message is a reply to a message that was never recorded, and this domain appears only in its recipient list - the address was likely carried over from the unrecorded message's recipients rather than added by this sender.".to_owned());
            }
            if entry.presence_is_partial {
                lines.push("- That count is a floor: some records for this domain predate per-message tracking and cannot be tied to a specific message.".to_owned());
            }
            if !entry.present_in_anchor_message && !entry.presence_is_partial {
                lines.push("- Not present in the message this alert fired on; it comes from earlier messages in the conversation.".to_owned());
            }
            for item in &entry.impersonations {
                let qualifier = if item.exact_local_part {
                    "identical"
                } else {
                    "similar"
                };
                lines.push(format!(
                    "- {} has an {qualifier} local part to {}.",
                    item.address, item.impersonates
                ));
            }
            lines.push(String::new());
        }
        let missing = analysis.missing_parent_message_ids.len();
        if missing > 0 {
            let (plural, verb) = if missing == 1 {
                ("message", "was")
            } else {
                ("messages", "were")
            };
            lines.push(format!(
                "_{missing} {plural} referenced by reply headers in this conversation {verb} never recorded - the timeline shows only the messages that were scanned._"
            ));
        }
        Some(lines.join("\n").trim().to_owned())
    }
}

/// One message of the timeline.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadMessage {
    /// From 1.
    pub index: u32,
    pub message_id: String,
    /// `%Y-%m-%d %H:%M:%S`, UTC: its Date header, or when it was recorded.
    pub date: Option<String>,
    /// It had no Date header, so `date` is when it was recorded.
    pub date_is_estimated: bool,
    /// `inbound` or `outbound`.
    pub direction: String,
    pub from_address: Option<String>,
    pub from_domain: Option<String>,
    pub from_is_lookalike: bool,
    /// Its Reply-To and Return-Path addresses besides its From.
    pub other_senders: Vec<OtherSender>,
    pub recipients: Vec<Recipient>,
    /// Recipients past the cap.
    pub recipients_omitted: u32,
    pub lookalike_domains_present: Vec<String>,
    /// It's the message the analysis is of.
    pub is_anchor: bool,
    /// Its In-Reply-To names a message the store has no record of.
    pub replies_to_unrecorded: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OtherSender {
    pub address: String,
    pub role: String,
    pub is_lookalike: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub address: String,
    pub is_lookalike: bool,
}

/// A domain of the conversation that looks like another of it, and what it did there.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Lookalike {
    /// The one taken for the look-alike.
    pub domain: String,
    pub counterpart: String,
    pub damerau_levenshtein: u32,
    pub jaro_winkler: f64,
    pub skeleton_equal: bool,
    pub techniques: Vec<String>,
    pub addresses: Vec<String>,
    pub roles: Vec<String>,
    /// Mail came from it (From or Return-Path).
    pub ever_sent: bool,
    /// Replies were directed to it.
    pub ever_reply_to: bool,
    pub reply_to_addresses: Vec<String>,
    /// Reply-To addresses messages from both domains point at.
    pub shared_reply_to: Vec<String>,
    pub message_count: u32,
    pub total_messages: u32,
    /// Some of its records can't be tied to a message, so `message_count` is a floor.
    pub presence_is_partial: bool,
    pub introduced_by_address: Option<String>,
    pub introduced_by_message_id: Option<String>,
    pub introduced_on: Option<String>,
    pub first_seen_replies_to_unrecorded: bool,
    pub likely_inherited: bool,
    pub present_in_anchor_message: bool,
    pub impersonations: Vec<Impersonation>,
}

/// An address on the look-alike domain whose local part is like one on its counterpart.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Impersonation {
    pub address: String,
    pub impersonates: String,
    pub exact_local_part: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn details_read_as_written_and_refuse_an_unknown_field() {
        let details = json!({"source_count": 10, "dest_count": null});
        let read: EmailConversationFrequencyAnalysis =
            serde_json::from_value(details.clone()).expect("reads");
        assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        assert!(
            serde_json::from_value::<EmailConversationFrequencyAnalysis>(
                json!({"source_count": 1, "dest_count": 1, "x": 1})
            )
            .is_err()
        );
    }
}
