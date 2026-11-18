//! `email_analysis`: what the email module found in an RFC 822 message (ace3's `EmailAnalysis`,
//! `saq/modules/email/rfc822.py`).
//!
//! The keys keep ace3's names, typos and all (`message-id`, `refereneces`), so stored results,
//! the analysis template and the reference dumps line up. A key ace3 sets only when a header is
//! present is optional and left out when it isn't; a key ace3 always sets is always written,
//! as null when it has no value.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::AnalysisType;

/// The details of an `email_analysis` result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailAnalysis {
    /// Why the message couldn't be parsed.
    pub parsing_error: Option<String>,
    /// Parts of the message that couldn't be extracted. The rest of the message still was.
    pub extraction_errors: Vec<ExtractionError>,
    pub email: Option<EmailDetails>,
}

impl AnalysisType for EmailAnalysis {
    const NAME: &'static str = "email_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "email_analyzer";
}

impl EmailAnalysis {
    /// Whether the result only carries the file's tags: the email module skipped the email analysis of
    /// an outbound journaled message under `scan_inbound_only`, where ace3 adds the tag and no analysis
    /// (8617ba8e). A module that reads the email's analysis takes this as none, as ace3's find none.
    pub fn is_tag_only(&self) -> bool {
        self.parsing_error.is_none() && self.extraction_errors.is_empty() && self.email.is_none()
    }

    /// Which of the files an email result added are its body parts, given their names in the order it
    /// added them, each with whether it is an HTML part: ace3's `EmailAnalysis.body_parts`, the
    /// unnamed text parts the email module extracts (`is_body_part`, `is_html_body_part`).
    pub fn body_parts_of(names: &[&str]) -> Vec<(usize, bool)> {
        names
            .iter()
            .enumerate()
            .filter_map(|(index, name)| {
                let html = name.contains(".unknown_text_html");
                (html || name.contains(".unknown_text_plain")).then_some((index, html))
            })
            .collect()
    }

    /// Which of the files an email result added is the email's body, given their names in the order
    /// it added them: ace3's `EmailAnalysis.body` (`saq/modules/email/rfc822.py`). A lone plain text
    /// part with no HTML is the body. Otherwise the first HTML part, then the first plain text part
    /// that isn't numbered 000.
    pub fn body_of(names: &[&str]) -> Option<usize> {
        let plain = names
            .iter()
            .position(|name| name.contains("unknown_text_plain"));
        let plains = names
            .iter()
            .filter(|name| name.contains("unknown_text_plain"))
            .count();
        let any_html = names.iter().any(|name| name.contains("unknown_text_html"));
        let mut first_html = None;
        let mut first_plain = None;
        for (index, name) in names.iter().enumerate() {
            if !name.contains(".unknown_") {
                continue;
            }
            if plains == 1 && !any_html {
                return plain;
            }
            if name.contains(".unknown_text_plain_000") {
                continue;
            }
            if first_html.is_none() && name.contains("unknown_text_html") {
                first_html = Some(index);
            } else if first_plain.is_none() && name.contains("unknown_text_plain") {
                first_plain = Some(index);
            }
        }
        first_html.or(first_plain)
    }
}

/// A MIME part that failed to extract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExtractionError {
    pub content_type: Option<String>,
    pub filename: Option<String>,
    /// The error, as `<kind>: <message>`.
    pub exception: String,
}

/// What the module read from the message's headers.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailDetails {
    /// Every header of the message analyzed, in order, as `[name, decoded value]`. For an Office
    /// 365 journaled message these are the original message's headers.
    pub headers: Vec<[String; 2]>,
    /// The `From` header, decoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// The address in the `From` header, as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_address: Option<String>,
    /// Who the message was delivered to: the journal report's recipients for a journaled
    /// message.
    pub env_rcpt_to: Vec<String>,
    /// The SMTP envelope sender, from a journal report.
    pub env_mail_from: Option<String>,
    /// Each `To` header, decoded.
    pub to: Vec<String>,
    /// The addresses in the `To` headers, as written.
    pub to_addresses: Vec<String>,
    /// The `Subject` header as written, encoded words and all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(
        default,
        rename = "message-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub message_id: Option<String>,
    #[serde(default, rename = "x-sender", skip_serializing_if = "Option::is_none")]
    pub x_sender: Option<String>,
    #[serde(
        default,
        rename = "x-sender-id",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_sender_id: Option<String>,
    #[serde(default, rename = "x-auth-id", skip_serializing_if = "Option::is_none")]
    pub x_auth_id: Option<String>,
    #[serde(
        default,
        rename = "x-original-sender",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_original_sender: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_path: Option<String>,
    /// The addresses in the `Cc` headers; set when the message has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    #[serde(
        default,
        rename = "user-agent",
        skip_serializing_if = "Option::is_none"
    )]
    pub user_agent: Option<String>,
    #[serde(default, rename = "x-mailer", skip_serializing_if = "Option::is_none")]
    pub x_mailer: Option<String>,
    /// The sender's IP address from `X-Originating-IP`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub originating_ip: Option<String>,
    #[serde(
        default,
        rename = "x-sender-ip",
        skip_serializing_if = "Option::is_none"
    )]
    pub x_sender_ip: Option<String>,
    /// The IP address of the first hop outside the organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_hop_ip: Option<String>,
    /// The name that hop gave in HELO or EHLO.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_hop_helo: Option<String>,
    /// The hop's host name from reverse DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_hop_from: Option<String>,
    /// The `d=` domain of each DKIM signature; set when there is at least one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dkim_signing_domains: Option<Vec<String>>,
    /// The sending organization's tenant GUID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_tenant_id: Option<String>,
    pub spf_result: Option<String>,
    pub dkim_result: Option<String>,
    pub dmarc_result: Option<String>,
    pub compauth_result: Option<String>,
    pub compauth_reason: Option<String>,
    pub is_anonymous_direct_send: bool,
    pub internal_org_sender: bool,
    pub message_directionality: Option<String>,
    /// DMARC or composite authentication failed.
    pub authentication_failed: bool,
    /// The `From` address is in one of the organization's email domains.
    pub mail_from_is_local: bool,
    /// The `From` address is the organization's own, authentication failed, and the message came
    /// in from outside.
    pub spoofed_internal: bool,
    /// The subject with its encoded words decoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoded_subject: Option<String>,
    /// The summary ace3 logs for each email it scans.
    pub log_entry: LogEntry,
}

/// The summary ace3 logs for each email it scans.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogEntry {
    /// When the message was scanned, as `%Y-%m-%d %H:%M:%S.%f %z`.
    pub date: String,
    /// The last `Received` header: the first hop.
    pub first_received: Option<String>,
    /// The first `Received` header: the last hop.
    pub last_received: Option<String>,
    pub env_mail_from: Option<String>,
    pub env_rcpt_to: Vec<String>,
    pub mail_from: Option<String>,
    pub mail_to: Vec<String>,
    pub reply_to: Option<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub subject: Option<String>,
    pub subject_raw: Option<String>,
    /// The parenthesized part of each `Received: from host (...)` header.
    pub path: Vec<String>,
    /// The message's size in bytes.
    pub size: u64,
    pub user_agent: Option<String>,
    pub x_mailer: Option<String>,
    pub originating_ip: Option<String>,
    /// Each header as `name: value` on one line, except Exchange's own `X-MS-Exchange-` headers.
    pub headers: Vec<String>,
    pub attachment_count: u64,
    pub attachment_sizes: Vec<u64>,
    pub attachment_types: Vec<String>,
    pub attachment_names: Vec<String>,
    pub attachment_hashes: Vec<String>,
    pub thread_topic: Option<String>,
    pub thread_index: Option<String>,
    /// The `References` header; ace3's key is misspelled.
    pub refereneces: Option<String>,
    pub x_sender: Option<String>,
    pub spf_result: Option<String>,
    pub dkim_result: Option<String>,
    pub dmarc_result: Option<String>,
    pub compauth_result: Option<String>,
    pub compauth_reason: Option<String>,
    pub is_anonymous_direct_send: bool,
    pub internal_org_sender: bool,
    pub message_directionality: Option<String>,
    pub authentication_failed: bool,
    pub mail_from_is_local: bool,
    pub spoofed_internal: bool,
}

#[cfg(test)]
mod tests {
    use super::EmailAnalysis as Email;

    #[test]
    fn the_body_is_ace3s_choice() {
        // a lone plain part, where it is among the rest
        let names = ["a.headers", "a.unknown_text_plain_000.txt", "x.docx"];
        assert_eq!(Email::body_of(&names), Some(1));
        // HTML first, whichever way round
        let names = [
            "a.unknown_text_plain_000.txt",
            "a.unknown_text_html_000.html",
        ];
        assert_eq!(Email::body_of(&names), Some(1));
        let names = [
            "a.unknown_text_html_000.html",
            "a.unknown_text_html_001.html",
        ];
        assert_eq!(Email::body_of(&names), Some(0));
        // two plain parts: 000 is skipped
        let names = [
            "a.unknown_text_plain_000.txt",
            "a.unknown_text_plain_001.txt",
        ];
        assert_eq!(Email::body_of(&names), Some(1));
        // an attachment isn't a body, by name alone
        assert_eq!(Email::body_of(&["unknown_text_plain.txt", "x.docx"]), None);
        assert_eq!(Email::body_of(&["a.headers", "x.docx"]), None);
        assert_eq!(Email::body_of(&[]), None);
        assert_eq!(
            Email::body_parts_of(&[
                "a.headers",
                "a.unknown_text_plain_000",
                "x.docx",
                "a.unknown_text_html_001",
                "unknown_text_plain.txt",
            ]),
            [(1, false), (3, true)]
        );
    }
}
