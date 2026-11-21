//! `email_analysis`: what the email module found in an RFC 822 message (ace3's `EmailAnalysis`,
//! `saq/modules/email/rfc822.py`).
//!
//! The keys keep ace3's names, typos and all (`message-id`, `refereneces`), so stored results,
//! the analysis template and the reference dumps line up. A key ace3 sets only when a header is
//! present is optional and left out when it isn't; a key ace3 always sets is always written,
//! as null when it has no value.

use std::collections::BTreeMap;

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
    /// Each part the module extracted, in order: its file, its declared content type and its role
    /// (ace3's `details["parts"]`, 5474fd6b). Absent from a result made before ace4 recorded them,
    /// whose body parts are told by their names, as ace3 tells an email's analyzed before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parts: Option<Vec<EmailPart>>,
}

/// A part the email module extracted (ace3's entry of `details["parts"]`). ace3 names the file by its
/// observable's uuid; ace4's observables have none, so it's named by its path in the alert, which the
/// comparison's normal form gives ace3's too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailPart {
    /// The file's path in the alert.
    pub path: String,
    /// The part's content type as the message declares it, lower case (Python's
    /// `get_content_type`).
    pub content_type: String,
    pub role: PartRole,
}

/// What a part is to its email: a body is an unnamed text/plain or text/html part, anything else an
/// attachment (ace3's `PART_ROLE_BODY` and `PART_ROLE_ATTACHMENT`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PartRole {
    Body,
    Attachment,
}

/// The content types an unnamed part is a body part of.
pub const BODY_PART_CONTENT_TYPES: [&str; 2] = ["text/plain", "text/html"];

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

    /// Which of the files an email result added are its body parts, in the order they were
    /// extracted, each with whether it is an HTML part: ace3's `EmailAnalysis.body_parts`
    /// (`is_body_part`, `is_html_body_part`). `paths` are the files' paths in the order the result
    /// added them. A result that records its parts says which they are; one made before that tells
    /// them by the names the module gives an unnamed text part, as ace3 does for an email analyzed
    /// before its 5474fd6b.
    pub fn body_parts_in(parts: Option<&[EmailPart]>, paths: &[&str]) -> Vec<(usize, bool)> {
        Self::body_part_types(parts, paths)
            .into_iter()
            .map(|(index, content_type)| (index, content_type == "text/html"))
            .collect()
    }

    /// Which of the files an email result added is the email's body: ace3's `EmailAnalysis.body`.
    /// The first HTML body part; else a lone plain text one; else, with more than one plain text
    /// part and no HTML, the second.
    pub fn body_in(parts: Option<&[EmailPart]>, paths: &[&str]) -> Option<usize> {
        let types = Self::body_part_types(parts, paths);
        let html = types
            .iter()
            .find(|(_, t)| *t == "text/html")
            .map(|(i, _)| *i);
        let plain: Vec<usize> = types
            .iter()
            .filter(|(_, t)| *t == "text/plain")
            .map(|(i, _)| *i)
            .collect();
        let plain = match plain.as_slice() {
            [only] => Some(*only),
            [_, second, ..] => Some(*second),
            [] => None,
        };
        html.or(plain)
    }

    /// (index in `paths`, content type) of each body part, in the order they were extracted
    /// (ace3's `_body_part_types`).
    fn body_part_types<'a>(
        parts: Option<&'a [EmailPart]>,
        paths: &[&str],
    ) -> Vec<(usize, &'a str)> {
        match parts {
            Some(parts) => parts
                .iter()
                .filter(|part| part.role == PartRole::Body)
                .filter_map(|part| {
                    let index = paths.iter().position(|p| *p == part.path)?;
                    Some((index, part.content_type.as_str()))
                })
                .collect(),
            None => paths
                .iter()
                .enumerate()
                .filter_map(|(index, path)| {
                    let name = path.rsplit('/').next().unwrap_or_default();
                    if name.contains("unknown_text_html") {
                        Some((index, "text/html"))
                    } else if name.contains("unknown_text_plain") {
                        Some((index, "text/plain"))
                    } else {
                        None
                    }
                })
                .collect(),
        }
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
    /// Where each recipient's copy went, from an Office 365 journal report's `Recipient:` lines
    /// (ace3's `deliveries`, aaeef15e): every address a line names and every local header address,
    /// normalized. Set only for a journal report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliveries: Option<BTreeMap<String, Delivery>>,
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

/// Where mail sent to one address went, by the journal (ace3's entry of `deliveries`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub reason: DeliveryReason,
    /// The mailboxes that received it: the address itself when delivered, the mailboxes a forward
    /// or a list expansion reached otherwise, none when the journal doesn't name the address.
    pub mailboxes: Vec<String>,
}

/// Why an address's copy went where it did (ace3's `DELIVERY_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryReason {
    /// The address has its own `Recipient:` line.
    Delivered,
    /// A `Forwarded:` annotation links it to the mailbox that received it.
    Forwarded,
    /// An `Expanded:` annotation names it as a distribution list.
    Expanded,
    /// In the headers, but no `Recipient:` line accounts for it. One message can be split across
    /// several journal reports, so this doesn't prove it received nothing.
    NotJournaled,
}

impl DeliveryReason {
    /// The tag the email module puts on the `email_delivery` of an address the journal didn't
    /// deliver to under that address (ace3's `DELIVERY_TAGS`), which remediation's coverage and
    /// timeline read; None for one it did.
    pub fn tag(self) -> Option<&'static str> {
        match self {
            DeliveryReason::Delivered => None,
            DeliveryReason::Forwarded => Some("delivery_forwarded"),
            DeliveryReason::Expanded => Some("delivery_expanded"),
            DeliveryReason::NotJournaled => Some("delivery_not_journaled"),
        }
    }

    /// The reason a delivery tag stands for (ace3's `DELIVERY_TAG_REASONS`), matched without case.
    pub fn of_tag(tag: &str) -> Option<DeliveryReason> {
        [
            DeliveryReason::Forwarded,
            DeliveryReason::Expanded,
            DeliveryReason::NotJournaled,
        ]
        .into_iter()
        .find(|reason| reason.tag().is_some_and(|t| t.eq_ignore_ascii_case(tag)))
    }

    /// What it says about mail sent to an address that didn't receive its own copy, naming the
    /// mailboxes that did when they are known: ace3's `describe_undelivered`, the one wording of
    /// the email summary, the remediation timeline and the coverage tooltip.
    pub fn describe_undelivered(self, mailboxes: &[String]) -> String {
        let mut shown = mailboxes
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if mailboxes.len() > 3 {
            shown = format!("{shown} and {} more", mailboxes.len() - 3);
        }
        match self {
            DeliveryReason::Forwarded => format!(
                "not delivered to this address; forwarded to {}",
                if shown.is_empty() {
                    "another mailbox"
                } else {
                    &shown
                }
            ),
            DeliveryReason::Expanded => {
                let mut text =
                    "distribution list; its members' copies are their own deliveries".to_owned();
                if !shown.is_empty() {
                    text = format!("{text}: {shown}");
                }
                text
            }
            DeliveryReason::Delivered | DeliveryReason::NotJournaled => {
                "no journal record of a copy delivered to this address".to_owned()
            }
        }
    }
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
    use super::{EmailAnalysis as Email, EmailPart, PartRole};

    fn by_name(names: &[&str]) -> Option<usize> {
        Email::body_in(None, names)
    }

    #[test]
    fn the_body_is_ace3s_choice_by_name_for_a_result_without_parts() {
        // a lone plain part, where it is among the rest
        let names = ["a.headers", "a.unknown_text_plain_000.txt", "x.docx"];
        assert_eq!(by_name(&names), Some(1));
        // HTML first, whichever way round
        let names = [
            "a.unknown_text_plain_000.txt",
            "a.unknown_text_html_000.html",
        ];
        assert_eq!(by_name(&names), Some(1));
        let names = [
            "a.unknown_text_html_000.html",
            "a.unknown_text_html_001.html",
        ];
        assert_eq!(by_name(&names), Some(0));
        // two plain parts: the first is skipped
        let names = [
            "a.unknown_text_plain_000.txt",
            "a.unknown_text_plain_001.txt",
        ];
        assert_eq!(by_name(&names), Some(1));
        assert_eq!(by_name(&["a.headers", "x.docx"]), None);
        assert_eq!(by_name(&[]), None);
        assert_eq!(
            Email::body_parts_in(
                None,
                &[
                    "a.headers",
                    "a.unknown_text_plain_000",
                    "x.docx",
                    "d/a.unknown_text_html_001",
                ]
            ),
            [(1, false), (3, true)]
        );
    }

    #[test]
    fn a_result_s_parts_say_which_are_its_body_whatever_their_names() {
        let part = |path: &str, content_type: &str, role| EmailPart {
            path: path.to_owned(),
            content_type: content_type.to_owned(),
            role,
        };
        // ace3's #1241: an attachment the sender named like a body part isn't one
        let parts = [
            part("e.unknown_text_plain_000.txt", "text/plain", PartRole::Body),
            part(
                "notes.unknown_text_html_000.html",
                "text/html",
                PartRole::Attachment,
            ),
        ];
        let paths = [
            "e.headers",
            "e.unknown_text_plain_000.txt",
            "notes.unknown_text_html_000.html",
        ];
        assert_eq!(Email::body_parts_in(Some(&parts), &paths), [(1, false)]);
        assert_eq!(Email::body_in(Some(&parts), &paths), Some(1));
        // an empty record has no body, though a name says otherwise
        assert_eq!(Email::body_in(Some(&[]), &paths), None);
        // a part whose file isn't among the result's is left out
        let parts = [part("gone.txt", "text/html", PartRole::Body)];
        assert_eq!(Email::body_parts_in(Some(&parts), &paths), []);
    }
}
