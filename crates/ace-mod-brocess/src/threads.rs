//! An email's place in its conversation, as ace3's `derive_thread_context`
//! (`saq/modules/email/conversation.py`) finds it from the email module's result: its thread, its
//! subject as threads match it, its date, and who took part.

use ace_mod_email::headers::{is_subdomain, parse_date};
use ace_pycompat::email_utils::parseaddr;
use ace_results::types::email::EmailDetails;
use ace_sdk::email_threads::normalize_email_address;
use ace_sdk::email_threads::{self, header_value, normalize_message_id};
use ace_sdk::writes::{ThreadParticipant, ThreadRecord};

use crate::similarity::registrable_domain;

/// The roles whose domains a new sender is scored by.
pub const SENDER_ROLES: [&str; 3] = ["from", "reply_to", "return_path"];

/// An address that took part, with its registrable domain, in one role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    pub address: String,
    pub domain: String,
    pub role: &'static str,
}

/// `ThreadContext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadContext {
    pub thread_id: String,
    pub thread_method: &'static str,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub normalized_subject: String,
    /// The `Date` header in UTC, as `%Y-%m-%d %H:%M:%S`.
    pub message_date: Option<String>,
    pub from_address: Option<String>,
    pub from_domain: Option<String>,
    pub direction: Option<i16>,
    /// From, Reply-To and Return-Path, then each To and Cc.
    pub participants: Vec<Participant>,
    /// The first three of those that are there.
    pub senders: Vec<Participant>,
}

/// `get_email_domain`: what follows the first `@`.
fn email_domain(address: &str) -> Option<&str> {
    address.split_once('@').map(|(_, domain)| domain)
}

/// `_participant`: an address with a registrable domain, or None.
fn participant(address: Option<&str>, role: &'static str) -> Option<Participant> {
    let address = address.filter(|a| !a.is_empty())?;
    let domain = registrable_domain(email_domain(address).unwrap_or(""));
    if domain.is_empty() {
        return None;
    }
    Some(Participant {
        address: address.to_owned(),
        domain,
        role,
    })
}

/// `is_local_email_domain`.
fn is_local(address: &str, local_email_domains: &[String]) -> bool {
    let Some(normalized) = normalize_email_address(address) else {
        return false;
    };
    let Some(domain) = email_domain(&normalized) else {
        return false;
    };
    local_email_domains
        .iter()
        .any(|local| is_subdomain(domain, local))
}

impl ThreadContext {
    /// `derive_thread_context`.
    pub fn of(email: &EmailDetails, local_email_domains: &[String]) -> ThreadContext {
        let message_id = email_threads::message_id(email);
        let (thread_id, thread_method) = email_threads::thread_id(email);
        let message_date = header_value(email, "date")
            .and_then(parse_date)
            .map(|date| date.naive_utc().format("%Y-%m-%d %H:%M:%S").to_string());
        let return_path = email.return_path.as_deref().map(|value| parseaddr(value).1);
        let mut senders = Vec::new();
        for (address, role) in [
            (email.from_address.as_deref(), "from"),
            (email.reply_to_address.as_deref(), "reply_to"),
            (return_path.as_deref(), "return_path"),
        ] {
            senders.extend(participant(address, role));
        }
        let from = senders.iter().find(|p| p.role == "from").cloned();
        let mut participants = senders.clone();
        for address in &email.to_addresses {
            participants.extend(participant(Some(address), "to"));
        }
        for value in email.cc.iter().flatten() {
            participants.extend(participant(Some(&parseaddr(value).1), "cc"));
        }
        let direction = from.as_ref().map(|from| {
            if is_local(&from.address, local_email_domains) {
                1
            } else {
                0
            }
        });
        ThreadContext {
            thread_id,
            thread_method,
            message_id: message_id.map(|id| normalize_message_id(&id)),
            in_reply_to: email.log_entry.in_reply_to.clone(),
            normalized_subject: email_threads::normalized_subject(email),
            message_date,
            from_address: from.as_ref().map(|p| p.address.clone()),
            from_domain: from.map(|p| p.domain),
            direction,
            participants,
            senders,
        }
    }

    /// The registrable domains of everyone who took part.
    pub fn participant_domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self.participants.iter().map(|p| p.domain.clone()).collect();
        domains.sort();
        domains.dedup();
        domains
    }

    /// What `record_thread` writes, for a message with a thread and an id.
    pub fn record(&self) -> Option<ThreadRecord> {
        let message_id = self.message_id.clone()?;
        if self.thread_id.is_empty() || message_id.is_empty() {
            return None;
        }
        Some(ThreadRecord {
            thread_id: self.thread_id.clone(),
            message_id,
            in_reply_to: self.in_reply_to.clone(),
            normalized_subject: Some(self.normalized_subject.clone()).filter(|s| !s.is_empty()),
            from_address: self.from_address.clone(),
            from_domain: self.from_domain.clone(),
            direction: self.direction,
            message_date: self.message_date.clone(),
            participants: self
                .participants
                .iter()
                .map(|p| ThreadParticipant {
                    domain: p.domain.clone(),
                    address: p.address.clone(),
                    role: p.role.to_owned(),
                })
                .collect(),
        })
    }
}
