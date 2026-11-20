//! The modules that read and write brocess, ace3's database of what its email modules have seen
//! before (PLAN.md 7.4). A worker holds no database credentials, so each reads it through the core
//! and writes it with its task's end (PLAN.md 7.2, `crates/ace-core/src/reads.md`).
//!
//! - `email_conversation_frequency_analyzer` (`frequency`): ace3's
//!   `EmailConversationFrequencyAnalyzer`, through the `smtp-counts` read.
//! - `email_logger` (`logger`): ace3's `EmailLoggingAnalyzer`, which writes `smtplog` and the
//!   thread store, reads the `email-thread-domains` read, and sends to fluent-bit (`fluent`).
//!
//! - `email_thread_analyzer` (`thread`): ace3's `EmailThreadAnalyzer`, which lays out the
//!   conversation the logger recorded a Message-ID in, through the `email-thread` read.
//!
//! - `email_conversation_attachment_analyzer` (`attachment`) and `email_conversation_link_analyzer`
//!   (`link`): ace3's `EmailConversationAttachmentAnalyzer` and `EmailConversationLinkAnalyzer`, parsers
//!   that read the frequency module's `new_sender` tags in the root's tree (PLAN.md 7.5 batch 8).
//!
//! `threads` finds an email's thread as ace3 does, and `similarity` is ace3's look-alike checks.
//!
//! `similarity` (ace3's `saq.domain_similarity`) and `thread::IgnoredDomainPairs` (the thread
//! settings' `is_ignored_pair`) are for a site's modules too, as ace3's are for its integrations:
//! a site's `mail_filter_email_thread_recovery` compares a recovered conversation's domains with
//! them (PLAN.md decision 29).

pub mod attachment;
pub mod fluent;
pub mod frequency;
pub mod link;
pub mod logger;
pub mod similarity;
pub mod thread;
pub mod threads;

pub use attachment::EmailConversationAttachmentAnalyzer;
pub use frequency::EmailConversationFrequencyAnalyzer;
pub use link::EmailConversationLinkAnalyzer;
pub use logger::EmailLogger;
pub use thread::{EmailThreadAnalyzer, IgnoredDomainPairs};
