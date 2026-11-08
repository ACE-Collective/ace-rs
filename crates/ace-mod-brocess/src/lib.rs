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
//! `threads` finds an email's thread as ace3 does, and `similarity` is ace3's look-alike checks.

pub mod fluent;
pub mod frequency;
pub mod logger;
pub mod similarity;
pub mod thread;
pub mod threads;

pub use frequency::EmailConversationFrequencyAnalyzer;
pub use logger::EmailLogger;
pub use thread::EmailThreadAnalyzer;
