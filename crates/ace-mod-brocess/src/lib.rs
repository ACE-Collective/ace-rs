//! The modules that read brocess, ace3's database of what its email modules have seen before
//! (PLAN.md 7.4). A worker holds no database credentials, so each reads it through the core
//! (PLAN.md 7.2, `crates/ace-core/src/reads.md`).
//!
//! - `email_conversation_frequency_analyzer` (`frequency`): ace3's
//!   `EmailConversationFrequencyAnalyzer`, through the `smtp-counts` read.

pub mod frequency;

pub use frequency::EmailConversationFrequencyAnalyzer;
