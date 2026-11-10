//! The modules on ACE's email archive (PLAN.md 7.5 batch 9). A worker holds no database credentials
//! and no encryption key, so each reads the archive through the core, or writes it with its task's
//! end (PLAN.md 7.2, `crates/ace-core/src/reads.md`), and the core seals and opens the emails:
//!
//! - `email_archiver` (`archiver`): ace3's `EmailArchiveAction`, which archives an email through the
//!   `email-archive` write.
//! - `encrypted_archive_analyzer` (`encrypted`): ace3's `EncryptedArchiveAnalyzer`, which opens an
//!   archived email file in the alert through the `decrypted-archive` read.
//! - `url_email_pivot_analyzer` (`pivot`): ace3's `URLEmailPivotAnalyzer`, which counts the archived
//!   emails that held a URL through the `archived-url-count` read.
//! - `message_id_analyzer_v2` (`message_id`): ace3's `MessageIDAnalyzerV2`, which pulls an archived
//!   email into the alert by its Message-ID through the `archived-email` read.

pub mod archiver;
pub mod encrypted;
pub mod message_id;
pub mod pivot;

pub use archiver::EmailArchiver;
pub use encrypted::EncryptedArchiveAnalyzer;
pub use message_id::MessageIdAnalyzer;
pub use pivot::UrlEmailPivotAnalyzer;

/// The tag ace3 gives an email it took out of the archive.
pub const DECRYPTED_EMAIL: &str = "decrypted_email";
