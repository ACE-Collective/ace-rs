//! The modules on ACE's email archive (PLAN.md 7.5 batch 9). A worker holds no database credentials
//! and no encryption key, so each reads the archive through the core, or writes it with its task's
//! end (PLAN.md 7.2, `crates/ace-core/src/reads.md`), and the core seals and opens the emails:
//!
//! - `email_archiver` (`archiver`): ace3's `EmailArchiveAction`, which archives an email through the
//!   `email-archive` write.
//! - `message_id_analyzer_v2` (`message_id`): ace3's `MessageIDAnalyzerV2`, which pulls an archived
//!   email into the alert by its Message-ID through the `archived-email` read.
//!
//! ace3's 4f1fa192 removed `encrypted_archive_analyzer` and `url_email_pivot_analyzer`, since the
//! archive is no longer searchable and no alert holds a `.gz.e` file, and ace4 removed them with it.

pub mod archiver;
pub mod message_id;

pub use archiver::EmailArchiver;
pub use message_id::MessageIdAnalyzer;

/// The tag ace3 gives an email it took out of the archive.
pub const DECRYPTED_EMAIL: &str = "decrypted_email";
