//! The modules of PLAN.md 7.5 batch 8 that walk an email's tree, as ace3's walk the `RootAnalysis`.
//! Each reads the root's tree on the lease (`Module::READS_TREE`, `ace_sdk::tree`).
//!
//! - `lure_url_analyzer` (`lure`): ace3's `LureURLAnalyzer`, which picks the URL an email lures its
//!   recipient to and adds `crawl` to it.
//! - `mailbox_email_analyzer` (`mailbox`): ace3's `MailboxEmailAnalyzer`, which names a mailbox
//!   alert after its email's subject, gives the root the email's details and tracks its Message-ID.

pub mod lure;
pub mod mailbox;

pub use lure::LureUrlAnalyzer;
pub use mailbox::MailboxEmailAnalyzer;
