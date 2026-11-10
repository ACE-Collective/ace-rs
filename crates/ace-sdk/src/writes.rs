//! Writes to ACE's own data (PLAN.md 7.2). A worker holds no database credentials, so a lookup
//! module that writes what ace3's modules write to its databases hands the rows to the core with
//! the task's end, which writes them in the end's own transaction: a task that's retried never
//! writes twice, and one that fails, is cancelled or delays writes nothing. The contract is
//! `crates/ace-core/src/reads.md`.
//!
//! A module declares the writes it makes in `Module::WRITES`, and makes one with
//! `TaskContext::write`, typed by the write's `WriteKind`:
//!
//! ```text
//! const WRITES: &'static [Write] = &[SmtpLog::WRITE];
//! ctx.write::<SmtpLog>(&SmtpLogRows { rows })?;
//! ```
//!
//! The pool sends what the task wrote with its end, when that end is a result or a skip. A parser
//! can't declare one, as it can't declare a read.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A write a module declares, by its name in the task's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Write {
    pub name: &'static str,
}

/// One write's body.
pub trait WriteKind {
    const WRITE: Write;
    type Body: Serialize + Send + Sync;
}

/// A write as a task's end carries it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireWrite {
    /// The write's name, as `Write::name`.
    pub write: String,
    pub body: Value,
}

/// `smtp-log`: one more email from each sender to each recipient, in brocess's `smtplog`
/// (`email_logger`).
pub struct SmtpLog;

impl WriteKind for SmtpLog {
    const WRITE: Write = Write { name: "smtp-log" };
    type Body = SmtpLogRows;
}

/// The conversations an email adds to `smtplog`, each counted once more, in order. ace3 writes
/// each address as UTF-8 cut to 255 bytes, and the core cuts them the same way.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpLogRows {
    pub rows: Vec<SmtpLogRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpLogRow {
    pub source: String,
    pub destination: String,
}

/// `email-thread`: an email's message and its participants in brocess's thread store, as ace3's
/// `record_thread` writes them (`email_logger`).
pub struct EmailThread;

impl WriteKind for EmailThread {
    const WRITE: Write = Write {
        name: "email-thread",
    };
    type Body = ThreadRecord;
}

/// One message of a thread, and who took part in it. A message already recorded in its thread,
/// and a participant already recorded for it, stay as they were.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadRecord {
    pub thread_id: String,
    /// The message's id, `<...>`.
    pub message_id: String,
    pub in_reply_to: Option<String>,
    /// None for a message with no subject left once its prefixes are gone.
    pub normalized_subject: Option<String>,
    pub from_address: Option<String>,
    pub from_domain: Option<String>,
    /// 0 inbound, 1 outbound; None without a From address.
    pub direction: Option<i16>,
    /// The `Date` header in UTC, as `%Y-%m-%d %H:%M:%S`.
    pub message_date: Option<String>,
    pub participants: Vec<ThreadParticipant>,
}

/// An address that took part in a message, in one role: `from`, `reply_to`, `return_path`, `to`
/// or `cc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadParticipant {
    pub domain: String,
    pub address: String,
    pub role: String,
}

/// `email-archive`: the task's own file, an email, kept in the email archive with its Message-ID and
/// envelope recipients (`email_archiver`). The core reads the file from the bucket, gzips and
/// encrypts it with ACE's key, and writes the archive's rows, as ace3's `archive_email` does; once
/// the root's analysis is done, it indexes the URLs below the email, as ace3's post-analysis does.
pub struct EmailArchive;

impl WriteKind for EmailArchive {
    const WRITE: Write = Write {
        name: "email-archive",
    };
    type Body = ArchivedEmailRecord;
}

/// What an archived email is found by: its Message-ID, as its email result has it, and its envelope
/// recipients, each normalized as ace3's `normalize_email_address` does; one it can't parse is left
/// out, as ace3's insert of a NULL fails and is passed over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedEmailRecord {
    pub message_id: String,
    pub recipients: Vec<String>,
}

/// Every write a module can declare, by name.
pub const ALL: &[Write] = &[SmtpLog::WRITE, EmailThread::WRITE, EmailArchive::WRITE];
