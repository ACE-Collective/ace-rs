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

use ace_results::ObservableRef;
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

/// `email-archive`: the task's own file, an email, kept in the email archive under its Message-ID
/// (`email_archiver`). The core reads the file from the bucket, gzips and encrypts it with ACE's key,
/// and writes the archive's row, the Message-ID to the email, as ace3's `archive_email` does.
pub struct EmailArchive;

impl WriteKind for EmailArchive {
    const WRITE: Write = Write {
        name: "email-archive",
    };
    type Body = ArchivedEmailRecord;
}

/// What an archived email is found by: its Message-ID, as its email result has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedEmailRecord {
    pub message_id: String,
}

/// `svs-capture`: the task's own file kept as an SVS sample for each YARA rule that matched it on an
/// alert graded TP or FP (`svs_yara_sample_capture`, PLAN.md 7.10 batch 2). The core copies the file from
/// the root's files into the bucket's `svs_samples` pool, held by the capture, and writes each capture's
/// row with its match record, as ace3's `saq.svs.capture.capture` does.
pub struct SvsCapture;

impl WriteKind for SvsCapture {
    const WRITE: Write = Write {
        name: "svs-capture",
    };
    type Body = SvsCaptures;
}

/// The captures of one file, one per rule.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsCaptures {
    pub captures: Vec<SvsCaptureCandidate>,
}

/// One file a YARA rule matched, and what a replay needs to scan it again: ace3's `CaptureCandidate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsCaptureCandidate {
    /// The file's sha256, lower case: the task's own file.
    pub sha256: String,
    /// The rule's uuid meta, which its detection's signature is.
    pub rule_uuid: String,
    pub rule_name: String,
    pub namespace: Option<String>,
    /// The commit of the rule's repository when it matched, or `unknown`.
    pub signature_version: String,
    /// The file's path in the alert, one of its paths there.
    pub file_path: String,
    pub yara_meta_tags: Vec<String>,
    /// The YARA result's scan_results entry for the rule, or None when the result doesn't have it.
    pub match_record: Option<Value>,
}

/// The most captures one `svs-capture` write makes.
pub const MAX_SVS_CAPTURES: usize = 1000;

/// `remediation-check`: a remediation check of the task's own observable by one of the core's probes,
/// for the task's root, and what the module found when it asked the same question itself (PLAN.md
/// decision 32). ace3's module looks for a pending check of the probe, target and alert
/// (`get_pending_external_check_by_observable`), queues one when there's none
/// (`queue_external_check`), and records its own answer as a try (`persist_probe_outcome`); the
/// core does the same in the end's transaction, so the module needs no read of the check. No module
/// of ace4's makes it: a site's remediation modules do.
pub struct RemediationCheck;

impl WriteKind for RemediationCheck {
    const WRITE: Write = Write {
        name: "remediation-check",
    };
    type Body = CheckRequest;
}

/// A remediation check a module asks for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    /// The probe's name, such as ace3's `msmail_filter`: a remediation check handler the core's catalog
    /// has (`crate::actions::ActionSpec`), which acts on the task's observable's type.
    pub probe: String,
    /// What the module knows that the probe's later tries need, such as the alert's event time,
    /// frozen on the check when it's queued (ace3's `context_json`). A pending check keeps its own.
    #[serde(default)]
    pub context: Option<serde_json::Map<String, Value>>,
    /// The module's own answer, recorded as one try of the check, as ace3's `persist_probe_outcome`
    /// after the module ran the probe itself. None to queue the check only.
    #[serde(default)]
    pub outcome: Option<crate::actions::ProbeOutcome>,
}

/// The most bytes a check's context takes, as JSON.
pub const MAX_CHECK_CONTEXT_BYTES: usize = 16 * 1024;

/// `file-collection`: a file collection of the task's own observable by one of the core's
/// collectors, for the task's root (PLAN.md decision 49). ace3's module joins a pending collection of
/// the same target by the same collector (`get_pending_file_collection_by_observable`,
/// `wait_on_file_collection`), or queues one (`queue_file_collection`), and then waits; the core does
/// the same in the end's transaction (`ace_core::actions::request_collection`): it joins a pending
/// one, from any alert or person, takes the root's own earlier success, or queues a new one. The
/// module reads where it stands with the `file-collection` read. No module of ace4's makes it:
/// a site's Endpoint modules do.
pub struct FileCollection;

impl WriteKind for FileCollection {
    const WRITE: Write = Write {
        name: "file-collection",
    };
    type Body = CollectionAsk;
}

/// A file collection a module asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionAsk {
    /// The collector's name, such as a site's `endpoint_file_collection`: a file collection handler
    /// the core's catalog has (`crate::actions::ActionSpec`), which acts on the task's observable's
    /// type.
    pub collector: String,
}

/// `file-collection-release`: the task's root stops waiting on collections it no longer needs, as
/// ace3's `endpoint_file_collector` cancels its siblings' once the identical file is in the alert
/// (`_cancel_sibling_collections`) (PLAN.md decision 49). For each named observable of the root, its
/// unfinished collection by the collector stops being the root's; it is cancelled only when no
/// other root waits on it and no person or caller asked for it, where ace3 cancels it whoever else
/// waits.
pub struct FileCollectionRelease;

impl WriteKind for FileCollectionRelease {
    const WRITE: Write = Write {
        name: "file-collection-release",
    };
    type Body = CollectionRelease;
}

/// The collections a module lets go of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionRelease {
    /// The collector, as `CollectionAsk::collector`.
    pub collector: String,
    /// The targets, each an observable of the root of the collector's type, the task's own among
    /// them or not; at most `MAX_RELEASED`.
    pub observables: Vec<ObservableRef>,
}

/// The most targets one `file-collection-release` names.
pub const MAX_RELEASED: usize = 100;

/// `sandbox-submission`: the task's own file's row in ace3's `sandbox_submissions` for a sandbox
/// (PLAN.md decision 50), as a site's ExampleSandbox module calls `record_submission` when it submits a file
/// or finds the sandbox already knows it, and `update_submission_result` once the analysis ends.
pub struct SandboxSubmission;

impl WriteKind for SandboxSubmission {
    const WRITE: Write = Write {
        name: "sandbox-submission",
    };
    type Body = SandboxSubmissionRecord;
}

/// What a module records of its file in a sandbox. The first record of a file for a sandbox makes
/// its row, and a later one keeps it, as ace3's unique key does (where ace3's second insert
/// raises); a verdict, in either, sets the row's verdict, score and completion time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSubmissionRecord {
    /// As `SandboxSubmissionRequest::sandbox_type`.
    pub sandbox_type: String,
    /// The sandbox's id for the file, at most 256 characters.
    #[serde(default)]
    pub external_id: Option<String>,
    /// True when the module sent the file, so it counts toward a daily cap; false when the sandbox
    /// already knew it.
    pub submitted: bool,
    /// The analysis's verdict, at most 64 characters, once it finished.
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub score: Option<i32>,
}

/// Whether a write lands with a delay as well as with a result or a skip: `remediation-check`, since
/// ace3's module queues its check and records its answer before it waits, and the core reuses the
/// pending check on the next run, as ace3's does; and `file-collection` and
/// `file-collection-release`, since ace3's module queues or joins a collection, or cancels its
/// siblings', and then waits; and `sandbox-submission`, since a site's sandbox module records the
/// file it sent and then waits for the analysis. Every other write lands only with a result or a skip, so a task that
/// delays writes nothing else.
pub fn lands_on_delay(write: &str) -> bool {
    write == RemediationCheck::WRITE.name
        || write == FileCollection::WRITE.name
        || write == FileCollectionRelease::WRITE.name
        || write == SandboxSubmission::WRITE.name
}

/// Every write a module can declare, by name.
pub const ALL: &[Write] = &[
    SmtpLog::WRITE,
    EmailThread::WRITE,
    EmailArchive::WRITE,
    SvsCapture::WRITE,
    RemediationCheck::WRITE,
    FileCollection::WRITE,
    FileCollectionRelease::WRITE,
    SandboxSubmission::WRITE,
];
