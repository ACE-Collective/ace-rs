//! Reads of ACE's own data (PLAN.md 7.2). A worker holds no database credentials, so a lookup
//! module that reads what ace3's modules query its databases for asks the core, through the lease
//! API: `POST /api/worker/v1/tasks/<id>/reads/<read>` with its pool's token. The contract, with
//! every read and how the core refuses one, is `crates/ace-core/src/reads.md`.
//!
//! A module declares the reads it makes in `Module::READS`, and makes one with
//! `TaskContext::read`, typed by the read's `ReadKind`:
//!
//! ```text
//! const READS: &'static [Read] = &[SnortSignature::READ];
//! let answer = ctx.read::<SnortSignature>(&SnortSignatureRequest::default()).await?;
//! ```
//!
//! A parser can't declare one: its task process has no network and no channel back while it runs.

use std::future::Future;
use std::pin::Pin;

use ace_results::ObservableRef;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::module::BoxError;

/// A read a module declares, by its name in the lease API's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Read {
    pub name: &'static str,
}

/// One read's request and answer.
pub trait ReadKind {
    const READ: Read;
    type Request: Serialize + Send + Sync;
    type Answer: DeserializeOwned;
}

/// Why a read wasn't answered.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The core refused it: 400, 401 or 403, with its reason.
    #[error("the core refused read {read} with {status}: {message}")]
    Refused {
        read: &'static str,
        status: u16,
        message: String,
    },
    /// The task isn't leased to this worker any more (409).
    #[error("read {0}: the task's lease was lost")]
    LeaseLost(&'static str),
    /// The core, or the store behind the read, couldn't answer (503), or couldn't be reached.
    #[error("read {read}: {source}")]
    Unavailable {
        read: &'static str,
        #[source]
        source: BoxError,
    },
    #[error("read {read}: {source}")]
    Other {
        read: &'static str,
        #[source]
        source: BoxError,
    },
}

/// What makes a task's reads: the pool's lease API client, or a test's fake.
pub trait Reader: Send + Sync {
    /// Read `read` for task `task` with `request`, answering the read's JSON.
    fn read<'a>(
        &'a self,
        task: i64,
        read: &'static str,
        request: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, ReadError>> + Send + 'a>>;
}

/// `snort-signature`: the rule line of the snort or suricata signature an observable names
/// (`snort_signature_analysis_v1`).
pub struct SnortSignature;

impl ReadKind for SnortSignature {
    const READ: Read = Read {
        name: "snort-signature",
    };
    type Request = SnortSignatureRequest;
    type Answer = SnortSignatureAnswer;
}

/// The subject of a `snort-signature` read: a `snort_sig` observable in the task's root, whose
/// value is `<gid>:<sid>:<rev>`. None is the task's own observable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnortSignatureRequest {
    #[serde(default)]
    pub subject: Option<ObservableRef>,
}

/// The answer to a `snort-signature` read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnortSignatureAnswer {
    /// The rule's line, as the rules file has it without surrounding whitespace, or None when the
    /// file has no rule with the subject's sid and rev.
    pub rule: Option<String>,
}

/// `smtp-counts`: how often brocess has seen an email conversation's sender, and the sender write
/// to its recipient (`email_conversation_frequency_analyzer`).
pub struct SmtpCounts;

impl ReadKind for SmtpCounts {
    const READ: Read = Read {
        name: "smtp-counts",
    };
    type Request = SmtpCountsRequest;
    type Answer = SmtpCountsAnswer;
}

/// The subject of an `smtp-counts` read: an `email_conversation` observable in the task's root,
/// `<sender>|<recipient>`. None is the task's own observable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpCountsRequest {
    #[serde(default)]
    pub subject: Option<ObservableRef>,
}

/// The answer to an `smtp-counts` read: brocess's `SUM(numconnections)` over `smtplog`, 0 when no
/// row counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpCountsAnswer {
    /// Emails seen from the sender, to anyone.
    pub source_count: i64,
    /// Emails seen from the sender to the recipient.
    pub conversation_count: i64,
}

/// `email-thread-domains`: the domains earlier messages of an email's thread established, and how
/// many messages the thread has (`email_logger`).
pub struct EmailThreadDomains;

impl ReadKind for EmailThreadDomains {
    const READ: Read = Read {
        name: "email-thread-domains",
    };
    type Request = EmailThreadDomainsRequest;
    type Answer = EmailThreadDomainsAnswer;
}

/// The thread an email belongs to, as ace3's `derive_thread_context` finds it. The core answers
/// only for a thread id an email in the task's root has as its Message-ID, an In-Reply-To or a
/// References id, and a normalized subject one of them has.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailThreadDomainsRequest {
    pub thread_id: String,
    /// `references` or `in_reply_to` for a thread its headers name, which is read by its id;
    /// `self` or `none` for a message that starts one, whose same-subject threads sharing one of
    /// `participant_domains` are read instead.
    pub thread_method: String,
    pub normalized_subject: String,
    /// The registrable domains of the email's participants. At most 100.
    pub participant_domains: Vec<String>,
}

/// The answer to an `email-thread-domains` read: ace3's `get_established_domains` and
/// `get_thread_message_count`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailThreadDomainsAnswer {
    /// One per domain, address and role, with its earliest sighting, in the order the store first
    /// recorded each.
    pub established: Vec<EstablishedDomain>,
    /// Messages recorded in the thread.
    pub thread_message_count: i64,
    /// True when `established` was cut at its cap of 10,000 rows read.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstablishedDomain {
    pub domain: String,
    pub address: String,
    pub role: String,
    /// When it was first seen, as `%Y-%m-%d %H:%M:%S`, as ace3's `str(datetime)` writes it.
    pub first_seen: Option<String>,
}

/// `email-thread`: the recorded conversation a Message-ID belongs to (`email_thread_analyzer`).
pub struct EmailThread;

impl ReadKind for EmailThread {
    const READ: Read = Read {
        name: "email-thread",
    };
    type Request = EmailThreadRequest;
    type Answer = EmailThreadAnswer;
}

/// The subject of an `email-thread` read, a `message_id` observable in the task's root, the task's
/// own by default, and how much of its conversation to assemble. The core caps each at 500.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailThreadRequest {
    #[serde(default)]
    pub subject: Option<ObservableRef>,
    pub max_messages: u32,
    pub max_threads: u32,
}

/// The answer to an `email-thread` read: ace3's `get_conversation`, or nothing recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailThreadAnswer {
    /// None when the store has no message with the id.
    pub conversation: Option<Conversation>,
    /// An email of the task's root is still to be recorded: a module that writes `email-thread` has
    /// a task there that hasn't finished. ace3 records an email at the end of its email-mode
    /// analysis, before a root that alerts is analyzed again for correlation, so its thread module
    /// sees the alert's own message; a module that asks here delays until that's done.
    #[serde(default)]
    pub recording: bool,
}

/// A recorded conversation: its messages, oldest first, with who took part in each.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conversation {
    /// The Message-ID asked about, `<...>`.
    pub anchor_message_id: String,
    pub normalized_subject: Option<String>,
    /// How many threads were joined into it.
    pub thread_count: u32,
    /// `headers` when its References or In-Reply-To grouped it, `self` when same-subject threads
    /// sharing a domain were joined.
    pub thread_method: String,
    /// The domains on both sides that joined same-subject threads, sorted.
    pub link_domains: Vec<String>,
    /// How many of the messages each joined thread has, largest first.
    pub thread_message_counts: Vec<u32>,
    /// Every role each domain had, and every address on it, across every thread that qualified,
    /// including any past the thread cap, each sorted.
    pub domain_roles: std::collections::BTreeMap<String, Vec<String>>,
    pub domain_addresses: std::collections::BTreeMap<String, Vec<String>>,
    pub messages: Vec<ConversationMessage>,
    /// The participants of the joined threads, each with the message it was on, or none when it
    /// was recorded before the store kept that.
    pub participants: Vec<MessageParticipant>,
    /// True when a cap trimmed the messages or the threads.
    pub truncated: bool,
    /// True when the core cut the rows the roles and addresses come from at 10,000.
    pub roles_truncated: bool,
}

/// A message of a conversation, as the store recorded it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessage {
    pub thread_id: String,
    pub message_id: String,
    /// The SHA-256 of the message id, in upper-case hex, which participants name it by.
    pub message_id_hex: String,
    pub in_reply_to: Option<String>,
    pub normalized_subject: Option<String>,
    pub from_address: Option<String>,
    pub from_domain: Option<String>,
    pub direction: Option<i16>,
    /// `%Y-%m-%d %H:%M:%S`, UTC.
    pub message_date: Option<String>,
    pub insert_date: Option<String>,
}

/// One participant of one message.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageParticipant {
    pub message_id_hex: Option<String>,
    pub domain: String,
    pub address: String,
    pub role: String,
    pub first_seen: Option<String>,
}

/// `newly-registered`: whether the task's own fqdn or url, or a parent of it down to its registrable
/// domain, is in the newly registered domains list (`nrd_analyzer`).
pub struct NewlyRegistered;

impl ReadKind for NewlyRegistered {
    const READ: Read = Read {
        name: "newly-registered",
    };
    type Request = NewlyRegisteredRequest;
    type Answer = NewlyRegisteredAnswer;
}

/// The subject of a `newly-registered` read: only the task's own observable, which None names. A
/// subject is accepted only when it is that observable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewlyRegisteredRequest {
    #[serde(default)]
    pub subject: Option<ObservableRef>,
}

/// The answer to a `newly-registered` read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewlyRegisteredAnswer {
    /// True when the value, normalized as ace3's `saq.nrd.util` does, or one of its parents down to
    /// its registrable domain is in the list.
    pub listed: bool,
}

/// A file a read put in the task's root (`archived-email`, `decrypted-archive`): its bytes are in
/// the bucket's `alert_files` pool, held by the root, so a result adds it by its sha256 and size
/// as a `NewFile` with no upload (`reads.md`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadFile {
    pub sha256: String,
    pub size: u64,
}

/// `archived-email`: the newest archived email with the task's Message-ID, decrypted in the core
/// and put in the task's root (`message_id_analyzer_v2`).
pub struct ArchivedEmail;

impl ReadKind for ArchivedEmail {
    const READ: Read = Read {
        name: "archived-email",
    };
    type Request = ArchivedEmailRequest;
    type Answer = ArchivedEmailAnswer;
}

/// The subject of an `archived-email` read: only the task's own `message_id` observable, which None
/// names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedEmailRequest {
    #[serde(default)]
    pub subject: Option<ObservableRef>,
}

/// The answer to an `archived-email` read. Neither is set when no email with the Message-ID is
/// archived.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchivedEmailAnswer {
    /// The archived email, decrypted and gunzipped.
    pub email: Option<ReadFile>,
    /// Why an email that is archived couldn't be opened, such as an object the bucket no longer
    /// has, a core with no encryption key, or one past the core's bound.
    pub error: Option<String>,
}

/// `observable-tags`: the tags analysts mapped to the task's own observable, by its type and the
/// sha256 of its value (`user_defined_tagging`).
pub struct ObservableTags;

impl ReadKind for ObservableTags {
    const READ: Read = Read {
        name: "observable-tags",
    };
    type Request = ObservableTagsRequest;
    type Answer = ObservableTagsAnswer;
}

/// The subject of an `observable-tags` read: only the task's own observable, which None names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableTagsRequest {
    #[serde(default)]
    pub subject: Option<ObservableRef>,
}

/// The answer to an `observable-tags` read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableTagsAnswer {
    /// The tags, in the order they were mapped, at most `MAX_OBSERVABLE_TAGS`.
    pub tags: Vec<String>,
    /// The observable had more tags than the answer holds.
    #[serde(default)]
    pub truncated: bool,
}

/// The most tags an `observable-tags` answer holds.
pub const MAX_OBSERVABLE_TAGS: usize = 1000;

/// `svs-capture-state`: what `svs_yara_sample_capture` needs to decide which of the task's file's YARA
/// matches SVS keeps as samples (PLAN.md 7.10 batch 2): whether the root is an alert graded TP or FP that
/// no unreviewed test run holds, the YARA detections on the file, and what SVS already has of it.
pub struct SvsCaptureState;

impl ReadKind for SvsCaptureState {
    const READ: Read = Read {
        name: "svs-capture-state",
    };
    type Request = SvsCaptureStateRequest;
    type Answer = SvsCaptureStateAnswer;
}

/// The subject of an `svs-capture-state` read: only the task's own file, which None names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsCaptureStateRequest {
    #[serde(default)]
    pub subject: Option<ObservableRef>,
}

/// The answer to an `svs-capture-state` read.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsCaptureStateAnswer {
    /// Whether the root is an alert.
    pub alert: bool,
    /// The alert's disposition; None while it's open.
    pub disposition: Option<String>,
    /// Whether the site's classification makes the disposition `tp` or `fp`: an unclassified alert
    /// teaches SVS nothing.
    pub classified: bool,
    /// Whether the alert is attributed to a test run that isn't reviewed (ace3's
    /// `unreviewed_run_condition`): its alerts teach nothing either.
    pub unreviewed_run: bool,
    /// The file's paths in the root, each with its `yara_meta` tags, in the order they were added.
    pub paths: Vec<SvsFilePath>,
    /// The detections on the file, in the order they were made, at most `MAX_SVS_DETECTIONS`.
    pub detections: Vec<SvsDetection>,
    /// The file had more detections than the answer holds.
    #[serde(default)]
    pub detections_truncated: bool,
    /// The file was deleted from SVS, which never captures it again.
    pub deleted: bool,
    /// What SVS has captured of the file from this root, by rule.
    pub captures: Vec<SvsCaptureRow>,
}

/// One of a file's paths in its root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsFilePath {
    pub path: String,
    pub yara_meta: Vec<String>,
}

/// A detection on the file, as it's stored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsDetection {
    pub description: String,
    pub details: Option<Value>,
    pub signature_uuid: Option<String>,
    pub signature_version: Option<String>,
}

/// A capture SVS already has, of the file from this root, for one rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvsCaptureRow {
    pub rule_uuid: String,
    /// `stored` or `missing`.
    pub state: String,
    /// `file`, `storage` or `match_record`, when it lacks something.
    pub missing_reason: Option<String>,
}

/// The most detections an `svs-capture-state` answer holds.
pub const MAX_SVS_DETECTIONS: usize = 1000;

/// `recorded-message-ids`: which of a set of Message-IDs the thread store holds, in any thread, as
/// ace3's `get_recorded_message_ids` (`saq/modules/email/conversation.py`). A module that rebuilds a
/// conversation from elsewhere, such as a site's thread recovery module from the mail
/// provider, tells a message ACE never scanned from one it scanned but recorded in a thread of its
/// own.
pub struct RecordedMessageIds;

impl ReadKind for RecordedMessageIds {
    const READ: Read = Read {
        name: "recorded-message-ids",
    };
    type Request = RecordedMessageIdsRequest;
    type Answer = RecordedMessageIdsAnswer;
}

/// A `recorded-message-ids` read: the Message-IDs to look up, at most `MAX_RECORDED_MESSAGE_IDS`,
/// each normalized as the email logger records them (`email_threads::normalize_message_id`). The
/// task's own observable must be a `message_id`; the read names no other subject.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedMessageIdsRequest {
    pub message_ids: Vec<String>,
}

/// The answer to a `recorded-message-ids` read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedMessageIdsAnswer {
    /// The requested ids the store holds, normalized as it stores them, sorted.
    pub recorded: Vec<String>,
}

/// The most Message-IDs a `recorded-message-ids` read asks about.
pub const MAX_RECORDED_MESSAGE_IDS: usize = 500;

/// `file-collection`: where the root's latest collection of an observable by a collector stands
/// (PLAN.md decision 49), as ace3's module reads its `file_collection` row
/// (`get_file_collection`) on each run after it queued one. Its file, once collected, is held by
/// each root the collection is for, so a result adds it by its sha256 and size with no upload.
pub struct FileCollectionState;

impl ReadKind for FileCollectionState {
    const READ: Read = Read {
        name: "file-collection",
    };
    type Request = FileCollectionStateRequest;
    type Answer = FileCollectionStateAnswer;
}

/// A `file-collection` read: the collector, a file collection handler of the core's catalog, and the
/// observable it collects, of its type: the task's own when None, else one in the task's root.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCollectionStateRequest {
    pub collector: String,
    #[serde(default)]
    pub subject: Option<ObservableRef>,
}

/// The answer to a `file-collection` read: None when the root has no collection of the subject by
/// the collector, or let go of the one it had (`file-collection-release`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCollectionStateAnswer {
    pub collection: Option<CollectionState>,
}

/// A file collection as a module reads it, in ace3's words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionState {
    pub id: i64,
    /// `NEW`, `IN_PROGRESS` (waiting to be tried again) or `COMPLETED`.
    pub status: String,
    /// How its latest try ended, such as `SUCCESS`, `HOST_OFFLINE` or `CANCELLED`.
    pub result: Option<String>,
    pub result_message: Option<String>,
    /// The tries so far.
    pub attempts: i32,
    pub max_attempts: Option<i32>,
    /// The file, once collected.
    pub file: Option<CollectedFile>,
}

/// A collected file, which the root holds: a result adds it as a `NewFile` with no upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedFile {
    pub sha256: String,
    pub size: u64,
    /// Its name as the collector saved it: one plain name.
    pub name: String,
}

/// `sandbox-submission`: what ace3's `sandbox_submissions` table holds of the task's own file for a
/// sandbox, and how many files were sent to that sandbox today (PLAN.md decision 50), as a site's
/// sandbox module reads `get_existing_submission` and `check_daily_submission_count` before it
/// submits.
pub struct SandboxSubmissionState;

impl ReadKind for SandboxSubmissionState {
    const READ: Read = Read {
        name: "sandbox-submission",
    };
    type Request = SandboxSubmissionRequest;
    type Answer = SandboxSubmissionAnswer;
}

/// A `sandbox-submission` read, or write: the sandbox, such as `example_sandbox`, 1 to 64 of a-z, 0-9, `_`
/// and `-`. It is about the task's own file, which the task's observable must be.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSubmissionRequest {
    pub sandbox_type: String,
}

/// The answer to a `sandbox-submission` read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSubmissionAnswer {
    /// The file's row for the sandbox, from any alert, or None.
    pub submission: Option<SandboxSubmissionRow>,
    /// How many files were sent to the sandbox since midnight UTC: only rows recorded as sent
    /// (`SandboxSubmissionRow::submitted`), as the owner decided, where ace3 counts every row from
    /// the node's local midnight.
    pub submitted_today: i64,
}

/// A file's row in `sandbox_submissions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSubmissionRow {
    /// The sandbox's id for it, such as the sandbox's sample id.
    pub external_id: Option<String>,
    /// None until the analysis finished, as ace3 waits on a row without one.
    pub verdict: Option<String>,
    pub score: Option<i32>,
    /// True when this ACE sent the file, false when the sandbox already knew it.
    pub submitted: bool,
    pub submitted_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Every read a module can declare, by name.
pub const ALL: &[Read] = &[
    SnortSignature::READ,
    SmtpCounts::READ,
    EmailThreadDomains::READ,
    EmailThread::READ,
    NewlyRegistered::READ,
    ArchivedEmail::READ,
    ObservableTags::READ,
    SvsCaptureState::READ,
    RecordedMessageIds::READ,
    FileCollectionState::READ,
    SandboxSubmissionState::READ,
];

/// The reads that put a file in the task's root, which a result may add without uploading it.
pub const FILE_READS: &[Read] = &[ArchivedEmail::READ, FileCollectionState::READ];
