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

/// Every read a module can declare, by name.
pub const ALL: &[Read] = &[
    SnortSignature::READ,
    SmtpCounts::READ,
    EmailThreadDomains::READ,
    EmailThread::READ,
    NewlyRegistered::READ,
];
