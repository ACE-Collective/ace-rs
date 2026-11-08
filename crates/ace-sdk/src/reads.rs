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

/// Every read a module can declare, by name.
pub const ALL: &[Read] = &[SnortSignature::READ, SmtpCounts::READ];
