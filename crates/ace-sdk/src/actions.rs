//! Actions (PLAN.md 7.9): what ACE does outside itself, or asks another system, about an observable,
//! as against analysis, which reads it. Three kinds, each ace3's own service:
//!
//! - a remediation, which removes something, such as an email from a mailbox, or restores what a
//!   removal removed (ace3's `saq/remediation/`, its `Remediator`);
//! - a remediation check, which asks another system whether it removed something by itself (ace3's
//!   `saq/remediation/external/`, its `ExternalRemediationProbe`);
//! - a file collection, which fetches a file from a host (ace3's `saq/file_collection/`, its
//!   `FileCollector`).
//!
//! ace3 runs each as a service of its own, three copies of one queue-service scaffold (#894): a
//! collector thread polling its table for rows, locking them by uuid, and handing them to per-handler
//! worker threads. Here all three are rows of one table, `queue.actions`, claimed through the lease API
//! as tasks are, by a network pool that hosts the handlers (`ace_pool::actions`). The core decides
//! everything about a row's state, its retries and its deadline from the handler's `ActionSpec`; the
//! pool runs the handler and says how it went (`ActionEnd`).
//!
//! A handler is named by its kind and its name, such as `remediation/test`, which a pool's list in
//! `ACE4_POOLS` carries as `@remediation/test` (`pool_entry`). Its spec says what observable type it
//! acts on, the TCP ports it connects to and the secrets it reads, as a lookup module's manifest does,
//! and whether it runs without an entry in the overlay's `actions:` (`ActionSpec::off_by_default`,
//! PLAN.md decision 28).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use ace_results::Sha256;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::wire::Presigned;

/// What an action is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Remediation,
    RemediationCheck,
    FileCollection,
}

impl ActionKind {
    pub const ALL: &'static [ActionKind] = &[
        ActionKind::Remediation,
        ActionKind::RemediationCheck,
        ActionKind::FileCollection,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Remediation => "remediation",
            ActionKind::RemediationCheck => "remediation_check",
            ActionKind::FileCollection => "file_collection",
        }
    }

    pub fn parse(text: &str) -> Option<ActionKind> {
        ActionKind::ALL.iter().copied().find(|k| k.as_str() == text)
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How often an action is tried, and for how long. A try that asks to be tried again waits
/// `min(max_delay, initial_delay * 2^attempts)` (ace3's `calculate_backoff_delay`), counting the
/// tries before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    pub initial_delay_seconds: u32,
    pub max_delay_seconds: u32,
    /// The most tries, None for no limit, as ace3's remediation, which tries a delayed one again
    /// every `delay_time_seconds` until it ends.
    pub max_attempts: Option<u32>,
    /// How long after it's queued an action may still run. Past it, the core ends it without
    /// running it: a remediation check as `EXPIRED`, a file collection as `FAILED`.
    pub deadline_seconds: Option<u32>,
}

impl Retry {
    /// ace3's remediation service: a delayed remediation runs again after `delay_time_seconds`, 60.
    pub const REMEDIATION: Retry = Retry {
        initial_delay_seconds: 60,
        max_delay_seconds: 60,
        max_attempts: None,
        deadline_seconds: None,
    };

    /// ace3's file collection service's defaults: 60 s doubling to an hour, 10 tries
    /// (`queue_file_collection`'s `max_retries`) and 7 days (`max_collection_time_seconds`).
    pub const FILE_COLLECTION: Retry = Retry {
        initial_delay_seconds: 60,
        max_delay_seconds: 3600,
        max_attempts: Some(10),
        deadline_seconds: Some(604_800),
    };

    /// ace3's `ExternalRemediationProbeConfig` defaults: 60 s doubling to an hour, 24 tries and 7 days.
    pub const REMEDIATION_CHECK: Retry = Retry {
        initial_delay_seconds: 60,
        max_delay_seconds: 3600,
        max_attempts: Some(24),
        deadline_seconds: Some(604_800),
    };

    /// The wait before the next try, after `attempts` tries.
    pub fn delay(&self, attempts: u32) -> Duration {
        let factor = 2u64.saturating_pow(attempts.min(63));
        let delay = u64::from(self.initial_delay_seconds).saturating_mul(factor);
        Duration::from_secs(delay.min(u64::from(self.max_delay_seconds)))
    }
}

/// What a handler is and does, as a module's manifest says what a module is. A site builds one
/// with `ActionSpec::new` and the methods after it, so a field added here doesn't break it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ActionSpec {
    pub kind: ActionKind,
    /// ace3's configured name, such as `test` or `office365_email`: up to 64 of a-z, 0-9, `_` and `-`.
    pub name: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    /// The observable type it acts on. ace3 finds a remediation's targets by it.
    pub observable_type: &'static str,
    /// The TCP ports it connects to, which its pool's containment allows.
    pub tcp_ports: &'static [u16],
    /// The secrets it reads, which its pool resolves from the overlay's `secrets:`.
    pub secrets: &'static [&'static str],
    /// The shared connections it takes (`crate::connections`), which its overlay entry binds with
    /// `connections:`; its pool resolves their secrets too.
    pub connections: &'static [crate::connections::ConnectionSlot],
    pub retry: Retry,
    /// A remediation check only: how long another source's confirmation of the same target has to be
    /// old before it ends this check as `SUPERSEDED` (ace3's `supersede_grace_seconds`, 12 hours), since a
    /// vendor's own events can come in late.
    pub supersede_grace_seconds: u32,
    /// False for a handler that runs only when the overlay has an entry for it in `actions:`, empty
    /// or not, as `Module::ENABLED_BY_DEFAULT` is for a module (PLAN.md decision 28): one that
    /// writes to another system, such as a mailbox. Off, `ace serve`'s catalog leaves it out, so
    /// nobody is offered it or can queue it, and no pool builds it.
    pub enabled_by_default: bool,
}

impl ActionSpec {
    /// A handler of `kind` called `name`, which acts on observables of `observable_type`, with
    /// ace3's retry for its kind, no ports, secrets or connections, and, for a remediation check,
    /// ace3's 12 hours of `supersede_grace_seconds`.
    pub const fn new(
        kind: ActionKind,
        name: &'static str,
        display_name: &'static str,
        description: &'static str,
        observable_type: &'static str,
    ) -> ActionSpec {
        ActionSpec {
            kind,
            name,
            display_name,
            description,
            observable_type,
            tcp_ports: &[],
            secrets: &[],
            connections: &[],
            retry: match kind {
                ActionKind::Remediation => Retry::REMEDIATION,
                ActionKind::RemediationCheck => Retry::REMEDIATION_CHECK,
                ActionKind::FileCollection => Retry::FILE_COLLECTION,
            },
            supersede_grace_seconds: match kind {
                ActionKind::RemediationCheck => 12 * 3600,
                _ => 0,
            },
            enabled_by_default: true,
        }
    }

    /// Off unless the overlay has an entry for it (`enabled_by_default`).
    pub const fn off_by_default(mut self) -> ActionSpec {
        self.enabled_by_default = false;
        self
    }

    /// Its key in the overlay's `actions:`, `<kind>/<name>`.
    pub fn overlay_entry(&self) -> String {
        format!("{}/{}", self.kind, self.name)
    }

    /// Whether it runs with `overlay`: always, unless it is off by default and the overlay has no
    /// entry for it.
    pub fn is_enabled(&self, overlay: &crate::Overlay) -> bool {
        self.enabled_by_default || overlay.actions.contains_key(&self.overlay_entry())
    }

    /// The TCP ports it connects to.
    pub const fn tcp_ports(mut self, tcp_ports: &'static [u16]) -> ActionSpec {
        self.tcp_ports = tcp_ports;
        self
    }

    /// The secrets it reads.
    pub const fn secrets(mut self, secrets: &'static [&'static str]) -> ActionSpec {
        self.secrets = secrets;
        self
    }

    /// The shared connections it takes.
    pub const fn connections(
        mut self,
        connections: &'static [crate::connections::ConnectionSlot],
    ) -> ActionSpec {
        self.connections = connections;
        self
    }

    /// Its tries and backoff, in place of its kind's.
    pub const fn retry(mut self, retry: Retry) -> ActionSpec {
        self.retry = retry;
        self
    }

    /// A remediation check's grace for another source's confirmation.
    pub const fn supersede_grace_seconds(mut self, seconds: u32) -> ActionSpec {
        self.supersede_grace_seconds = seconds;
        self
    }

    /// Its entry in a pool's list in `ACE4_POOLS`.
    pub fn pool_entry(&self) -> String {
        pool_entry(self.kind, self.name)
    }

    /// Why the spec can't be used, if it can't.
    pub fn refusal(&self) -> Option<String> {
        if !is_handler_name(self.name) {
            return Some(format!(
                "{:?} isn't a handler's name: up to 64 of a-z, 0-9, _ and -",
                self.name
            ));
        }
        if self.retry.initial_delay_seconds == 0 || self.retry.max_attempts == Some(0) {
            return Some(format!(
                "{}: a retry needs a delay and a try",
                self.pool_entry()
            ));
        }
        None
    }
}

/// A handler's name: 1 to 64 of a-z, 0-9, `_` and `-`.
pub fn is_handler_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// What a pool's list in `ACE4_POOLS` names a handler it runs with: `@<kind>/<name>`.
pub fn pool_entry(kind: ActionKind, name: &str) -> String {
    format!("@{}/{name}", kind.as_str())
}

/// The handler a pool-list entry names, if it names one.
pub fn parse_pool_entry(entry: &str) -> Option<(ActionKind, String)> {
    let (kind, name) = entry.strip_prefix('@')?.split_once('/')?;
    let kind = ActionKind::parse(kind)?;
    is_handler_name(name).then(|| (kind, name.to_owned()))
}

/// ace3's remediation actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationAction {
    Remove,
    Restore,
}

impl RemediationAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RemediationAction::Remove => "remove",
            RemediationAction::Restore => "restore",
        }
    }

    pub fn parse(text: &str) -> Option<RemediationAction> {
        match text {
            "remove" => Some(RemediationAction::Remove),
            "restore" => Some(RemediationAction::Restore),
            _ => None,
        }
    }
}

/// How one try of a remediator went: ace3's `RemediatorStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemediatorStatus {
    /// Not done yet: try again after the remediator's delay.
    Delayed,
    Error,
    Failed,
    Ignore,
    Success,
    Cancelled,
    /// The target isn't where the remediator looked, so there's nothing left to act on.
    NotFound,
}

impl RemediatorStatus {
    pub const ALL: &'static [RemediatorStatus] = &[
        RemediatorStatus::Delayed,
        RemediatorStatus::Error,
        RemediatorStatus::Failed,
        RemediatorStatus::Ignore,
        RemediatorStatus::Success,
        RemediatorStatus::Cancelled,
        RemediatorStatus::NotFound,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RemediatorStatus::Delayed => "DELAYED",
            RemediatorStatus::Error => "ERROR",
            RemediatorStatus::Failed => "FAILED",
            RemediatorStatus::Ignore => "IGNORE",
            RemediatorStatus::Success => "SUCCESS",
            RemediatorStatus::Cancelled => "CANCELLED",
            RemediatorStatus::NotFound => "NOT_FOUND",
        }
    }

    pub fn parse(text: &str) -> Option<RemediatorStatus> {
        RemediatorStatus::ALL
            .iter()
            .copied()
            .find(|s| s.as_str() == text)
    }

    /// Only a delayed one runs again; ace3 completes the rest, an error included.
    pub fn in_progress(self) -> bool {
        self == RemediatorStatus::Delayed
    }
}

/// How one try of a file collector went: ace3's `FileCollectorStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CollectorStatus {
    Delayed,
    Error,
    Failed,
    Success,
    Cancelled,
    HostOffline,
    FileNotFound,
}

impl CollectorStatus {
    pub const ALL: &'static [CollectorStatus] = &[
        CollectorStatus::Delayed,
        CollectorStatus::Error,
        CollectorStatus::Failed,
        CollectorStatus::Success,
        CollectorStatus::Cancelled,
        CollectorStatus::HostOffline,
        CollectorStatus::FileNotFound,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CollectorStatus::Delayed => "DELAYED",
            CollectorStatus::Error => "ERROR",
            CollectorStatus::Failed => "FAILED",
            CollectorStatus::Success => "SUCCESS",
            CollectorStatus::Cancelled => "CANCELLED",
            CollectorStatus::HostOffline => "HOST_OFFLINE",
            CollectorStatus::FileNotFound => "FILE_NOT_FOUND",
        }
    }

    pub fn parse(text: &str) -> Option<CollectorStatus> {
        CollectorStatus::ALL
            .iter()
            .copied()
            .find(|s| s.as_str() == text)
    }

    /// ace3's `is_final`: no more tries, whatever is left of them.
    pub fn is_final(self) -> bool {
        matches!(
            self,
            CollectorStatus::Success
                | CollectorStatus::FileNotFound
                | CollectorStatus::Failed
                | CollectorStatus::Cancelled
        )
    }
}

/// How a remediation check ended: ace3's `CheckResult`. A check still being polled has none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckResult {
    /// The probe found the other system's events: they're on the row.
    Confirmed,
    NotFound,
    /// Its deadline passed, or its tries ran out, with nothing found.
    Expired,
    Error,
    Cancelled,
    /// Another probe, or ACE's own remediation, confirmed the same target first.
    Superseded,
}

impl CheckResult {
    pub const ALL: &'static [CheckResult] = &[
        CheckResult::Confirmed,
        CheckResult::NotFound,
        CheckResult::Expired,
        CheckResult::Error,
        CheckResult::Cancelled,
        CheckResult::Superseded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CheckResult::Confirmed => "CONFIRMED",
            CheckResult::NotFound => "NOT_FOUND",
            CheckResult::Expired => "EXPIRED",
            CheckResult::Error => "ERROR",
            CheckResult::Cancelled => "CANCELLED",
            CheckResult::Superseded => "SUPERSEDED",
        }
    }

    pub fn parse(text: &str) -> Option<CheckResult> {
        CheckResult::ALL
            .iter()
            .copied()
            .find(|s| s.as_str() == text)
    }
}

/// One thing another system did to a target, as a probe found it: ace3's `RemediationEvent`, which its
/// alert page's remediation timeline shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediationEvent {
    /// Who did it, as the coverage badge names it, such as `Mail filter`.
    pub source: String,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    #[serde(default)]
    pub event_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub portal_url: Option<String>,
    #[serde(default)]
    pub metadata: serde_json::Map<String, Value>,
}

/// How one try of a probe went: ace3's `ProbeOutcome`, one of its five shapes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeOutcome {
    /// The other system removed it: these are its events. The check ends `CONFIRMED`.
    FoundEvents {
        events: Vec<RemediationEvent>,
        #[serde(default)]
        message: Option<String>,
    },
    /// The target doesn't exist there. The check ends `NOT_FOUND`.
    NotFound {
        #[serde(default)]
        message: Option<String>,
    },
    /// Nothing yet: ask again later, until the tries or the deadline run out (`EXPIRED`).
    Pending {
        #[serde(default)]
        message: Option<String>,
    },
    /// Asking failed in a way that may pass: ask again later, until the tries run out (`ERROR`).
    TransientError {
        error: String,
        #[serde(default)]
        message: Option<String>,
    },
    /// Asking can't work: the check ends `ERROR` now.
    PermanentError {
        error: String,
        #[serde(default)]
        message: Option<String>,
    },
}

/// The most events one confirmation records.
pub const MAX_EVENTS: usize = 1000;

/// What a remediator, a probe or a collector is given: the action's row as it's leased.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasedAction {
    pub id: i64,
    pub kind: ActionKind,
    /// The handler's name.
    pub handler: String,
    pub observable_type: String,
    pub observable_value: String,
    /// The tries before this one.
    pub attempts: u32,
    pub max_attempts: Option<u32>,
    pub deadline: Option<DateTime<Utc>>,
    /// A remediation's action.
    #[serde(default)]
    pub action: Option<RemediationAction>,
    /// A restore's key: what the removal it undoes gave back.
    #[serde(default)]
    pub restore_key: Option<String>,
    /// A remediation check's context: what the module that queued it knew, such as the recipient.
    #[serde(default)]
    pub context: Option<Value>,
    /// The alerts it's for: a check's one, and every alert a file collection belongs to.
    #[serde(default)]
    pub roots: Vec<Uuid>,
    /// How long each renewal extends the lease.
    pub lease_seconds: f64,
}

/// What a remediator returns: ace3's `RemediatorResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemediatorResult {
    pub status: RemediatorStatus,
    #[serde(default)]
    pub message: Option<String>,
    /// What a restore of this removal needs, such as where the email was moved to.
    #[serde(default)]
    pub restore_key: Option<String>,
}

impl RemediatorResult {
    pub fn new(status: RemediatorStatus, message: impl Into<String>) -> Self {
        RemediatorResult {
            status,
            message: Some(message.into()),
            restore_key: None,
        }
    }
}

/// What a collector returns: ace3's `FileCollectorResult`. The file is in the directory the pool gave
/// it, and the pool uploads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorResult {
    pub status: CollectorStatus,
    pub message: Option<String>,
    /// The collected file, on success.
    pub file: Option<PathBuf>,
}

/// A collected file the pool uploaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectedFile {
    pub sha256: Sha256,
    pub size: u64,
    /// The file's name, as the collector saved it: a plain name, at most 255 bytes.
    pub name: String,
}

/// How a pool ended an action's try.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionEnd {
    Remediation {
        result: RemediatorResult,
    },
    RemediationCheck {
        outcome: ProbeOutcome,
    },
    FileCollection {
        status: CollectorStatus,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        file: Option<CollectedFile>,
    },
}

impl ActionEnd {
    pub fn kind(&self) -> ActionKind {
        match self {
            ActionEnd::Remediation { .. } => ActionKind::Remediation,
            ActionEnd::RemediationCheck { .. } => ActionKind::RemediationCheck,
            ActionEnd::FileCollection { .. } => ActionKind::FileCollection,
        }
    }

    /// The end of a try that failed before or inside its handler, as ace3's workers record an
    /// exception: `ERROR`, or a check's transient error, which is tried again.
    pub fn error(kind: ActionKind, error: &str) -> ActionEnd {
        match kind {
            ActionKind::Remediation => ActionEnd::Remediation {
                result: RemediatorResult::new(RemediatorStatus::Error, error),
            },
            ActionKind::RemediationCheck => ActionEnd::RemediationCheck {
                outcome: ProbeOutcome::TransientError {
                    error: error.to_owned(),
                    message: Some("the probe failed".to_owned()),
                },
            },
            ActionKind::FileCollection => ActionEnd::FileCollection {
                status: CollectorStatus::Error,
                message: Some(error.to_owned()),
                file: None,
            },
        }
    }
}

/// A pool asking for an action of one of its handlers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionLeaseRequest {
    pub worker: String,
    #[serde(default)]
    pub wait_seconds: u64,
}

/// The core's answer to a renewal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRenewal {
    /// Someone cancelled the action: stop, and send no end.
    pub cancelled: bool,
}

/// A pool asking where to upload a collected file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionUploadRequest {
    pub sha256: Sha256,
    pub size: u64,
}

/// Where to upload a collected file.
pub type ActionUpload = Presigned;

/// The lease API's paths for actions.
pub mod paths {
    pub const LEASE: &str = "/api/worker/v1/actions/lease";

    /// `/api/worker/v1/actions/<id>/<what>`, where what is `renew`, `upload` or `end`.
    pub fn action(id: i64, what: &str) -> String {
        format!("/api/worker/v1/actions/{id}/{what}")
    }
}

/// A handler's future: what one try returns.
pub type ActionFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// ace3's `Remediator`: removes a target, and restores what a removal removed. A try may take as long
/// as it needs while its pool renews its lease; one that panics or fails ends `ERROR`.
pub trait Remediator: Send + Sync + 'static {
    fn spec(&self) -> &'static ActionSpec;
    fn remove<'a>(&'a self, target: &'a LeasedAction) -> ActionFuture<'a, RemediatorResult>;
    fn restore<'a>(&'a self, target: &'a LeasedAction) -> ActionFuture<'a, RemediatorResult>;
}

/// ace3's `ExternalRemediationProbe`: asks another system whether it removed a target by itself. A try
/// only reads that system.
pub trait RemediationProbe: Send + Sync + 'static {
    fn spec(&self) -> &'static ActionSpec;
    fn probe<'a>(&'a self, target: &'a LeasedAction) -> ActionFuture<'a, ProbeOutcome>;
}

/// ace3's `FileCollector`: fetches a file from a host into `dir`, a directory of the try's own, and
/// names it in its result.
pub trait FileCollector: Send + Sync + 'static {
    fn spec(&self) -> &'static ActionSpec;
    fn collect<'a>(
        &'a self,
        target: &'a LeasedAction,
        dir: &'a Path,
    ) -> ActionFuture<'a, CollectorResult>;
}

/// ace3's test remediator (`saq/remediation/test.py`), which ace3 ships enabled: it acts on `test`
/// observables, and a try ends with the status the value names, such as `SUCCESS` or `DELAYED`, or
/// `ERROR` when the value names none. It touches nothing outside ACE.
pub struct TestRemediator;

/// `TestRemediator`'s spec: ace3's `remediator_test`.
pub static TEST_REMEDIATOR: ActionSpec = ActionSpec {
    kind: ActionKind::Remediation,
    name: "test",
    display_name: "Test Remediator",
    description: "For testing the remediation system in ACE.",
    observable_type: "test",
    tcp_ports: &[],
    secrets: &[],
    connections: &[],
    retry: Retry::REMEDIATION,
    supersede_grace_seconds: 0,
    enabled_by_default: true,
};

impl TestRemediator {
    fn execute(target: &LeasedAction) -> RemediatorResult {
        match RemediatorStatus::parse(&target.observable_value) {
            Some(status) => RemediatorResult::new(status, "test remediation system"),
            None => RemediatorResult::new(
                RemediatorStatus::Error,
                format!(
                    "unexpected target key value (should be a RemediatorStatus value): {}",
                    target.observable_value
                ),
            ),
        }
    }
}

impl Remediator for TestRemediator {
    fn spec(&self) -> &'static ActionSpec {
        &TEST_REMEDIATOR
    }

    fn remove<'a>(&'a self, target: &'a LeasedAction) -> ActionFuture<'a, RemediatorResult> {
        Box::pin(async move { TestRemediator::execute(target) })
    }

    fn restore<'a>(&'a self, target: &'a LeasedAction) -> ActionFuture<'a, RemediatorResult> {
        Box::pin(async move { TestRemediator::execute(target) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delay_doubles_to_its_bound() {
        let retry = Retry::FILE_COLLECTION;
        assert_eq!(retry.delay(0), Duration::from_secs(60));
        assert_eq!(retry.delay(1), Duration::from_secs(120));
        assert_eq!(retry.delay(5), Duration::from_secs(1920));
        assert_eq!(retry.delay(6), Duration::from_secs(3600));
        assert_eq!(retry.delay(200), Duration::from_secs(3600));
        assert_eq!(Retry::REMEDIATION.delay(9), Duration::from_secs(60));
    }

    #[test]
    fn a_pool_entry_names_a_handler() {
        assert_eq!(TEST_REMEDIATOR.pool_entry(), "@remediation/test");
        assert_eq!(
            parse_pool_entry("@file_collection/endpoint_file_collection"),
            Some((
                ActionKind::FileCollection,
                "endpoint_file_collection".to_owned()
            ))
        );
        for entry in ["@scan/phishkit", "@remediation/", "@remediation/A", "test"] {
            assert_eq!(parse_pool_entry(entry), None, "{entry}");
        }
        assert_eq!(TEST_REMEDIATOR.refusal(), None);
    }

    /// A handler is on unless its spec says it is off by default, and then only with an entry in the
    /// overlay's `actions:`, empty or not (PLAN.md decision 28).
    #[test]
    fn a_handler_off_by_default_runs_only_with_an_overlay_entry() {
        static OFF: ActionSpec = ActionSpec::new(
            ActionKind::Remediation,
            "mailbox",
            "Mailbox",
            "moves mail",
            "email_delivery",
        )
        .off_by_default();
        let none = crate::Overlay::default();
        assert!(TEST_REMEDIATOR.is_enabled(&none));
        assert!(!OFF.is_enabled(&none));
        assert_eq!(OFF.overlay_entry(), "remediation/mailbox");
        let entry = crate::Overlay::from_yaml("actions:\n  remediation/mailbox: {}\n")
            .expect("the overlay");
        assert!(OFF.is_enabled(&entry));
        let other =
            crate::Overlay::from_yaml("actions:\n  remediation/test: {}\n").expect("the overlay");
        assert!(!OFF.is_enabled(&other));
        assert!(TEST_REMEDIATOR.is_enabled(&other));
    }

    #[test]
    fn an_end_reads_as_written() {
        let end = ActionEnd::RemediationCheck {
            outcome: ProbeOutcome::Pending { message: None },
        };
        let json = serde_json::to_value(&end).expect("serializes");
        assert_eq!(
            json,
            serde_json::json!({"kind": "remediation_check", "outcome": {"outcome": "pending", "message": null}})
        );
        assert_eq!(
            serde_json::from_value::<ActionEnd>(json).expect("reads"),
            end
        );
        let end = ActionEnd::Remediation {
            result: RemediatorResult::new(RemediatorStatus::NotFound, "gone"),
        };
        let json = serde_json::to_value(&end).expect("serializes");
        assert_eq!(json["result"]["status"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn the_test_remediator_ends_as_its_value_says() {
        let target = |value: &str| LeasedAction {
            id: 1,
            kind: ActionKind::Remediation,
            handler: "test".to_owned(),
            observable_type: "test".to_owned(),
            observable_value: value.to_owned(),
            attempts: 0,
            max_attempts: None,
            deadline: None,
            action: Some(RemediationAction::Remove),
            restore_key: None,
            context: None,
            roots: Vec::new(),
            lease_seconds: 60.0,
        };
        let done = TestRemediator.remove(&target("SUCCESS")).await;
        assert_eq!(done.status, RemediatorStatus::Success);
        let delayed = TestRemediator.restore(&target("DELAYED")).await;
        assert_eq!(delayed.status, RemediatorStatus::Delayed);
        let odd = TestRemediator.remove(&target("nope")).await;
        assert_eq!(odd.status, RemediatorStatus::Error);
    }
}
