//! What the core and a pool send each other over the lease API (PLAN.md 2.14).
//!
//! A worker leases a task, renews its lease while the module runs, and ends it with a
//! `TaskEnd`. A file's bytes never pass through the API: a leased task carries a presigned URL
//! to download its input from the bucket, and the worker asks for a presigned URL to upload each
//! file the module wrote. So a worker holds an API token and nothing else.

use std::collections::BTreeMap;
use std::path::Path;

use ace_results::{
    AlertPath, ObservableKind, ObservableRef, Relationship, ResultEnvelope, Sha256, YaraMeta,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::context::{DelayedRun, InputFile, Observable};
use crate::lists::WireList;
use crate::writes::WireWrite;

/// The paths of the lease API, under its base URL.
pub mod paths {
    pub const LEASE: &str = "/api/worker/v1/lease";

    /// The ruleset a YARA pool should scan with (PLAN.md 2.26).
    pub const RULESET: &str = "/api/worker/v1/yara/ruleset";

    /// `/api/worker/v1/tasks/<id>/<action>`, where action is `renew`, `end`, `release` or
    /// `uploads`.
    pub fn task(id: i64, action: &str) -> String {
        format!("/api/worker/v1/tasks/{id}/{action}")
    }

    /// A read of ACE's own data for a leased task (PLAN.md 7.2, `crate::reads`).
    pub fn read(id: i64, read: &str) -> String {
        format!("/api/worker/v1/tasks/{id}/reads/{read}")
    }

    /// The same read for a task being replayed, with the admin token and no lease.
    pub fn replay_read(id: i64, read: &str) -> String {
        format!("/api/admin/v1/tasks/{id}/reads/{read}")
    }

    /// The replay view of a task, for `ace task replay` (PLAN.md 2.20).
    pub fn replay(id: i64) -> String {
        format!("/api/admin/v1/tasks/{id}/replay")
    }

    /// A GUI command for a pool that runs them (PLAN.md 5.12).
    pub const COMMAND_LEASE: &str = "/api/worker/v1/commands/lease";

    /// `/api/worker/v1/commands/<id>/<action>`, where action is `report` or `end`.
    pub fn command(id: i64, action: &str) -> String {
        format!("/api/worker/v1/commands/{id}/{action}")
    }
}

/// What a pool lists among its modules in `ACE4_POOLS` to run GUI commands (PLAN.md 5.12). No module
/// can have the name, and it's the payload that wakes the pools waiting for a command.
pub const COMMANDS: &str = "@commands";

/// A worker asking for a task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    /// The worker's name, unique within its pool, such as `<host>/<pid>/<slot>`.
    pub worker: String,
    /// Only these of the pool's modules; empty means all of them.
    #[serde(default)]
    pub modules: Vec<String>,
    /// How long the core may hold the request open waiting for a task, up to its own limit.
    #[serde(default)]
    pub wait_seconds: u64,
}

/// A URL the bucket accepts without credentials until it expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presigned {
    pub url: String,
    /// Headers the request must send as they are, because the signature covers them.
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

/// A file observable's record, and where to download it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskFile {
    pub path: AlertPath,
    pub sha256: Sha256,
    pub size: u64,
    pub mime_type: String,
    #[serde(default)]
    pub yara_meta: Vec<YaraMeta>,
    pub download: Presigned,
}

/// The observable a leased task analyzes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskObservable {
    #[serde(rename = "type")]
    pub kind: ObservableKind,
    pub value: String,
    #[serde(default)]
    pub time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub directives: Vec<String>,
    /// Set when the observable is a file.
    #[serde(default)]
    pub file: Option<TaskFile>,
    /// The observable this one stands in for, such as the document a part came out of.
    #[serde(default)]
    pub redirection: Option<ObservableRef>,
    /// Its relationships to other observables, such as the host a command line ran on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<Relationship>,
}

impl TaskObservable {
    /// The observable as a module sees it, with a file's bytes at `local_path`.
    pub fn to_observable(&self, local_path: Option<&Path>) -> Observable {
        let file = match (&self.file, local_path) {
            (Some(file), Some(local_path)) => Some(InputFile {
                path: file.path.clone(),
                sha256: file.sha256,
                size: file.size,
                yara_meta: file.yara_meta.clone(),
                mime_type: Some(file.mime_type.clone()),
                local_path: local_path.to_owned(),
            }),
            _ => None,
        };
        Observable {
            kind: self.kind,
            value: self.value.clone(),
            time: self.time,
            file,
            directives: self.directives.clone(),
            redirection: self.redirection.clone(),
            relationships: self.relationships.clone(),
        }
    }
}

/// A task a worker holds the lease on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasedTask {
    pub id: i64,
    pub root: Uuid,
    pub module: String,
    /// This lease included.
    pub attempts: i32,
    pub lease_expires_at: DateTime<Utc>,
    /// How long each renewal extends the lease.
    pub lease_seconds: f64,
    pub observable: TaskObservable,
    /// Set when the module asked for a delay on an earlier run.
    #[serde(default)]
    pub delayed: Option<DelayedRun>,
    #[serde(default)]
    pub input_hashes: Vec<String>,
    /// The email that carried the task's observable, for a module that reads it
    /// (`Module::READS_CARRYING_EMAIL`). None when the module doesn't, or no email carried it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carrying_email: Option<CarryingEmail>,
    /// For a module that reads its carrying email: an email in the root hasn't been parsed yet, so
    /// `carrying_email` can't be told yet. A module that needs it delays itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub emails_pending: bool,
    /// The YARA rules that matched the task's observable or anything below it, by name, for a module
    /// that runs last (`Module::RUNS_LAST`). Empty for any other.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub yara_rules_below: Vec<String>,
    /// The analyst-edited lists the module reads (`Module::LISTS`), as they were when the core handed
    /// the task out (PLAN.md 5.14). Empty for a module that reads none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<WireList>,
    /// The observable's results from the modules the task's module depends on
    /// (`Module::DEPENDS_ON`): each one's details, by module.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependency_results: BTreeMap<String, Value>,
    /// For a module that runs last, the observables below the task's of the types it reads there
    /// (`Module::READS_BELOW`), in the order they were added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observables_below: Vec<ObservableRef>,
}

/// What a module may read of the email that carried its observable (PLAN.md 4.6). A worker holds no
/// database credentials, so the core looks it up when it hands out the task. PLAN.md 7.2's read
/// endpoints are the general form of this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarryingEmail {
    /// The email's body, which a message with no text part doesn't have.
    pub body: Option<Presigned>,
}

/// The ruleset a YARA pool should scan with: the latest the core built (PLAN.md 2.26), and
/// where to download its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRuleset {
    /// The sha256 of the serialized ruleset.
    pub key: Sha256,
    /// The commit of the signatures repository it was built from.
    pub commit: String,
    pub download: Presigned,
}

/// A renewed lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Renewal {
    pub expires_at: DateTime<Utc>,
    /// The task's root was cancelled: stop the module.
    pub cancel_requested: bool,
}

/// How a task ended, as the worker reports it.
// One is made per task and sent once, so the size of the result variant costs nothing worth a
// Box, as with `Outcome`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaskEnd {
    /// The module's result. Its files must have been uploaded first. The writes to ACE's data the
    /// task made (`Module::WRITES`) land in the result's transaction.
    Done {
        result: ResultEnvelope<Value>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        writes: Vec<WireWrite>,
    },
    /// The module had nothing to store about the observable, and its writes, if it made any, land
    /// as the task ends.
    Skipped {
        reason: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        writes: Vec<WireWrite>,
    },
    /// Run the task again after `after_seconds`, with `state` for the next run.
    Delay {
        after_seconds: f64,
        #[serde(default)]
        state: Value,
    },
    /// The module or its setup failed.
    Failed { error: String },
    /// The module stopped because the task was cancelled.
    Cancelled,
}

/// A worker asking where to upload a file a module wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRequest {
    pub sha256: Sha256,
    pub size: u64,
}

/// One field of a result that failed its schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldError {
    /// A JSON pointer, such as `/details/attachment_count`.
    pub path: String,
    pub message: String,
}

/// An error the API answers with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub error: String,
    /// For a result that failed its schema, each field that failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<FieldError>,
}

/// A failed task as `ace task replay` sees it: the leased form, with fresh download URLs.
pub type ReplayTask = LeasedTask;

/// A pool asking for a GUI command (PLAN.md 5.12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandLeaseRequest {
    pub worker: String,
    #[serde(default)]
    pub wait_seconds: u64,
}

/// A GUI command a pool holds the lease on: the words after `ace`, and how long it may run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasedCommand {
    pub id: i64,
    pub argv: Vec<String>,
    pub timeout_seconds: u32,
    /// How long from now until its deadline, by the core's clock: the pool kills it then.
    pub deadline_seconds: f64,
    /// How long each report extends the lease.
    pub lease_seconds: f64,
}

/// What a running command has written so far, which also renews its lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReport {
    pub output: String,
    pub output_truncated: bool,
}

/// The core's answer to a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReply {
    /// Someone cancelled it: kill it and end it as cancelled.
    pub cancel_requested: bool,
}

/// How a command ended, as its pool saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandOutcome {
    /// It exited with this code.
    Completed { exit_code: i32 },
    /// It was killed at its deadline.
    TimedOut,
    /// It was killed because someone cancelled it.
    Cancelled,
    /// It didn't run, or a signal killed it.
    Failed { error: String },
    /// Its pool stopped while it ran, and killed it.
    Abandoned { error: String },
}

/// A command's end: how, and all it wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandEnd {
    pub outcome: CommandOutcome,
    pub output: String,
    pub output_truncated: bool,
}
