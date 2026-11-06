//! What the core and a pool send each other over the lease API (PLAN.md 2.14).
//!
//! A worker leases a task, renews its lease while the module runs, and ends it with a
//! `TaskEnd`. A file's bytes never pass through the API: a leased task carries a presigned URL
//! to download its input from the bucket, and the worker asks for a presigned URL to upload each
//! file the module wrote. So a worker holds an API token and nothing else.

use std::path::Path;

use ace_results::{AlertPath, ObservableKind, ObservableRef, ResultEnvelope, Sha256, YaraMeta};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::context::{DelayedRun, InputFile, Observable};

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

    /// The replay view of a task, for `ace task replay` (PLAN.md 2.20).
    pub fn replay(id: i64) -> String {
        format!("/api/admin/v1/tasks/{id}/replay")
    }
}

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
    /// The module's result. Its files must have been uploaded first.
    Done { result: ResultEnvelope<Value> },
    /// The module had nothing to say about the observable.
    Skipped { reason: String },
    /// Run the task again after `after_seconds`, with `state` for the next run.
    Delay {
        after_seconds: f64,
        #[serde(default)]
        state: Value,
    },
    /// The module or its setup failed.
    Failed { error: String },
    /// A pool's supervisor killed a hung worker, and took its stacks first (PLAN.md 4.3). The task
    /// fails as with `Failed`, and its row keeps `stacks` too. Only a supervisor sends it. A reply
    /// from a worker or a task process that says this is refused, because the stacks are the
    /// supervisor's account of the worker.
    Hung { error: String, stacks: String },
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
