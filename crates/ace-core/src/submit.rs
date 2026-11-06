//! Submissions (PLAN.md 2.28): a new root with its observables, files and analysis mode, and
//! its first tasks.
//!
//! The lease API takes them at `POST /api/analysis/v1/submit` as ace3's `/api/analysis/submit`
//! does: a multipart form with the submission as JSON in its `analysis` field and each file in a
//! `file` field, whose file name is the file's path in the alert. The submission's
//! `file_yara_meta` can give a file `yara_meta` tags. One transaction creates the
//! root, puts each file in the bucket's `alert_files` pool held by the root, adds the
//! observables and the file observables, and queues what is eligible in the root's mode
//! (`Orchestrator::start`).

use std::collections::BTreeMap;

use ace_results::{AlertPath, NewObservable, ObservableKind, YaraMeta};
use ace_store::Spooled;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::bucket::{ALERT_FILES, Bucket, BucketError, Hold};
use crate::db::{Db, DbError, Isolation, Retryable};
use crate::orchestrator::{Orchestrator, OrchestratorError};
use crate::tree::{self, EventTime, NewRoot};

/// What a submitter sends in the `analysis` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub description: String,
    /// The root's analysis mode; the default mode when it's left out.
    #[serde(default)]
    pub analysis_mode: Option<String>,
    /// When the event happened. Left out, the root's event time is the time it was submitted.
    #[serde(default)]
    pub event_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub observables: Vec<SubmittedObservable>,
    /// `yara_meta` tags for submitted files, by the file's path in the alert: what a submitter
    /// that took the file from something else already knows it is, such as an email's
    /// attachment (`type=email.attachment`). YARA rules with `meta_tags` scan by these.
    #[serde(default)]
    pub file_yara_meta: BTreeMap<String, Vec<YaraMeta>>,
}

/// An observable the submission adds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmittedObservable {
    #[serde(rename = "type")]
    pub kind: ObservableKind,
    pub value: String,
    #[serde(default)]
    pub time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub directives: Vec<String>,
    #[serde(default)]
    pub exclude_modules: Vec<String>,
}

/// A submitted file: its bytes, spooled on this node, and its path in the alert.
#[derive(Debug)]
pub struct SubmittedFile {
    pub path: AlertPath,
    pub spooled: Spooled,
}

/// What a submission made: the root and the tasks it queued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submitted {
    pub uuid: Uuid,
    pub queued: Vec<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum SubmitError {
    /// The submission can't be taken as it is, and nothing from it was written.
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Bucket(#[from] BucketError),
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
}

impl From<DbError> for SubmitError {
    fn from(error: DbError) -> Self {
        SubmitError::Orchestrator(OrchestratorError::Db(error))
    }
}

impl Retryable for SubmitError {
    fn is_retryable(&self) -> bool {
        match self {
            SubmitError::Bucket(BucketError::Db(e)) => e.is_retryable(),
            SubmitError::Orchestrator(e) => e.is_retryable(),
            _ => false,
        }
    }
}

/// Creates the root and queues its first tasks, all in one transaction.
pub async fn submit(
    db: &Db,
    bucket: &Bucket,
    orchestrator: &Orchestrator,
    submission: &Submission,
    files: &[SubmittedFile],
) -> Result<Submitted, SubmitError> {
    let modes = orchestrator.modes();
    let mode = submission
        .analysis_mode
        .clone()
        .unwrap_or_else(|| modes.default_mode().to_owned());
    if modes.mode(&mode).is_none() {
        return Err(SubmitError::Invalid(format!("no analysis mode {mode:?}")));
    }
    // Postgres refuses a NUL in text. A submitter can change what it sends, unlike a task's end
    // (`without_nul` in `api`), so it's told, rather than a value in the alert being altered.
    if serde_json::to_string(submission).is_ok_and(|json| json.contains("\\u0000")) {
        return Err(SubmitError::Invalid(
            "a submission can't hold a NUL character".to_owned(),
        ));
    }
    if let Some(path) = submission
        .file_yara_meta
        .keys()
        .find(|path| !files.iter().any(|f| f.path.as_str() == path.as_str()))
    {
        return Err(SubmitError::Invalid(format!(
            "file_yara_meta names {path:?}, which isn't a submitted file"
        )));
    }
    let root = NewRoot {
        description: submission.description.clone(),
        event_time: match submission.event_time {
            Some(time) => EventTime::Event(time),
            None => EventTime::Now(Utc::now()),
        },
        ..NewRoot::new(mode)
    };
    let hold = Hold::root(root.id);
    let (root, hold) = (&root, &hold);
    let queued = db
        .transaction(Isolation::ReadCommitted, |tx| {
            Box::pin(async move {
                tree::create_root(tx, root).await?;
                for observable in &submission.observables {
                    let mut new = NewObservable::new(observable.kind, observable.value.clone());
                    new.time = observable.time;
                    new.tags = observable.tags.clone();
                    new.directives = observable.directives.clone();
                    new.exclude_modules = observable.exclude_modules.clone();
                    tree::upsert_observable(tx, root.id, &new).await?;
                }
                for file in files {
                    bucket
                        .put_in(tx, ALERT_FILES, &file.spooled, Some(hold))
                        .await?;
                    let new =
                        NewObservable::new(ObservableKind::File, file.spooled.sha256.to_hex());
                    let id = tree::upsert_observable(tx, root.id, &new).await?.id;
                    let yara_meta: Vec<String> = submission
                        .file_yara_meta
                        .get(file.path.as_str())
                        .into_iter()
                        .flatten()
                        .map(|tag| tag.as_str().to_owned())
                        .collect();
                    tree::add_file(tx, root.id, id, file.path.as_str(), &yara_meta).await?;
                }
                Ok::<_, SubmitError>(orchestrator.start(tx, root.id).await?)
            })
        })
        .await?;
    tracing::info!(
        root = %root.id,
        mode = %root.analysis_mode,
        files = files.len(),
        tasks = queued.len(),
        "a submission created a root"
    );
    Ok(Submitted {
        uuid: root.id,
        queued: queued.into_iter().map(|id| id.0).collect(),
    })
}
