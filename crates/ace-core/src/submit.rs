//! Submissions (PLAN.md 2.28): a new root with its observables, files and analysis mode, and
//! its first tasks.
//!
//! `ace-api` takes them at `POST /api/analysis/v1/submit` (PLAN.md 5.5), and
//! `ace_service::Service::submit` records who made one, in the transaction this module writes in.
//! The core keeps what a submission does to the tree and the queue, as it keeps what a disposition
//! does (`Orchestrator::stop_for_disposition`), and can't make a root from a submission on its own.
//!
//! `prepare` checks a submission before anything is written. `create` then, in the caller's
//! transaction, creates the root, puts each file in the bucket's `alert_files` pool held by the
//! root, adds the observables and the file observables, and queues what is eligible in the root's
//! mode (`Orchestrator::start`). A file's path in the alert is the name it was sent with, and the
//! submission's `file_yara_meta` can give a file `yara_meta` tags.
//!
//! A submitter inside ACE, such as the hunter (PLAN.md 6.4), adds an [`Origin`]: what the API's
//! submission doesn't take yet. Its observables carry display types, relationships and detections,
//! a detection makes the root an alert as it's created, as ace3's hunter does with a correlation
//! root's detection point, and the rest of what the submitter said about the root, such as ace3's
//! alert type, tool, queue and details, is kept as it said it in `analysis.roots.origin` until roots
//! have columns for them. The queue has one (PLAN.md 7.13): `Origin::queue` is the alert's first.

use std::collections::BTreeMap;

use ace_results::{AlertPath, NewObservable, ObservableKind, YaraMeta};
use ace_store::Spooled;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::bucket::{ALERT_FILES, Bucket, BucketError, Hold};
use crate::db::{DbError, Retryable, Tx};
use crate::orchestrator::{Orchestrator, OrchestratorError};
use crate::queue::TaskId;
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

/// What a submitter inside ACE adds to a [`Submission`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Origin {
    /// The event time is the time the submitter processed the event, ace3's `query_time`, because
    /// the event had no time of its own.
    pub event_time_from_query: bool,
    /// Observables with what the API's don't carry, added after the submission's own.
    pub observables: Vec<NewObservable>,
    /// What the submitter said about the root, kept as it is in `analysis.roots.origin`.
    pub details: Option<serde_json::Value>,
    /// The queue the alert starts in, such as a hunt's `queue`; `tree::DEFAULT_QUEUE` when None. A
    /// router's decision never takes an alert out of a queue a submitter named (PLAN.md 7.13).
    pub queue: Option<String>,
}

impl Origin {
    fn alerts(&self) -> bool {
        self.observables.iter().any(|o| !o.detections.is_empty())
    }
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

/// Checks a submission and makes the root it would create, in its mode or the default one. Nothing
/// is written.
pub fn prepare(
    orchestrator: &Orchestrator,
    submission: &Submission,
    origin: &Origin,
    files: &[SubmittedFile],
) -> Result<NewRoot, SubmitError> {
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
    let has_nul =
        |json: Result<String, serde_json::Error>| json.is_ok_and(|j| j.contains("\\u0000"));
    if has_nul(serde_json::to_string(submission))
        || has_nul(serde_json::to_string(&origin.observables))
        || has_nul(serde_json::to_string(&origin.details))
    {
        return Err(SubmitError::Invalid(
            "a submission can't hold a NUL character".to_owned(),
        ));
    }
    if let Some(queue) = &origin.queue {
        tree::check_queue_name(queue).map_err(SubmitError::Invalid)?;
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
    Ok(NewRoot {
        description: submission.description.clone(),
        event_time: match submission.event_time {
            Some(time) if origin.event_time_from_query => EventTime::QueryTime(time),
            Some(time) => EventTime::Event(time),
            None => EventTime::Now(Utc::now()),
        },
        ..NewRoot::new(mode)
    })
}

/// Creates `prepare`'s root in the caller's transaction with the submission's observables and
/// files, and queues its first tasks. The caller commits, and may run this again on a retry.
pub async fn create(
    tx: &mut Tx<'_>,
    bucket: &Bucket,
    orchestrator: &Orchestrator,
    root: &NewRoot,
    submission: &Submission,
    origin: &Origin,
    files: &[SubmittedFile],
) -> Result<Vec<TaskId>, SubmitError> {
    let hold = Hold::root(root.id);
    tree::create_root(tx, root).await?;
    if origin.details.is_some() || origin.alerts() {
        sqlx::query!(
            "UPDATE analysis.roots
             SET origin = $2, alerted_at = CASE WHEN $3 THEN now() ELSE alerted_at END
             WHERE id = $1",
            root.id,
            origin.details,
            origin.alerts(),
        )
        .execute(tx.conn())
        .await
        .map_err(DbError::from)?;
    }
    if let Some(queue) = &origin.queue {
        sqlx::query!(
            "UPDATE analysis.roots SET queue = $2 WHERE id = $1",
            root.id,
            queue,
        )
        .execute(tx.conn())
        .await
        .map_err(DbError::from)?;
    }
    for observable in &submission.observables {
        let mut new = NewObservable::new(observable.kind, observable.value.clone());
        new.time = observable.time;
        new.tags = observable.tags.clone();
        new.directives = observable.directives.clone();
        new.exclude_modules = observable.exclude_modules.clone();
        tree::upsert_observable(tx, root.id, &new).await?;
    }
    for observable in &origin.observables {
        let id = tree::upsert_observable(tx, root.id, observable).await?.id;
        for detection in &observable.detections {
            tree::add_detection(tx, root.id, id, None, detection).await?;
        }
    }
    for file in files {
        bucket
            .put_in(tx, ALERT_FILES, &file.spooled, Some(&hold))
            .await?;
        let new = NewObservable::new(ObservableKind::File, file.spooled.sha256.to_hex());
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
    Ok(orchestrator.start(tx, root.id).await?)
}
