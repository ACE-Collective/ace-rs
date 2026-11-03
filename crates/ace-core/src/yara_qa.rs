//! YARA QA (PLAN.md 2.27): the matches of rules in QA mode, recorded off the scanning path.
//!
//! A QA rule never alerts: the YARA module makes no detection for it. When a YARA result with a
//! QA match lands, the orchestrator queues a `yara_qa` task on the file in the same transaction,
//! and the core's recorder runs it: for each QA match it writes or renews a row of
//! `yara.qa_matches`, one per (rule uuid, rule version, file), and holds the file in the
//! `alert_files` pool until the row expires. The file is already in the bucket, so ace3's spool
//! directory and its hardlinks (`saq/yara_scanning/qa.py`) have no counterpart. As in ace3, the
//! version is the commit of the rule's repository, a match of a rule without a uuid isn't kept,
//! and a row lasts 30 days after the file last matched.

use std::time::Duration;

use ace_results::types::yara::{ScanResult, YaraScanResults};
use ace_results::{AnalysisType, ResultEnvelope, Sha256};
use ace_yara::Meta;
use chrono::Utc;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::bucket::{ALERT_FILES, Bucket, BucketError, Hold};
use crate::db::{Db, DbError, Isolation, Retryable, Tx};
use crate::queue::{self, QueueError, Task, TaskState, Wakeups, Worker};

/// The module key of a QA task. No pool runs it; the core's recorder does.
pub const QA_MODULE: &str = "yara_qa";

/// How long a QA match keeps its file after it last matched: ace3's `yara_qa.retention_days`.
pub const RETENTION: Duration = Duration::from_secs(30 * 86_400);

/// A hold's kind for a QA match; its id is the match's row id.
pub const HOLDER_KIND: &str = "yara_qa";

/// The signature version of a rule that didn't come from a repository's commit, as ace3's.
const VERSION_UNKNOWN: &str = "unknown";

/// The scan results in a YARA result whose rules are in QA mode, as ace3's
/// `select_qa_matches`: enabled, with `qa` in their modifiers. Rules without a uuid are among
/// them; the recorder skips those.
pub fn qa_matches(result: &ResultEnvelope<Value>) -> Vec<ScanResult> {
    if result.analysis_type() != YaraScanResults::NAME {
        return Vec::new();
    }
    qa_in(&result.details)
}

/// `qa_matches` of a YARA result's details.
fn qa_in(details: &Value) -> Vec<ScanResult> {
    let Ok(details) = serde_json::from_value::<YaraScanResults>(details.clone()) else {
        return Vec::new();
    };
    details
        .scan_results
        .into_iter()
        .filter(|m| {
            let meta = Meta::from_json(&m.meta);
            meta.enabled() && meta.is_qa()
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum QaError {
    #[error(transparent)]
    Queue(#[from] QueueError),
    #[error(transparent)]
    Bucket(#[from] BucketError),
    #[error(transparent)]
    Db(#[from] DbError),
    #[error("{0}")]
    Invalid(String),
}

impl From<sqlx::Error> for QaError {
    fn from(error: sqlx::Error) -> Self {
        QaError::Db(DbError::Sqlx(error))
    }
}

impl Retryable for QaError {
    fn is_retryable(&self) -> bool {
        match self {
            QaError::Queue(e) => e.is_retryable(),
            QaError::Bucket(BucketError::Db(e)) | QaError::Db(e) => e.is_retryable(),
            _ => false,
        }
    }
}

/// Records a claimed QA task's matches and ends it, in one transaction: the task's end, a row
/// per match and the holds on the file. Returns the rows' ids.
pub async fn record(worker: &Worker, bucket: &Bucket, task: &Task) -> Result<Vec<i64>, QaError> {
    let sha256: Sha256 = task.observable.value.parse().map_err(|_| {
        QaError::Invalid(format!("{} isn't a file's sha256", task.observable.value))
    })?;
    worker
        .db()
        .transaction(Isolation::ReadCommitted, |tx| {
            Box::pin(async move {
                let root = worker.finish_in(tx, task.id, TaskState::Done, None).await?;
                let ids = record_in(tx, bucket, task, &sha256).await?;
                queue::check_completion(tx, root).await?;
                Ok::<_, QaError>(ids)
            })
        })
        .await
}

async fn record_in(
    tx: &mut Tx<'_>,
    bucket: &Bucket,
    task: &Task,
    sha256: &Sha256,
) -> Result<Vec<i64>, QaError> {
    let results = sqlx::query_scalar!(
        "SELECT details FROM analysis.results
         WHERE root_id = $1 AND observable_id = $2 AND analysis_type = $3 ORDER BY id",
        task.root,
        task.observable.id.0,
        YaraScanResults::NAME,
    )
    .fetch_all(tx.conn())
    .await?;
    let expires_at = Utc::now()
        + chrono::Duration::from_std(RETENTION).map_err(|e| QaError::Invalid(e.to_string()))?;
    let mut ids = Vec::new();
    for details in results {
        for m in qa_in(&details) {
            let meta = Meta::from_json(&m.meta);
            let Some(uuid) = meta.uuid().filter(|u| !u.is_empty()) else {
                tracing::warn!(rule = %m.rule, "a rule in QA mode has no uuid; its match isn't kept");
                continue;
            };
            let version = m
                .commit
                .clone()
                .unwrap_or_else(|| VERSION_UNKNOWN.to_owned());
            let recorded = serde_json::to_value(&m).map_err(|e| QaError::Invalid(e.to_string()))?;
            let id = sqlx::query_scalar!(
                "INSERT INTO yara.qa_matches AS q
                     (signature_uuid, signature_version, rule, namespace, ruleset, sha256,
                      file_path, root_id, observable_id, match, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (signature_uuid, signature_version, sha256) DO UPDATE
                 SET hit_count = q.hit_count + 1, last_seen = now(),
                     expires_at = EXCLUDED.expires_at, rule = EXCLUDED.rule,
                     namespace = EXCLUDED.namespace, file_path = EXCLUDED.file_path,
                     root_id = EXCLUDED.root_id, observable_id = EXCLUDED.observable_id,
                     match = EXCLUDED.match
                 RETURNING id",
                uuid,
                version,
                m.rule,
                m.namespace,
                m.ruleset,
                sha256.to_hex(),
                m.target,
                task.root,
                task.observable.id.0,
                recorded,
                expires_at,
            )
            .fetch_one(tx.conn())
            .await?;
            bucket
                .hold_in(
                    tx,
                    ALERT_FILES,
                    sha256,
                    &Hold::new(HOLDER_KIND, id.to_string()).until(expires_at),
                )
                .await?;
            tracing::info!(rule = %m.rule, %uuid, %version, %sha256, id, "recorded a YARA QA match");
            ids.push(id);
        }
    }
    Ok(ids)
}

/// The core's QA recorder: claims `yara_qa` tasks as `worker`, waking on the queue's
/// notifications with `fallback` as the longest wait, and records each, until `stop` fires. A
/// task that can't be recorded fails with why.
pub async fn run_recorder(
    worker: Worker,
    bucket: Bucket,
    fallback: Duration,
    stop: CancellationToken,
) {
    let mut wakeups = None;
    loop {
        if wakeups.is_none() {
            match tokio::time::timeout(fallback, Wakeups::listen(worker.db())).await {
                Ok(Ok(listening)) => wakeups = Some(listening),
                Ok(Err(e)) => tracing::warn!("the QA recorder can't listen for tasks: {e}"),
                Err(_) => tracing::warn!("the QA recorder's listener didn't connect in time"),
            }
        }
        let next = match wakeups.as_mut() {
            Some(wakeups) => tokio::select! {
                () = stop.cancelled() => return,
                next = worker.next_task(wakeups, fallback) => next.map(|(task, _)| Some(task)),
            },
            None => tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(fallback) => worker.claim().await,
            },
        };
        let task = match next {
            Ok(Some(task)) => task,
            Ok(None) => continue,
            Err(e) => {
                tracing::error!("the QA recorder couldn't claim a task: {e}");
                wakeups = None;
                tokio::time::sleep(fallback).await;
                continue;
            }
        };
        if let Err(e) = record(&worker, &bucket, &task).await {
            tracing::error!(task = %task.id, "recording the QA matches failed: {e}");
            if let Err(e) = worker.fail(task.id, &e.to_string()).await {
                tracing::error!(task = %task.id, "failing the QA task failed: {e}");
            }
        }
    }
}

/// The recorder's worker: one per core process, named for the host and process.
pub fn recorder_worker(db: Db) -> Worker {
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "core".to_owned());
    Worker::new(
        db,
        format!("core/{host}/{}/yara_qa", std::process::id()),
        vec![QA_MODULE.to_owned()],
        Duration::from_secs(60),
    )
}
