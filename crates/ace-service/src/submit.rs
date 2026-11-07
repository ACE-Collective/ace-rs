//! Submitting analysis (PLAN.md 5.5): ace3's `POST /api/v2/analysis`, which needs `alert:create`. The
//! core's `submit` module writes the root, its observables and files and its first tasks, and this
//! records who submitted it, on the root and in its audit row, in the same transaction.

use ace_core::bucket::Bucket;
use ace_core::submit::{self, Submission, SubmitError, Submitted, SubmittedFile};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::types::Json;

use crate::gate::{Audited, Change, Recorded, TITLE_LIMIT, Target};
use crate::permission::ALERT_CREATE;
use crate::{Service, ServiceError};

/// A submission's audit row: what it made, not what it held, which is the root's to keep. ace3's line
/// names the root, its mode and how many files it had.
#[derive(Serialize)]
struct SubmissionRecord<'a> {
    analysis_mode: &'a str,
    event_time: Option<DateTime<Utc>>,
    observables: usize,
    files: usize,
    queued: usize,
}

impl Recorded for SubmissionRecord<'_> {}

#[derive(Serialize)]
struct Title<'a> {
    title: &'a str,
}

impl Recorded for Title<'_> {}

impl From<SubmitError> for ServiceError {
    fn from(error: SubmitError) -> Self {
        match error {
            SubmitError::Invalid(why) => ServiceError::InvalidRequest(why),
            SubmitError::Bucket(e) => ServiceError::Bucket(e),
            SubmitError::Orchestrator(e) => ServiceError::Orchestrator(e),
        }
    }
}

/// The first `TITLE_LIMIT` characters, as the audit keeps of an alert's title.
fn capped(text: &str) -> &str {
    match text
        .char_indices()
        .nth(usize::try_from(TITLE_LIMIT).unwrap_or(usize::MAX))
    {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

impl Service {
    /// Creates a root from a submission, with its files already spooled on this node, and queues its
    /// first tasks. It needs `alert:create`, and the root records the actor in `submitted_by`. The
    /// submission is checked after the permission, so an actor without it learns nothing about the
    /// modes. A submission that can't be taken is `ServiceError::InvalidRequest` and writes nothing.
    pub async fn submit(
        &self,
        actor: &crate::Actor,
        bucket: &Bucket,
        submission: &Submission,
        files: &[SubmittedFile],
    ) -> Result<Submitted, ServiceError> {
        self.gate
            .write(actor, "submit", &ALERT_CREATE, &|tx| {
                Box::pin(async move {
                    let root = submit::prepare(&self.orchestrator, submission, files)?;
                    let queued =
                        submit::create(tx, bucket, &self.orchestrator, &root, submission, files)
                            .await?;
                    sqlx::query!(
                        "UPDATE analysis.roots SET submitted_by = $2::jsonb WHERE id = $1",
                        root.id,
                        Json(actor) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                    let change = Change::added(
                        Target::root(root.id),
                        &SubmissionRecord {
                            analysis_mode: &root.analysis_mode,
                            event_time: root.event_time.time(),
                            observables: submission.observables.len(),
                            files: files.len(),
                            queued: queued.len(),
                        },
                    )?
                    .details(&Title {
                        title: capped(&root.description),
                    })?;
                    Ok(Audited::changed(
                        Submitted {
                            uuid: root.id,
                            queued: queued.into_iter().map(|id| id.0).collect(),
                        },
                        change,
                    ))
                })
            })
            .await
    }
}
