//! Submitting analysis (PLAN.md 5.5): ace3's `POST /api/v2/analysis`, which needs `alert:create`. The
//! core's `submit` module writes the root, its observables and files and its first tasks, and this
//! records who submitted it, on the root and in its audit row, in the same transaction.

use ace_core::bucket::Bucket;
use ace_core::submit::{self, Origin, Submission, SubmitError, Submitted, SubmittedFile};
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

/// Who stamped a submission's directives (PLAN.md decision 44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StampedBy<'a> {
    /// The submitter, the actor.
    Submitter,
    /// The hunt of this name, whose run submits as the hunter's actor.
    Hunt(&'a str),
}

/// Creates a submission's root in the caller's transaction, records who made it, and gives the audit
/// row's change. `Service::submit` and the hunter's runs (`crate::hunts`) both write through it. The
/// observables' directives are recorded as the hunt's when `stamped` names one, else as a
/// submission's by the actor.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_in(
    tx: &mut ace_core::db::Tx<'_>,
    service: &Service,
    bucket: &Bucket,
    actor: &crate::Actor,
    submission: &Submission,
    origin: &Origin,
    files: &[SubmittedFile],
    stamped: StampedBy<'_>,
) -> Result<(Submitted, Change), ServiceError> {
    let root = submit::prepare(&service.orchestrator, submission, origin, files)?;
    let submitter = actor.to_string();
    let from = match stamped {
        StampedBy::Submitter => ace_core::tree::DirectivesFrom::submission(&submitter),
        StampedBy::Hunt(name) => ace_core::tree::DirectivesFrom::hunt(name),
    };
    let queued = submit::create(
        tx,
        bucket,
        &service.orchestrator,
        &root,
        submission,
        origin,
        files,
        from,
    )
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
            observables: submission.observables.len() + origin.observables.len(),
            files: files.len(),
            queued: queued.len(),
        },
    )?
    .details(&Title {
        title: capped(&root.description),
    })?;
    Ok((
        Submitted {
            uuid: root.id,
            queued: queued.into_iter().map(|id| id.0).collect(),
        },
        change,
    ))
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
                    let (submitted, change) = submit_in(
                        tx,
                        self,
                        bucket,
                        actor,
                        submission,
                        &Origin::default(),
                        files,
                        StampedBy::Submitter,
                    )
                    .await?;
                    Ok(Audited::changed(submitted, change))
                })
            })
            .await
    }
}
