//! Submitting analysis (PLAN.md 5.5): ace3's `POST /api/v2/analysis`, which needs `alert:create`. The
//! core's `submit` module writes the root, its observables and files and its first tasks, and this
//! records who submitted it, on the root and in its audit row, in the same transaction.

use ace_core::bucket::Bucket;
use ace_core::submit::{self, Origin, Submission, SubmitError, Submitted, SubmittedFile};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::types::Json;
use uuid::Uuid;

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

/// The analysis mode of a manual alert, as ace3's `new_alert` submits it.
const MANUAL_MODE: &str = "correlation";

/// The longest alert template name a manual alert can carry, as `ace_app::App::alert_template` allows.
const MAX_TEMPLATE_NAME: usize = 256;

/// An alert an analyst makes by hand on the Analyze page (PLAN.md 7.18), ace3's `new_alert` without its
/// form: the form's text is read by the GUI, and this is what it read.
#[derive(Debug)]
pub struct ManualAlert {
    /// The alert's title, or each alert's title before its observable is added to it.
    pub description: String,
    /// The queue the alert starts in.
    pub queue: String,
    /// The template the alert page is drawn with, ace3's `extensions.alert_template`; None for the
    /// alert type's own. The GUI offers only the binary's named summaries, and checks the name.
    pub alert_template: Option<String>,
    pub event_time: DateTime<Utc>,
    pub observables: Vec<ManualObservable>,
    pub alerts: ManualAlerts,
}

/// How many alerts a manual submission makes, ace3's `submit_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualAlerts {
    /// One alert holding every observable (`single`).
    One,
    /// One alert for each observable, each with only its own file (`multiple`).
    PerObservable,
}

/// One observable of a manual alert.
#[derive(Debug)]
pub struct ManualObservable {
    pub kind: ace_results::ObservableKind,
    pub value: ManualValue,
    pub time: Option<DateTime<Utc>>,
    pub directives: Vec<String>,
}

/// A manual observable's value: text, or for a file an upload, never a path on this node.
#[derive(Debug)]
pub enum ManualValue {
    Text(String),
    File(SubmittedFile),
}

impl ManualObservable {
    /// ace3's `alert_title`: the file's name for a file, else the value.
    fn title(&self, description: &str) -> String {
        match &self.value {
            ManualValue::Text(value) => format!("{description} ({value})"),
            ManualValue::File(file) => format!("{description} ({})", file.path.as_str()),
        }
    }
}

/// One alert's submission and files.
struct ManualPart {
    submission: Submission,
    files: Vec<SubmittedFile>,
}

fn manual_part(
    description: String,
    event_time: DateTime<Utc>,
    observables: Vec<ManualObservable>,
) -> Result<ManualPart, ServiceError> {
    let mut submitted = Vec::with_capacity(observables.len());
    let mut files = Vec::new();
    for observable in observables {
        let is_file = observable.kind == ace_results::ObservableKind::File;
        let value = match observable.value {
            ManualValue::Text(_) if is_file => {
                return Err(ServiceError::InvalidRequest(
                    "a file observable is an uploaded file".to_owned(),
                ));
            }
            ManualValue::File(_) if !is_file => {
                return Err(ServiceError::InvalidRequest(format!(
                    "a {} observable can't be a file",
                    observable.kind
                )));
            }
            ManualValue::Text(value) => value,
            ManualValue::File(file) => {
                // the core adds the file's observable by its sha256 too; this one carries the
                // analyst's time and directives, and the two are one observable
                let value = file.spooled.sha256.to_hex();
                files.push(file);
                value
            }
        };
        submitted.push(submit::SubmittedObservable {
            kind: observable.kind,
            value,
            time: observable.time,
            tags: Vec::new(),
            directives: observable.directives,
            exclude_modules: Vec::new(),
        });
    }
    Ok(ManualPart {
        submission: Submission {
            description,
            analysis_mode: Some(MANUAL_MODE.to_owned()),
            event_time: Some(event_time),
            observables: submitted,
            file_yara_meta: std::collections::BTreeMap::new(),
        },
        files,
    })
}

impl Service {
    /// Makes a manual alert, or one per observable, as ace3's Analyze page does (PLAN.md 7.18). It needs
    /// `alert:create`. Each alert is a `correlation` root whose origin says it is ace3's `manual` type
    /// from the `gui` tool, made by the actor, in the queue the analyst chose, owned by the actor's user,
    /// and is a write and an audit row of its own. One observable's alert is titled with its value, or
    /// its file's name. Returns the alerts made, in order. A submission that can't be taken is
    /// `InvalidRequest` and makes no alert; one alert of several that fails stops the rest, and those
    /// made before it stay, as in ace3.
    pub async fn submit_manual(
        &self,
        actor: &crate::Actor,
        bucket: &Bucket,
        alert: ManualAlert,
    ) -> Result<Vec<Uuid>, ServiceError> {
        if let Some(template) = &alert.alert_template
            && (template.is_empty() || template.len() > MAX_TEMPLATE_NAME)
        {
            return Err(ServiceError::InvalidRequest(format!(
                "an alert template's name is 1 to {MAX_TEMPLATE_NAME} bytes"
            )));
        }
        ace_core::tree::check_queue_name(&alert.queue).map_err(ServiceError::InvalidRequest)?;
        let ManualAlert {
            description,
            queue,
            alert_template,
            event_time,
            observables,
            alerts,
        } = alert;
        let parts = match alerts {
            ManualAlerts::One => {
                let title = match observables.as_slice() {
                    [only] => only.title(&description),
                    _ => description.clone(),
                };
                vec![manual_part(title, event_time, observables)?]
            }
            ManualAlerts::PerObservable if observables.is_empty() => {
                return Err(ServiceError::InvalidRequest(
                    "one alert per observable needs an observable".to_owned(),
                ));
            }
            ManualAlerts::PerObservable => observables
                .into_iter()
                .map(|observable| {
                    manual_part(observable.title(&description), event_time, vec![observable])
                })
                .collect::<Result<_, _>>()?,
        };
        let (user, owner) = match actor {
            crate::Actor::User { id, name } => (name.clone(), Some(*id)),
            crate::Actor::ApiKey { name, owner, .. } => (name.clone(), *owner),
            crate::Actor::Internal { .. } => (actor.to_string(), None),
        };
        let mut details = serde_json::json!({
            "alert_type": "manual",
            "tool": "gui",
            "details": {"user": user, "comment": ""},
        });
        if let Some(template) = alert_template {
            details["extensions"] = serde_json::json!({"alert_template": template});
        }
        let origin = Origin {
            details: Some(details),
            queue: Some(queue),
            ..Origin::default()
        };
        let mut made = Vec::with_capacity(parts.len());
        for part in &parts {
            let uuid = self
                .gate
                .write(actor, "submit_manual", &ALERT_CREATE, &|tx| {
                    let origin = &origin;
                    Box::pin(async move {
                        let (submitted, change) = submit_in(
                            tx,
                            self,
                            bucket,
                            actor,
                            &part.submission,
                            origin,
                            &part.files,
                            StampedBy::Submitter,
                        )
                        .await?;
                        if let Some(owner) = owner {
                            // ace3's `new_alert` gives the analyst the alert it made
                            sqlx::query!(
                                "UPDATE analysis.roots SET owner_id = $2, owned_at = now()
                                 WHERE id = $1",
                                submitted.uuid,
                                owner.0,
                            )
                            .execute(tx.conn())
                            .await?;
                        }
                        Ok(Audited::changed(submitted.uuid, change))
                    })
                })
                .await?;
            tracing::info!(root = %uuid, actor = %actor, "a manual alert was made");
            made.push(uuid);
        }
        Ok(made)
    }
}
