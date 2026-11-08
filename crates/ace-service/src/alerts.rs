//! Reading alerts (PLAN.md 5.5): the alert list, one alert, its observables with what modules found, and
//! a file's download. An alert is a root a detection turned into one (`analysis.roots.alerted_at`). Each
//! read needs `alert:read`, as ace3's routes do, and an actor without it learns nothing, not even whether
//! the alert exists. A read writes no audit row, except a download, which ace3 audits and so does this.
//!
//! Lists are pages in a fixed order with a cursor, so a client paging through while alerts arrive sees
//! each one once: the alert list newest first by when each became an alert, and an alert's observables by
//! when each was added. A page's size is bounded here, so the GUI's list (5.10) shares the bound.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most alerts one page holds, as ace3's listing.
pub const MAX_ALERTS_PAGE: u32 = 1000;
/// The most observables one page holds. Each carries its results, which are larger than an alert row.
pub const MAX_OBSERVABLES_PAGE: u32 = 500;

/// An actor as a row recorded it: its identity and the name it had then.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RecordedActor {
    pub kind: String,
    pub id: String,
    pub name: Option<String>,
}

impl RecordedActor {
    pub(crate) fn from_row(value: Option<Value>) -> Result<Option<Self>, ServiceError> {
        value
            .map(|value| {
                serde_json::from_value(value).map_err(|e| {
                    ServiceError::from(ace_core::DbError::Decode(format!("a stored actor: {e}")))
                })
            })
            .transpose()
    }
}

/// Where an alert's analysis is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisState {
    /// Tasks are queued or running for its current pass.
    Running,
    /// Its current pass completed.
    Complete,
    /// Its analysis was cancelled and hasn't started again.
    Cancelled,
}

/// One alert's row.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertSummary {
    pub id: Uuid,
    /// The submission's description, as the sender wrote it.
    pub title: String,
    pub analysis_mode: String,
    pub event_time: Option<DateTime<Utc>>,
    pub event_time_source: String,
    pub created_at: DateTime<Utc>,
    pub alerted_at: DateTime<Utc>,
    pub disposition: Option<String>,
    pub dispositioned_at: Option<DateTime<Utc>>,
    pub dispositioned_by: Option<RecordedActor>,
    pub submitted_by: Option<RecordedActor>,
    pub analysis: AnalysisState,
}

/// One page of the alert list, and the cursor for the next, None on the last.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertPage {
    pub alerts: Vec<AlertSummary>,
    pub next: Option<Uuid>,
}

/// An alert, with how much it holds.
#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub summary: AlertSummary,
    pub observables: i64,
    pub files: i64,
    pub detections: i64,
}

/// A path a file observable has in the alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertFile {
    pub path: String,
    pub yara_meta: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relationship {
    pub kind: String,
    pub target_type: String,
    pub target_value: String,
}

/// What one module found about an observable.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleResult {
    pub module: String,
    pub analysis_type: String,
    pub schema_version: i32,
    pub summary: Option<String>,
    pub tags: Vec<String>,
    pub details: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AlertDetection {
    pub description: String,
    pub details: Option<Value>,
    /// The module whose result raised it, or None for one a submission or the core added.
    pub module: Option<String>,
}

/// An observable of an alert and everything recorded about it.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertObservable {
    pub id: i64,
    pub kind: String,
    pub value: String,
    pub time: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
    pub directives: Vec<String>,
    pub exclude_modules: Vec<String>,
    /// The observable an analyst should look at instead, as (type, value).
    pub redirection: Option<(String, String)>,
    pub files: Vec<AlertFile>,
    pub relationships: Vec<Relationship>,
    pub results: Vec<ModuleResult>,
    pub detections: Vec<AlertDetection>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ObservablePage {
    pub observables: Vec<AlertObservable>,
    pub next: Option<i64>,
}

/// A file an actor was let download: its bytes are the bucket's object with this hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDownload {
    pub sha256: String,
    pub path: String,
}

/// A download's audit row: what was read.
#[derive(Serialize)]
struct FileRead<'a> {
    sha256: &'a str,
    path: &'a str,
}

impl Recorded for FileRead<'_> {}

/// The columns of a root that `AlertSummary` reads.
struct AlertRow {
    id: Uuid,
    description: String,
    analysis_mode: String,
    event_time: Option<DateTime<Utc>>,
    event_time_source: String,
    created_at: DateTime<Utc>,
    alerted_at: DateTime<Utc>,
    disposition: Option<String>,
    dispositioned_at: Option<DateTime<Utc>>,
    dispositioned_by: Option<Value>,
    submitted_by: Option<Value>,
    pass: i32,
    completed_pass: i32,
    cancelled: bool,
}

impl AlertRow {
    fn summary(self) -> Result<AlertSummary, ServiceError> {
        let analysis = if self.cancelled {
            AnalysisState::Cancelled
        } else if self.pass > 0 && self.completed_pass == self.pass {
            AnalysisState::Complete
        } else {
            AnalysisState::Running
        };
        Ok(AlertSummary {
            id: self.id,
            title: self.description,
            analysis_mode: self.analysis_mode,
            event_time: self.event_time,
            event_time_source: self.event_time_source,
            created_at: self.created_at,
            alerted_at: self.alerted_at,
            disposition: self.disposition,
            dispositioned_at: self.dispositioned_at,
            dispositioned_by: RecordedActor::from_row(self.dispositioned_by)?,
            submitted_by: RecordedActor::from_row(self.submitted_by)?,
            analysis,
        })
    }
}

pub(crate) fn page_limit(limit: Option<u32>, max: u32) -> Result<i64, ServiceError> {
    match limit {
        None => Ok(i64::from(max.min(100))),
        Some(limit) if (1..=max).contains(&limit) => Ok(i64::from(limit)),
        Some(limit) => Err(ServiceError::InvalidRequest(format!(
            "a page holds 1 to {max}, not {limit}"
        ))),
    }
}

pub(crate) fn no_alert(id: Uuid) -> ServiceError {
    ServiceError::NotFound(format!("no alert {id}"))
}

impl Service {
    /// A page of alerts, newest first, of up to `limit` (100 when None, at most `MAX_ALERTS_PAGE`), after
    /// the alert `after` names. ace3's filters are the manage page's language, which comes with its list
    /// in 5.10.
    pub async fn alerts(
        &self,
        actor: &crate::Actor,
        limit: Option<u32>,
        after: Option<Uuid>,
    ) -> Result<AlertPage, ServiceError> {
        let limit = page_limit(limit, MAX_ALERTS_PAGE)?;
        self.gate
            .read(actor, "alerts", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    if let Some(after) = after {
                        let known = sqlx::query_scalar!(
                            r#"SELECT EXISTS (SELECT FROM analysis.roots
                                              WHERE id = $1 AND alerted_at IS NOT NULL) AS "known!""#,
                            after,
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        if !known {
                            return Err(ServiceError::InvalidRequest(format!(
                                "the cursor {after} names no alert"
                            )));
                        }
                    }
                    let mut rows = sqlx::query_as!(
                        AlertRow,
                        r#"SELECT r.id, r.description, r.analysis_mode, r.event_time,
                                  r.event_time_source::text AS "event_time_source!",
                                  r.created_at, r.alerted_at AS "alerted_at!", r.disposition,
                                  r.dispositioned_at,
                                  r.dispositioned_by AS "dispositioned_by: Value",
                                  r.submitted_by AS "submitted_by: Value",
                                  r.pass, r.completed_pass,
                                  r.cancelled_at IS NOT NULL AS "cancelled!"
                           FROM analysis.roots r
                           WHERE r.alerted_at IS NOT NULL
                             AND ($2::uuid IS NULL OR (r.alerted_at, r.id) <
                                  (SELECT a.alerted_at, a.id FROM analysis.roots a WHERE a.id = $2))
                           ORDER BY r.alerted_at DESC, r.id DESC
                           LIMIT $1"#,
                        limit + 1,
                        after,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
                    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                    let alerts = rows
                        .into_iter()
                        .map(AlertRow::summary)
                        .collect::<Result<Vec<_>, _>>()?;
                    let next = if more {
                        alerts.last().map(|alert| alert.id)
                    } else {
                        None
                    };
                    Ok(AlertPage { alerts, next })
                })
            })
            .await
    }

    /// One alert, with how many observables, files and detections it has.
    pub async fn alert(&self, actor: &crate::Actor, id: Uuid) -> Result<Alert, ServiceError> {
        self.gate
            .read(actor, "alert", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let row = sqlx::query_as!(
                        AlertRow,
                        r#"SELECT r.id, r.description, r.analysis_mode, r.event_time,
                                  r.event_time_source::text AS "event_time_source!",
                                  r.created_at, r.alerted_at AS "alerted_at!", r.disposition,
                                  r.dispositioned_at,
                                  r.dispositioned_by AS "dispositioned_by: Value",
                                  r.submitted_by AS "submitted_by: Value",
                                  r.pass, r.completed_pass,
                                  r.cancelled_at IS NOT NULL AS "cancelled!"
                           FROM analysis.roots r
                           WHERE r.id = $1 AND r.alerted_at IS NOT NULL"#,
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| no_alert(id))?;
                    let counts = sqlx::query!(
                        r#"SELECT
                             (SELECT count(*) FROM analysis.observables WHERE root_id = $1) AS "observables!",
                             (SELECT count(*) FROM analysis.files WHERE root_id = $1) AS "files!",
                             (SELECT count(*) FROM analysis.detections WHERE root_id = $1) AS "detections!""#,
                        id,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    Ok(Alert {
                        summary: row.summary()?,
                        observables: counts.observables,
                        files: counts.files,
                        detections: counts.detections,
                    })
                })
            })
            .await
    }

    /// A page of an alert's observables in the order they were added, each with its files, relationships,
    /// results and detections, of up to `limit` (100 when None, at most `MAX_OBSERVABLES_PAGE`) after the
    /// observable `after` names.
    pub async fn alert_observables(
        &self,
        actor: &crate::Actor,
        id: Uuid,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<ObservablePage, ServiceError> {
        let limit = page_limit(limit, MAX_OBSERVABLES_PAGE)?;
        self.gate
            .read(actor, "alert_observables", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let alert = sqlx::query_scalar!(
                        "SELECT alerted_at IS NOT NULL FROM analysis.roots WHERE id = $1",
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .flatten();
                    if alert != Some(true) {
                        return Err(no_alert(id));
                    }
                    let mut rows = sqlx::query!(
                        "SELECT id, type, value, time, tags, directives, exclude_modules,
                                redirection_type, redirection_value
                         FROM analysis.observables
                         WHERE root_id = $1 AND id > $2
                         ORDER BY id LIMIT $3",
                        id,
                        after.unwrap_or(0),
                        limit + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
                    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                    let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
                    let mut observables: Vec<AlertObservable> = rows
                        .into_iter()
                        .map(|row| AlertObservable {
                            id: row.id,
                            kind: row.r#type,
                            value: row.value,
                            time: row.time,
                            tags: row.tags,
                            directives: row.directives,
                            exclude_modules: row.exclude_modules,
                            redirection: row.redirection_type.zip(row.redirection_value),
                            files: Vec::new(),
                            relationships: Vec::new(),
                            results: Vec::new(),
                            detections: Vec::new(),
                        })
                        .collect();
                    let at = |observable: i64| ids.binary_search(&observable).ok();

                    for row in sqlx::query!(
                        "SELECT observable_id, path, yara_meta FROM analysis.files
                         WHERE root_id = $1 AND observable_id = ANY($2)
                         ORDER BY observable_id, path",
                        id,
                        &ids,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        if let Some(i) = at(row.observable_id) {
                            observables[i].files.push(AlertFile {
                                path: row.path,
                                yara_meta: row.yara_meta,
                            });
                        }
                    }
                    for row in sqlx::query!(
                        "SELECT observable_id, kind, target_type, target_value
                         FROM analysis.relationships
                         WHERE root_id = $1 AND observable_id = ANY($2)
                         ORDER BY observable_id, kind, target_type, target_value",
                        id,
                        &ids,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        if let Some(i) = at(row.observable_id) {
                            observables[i].relationships.push(Relationship {
                                kind: row.kind,
                                target_type: row.target_type,
                                target_value: row.target_value,
                            });
                        }
                    }
                    for row in sqlx::query!(
                        "SELECT observable_id, module, analysis_type, schema_version, summary, tags,
                                details, created_at
                         FROM analysis.results
                         WHERE root_id = $1 AND observable_id = ANY($2)
                         ORDER BY observable_id, module",
                        id,
                        &ids,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        if let Some(i) = at(row.observable_id) {
                            observables[i].results.push(ModuleResult {
                                module: row.module,
                                analysis_type: row.analysis_type,
                                schema_version: row.schema_version,
                                summary: row.summary,
                                tags: row.tags,
                                details: row.details,
                                created_at: row.created_at,
                            });
                        }
                    }
                    for row in sqlx::query!(
                        r#"SELECT d.observable_id, d.description, d.details,
                                  r.module AS "module?"
                           FROM analysis.detections d
                           LEFT JOIN analysis.results r ON r.id = d.result_id
                           WHERE d.root_id = $1 AND d.observable_id = ANY($2)
                           ORDER BY d.id"#,
                        id,
                        &ids,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        if let Some(i) = at(row.observable_id) {
                            observables[i].detections.push(AlertDetection {
                                description: row.description,
                                details: row.details,
                                module: row.module,
                            });
                        }
                    }
                    let next = if more {
                        observables.last().map(|observable| observable.id)
                    } else {
                        None
                    };
                    Ok(ObservablePage { observables, next })
                })
            })
            .await
    }

    /// Lets an actor download a file observable of an alert, and records that they did, as ace3's
    /// download routes log it. It needs `alert:read`. The caller fetches the bytes by the hash: the row
    /// says the file was asked for, and is written whether or not the bytes then arrive.
    pub async fn download_file(
        &self,
        actor: &crate::Actor,
        id: Uuid,
        observable: i64,
    ) -> Result<FileDownload, ServiceError> {
        self.gate
            .write(actor, "download_file", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let found = sqlx::query!(
                        r#"SELECT o.type, o.value, r.alerted_at IS NOT NULL AS "alert!",
                                  (SELECT f.path FROM analysis.files f
                                   WHERE f.root_id = o.root_id AND f.observable_id = o.id
                                   ORDER BY f.created_at, f.path LIMIT 1) AS path
                           FROM analysis.observables o
                           JOIN analysis.roots r ON r.id = o.root_id
                           WHERE o.root_id = $1 AND o.id = $2"#,
                        id,
                        observable,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    let Some(found) = found.filter(|found| found.alert) else {
                        return Err(ServiceError::NotFound(format!(
                            "no observable {observable} in alert {id}"
                        )));
                    };
                    let Some(path) = found.path.filter(|_| found.r#type == "file") else {
                        return Err(ServiceError::InvalidRequest(format!(
                            "observable {observable} isn't a file"
                        )));
                    };
                    let change = Change::read(
                        Target::observable(id, observable),
                        &FileRead {
                            sha256: &found.value,
                            path: &path,
                        },
                    )?;
                    Ok(Audited::changed(
                        FileDownload {
                            sha256: found.value,
                            path,
                        },
                        change,
                    ))
                })
            })
            .await
    }
}
