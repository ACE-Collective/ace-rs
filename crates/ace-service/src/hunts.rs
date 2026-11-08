//! Hunts (PLAN.md 6.4): the hunts the hunter loaded, each hunt's state, and a run's submissions.
//!
//! The hunter (`ace_app::hunter`) acts as the component `hunter`, which migration 0034 grants
//! `alert:create`, `hunt:read` and `hunt:write`. It records the hunts it loaded with [`Service::sync_hunts`],
//! reads a hunt's state with [`Service::hunt_state`] before a run, and records the run with
//! [`Service::record_hunt_run`]: the run's roots and the hunt's new state in one transaction, which
//! fails with nothing written when the state moved since the run read it. So a run that dies before
//! its commit leaves its window to the next run, and one that commits isn't run again.
//!
//! The `hunt` router reads [`Service::hunts`] and [`Service::hunt`] under `hunt:read`.

use std::collections::BTreeMap;

use ace_core::bucket::Bucket;
use ace_core::submit::{Origin, Submission};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::types::Json;
use uuid::Uuid;

use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{ALERT_CREATE, HUNT_READ, HUNT_WRITE};
use crate::{Actor, Service, ServiceError};

/// A hunt file as the hunter loaded it: the hunt, or why it didn't load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoadedHuntRow {
    #[serde(rename = "type")]
    pub kind: String,
    /// The file, relative to the signatures checkout.
    pub path: String,
    pub name: Option<String>,
    pub uuid: Option<String>,
    pub enabled: Option<bool>,
    pub frequency: Option<String>,
    pub error: Option<String>,
}

impl Recorded for LoadedHuntRow {}

/// What ace3 keeps about a hunt between runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HuntState {
    pub last_executed_time: Option<DateTime<Utc>>,
    pub last_end_time: Option<DateTime<Utc>>,
    pub last_alert_time: Option<DateTime<Utc>>,
    pub last_alert_times: BTreeMap<String, DateTime<Utc>>,
}

impl Recorded for HuntState {}

/// A hunt as the router lists it: as it loaded, and its state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HuntRow {
    #[serde(flatten)]
    pub hunt: LoadedHuntRow,
    pub loaded_at: DateTime<Utc>,
    /// None for a hunt that hasn't run.
    pub state: Option<HuntState>,
}

/// One run of a hunt, to record.
#[derive(Debug, Clone)]
pub struct HuntRun {
    pub kind: String,
    pub name: String,
    /// The state the run started from.
    pub read: HuntState,
    /// The state after it.
    pub state: HuntState,
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    pub submissions: Vec<(Submission, Origin)>,
    /// How many submissions a suppression dropped.
    pub suppressed: usize,
}

/// What recording a run made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecorded {
    pub roots: Vec<Uuid>,
}

#[derive(Serialize)]
struct RunDetails<'a> {
    window_start: Option<DateTime<Utc>>,
    window_end: Option<DateTime<Utc>>,
    roots: &'a [Uuid],
    suppressed: usize,
}

impl Recorded for RunDetails<'_> {}

#[derive(Serialize)]
struct Loaded<'a> {
    hunts: &'a [LoadedHuntRow],
}

impl Recorded for Loaded<'_> {}

fn state_of(
    last_executed_time: Option<DateTime<Utc>>,
    last_end_time: Option<DateTime<Utc>>,
    last_alert_time: Option<DateTime<Utc>>,
    last_alert_times: serde_json::Value,
) -> Result<HuntState, ServiceError> {
    Ok(HuntState {
        last_executed_time,
        last_end_time,
        last_alert_time,
        last_alert_times: serde_json::from_value(last_alert_times)?,
    })
}

impl Service {
    /// Replaces the hunts of a type with the ones the hunter just loaded. A load that found the same
    /// hunts writes nothing.
    pub async fn sync_hunts(
        &self,
        actor: &Actor,
        kind: &str,
        hunts: &[LoadedHuntRow],
    ) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "sync_hunts", &HUNT_WRITE, &|tx| {
                Box::pin(async move {
                    let rows = sqlx::query!(
                        "SELECT type, path, name, uuid, enabled, frequency, error
                         FROM hunts.hunts WHERE type = $1 ORDER BY path",
                        kind,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let before: Vec<LoadedHuntRow> = rows
                        .into_iter()
                        .map(|r| LoadedHuntRow {
                            kind: r.r#type,
                            path: r.path,
                            name: r.name,
                            uuid: r.uuid,
                            enabled: r.enabled,
                            frequency: r.frequency,
                            error: r.error,
                        })
                        .collect();
                    let mut after = hunts.to_vec();
                    after.sort_by(|a, b| a.path.cmp(&b.path));
                    if before == after {
                        return Ok(Audited::unchanged(()));
                    }
                    sqlx::query!("DELETE FROM hunts.hunts WHERE type = $1", kind)
                        .execute(tx.conn())
                        .await?;
                    for hunt in &after {
                        sqlx::query!(
                            "INSERT INTO hunts.hunts (type, path, name, uuid, enabled, frequency, error, loaded_at)
                             VALUES ($1, $2, $3, $4, $5, $6, $7, now())",
                            kind,
                            hunt.path,
                            hunt.name,
                            hunt.uuid,
                            hunt.enabled,
                            hunt.frequency,
                            hunt.error,
                        )
                        .execute(tx.conn())
                        .await?;
                    }
                    let change = Change::updated(
                        Target::hunt_type(kind),
                        &Loaded { hunts: &before },
                        &Loaded { hunts: &after },
                    )?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }

    /// A hunt's state, the default for one that hasn't run.
    pub async fn hunt_state(
        &self,
        actor: &Actor,
        kind: &str,
        name: &str,
    ) -> Result<HuntState, ServiceError> {
        self.gate
            .read(actor, "hunt_state", &HUNT_READ, &|tx| {
                Box::pin(async move {
                    let row = sqlx::query!(
                        "SELECT last_executed_time, last_end_time, last_alert_time, last_alert_times
                         FROM hunts.state WHERE type = $1 AND name = $2",
                        kind,
                        name,
                    )
                    .fetch_optional(tx.conn())
                    .await?;
                    match row {
                        None => Ok(HuntState::default()),
                        Some(r) => state_of(
                            r.last_executed_time,
                            r.last_end_time,
                            r.last_alert_time,
                            r.last_alert_times,
                        ),
                    }
                })
            })
            .await
    }

    /// Records a run: its roots, each submitted as `actor`, and the hunt's new state, in one
    /// transaction. When the stored state isn't the one the run read, another run recorded first and
    /// this is `ServiceError::Conflict`, with nothing written.
    pub async fn record_hunt_run(
        &self,
        actor: &Actor,
        bucket: &Bucket,
        run: &HuntRun,
    ) -> Result<RunRecorded, ServiceError> {
        self.gate
            .write(actor, "record_hunt_run", &ALERT_CREATE, &|tx| {
                Box::pin(async move {
                    sqlx::query!(
                        "INSERT INTO hunts.state (type, name) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        run.kind,
                        run.name,
                    )
                    .execute(tx.conn())
                    .await?;
                    let r = sqlx::query!(
                        "SELECT last_executed_time, last_end_time, last_alert_time, last_alert_times
                         FROM hunts.state WHERE type = $1 AND name = $2 FOR UPDATE",
                        run.kind,
                        run.name,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let stored = state_of(
                        r.last_executed_time,
                        r.last_end_time,
                        r.last_alert_time,
                        r.last_alert_times,
                    )?;
                    if stored != run.read {
                        return Err(ServiceError::Conflict(format!(
                            "hunt {} ({}) was run elsewhere since this run read its state",
                            run.name, run.kind
                        )));
                    }
                    let mut roots = Vec::with_capacity(run.submissions.len());
                    for (submission, origin) in &run.submissions {
                        let (submitted, _) =
                            crate::submit::submit_in(tx, self, bucket, actor, submission, origin, &[])
                                .await?;
                        roots.push(submitted.uuid);
                    }
                    sqlx::query!(
                        "UPDATE hunts.state
                         SET last_executed_time = $3, last_end_time = $4, last_alert_time = $5,
                             last_alert_times = $6, updated_at = now()
                         WHERE type = $1 AND name = $2",
                        run.kind,
                        run.name,
                        run.state.last_executed_time,
                        run.state.last_end_time,
                        run.state.last_alert_time,
                        Json(&run.state.last_alert_times) as _,
                    )
                    .execute(tx.conn())
                    .await?;
                    let change = Change::updated(Target::hunt(&run.kind, &run.name), &stored, &run.state)?
                        .details(&RunDetails {
                            window_start: run.window_start,
                            window_end: run.window_end,
                            roots: &roots,
                            suppressed: run.suppressed,
                        })?;
                    Ok(Audited::changed(RunRecorded { roots }, change))
                })
            })
            .await
    }

    /// Every hunt the hunter loaded, by type and path, with its state.
    pub async fn hunts(&self, actor: &Actor) -> Result<Vec<HuntRow>, ServiceError> {
        self.gate
            .read(actor, "hunts", &HUNT_READ, &|tx| {
                Box::pin(async move {
                    let rows = sqlx::query!(
                        r#"SELECT h.type, h.path, h.name, h.uuid, h.enabled, h.frequency, h.error, h.loaded_at,
                                  s.type AS "state_type?", s.last_executed_time, s.last_end_time,
                                  s.last_alert_time, s.last_alert_times AS "last_alert_times?"
                           FROM hunts.hunts h
                           LEFT JOIN hunts.state s ON s.type = h.type AND s.name = h.name
                           ORDER BY h.type, h.path"#,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    rows.into_iter()
                        .map(|r| {
                            let state = match r.state_type {
                                None => None,
                                Some(_) => Some(state_of(
                                    r.last_executed_time,
                                    r.last_end_time,
                                    r.last_alert_time,
                                    r.last_alert_times.unwrap_or_default(),
                                )?),
                            };
                            Ok(HuntRow {
                                hunt: LoadedHuntRow {
                                    kind: r.r#type,
                                    path: r.path,
                                    name: r.name,
                                    uuid: r.uuid,
                                    enabled: r.enabled,
                                    frequency: r.frequency,
                                    error: r.error,
                                },
                                loaded_at: r.loaded_at,
                                state,
                            })
                        })
                        .collect()
                })
            })
            .await
    }

    /// One hunt by its uuid, with its state.
    pub async fn hunt(&self, actor: &Actor, uuid: &str) -> Result<HuntRow, ServiceError> {
        let all = self.hunts(actor).await?;
        all.into_iter()
            .find(|h| h.hunt.uuid.as_deref() == Some(uuid))
            .ok_or_else(|| ServiceError::NotFound(format!("no hunt {uuid}")))
    }
}

/// What a validation of a hunt did, for its audit row: ace3 writes one `HUNT_AUDIT` line per request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HuntValidation {
    /// The package's target file.
    pub target: String,
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub name: Option<String>,
    pub uuid: Option<String>,
    pub valid: bool,
    pub error: Option<String>,
    /// How many events it was run over, when it was run.
    pub events: Option<usize>,
    pub roots: usize,
}

impl Recorded for HuntValidation {}

impl Service {
    /// Validates a hunt with `validate` once `actor` holds `hunt:write`, and records what it did as an
    /// audited read: a validation writes no root.
    pub async fn validate_hunt<T: Send>(
        &self,
        actor: &Actor,
        validate: &(dyn Fn() -> (HuntValidation, T) + Sync),
    ) -> Result<T, ServiceError> {
        self.gate
            .write(actor, "validate_hunt", &HUNT_WRITE, &|_tx| {
                Box::pin(async move {
                    let (record, value) = validate();
                    let target = Target::hunt_type(record.kind.as_deref().unwrap_or("unknown"));
                    Ok(Audited::changed(value, Change::read(target, &record)?))
                })
            })
            .await
    }
}
