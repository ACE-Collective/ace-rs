//! Hunts (PLAN.md 6.4): the hunts the hunter loaded, each hunt's state, and a run's submissions.
//!
//! The hunter (`ace_app::hunter`) acts as the component `hunter`, which migration 0034 grants
//! `alert:create`, `hunt:read` and `hunt:write`. It records the hunts it loaded with [`Service::sync_hunts`],
//! reads a hunt's state with [`Service::hunt_state`] before a run, and records the run with
//! [`Service::record_hunt_run`]: the run's roots and the hunt's new state in one transaction, which
//! fails with nothing written when the state moved since the run read it. So a run that dies before
//! its commit leaves its window to the next run, and one that commits isn't run again.
//!
//! **Suppression records** (PLAN.md 6.5, ace3 #840). ace3 drops a hit two ways, and says so only in
//! a log line. A grouped hunt with a `suppression` drops a group that alerted less than `suppression`
//! ago (`QueryHunt.process_query_results`); the hunter decides that ([`HuntRun::suppressed`]). And
//! ace3's collector drops a submission whose dedup key it made a root for less than 4 hours ago
//! (`DuplicateSubmissionFilter`), which [`Service::record_hunt_run`] does here, against
//! `hunts.dedup_keys`. Each drop is a row of `hunts.suppressions` ([`Suppression`]): the hunt, the hit's
//! key, group value, description and event time, the window it fell into, why, when, and the root of
//! the earlier hit that opened the window. They're written in the run's transaction, with its roots
//! and its state, so a run is never recorded without its decisions or the reverse.
//!
//! An ungrouped hunt with a `suppression` doesn't search while it's suppressed, so no hit is dropped and
//! there's no row: the window is its state's `last_alert_time` plus the hunt's `suppression`.
//!
//! Growth: a run writes at most one row per submission it would have made, which its search's rows bound
//! (`max_result_count`, 100 by default, which Splunk applies), and a grouped hunt makes one per group,
//! with the rows it held as `events`. Rows go after [`SUPPRESSION_RETENTION`], in each run's
//! transaction. ace3 keeps no such rows: its SVS keeps the first dropped match per SVS run and hunt
//! (`svs_suppressed_matches`) while a run is open, which ace4 has no SVS for yet (7.10).
//!
//! The `hunt` router reads [`Service::hunts`], [`Service::hunt`] and [`Service::hunt_suppressions`]
//! under `hunt:read`.

use std::collections::BTreeMap;

use ace_core::bucket::Bucket;
use ace_core::submit::{Origin, Submission};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
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
    /// The hunt's uuid, which its suppression rows are listed by.
    pub uuid: String,
    /// When the run read the clock, which its decisions are dated by.
    pub at: DateTime<Utc>,
    /// The state the run started from.
    pub read: HuntState,
    /// The state after it.
    pub state: HuntState,
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    /// What the run would submit, in order; a duplicate of a live dedup key is dropped here.
    pub submissions: Vec<HuntSubmission>,
    /// The submissions a group's suppression dropped.
    pub suppressed: Vec<GroupSuppressed>,
}

/// A submission of a run, with the keys ace3 drops it by.
#[derive(Debug, Clone)]
pub struct HuntSubmission {
    pub submission: Submission,
    pub origin: Origin,
    /// Its dedup key, `<hunt uuid>:<rendered dedup_key>`: ace3's collector drops a submission whose key
    /// it made a root for less than [`DEDUP_KEY_LIFETIME`] ago.
    pub dedup_key: Option<String>,
    /// The key its group's alert time is kept under, for a grouped hunt.
    pub suppression_key: Option<String>,
    /// The `group_by` value that made it.
    pub group_value: Option<serde_json::Value>,
    /// How many of the search's rows it holds.
    pub events: usize,
}

/// A submission a group's suppression dropped: its group alerted at `since`, less than the hunt's
/// suppression before the run.
#[derive(Debug, Clone)]
pub struct GroupSuppressed {
    pub key: String,
    pub group_value: Option<serde_json::Value>,
    pub description: String,
    pub event_time: DateTime<Utc>,
    pub events: usize,
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
}

/// How long a dedup key drops the submissions that repeat it: ace3's collector deletes a key 4 hours
/// after its last update (`persistence_unmodified_expiration_seconds`) or 24 after it was made
/// (`persistence_expiration_seconds`), and a key is never updated after it's made.
pub const DEDUP_KEY_LIFETIME: TimeDelta = TimeDelta::hours(4);

/// How long a suppression row is kept.
pub const SUPPRESSION_RETENTION: TimeDelta = TimeDelta::days(30);

/// Why a hit was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionReason {
    /// Its group alerted within the hunt's `suppression`.
    Group,
    /// Its dedup key made a root within [`DEDUP_KEY_LIFETIME`].
    Duplicate,
}

impl SuppressionReason {
    fn as_str(self) -> &'static str {
        match self {
            SuppressionReason::Group => "group",
            SuppressionReason::Duplicate => "duplicate",
        }
    }
}

/// A suppression decision: a hit a hunt dropped, why, and the earlier hit that dropped it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suppression {
    pub id: i64,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub uuid: String,
    pub reason: SuppressionReason,
    /// The group's suppression key, or the dedup key.
    pub key: String,
    pub group_value: Option<serde_json::Value>,
    pub description: String,
    pub event_time: DateTime<Utc>,
    pub events: i32,
    /// The window it fell into, opened by the earlier hit.
    pub window_start: DateTime<Utc>,
    pub window_end: DateTime<Utc>,
    /// The earlier hit's root, None when ace4 didn't make it.
    pub cause_root: Option<Uuid>,
    pub search_start: Option<DateTime<Utc>>,
    pub search_end: Option<DateTime<Utc>>,
    pub decided_at: DateTime<Utc>,
}

/// A page of a hunt's suppressions, newest first, and the cursor for the next, None on the last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionPage {
    pub suppressions: Vec<Suppression>,
    pub next: Option<i64>,
}

const DEFAULT_SUPPRESSIONS_PAGE: u32 = 50;
pub const MAX_SUPPRESSIONS_PAGE: u32 = 500;

/// What recording a run made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecorded {
    pub roots: Vec<Uuid>,
    /// The ids of the suppression rows it wrote, in the order it decided them.
    pub suppressions: Vec<i64>,
}

#[derive(Serialize)]
struct RunDetails<'a> {
    window_start: Option<DateTime<Utc>>,
    window_end: Option<DateTime<Utc>>,
    roots: &'a [Uuid],
    suppressed: usize,
    duplicates: usize,
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
                    let recorded = record_decisions(tx, self, bucket, actor, run).await?;
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
                            roots: &recorded.roots,
                            suppressed: run.suppressed.len(),
                            duplicates: recorded.suppressions.len() - run.suppressed.len(),
                        })?;
                    Ok(Audited::changed(recorded, change))
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

/// A suppression row to write.
struct Decision<'a> {
    reason: SuppressionReason,
    key: &'a str,
    group_value: Option<&'a serde_json::Value>,
    description: &'a str,
    event_time: DateTime<Utc>,
    events: usize,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    cause_root: Option<Uuid>,
}

async fn decide(
    tx: &mut ace_core::db::Tx<'_>,
    run: &HuntRun,
    decision: &Decision<'_>,
) -> Result<i64, ServiceError> {
    let events = i32::try_from(decision.events).unwrap_or(i32::MAX);
    Ok(sqlx::query_scalar!(
        "INSERT INTO hunts.suppressions
             (type, name, uuid, reason, key, group_value, description, event_time, events,
              window_start, window_end, cause_root, search_start, search_end, decided_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
         RETURNING id",
        run.kind,
        run.name,
        run.uuid,
        decision.reason.as_str(),
        decision.key,
        decision.group_value.map(Json) as _,
        decision.description,
        decision.event_time,
        events,
        decision.window_start,
        decision.window_end,
        decision.cause_root,
        run.window_start,
        run.window_end,
        run.at,
    )
    .fetch_one(tx.conn())
    .await?)
}

/// A run's roots and its suppression decisions, in the run's transaction: a row for each group its
/// suppression dropped, pointing at the root the group last alerted with, then each submission in order,
/// dropped with a row when its dedup key made a root less than [`DEDUP_KEY_LIFETIME`] ago, as ace3's
/// collector drops it, and submitted otherwise. Expired dedup keys and suppression rows past
/// [`SUPPRESSION_RETENTION`] go first.
async fn record_decisions(
    tx: &mut ace_core::db::Tx<'_>,
    service: &Service,
    bucket: &Bucket,
    actor: &Actor,
    run: &HuntRun,
) -> Result<RunRecorded, ServiceError> {
    sqlx::query!(
        "DELETE FROM hunts.dedup_keys WHERE created_at <= $1",
        run.at - DEDUP_KEY_LIFETIME,
    )
    .execute(tx.conn())
    .await?;
    sqlx::query!(
        "DELETE FROM hunts.suppressions WHERE decided_at < $1",
        run.at - SUPPRESSION_RETENTION,
    )
    .execute(tx.conn())
    .await?;
    let mut recorded = RunRecorded {
        roots: Vec::with_capacity(run.submissions.len()),
        suppressions: Vec::new(),
    };
    for group in &run.suppressed {
        let cause = sqlx::query_scalar!(
            "SELECT root FROM hunts.alert_keys
             WHERE type = $1 AND name = $2 AND hash = sha256(convert_to($3, 'UTF8'))",
            run.kind,
            run.name,
            group.key,
        )
        .fetch_optional(tx.conn())
        .await?;
        let decision = Decision {
            reason: SuppressionReason::Group,
            key: &group.key,
            group_value: group.group_value.as_ref(),
            description: &group.description,
            event_time: group.event_time,
            events: group.events,
            window_start: group.since,
            window_end: group.until,
            cause_root: cause,
        };
        recorded
            .suppressions
            .push(decide(tx, run, &decision).await?);
    }
    for hit in &run.submissions {
        let seen = match &hit.dedup_key {
            None => None,
            Some(key) => sqlx::query!(
                "SELECT root, created_at FROM hunts.dedup_keys
                 WHERE hash = sha256(convert_to($1, 'UTF8')) AND created_at > $2",
                key,
                run.at - DEDUP_KEY_LIFETIME,
            )
            .fetch_optional(tx.conn())
            .await?
            .map(|r| (key, r.root, r.created_at)),
        };
        let root = match seen {
            Some((key, cause, created_at)) => {
                let decision = Decision {
                    reason: SuppressionReason::Duplicate,
                    key,
                    group_value: hit.group_value.as_ref(),
                    description: &hit.submission.description,
                    event_time: hit.submission.event_time.unwrap_or(run.at),
                    events: hit.events,
                    window_start: created_at,
                    window_end: created_at + DEDUP_KEY_LIFETIME,
                    cause_root: Some(cause),
                };
                recorded
                    .suppressions
                    .push(decide(tx, run, &decision).await?);
                cause
            }
            None => {
                let (submitted, _) = crate::submit::submit_in(
                    tx,
                    service,
                    bucket,
                    actor,
                    &hit.submission,
                    &hit.origin,
                    &[],
                )
                .await?;
                if let Some(key) = &hit.dedup_key {
                    sqlx::query!(
                        "INSERT INTO hunts.dedup_keys (hash, root, created_at)
                         VALUES (sha256(convert_to($1, 'UTF8')), $2, $3)
                         ON CONFLICT (hash) DO UPDATE SET root = $2, created_at = $3",
                        key,
                        submitted.uuid,
                        run.at,
                    )
                    .execute(tx.conn())
                    .await?;
                }
                recorded.roots.push(submitted.uuid);
                submitted.uuid
            }
        };
        // the root the group's alert time now points to: ace3 records a group's alert time for a
        // submission its collector then drops as a duplicate, so that one's is the earlier root
        if let Some(key) = &hit.suppression_key
            && run.state.last_alert_times.contains_key(key)
        {
            sqlx::query!(
                "INSERT INTO hunts.alert_keys (type, name, hash, key, root)
                 VALUES ($1, $2, sha256(convert_to($3, 'UTF8')), $3, $4)
                 ON CONFLICT (type, name, hash) DO UPDATE SET root = $4",
                run.kind,
                run.name,
                key,
                root,
            )
            .execute(tx.conn())
            .await?;
        }
    }
    let kept: Vec<String> = run.state.last_alert_times.keys().cloned().collect();
    sqlx::query!(
        "DELETE FROM hunts.alert_keys WHERE type = $1 AND name = $2 AND NOT (key = ANY($3))",
        run.kind,
        run.name,
        &kept,
    )
    .execute(tx.conn())
    .await?;
    Ok(recorded)
}

impl Service {
    /// A page of a hunt's suppression decisions, newest first, of up to `limit` (50 when None, at most
    /// [`MAX_SUPPRESSIONS_PAGE`]), after the row `after` names. NotFound when no loaded hunt has the uuid.
    pub async fn hunt_suppressions(
        &self,
        actor: &Actor,
        uuid: &str,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<SuppressionPage, ServiceError> {
        let limit = match limit.unwrap_or(DEFAULT_SUPPRESSIONS_PAGE) {
            limit @ 1..=MAX_SUPPRESSIONS_PAGE => i64::from(limit),
            limit => {
                return Err(ServiceError::InvalidRequest(format!(
                    "a page holds 1 to {MAX_SUPPRESSIONS_PAGE}, not {limit}"
                )));
            }
        };
        self.gate
            .read(actor, "hunt_suppressions", &HUNT_READ, &|tx| {
                Box::pin(async move {
                    let known = sqlx::query_scalar!(
                        r#"SELECT EXISTS (SELECT FROM hunts.hunts WHERE uuid = $1) AS "known!""#,
                        uuid,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    if !known {
                        return Err(ServiceError::NotFound(format!("no hunt {uuid}")));
                    }
                    if let Some(after) = after {
                        let known = sqlx::query_scalar!(
                            r#"SELECT EXISTS (SELECT FROM hunts.suppressions
                                              WHERE id = $1 AND uuid = $2) AS "known!""#,
                            after,
                            uuid,
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        if !known {
                            return Err(ServiceError::InvalidRequest(format!(
                                "the cursor {after} names no suppression of this hunt"
                            )));
                        }
                    }
                    let rows = sqlx::query!(
                        r#"SELECT id, type, name, uuid, reason, key, group_value, description,
                                  event_time, events, window_start, window_end, cause_root,
                                  search_start, search_end, decided_at
                           FROM hunts.suppressions
                           WHERE uuid = $1 AND ($3::bigint IS NULL OR id < $3)
                           ORDER BY id DESC
                           LIMIT $2"#,
                        uuid,
                        limit + 1,
                        after,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let mut suppressions = Vec::with_capacity(rows.len());
                    for r in rows {
                        suppressions.push(Suppression {
                            id: r.id,
                            kind: r.r#type,
                            name: r.name,
                            uuid: r.uuid,
                            reason: if r.reason == "group" {
                                SuppressionReason::Group
                            } else {
                                SuppressionReason::Duplicate
                            },
                            key: r.key,
                            group_value: r.group_value,
                            description: r.description,
                            event_time: r.event_time,
                            events: r.events,
                            window_start: r.window_start,
                            window_end: r.window_end,
                            cause_root: r.cause_root,
                            search_start: r.search_start,
                            search_end: r.search_end,
                            decided_at: r.decided_at,
                        });
                    }
                    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                    let more = suppressions.len() > limit;
                    suppressions.truncate(limit);
                    let next = if more {
                        suppressions.last().map(|s| s.id)
                    } else {
                        None
                    };
                    Ok(SuppressionPage { suppressions, next })
                })
            })
            .await
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
