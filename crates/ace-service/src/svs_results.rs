//! A run's result (PLAN.md 7.10 batch 5, part 5b): ace3's `saq/svs/results.py` and `result_state.py`,
//! over `ace_core::svs::results`, which holds what a result decides without the database.
//!
//! The result is one row of `svs.run_results` per signature: what fired during the run, read from the
//! run's attributions that hold and their detections, against the test's decisions on the run's platform
//! and the ignores that apply to it. It's computed when the run ends, and again by the timers whenever it
//! is stale. Everything that changes what a result would be marks the run stale in its own transaction,
//! which bumps the run's generation: an attribution (batch 6), the run ending, and a decision about the
//! test. A computation reads the generation before anything else and clears the stale flag only if the
//! generation is still the one it read, so a change that lands while it computes is never lost.
//!
//! [`Service::compute_svs_result`] and [`Service::recompute_stale_svs_results`] need `svs:run_timers`,
//! which only the scheduler's `svs_run_timers` holds; a person's end of a run computes in the end's own
//! transaction (`compute`).
//!
//! What differs from ace3's:
//! - A signature's name and rule hash come from the built-ins (`ace_core::svs::signatures::BUILTINS`),
//!   the hunts the hunter recorded, and the YARA rules of the ruleset the pools scan with
//!   (`yara.rulesets.signatures`), where ace3 reads its signature inventory from the checkout.
//! - An attribution names a detection, whose row carries the signature (migration 0047), so what fired is
//!   read through the detections.
//! - The hunt alert that may have suppressed a missing hunt is judged by when it became an alert
//!   (`analysis.roots.alerted_at`), where ace3 reads its insert date, and a result names it by its root.
//! - The transaction is READ COMMITTED, where ace3's reads one snapshot. The generation is still read
//!   first and the flag cleared by it, so a change committed after a statement here read its data has
//!   bumped the generation by then and the run stays stale.
//! - A computation that changed a row writes an audit row; the event in the run's log names the actor that
//!   computed it, where ace3's says `svs`.

use std::collections::{BTreeMap, BTreeSet};

use ace_core::svs::results::{
    self, Decisions, FALLBACK_EVENT_TIME_SOURCES, Fired, LastKnown, RECOMPUTE_BATCH, ResultRow,
    ResultStatus,
};
use ace_core::svs::signatures::{KnownSignature, builtin_signatures, describe_signatures};
use ace_core::svs::windows::recorded_hunts;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::SVS_RUN_TIMERS;
use crate::{Actor, Service, ServiceError};

/// What one computation of a run's result did: ace3's `ComputedResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputedResult {
    pub run: Uuid,
    pub rows: Vec<ResultRow>,
    /// The signatures per status now, and before this computation.
    pub counts: BTreeMap<String, i64>,
    pub previous_counts: BTreeMap<String, i64>,
    /// The rows whose status changed, each with the status it had (None for a new row).
    pub changed: Vec<(ResultRow, Option<String>)>,
    /// The computation was current when it finished: nothing marked the run stale meanwhile.
    pub current: bool,
    /// It changed a row, or the counts.
    pub wrote: bool,
    /// How many rows it added, changed or removed.
    pub rows_changed: usize,
    test_guid: Uuid,
    marker: String,
}

/// Which runs' results a change makes stale.
pub(crate) enum StaleRuns<'a> {
    /// The test's runs on one platform: an expectation.
    TestOnPlatform(Uuid, &'a str),
    /// The test's runs: its ignore.
    Test(Uuid),
    /// Every run: a global ignore.
    Every,
}

/// Marks stale, in the caller's transaction, the results of the runs that have one and that `runs` names,
/// in run id order, so two writers lock the rows in the same order: ace3's `mark_runs_stale` with its
/// conditions. A started run has no result yet, but marking it closes the race with its end.
pub(crate) async fn mark_stale_where(
    conn: &mut PgConnection,
    runs: &StaleRuns<'_>,
) -> Result<(), ServiceError> {
    let (test, platform) = match runs {
        StaleRuns::TestOnPlatform(test, platform) => (Some(*test), Some(*platform)),
        StaleRuns::Test(test) => (Some(*test), None),
        StaleRuns::Every => (None, None),
    };
    sqlx::query!(
        "INSERT INTO svs.run_result_state (run_id, generation, stale)
         SELECT id, 1, true FROM svs.runs
         WHERE state IN ('started', 'ended', 'reviewed')
           AND ($1::uuid IS NULL OR test_guid = $1)
           AND ($2::text IS NULL OR platform = $2)
         ORDER BY id
         ON CONFLICT (run_id) DO UPDATE
         SET generation = svs.run_result_state.generation + 1, stale = true",
        test,
        platform,
    )
    .execute(conn)
    .await?;
    Ok(())
}

struct KnownRow {
    id: i64,
    family: Option<String>,
    name: Option<String>,
    status: Option<String>,
    alert_count: i32,
    late_only: bool,
    context_only: bool,
    fallback_time: bool,
    content_hash: Option<String>,
    suppressing_root_id: Option<Uuid>,
    reviewed_status: Option<String>,
}

/// The signatures the run's attributions that hold carry, but those a result never counts: ace3's
/// `fired_signatures`. An attribution is its run's cleanup's when its event time is at or after the run's
/// `cleanup_at`.
async fn fired_signatures(
    conn: &mut PgConnection,
    run: i64,
) -> Result<BTreeMap<String, Fired>, ServiceError> {
    let untracked = results::untracked_signatures();
    let fallback: Vec<String> = FALLBACK_EVENT_TIME_SOURCES
        .iter()
        .map(|source| (*source).to_owned())
        .collect();
    let groups = sqlx::query!(
        r#"SELECT d.signature_uuid AS "signature_uuid!",
                  (r.cleanup_at IS NOT NULL AND a.event_time IS NOT NULL
                   AND a.event_time >= r.cleanup_at) AS "cleanup!",
                  max(d.signature_family) AS family,
                  count(DISTINCT a.root_id) AS "alerts!",
                  bool_and(a.late) AS "late_only!",
                  bool_and(a.confidence = 'context') AS "context_only!",
                  COALESCE(bool_or(a.event_time_source = ANY ($3)), false) AS "fallback_time!"
           FROM svs.attributions a
           JOIN svs.runs r ON r.id = a.run_id
           JOIN analysis.detections d ON d.id = a.detection_id
           WHERE a.run_id = $1 AND a.removed_at IS NULL
             AND d.signature_uuid IS NOT NULL AND d.signature_uuid <> ''
             AND d.signature_uuid <> ALL ($2)
           GROUP BY 1, 2"#,
        run,
        &untracked,
        &fallback,
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .map(|row| Fired {
        signature_uuid: row.signature_uuid,
        family: row.family,
        alert_count: row.alerts,
        late_only: row.late_only,
        context_only: row.context_only,
        cleanup: row.cleanup,
        fallback_time: row.fallback_time,
    })
    .collect();
    Ok(results::merge_fired(groups))
}

/// The test's expectations on the platform, and the ignores that apply to its runs on every platform:
/// ace3's `test_decisions`.
async fn test_decisions(
    conn: &mut PgConnection,
    test: Uuid,
    platform: &str,
) -> Result<Decisions, ServiceError> {
    let mut decisions = Decisions::default();
    for row in sqlx::query!(
        "SELECT signature_uuid, state, signature_family, signature_name
         FROM svs.expectations WHERE test_guid = $1 AND platform = $2",
        test,
        platform,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        let known = LastKnown {
            family: row.signature_family,
            name: row.signature_name,
        };
        if row.state == "expected" {
            decisions.expected.insert(row.signature_uuid, known);
        } else {
            decisions.rejected.insert(row.signature_uuid, known);
        }
    }
    decisions.ignored = sqlx::query_scalar!(
        "SELECT signature_uuid FROM svs.ignores WHERE test_guid IS NULL OR test_guid = $1",
        test,
    )
    .fetch_all(conn)
    .await?
    .into_iter()
    .collect();
    Ok(decisions)
}

/// The YARA rules of the ruleset the pools scan with, as SVS knows them; none when no ruleset was built,
/// or the latest was built before its signatures were recorded.
pub(crate) async fn yara_signatures(
    conn: &mut PgConnection,
) -> Result<Vec<KnownSignature>, ServiceError> {
    let ruleset = ace_core::rulesets::current_with(&mut *conn).await?;
    Ok(ruleset
        .and_then(|row| row.signatures)
        .unwrap_or_default()
        .into_iter()
        .map(|rule| KnownSignature {
            uuid: rule.uuid,
            name: rule.name,
            content_hash: rule.content_hash,
            tags: rule.tags,
            counts: rule.counts,
        })
        .collect())
}

/// What a computation's audit row keeps: the signatures per status.
#[derive(Serialize)]
struct ResultRecord<'a> {
    result: &'a BTreeMap<String, i64>,
}

impl Recorded for ResultRecord<'_> {}

#[derive(Serialize)]
struct ComputedRecord {
    call: &'static str,
    rows_changed: usize,
}

impl Recorded for ComputedRecord {}

/// Computes the run's live result and writes it, in the caller's transaction: ace3's `compute_result`.
/// None for a run that isn't there.
pub(crate) async fn compute(
    conn: &mut PgConnection,
    run: i64,
    actor: &Actor,
    now: DateTime<Utc>,
) -> Result<Option<ComputedResult>, ServiceError> {
    // the generation is read first: a change committed after this bumps it past what was read, so the
    // run stays stale
    let generation = sqlx::query_scalar!(
        "SELECT generation FROM svs.run_result_state WHERE run_id = $1",
        run,
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(the_run) = sqlx::query!(
        "SELECT uuid, test_guid, platform, marker, started_at, ended_at FROM svs.runs WHERE id = $1",
        run,
    )
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };

    let mut known: BTreeMap<String, KnownRow> = sqlx::query!(
        "SELECT id, signature_uuid, signature_family, signature_name, status, alert_count, late_only,
                context_only, fallback_time, content_hash, suppressing_root_id, reviewed_status
         FROM svs.run_results WHERE run_id = $1",
        run,
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| {
        (
            row.signature_uuid,
            KnownRow {
                id: row.id,
                family: row.signature_family,
                name: row.signature_name,
                status: row.status,
                alert_count: row.alert_count,
                late_only: row.late_only,
                context_only: row.context_only,
                fallback_time: row.fallback_time,
                content_hash: row.content_hash,
                suppressing_root_id: row.suppressing_root_id,
                reviewed_status: row.reviewed_status,
            },
        )
    })
    .collect();

    let fired = fired_signatures(conn, run).await?;
    let decisions = test_decisions(conn, the_run.test_guid, &the_run.platform).await?;
    let missing = results::missing(&fired, &decisions);

    let mut suppressed = BTreeSet::new();
    let mut suppressing = BTreeMap::new();
    let info = if fired.is_empty() && missing.is_empty() {
        BTreeMap::new()
    } else {
        let hunts = recorded_hunts(conn).await?;
        let yara = yara_signatures(conn).await?;
        if !missing.is_empty() {
            suppressed = sqlx::query_scalar!(
                "SELECT hunt_uuid FROM svs.suppressed_matches WHERE run_id = $1",
                run,
            )
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .collect();
        }
        for uuid in &missing {
            if suppressed.contains(uuid) {
                continue;
            }
            // a hunt without group_by suppresses as a whole, by not running, so there's no match to
            // record: its latest alert inside its suppression period before the run's window closed, on
            // an alert not attributed to the run. A hunt checks its suppression each time it runs, and
            // the run that would have caught the test comes up to its latency after the start, so the
            // period reaches back from the run's end.
            let Some(hunt) = hunts.get(uuid).filter(|hunt| !hunt.per_group) else {
                continue;
            };
            let (Some(suppression), Some(started_at)) = (hunt.suppression, the_run.started_at)
            else {
                continue;
            };
            let alert = sqlx::query_scalar!(
                "SELECT r.id FROM analysis.roots r
                 WHERE r.alerted_at >= $2 AND r.alerted_at < $3
                   AND EXISTS (SELECT FROM analysis.detections d
                               WHERE d.root_id = r.id AND d.signature_uuid = $1)
                   AND NOT EXISTS (SELECT FROM svs.attributions a
                                   WHERE a.run_id = $4 AND a.root_id = r.id)
                 ORDER BY r.alerted_at DESC, r.id DESC
                 LIMIT 1",
                uuid,
                started_at - suppression,
                the_run.ended_at.unwrap_or(now),
                run,
            )
            .fetch_optional(&mut *conn)
            .await?;
            if let Some(alert) = alert {
                suppressing.insert(uuid.clone(), alert);
            }
        }
        describe_signatures(
            fired.keys().chain(missing.iter()).map(String::as_str),
            &builtin_signatures(),
            &hunts,
            &yara,
        )
    };

    let last_known: BTreeMap<String, LastKnown> = known
        .iter()
        .map(|(uuid, row)| {
            (
                uuid.clone(),
                LastKnown {
                    family: row.family.clone(),
                    name: row.name.clone(),
                },
            )
        })
        .collect();
    let rows = results::rows(
        &fired,
        &decisions,
        &info,
        &last_known,
        &suppressed,
        &suppressing,
    );

    let previous_counts = results::counts(
        known
            .values()
            .filter_map(|row| row.status.as_deref())
            .collect::<Vec<_>>(),
    );
    let mut changed = Vec::new();
    let mut rows_changed = 0usize;
    for row in &rows {
        let alert_count = i32::try_from(row.alert_count).unwrap_or(i32::MAX);
        match known.remove(&row.signature_uuid) {
            None => {
                sqlx::query!(
                    "INSERT INTO svs.run_results
                         (run_id, signature_uuid, signature_family, signature_name, status, alert_count,
                          late_only, context_only, fallback_time, content_hash, suppressing_root_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                    run,
                    row.signature_uuid,
                    row.family,
                    row.name,
                    row.status.as_str(),
                    alert_count,
                    row.late_only,
                    row.context_only,
                    row.fallback_time,
                    row.content_hash,
                    row.suppressing_alert,
                )
                .execute(&mut *conn)
                .await?;
                rows_changed += 1;
                changed.push((row.clone(), None));
            }
            Some(existing) => {
                let same = existing.status.as_deref() == Some(row.status.as_str())
                    && existing.family == row.family
                    && existing.name == row.name
                    && existing.alert_count == alert_count
                    && existing.late_only == row.late_only
                    && existing.context_only == row.context_only
                    && existing.fallback_time == row.fallback_time
                    && existing.content_hash == row.content_hash
                    && existing.suppressing_root_id == row.suppressing_alert;
                if !same {
                    sqlx::query!(
                        "UPDATE svs.run_results
                         SET signature_family = $2, signature_name = $3, status = $4, alert_count = $5,
                             late_only = $6, context_only = $7, fallback_time = $8, content_hash = $9,
                             suppressing_root_id = $10
                         WHERE id = $1",
                        existing.id,
                        row.family,
                        row.name,
                        row.status.as_str(),
                        alert_count,
                        row.late_only,
                        row.context_only,
                        row.fallback_time,
                        row.content_hash,
                        row.suppressing_alert,
                    )
                    .execute(&mut *conn)
                    .await?;
                    rows_changed += 1;
                }
                if existing.status.as_deref() != Some(row.status.as_str()) {
                    changed.push((row.clone(), existing.status));
                }
            }
        }
    }
    // what left the live result: kept, without a live status, only for the reviewed result
    for existing in known.values() {
        if existing.reviewed_status.is_none() {
            sqlx::query!("DELETE FROM svs.run_results WHERE id = $1", existing.id)
                .execute(&mut *conn)
                .await?;
            rows_changed += 1;
        } else if existing.status.is_some() {
            sqlx::query!(
                "UPDATE svs.run_results SET status = NULL WHERE id = $1",
                existing.id
            )
            .execute(&mut *conn)
            .await?;
            rows_changed += 1;
        }
    }

    let counts = results::counts(rows.iter().map(|row| row.status.as_str()));
    if counts != previous_counts {
        crate::svs_runs::add_event(
            conn,
            run,
            "result_computed",
            actor,
            None,
            None,
            Some(json!({"counts": counts, "previous": previous_counts})),
            now,
        )
        .await?;
    }

    let current = match generation {
        // nothing ever marked it; a writer that marks it meanwhile keeps its row stale
        None => {
            sqlx::query!(
                "INSERT INTO svs.run_result_state
                     (run_id, generation, stale, computed_generation, computed_at)
                 VALUES ($1, 0, false, 0, $2)
                 ON CONFLICT (run_id) DO NOTHING",
                run,
                now,
            )
            .execute(&mut *conn)
            .await?;
            !sqlx::query_scalar!(
                "SELECT stale FROM svs.run_result_state WHERE run_id = $1",
                run,
            )
            .fetch_one(&mut *conn)
            .await?
        }
        Some(generation) => {
            sqlx::query!(
                "UPDATE svs.run_result_state
                 SET stale = false, computed_generation = $2, computed_at = $3
                 WHERE run_id = $1 AND generation = $2",
                run,
                generation,
                now,
            )
            .execute(&mut *conn)
            .await?
            .rows_affected()
                == 1
        }
    };

    Ok(Some(ComputedResult {
        run: the_run.uuid,
        wrote: rows_changed > 0 || counts != previous_counts,
        rows_changed,
        rows,
        counts,
        previous_counts,
        changed,
        current,
        test_guid: the_run.test_guid,
        marker: the_run.marker,
    }))
}

/// The audit row of a computation that changed something.
pub(crate) fn computed_change(result: &ComputedResult) -> Result<Option<Change>, ServiceError> {
    if !result.wrote {
        return Ok(None);
    }
    let rows_changed = result.rows_changed;
    Ok(Some(
        Change::updated(
            Target::svs_run(result.run),
            &ResultRecord {
                result: &result.previous_counts,
            },
            &ResultRecord {
                result: &result.counts,
            },
        )?
        .details(&ComputedRecord {
            call: "result",
            rows_changed,
        })?,
    ))
}

/// Logs a computed result once its transaction has committed: ace3's `_log`.
pub(crate) fn log_computed(result: &ComputedResult) {
    let summary = if result.counts.is_empty() {
        "nothing".to_owned()
    } else {
        result
            .counts
            .iter()
            .map(|(status, count)| format!("{count} {status}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    tracing::info!(
        svs_run = %result.run,
        svs_test = %result.test_guid,
        svs_marker = result.marker,
        counts = %json!(result.counts),
        "svs run result computed: {summary}"
    );
    for row in &result.rows {
        tracing::debug!(
            svs_run = %result.run,
            svs_test = %result.test_guid,
            svs_marker = result.marker,
            signature_uuid = row.signature_uuid,
            signature_family = row.family,
            status = row.status.as_str(),
            alert_count = row.alert_count,
            "svs run result signature"
        );
    }
    for (row, previous) in &result.changed {
        let was_missing = previous
            .as_deref()
            .and_then(ResultStatus::parse)
            .is_some_and(ResultStatus::is_missing);
        if row.status.is_missing() && !was_missing {
            let possibly_suppressed = row.status == ResultStatus::PossiblySuppressed;
            tracing::info!(
                svs_run = %result.run,
                svs_test = %result.test_guid,
                svs_marker = result.marker,
                signature_uuid = row.signature_uuid,
                signature_family = row.family,
                possibly_suppressed,
                suppressing_alert_uuid = row.suppressing_alert.map(|alert| alert.to_string()),
                "svs run is missing expected signature {} ({}){}",
                row.signature_uuid,
                row.name.as_deref().unwrap_or("unknown"),
                if possibly_suppressed {
                    ", possibly suppressed"
                } else {
                    ""
                }
            );
        }
    }
}

impl Service {
    /// Computes a run's live result and writes it, in a transaction of its own: ace3's `compute_result`.
    /// It needs `svs:run_timers`. A run that isn't there is `NotFound`. The result says whether it was
    /// current when it finished; one that wasn't stays stale, and the timers compute it again.
    pub async fn compute_svs_result(
        &self,
        actor: &Actor,
        run: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ComputedResult, ServiceError> {
        let result = self
            .gate
            .write(actor, "compute_svs_result", &SVS_RUN_TIMERS, &|tx| {
                Box::pin(async move {
                    let id = sqlx::query_scalar!("SELECT id FROM svs.runs WHERE uuid = $1", run)
                        .fetch_optional(tx.conn())
                        .await?
                        .ok_or_else(|| ServiceError::NotFound(format!("run {run} not found")))?;
                    let result = compute(tx.conn(), id, actor, now)
                        .await?
                        .ok_or_else(|| ServiceError::NotFound(format!("run {run} not found")))?;
                    Ok(match computed_change(&result)? {
                        Some(change) => Audited::changed(result, change),
                        None => Audited::unchanged(result),
                    })
                })
            })
            .await?;
        log_computed(&result);
        Ok(result)
    }

    /// Recomputes the stale results of ended and reviewed runs, at most `limit` of them
    /// (`RECOMPUTE_BATCH` when None), each in its own transaction; a run that fails is logged and stays
    /// stale. How many were computed. ace3's `recompute_stale_results`. It needs `svs:run_timers`.
    pub async fn recompute_stale_svs_results(
        &self,
        actor: &Actor,
        now: DateTime<Utc>,
        limit: Option<i64>,
    ) -> Result<u64, ServiceError> {
        let limit = limit.unwrap_or(RECOMPUTE_BATCH).clamp(1, RECOMPUTE_BATCH);
        let stale = self
            .gate
            .read(
                actor,
                "recompute_stale_svs_results",
                &SVS_RUN_TIMERS,
                &|tx| {
                    Box::pin(async move {
                        Ok(sqlx::query_scalar!(
                            "SELECT r.uuid FROM svs.run_result_state s
                             JOIN svs.runs r ON r.id = s.run_id
                             WHERE s.stale AND r.state IN ('ended', 'reviewed')
                             ORDER BY s.run_id LIMIT $1",
                            limit,
                        )
                        .fetch_all(tx.conn())
                        .await?)
                    })
                },
            )
            .await?;
        let mut computed = 0;
        for run in stale {
            match self.compute_svs_result(actor, run, now).await {
                Ok(_) => computed += 1,
                Err(error) => {
                    tracing::error!(svs_run = %run, "unable to compute the result of an svs run: {error}");
                }
            }
        }
        Ok(computed)
    }
}
