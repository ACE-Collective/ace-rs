//! What alert automation's rules did (PLAN.md 7.22), for `ace alert-automation list` and `report`: ace3's
//! `saq/alert_automation/runs.py`'s `list_runs` and `dry_run_report`, which its CLI prints.
//!
//! Both read `analysis.alert_automation_runs` under `alert_automation:run`, the permission of the
//! scheduler's component `scheduler:alert_automation` (migration 0092), which the command acts as, as
//! `ace svs` acts as the scheduler's components: ace3's commands read its database with no check.
//!
//! **The report** compares a rule's dry runs with what happened to each alert since, as ace3's does: the
//! disposition the run decided (its first done action that recorded one) against the alert's now. Each
//! run is counted once, in the first of: no disposition decided, alert deleted, still open, dispositioned
//! by ACE, dispositioned the same way, dispositioned differently. "By ACE" is a disposition one of ACE's
//! components made (`dispositioned_by` of kind `internal`), where ace3 compares with its automation user.
//! It reads the runs a batch of `REPORT_BATCH` at a time, each batch its own snapshot, as ace3's does, so
//! a rule's whole history is read in bounded pieces.

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::alert_automation::ActionRecord;
use crate::permission::ALERT_AUTOMATION_RUN;
use crate::{Actor, Service, ServiceError};

/// The most runs one list gives.
pub const MAX_LISTED_RUNS: u32 = 10_000;

/// How many dry runs the report reads at once.
const REPORT_BATCH: i64 = 1000;

/// Which runs a list gives: ace3's `--rule`, `--mode`, `--since` and `--limit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunsQuery {
    pub rule: Option<String>,
    /// `dry_run` or `enforce`.
    pub mode: Option<ace_sdk::alert_automation::Mode>,
    /// Only runs recorded at or after this.
    pub since: Option<DateTime<Utc>>,
    /// 1 to `MAX_LISTED_RUNS`; ace3's default is 100.
    pub limit: u32,
}

impl Default for RunsQuery {
    fn default() -> Self {
        RunsQuery {
            rule: None,
            mode: None,
            since: None,
            limit: 100,
        }
    }
}

/// One rule's run on one alert, as its row holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct AutomationRun {
    pub id: i64,
    pub rule: String,
    pub alert: Uuid,
    /// `dry_run` or `enforce`.
    pub mode: String,
    /// `pending`, `done` or `failed`.
    pub status: String,
    pub evidence: Value,
    pub actions: Vec<ActionRecord>,
    pub created_at: DateTime<Utc>,
}

/// How a rule's dry-run decisions compare with what happened to each alert since: ace3's `DryRunReport`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DryRunReport {
    pub rule: String,
    pub runs: u64,
    /// Analysts gave the alert the disposition the dry run decided on.
    pub same: u64,
    /// Analysts gave it another: (alert, decided, the alert's).
    pub different: Vec<(Uuid, String, String)>,
    pub still_open: u64,
    /// One of ACE's components dispositioned it: an enforce run of a rule, SVS.
    pub automated: u64,
    /// The alert is gone.
    pub missing: u64,
    /// The dry run recorded no disposition: the rule has no disposition action, or it didn't get there.
    pub undecided: u64,
}

struct RunRow {
    id: i64,
    rule_name: String,
    root_id: Uuid,
    mode: String,
    status: String,
    evidence: Value,
    actions: Value,
    created_at: DateTime<Utc>,
}

impl RunRow {
    fn into_run(self) -> Result<AutomationRun, ServiceError> {
        let actions = serde_json::from_value(self.actions).map_err(|e| {
            ServiceError::from(ace_core::DbError::Decode(format!(
                "alert automation run {}'s actions: {e}",
                self.id
            )))
        })?;
        Ok(AutomationRun {
            id: self.id,
            rule: self.rule_name,
            alert: self.root_id,
            mode: self.mode,
            status: self.status,
            evidence: self.evidence,
            actions,
            created_at: self.created_at,
        })
    }
}

/// The disposition a run decided: its first done action that recorded one, ace3's `_decided_disposition`.
fn decided(run: &AutomationRun) -> Option<&str> {
    run.actions
        .iter()
        .filter(|action| action.status == crate::alert_automation::ActionStatus::Done)
        .find_map(|action| action.detail.disposition.as_deref())
}

impl Service {
    /// The most recent runs, newest first, ace3's `list_runs`. It needs `alert_automation:run`.
    pub async fn alert_automation_runs(
        &self,
        actor: &Actor,
        query: &RunsQuery,
    ) -> Result<Vec<AutomationRun>, ServiceError> {
        if !(1..=MAX_LISTED_RUNS).contains(&query.limit) {
            return Err(ServiceError::InvalidRequest(format!(
                "a list holds 1 to {MAX_LISTED_RUNS} runs, not {}",
                query.limit
            )));
        }
        let mode = query.mode.map(|mode| mode.as_str());
        self.gate
            .read(
                actor,
                "alert_automation_runs",
                &ALERT_AUTOMATION_RUN,
                &|tx| {
                    Box::pin(async move {
                        sqlx::query_as!(
                        RunRow,
                        "SELECT id, rule_name, root_id, mode, status, evidence, actions, created_at
                         FROM analysis.alert_automation_runs
                         WHERE ($1::text IS NULL OR rule_name = $1)
                           AND ($2::text IS NULL OR mode = $2)
                           AND ($3::timestamptz IS NULL OR created_at >= $3)
                         ORDER BY id DESC LIMIT $4",
                        query.rule.as_deref(),
                        mode,
                        query.since,
                        i64::from(query.limit),
                    )
                        .fetch_all(tx.conn())
                        .await?
                        .into_iter()
                        .map(RunRow::into_run)
                        .collect()
                    })
                },
            )
            .await
    }

    /// How a rule's dry runs since `since` compare with what happened to each alert, ace3's
    /// `dry_run_report` (the module's docs). It needs `alert_automation:run`.
    pub async fn alert_automation_report(
        &self,
        actor: &Actor,
        rule: &str,
        since: Option<DateTime<Utc>>,
    ) -> Result<DryRunReport, ServiceError> {
        let mut report = DryRunReport {
            rule: rule.to_owned(),
            ..DryRunReport::default()
        };
        let mut after = 0_i64;
        loop {
            let rows = self
                .gate
                .read(
                    actor,
                    "alert_automation_report",
                    &ALERT_AUTOMATION_RUN,
                    &|tx| {
                        Box::pin(async move {
                            let rows = sqlx::query!(
                            r#"SELECT u.id, u.rule_name, u.root_id, u.mode, u.status, u.evidence,
                                      u.actions, u.created_at, r.id IS NOT NULL AS "alert_exists!",
                                      r.disposition AS "disposition?",
                                      (r.dispositioned_by ->> 'kind') = 'internal' AS "by_ace?"
                               FROM analysis.alert_automation_runs u
                               LEFT JOIN analysis.roots r ON r.id = u.root_id
                               WHERE u.rule_name = $1 AND u.mode = 'dry_run' AND u.id > $2
                                 AND ($3::timestamptz IS NULL OR u.created_at >= $3)
                               ORDER BY u.id LIMIT $4"#,
                            rule,
                            after,
                            since,
                            REPORT_BATCH,
                        )
                        .fetch_all(tx.conn())
                        .await?;
                            rows.into_iter()
                                .map(|row| {
                                    let run = RunRow {
                                        id: row.id,
                                        rule_name: row.rule_name,
                                        root_id: row.root_id,
                                        mode: row.mode,
                                        status: row.status,
                                        evidence: row.evidence,
                                        actions: row.actions,
                                        created_at: row.created_at,
                                    }
                                    .into_run()?;
                                    let alert = row
                                        .alert_exists
                                        .then(|| (row.disposition, row.by_ace.unwrap_or(false)));
                                    Ok((run, alert))
                                })
                                .collect::<Result<Vec<_>, ServiceError>>()
                        })
                    },
                )
                .await?;
            let full = i64::try_from(rows.len()).unwrap_or(i64::MAX) == REPORT_BATCH;
            for (run, alert) in rows {
                after = run.id;
                report.runs += 1;
                let Some(decided) = decided(&run) else {
                    report.undecided += 1;
                    continue;
                };
                match alert {
                    None => report.missing += 1,
                    Some((None, _)) => report.still_open += 1,
                    Some((Some(disposition), _)) if disposition == crate::observables::OPEN => {
                        report.still_open += 1;
                    }
                    Some((Some(_), true)) => report.automated += 1,
                    Some((Some(disposition), false)) if disposition == decided => report.same += 1,
                    Some((Some(disposition), false)) => {
                        report
                            .different
                            .push((run.alert, decided.to_owned(), disposition));
                    }
                }
            }
            if !full {
                return Ok(report);
            }
        }
    }
}
