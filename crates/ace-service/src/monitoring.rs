//! Monitoring (PLAN.md 7.12): ace3's `monitoring` service, whose checks the scheduler in `ace serve`
//! runs (`ace_core::monitoring` lists each of ace3's monitors with what it is here), and what the
//! administration area reads of them.
//!
//! **The checks.** `report_monitor` runs one check as the component the scheduler gave it, which
//! migration 0060 grants `monitoring:report` and nothing else: it reads what the check reports on,
//! writes each record to the log, and replaces the check's records in `monitoring.records`. A refusal is
//! `ServiceError::PermissionDenied`, before anything is read. It writes no audit row, and why: the
//! records are measurements of state other writes made, each of which has its own record where it
//! happened. Nothing reads them to decide anything, a run replaces them whole, and ace3 audits its
//! monitors nowhere. What each run emitted is counted in its row of `scheduler.runs`.
//!
//! **The reads.** `monitoring_state` is what the page shows: every scheduled task's state, the runs of
//! all of them or of one, newest first, and the records the checks last emitted. It needs
//! `monitoring:read`. ace3 shows none of this: its records and its cron runs' outcomes go to fluent-bit.

use ace_core::bucket::{Bucket, Retention};
use ace_core::monitoring::{self, Found};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::permission::{MONITORING_READ, MONITORING_REPORT};
use crate::{Actor, Service, ServiceError};

/// The most monitor records one read returns: what every check emits in one run, with room.
pub const MAX_MONITOR_RECORDS_READ: i64 = 5000;

/// A monitoring check: one of ace3's monitors, or what stands in for it (`ace_core::monitoring`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorCheck {
    /// ace3's `distributed_workload`.
    Workload,
    /// ace3's `distributed_delayed_analysis`.
    DelayedAnalysis,
    /// ace3's `distributed_locks`.
    Leases,
    /// What stands in for ace3's `node_status`.
    Queue,
    /// ace3's `cas_pools`.
    BucketPools,
    /// ace3's cron runs' outcomes.
    Scheduler,
    /// ace3's hourly `ace cas node-stats`.
    NodeCache,
}

impl MonitorCheck {
    pub const ALL: [MonitorCheck; 7] = [
        MonitorCheck::Workload,
        MonitorCheck::DelayedAnalysis,
        MonitorCheck::Leases,
        MonitorCheck::Queue,
        MonitorCheck::BucketPools,
        MonitorCheck::Scheduler,
        MonitorCheck::NodeCache,
    ];

    /// The scheduled task that runs it, which is the name its records are kept under.
    pub fn task(self) -> &'static str {
        match self {
            MonitorCheck::Workload => "monitor_workload",
            MonitorCheck::DelayedAnalysis => "monitor_delayed_analysis",
            MonitorCheck::Leases => "monitor_leases",
            MonitorCheck::Queue => "monitor_queue",
            MonitorCheck::BucketPools => "monitor_bucket_pools",
            MonitorCheck::Scheduler => "monitor_scheduler",
            MonitorCheck::NodeCache => "bucket_node_stats",
        }
    }
}

/// What a check's run emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct MonitorReport {
    /// How many records it emitted.
    pub records: usize,
    /// How many more it would have emitted without `ace_core::monitoring::MAX_RECORDS`.
    pub left_out: i64,
}

/// A record a check last emitted.
#[derive(Debug, Clone, PartialEq)]
pub struct MonitorRecord {
    pub task: String,
    /// ace3's monitor path.
    pub path: String,
    pub identifier: Option<String>,
    pub value: Value,
    pub emitted_at: DateTime<Utc>,
}

/// A scheduled task's state.
pub type ScheduledTask = ace_core::monitoring::TaskState;
/// A run of a scheduled task.
pub type ScheduledRun = ace_core::scheduler::Run;

/// What the monitoring page shows.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct MonitoringState {
    /// Every scheduled task, by name.
    pub tasks: Vec<ScheduledTask>,
    /// The runs asked for, newest first.
    pub runs: Vec<ScheduledRun>,
    /// The records each check last emitted, by check.
    pub records: Vec<MonitorRecord>,
}

impl Service {
    /// Runs one monitoring check: reads what it reports on, writes each record to the log and replaces
    /// the check's records. `node` names this process, for the check that reports on it. It needs
    /// `monitoring:report`.
    pub async fn report_monitor(
        &self,
        actor: &Actor,
        check: MonitorCheck,
        bucket: &Bucket,
        node: &str,
    ) -> Result<MonitorReport, ServiceError> {
        if !self.gate.allowed(actor, &MONITORING_REPORT).await? {
            tracing::warn!(%actor, permission = %MONITORING_REPORT, action = "report_monitor", "permission denied");
            return Err(ServiceError::PermissionDenied {
                actor: actor.to_string(),
                permission: MONITORING_REPORT.clone(),
            });
        }
        let db = self.gate.db();
        let found: Found = match check {
            MonitorCheck::Workload => monitoring::workload(db).await?,
            MonitorCheck::DelayedAnalysis => monitoring::delayed_analysis(db).await?,
            MonitorCheck::Leases => monitoring::leases(db).await?,
            MonitorCheck::Queue => monitoring::queue(db).await?,
            MonitorCheck::BucketPools => {
                let pools: Vec<(String, Retention)> = bucket
                    .pools()
                    .map(|(name, retention)| (name.to_owned(), retention))
                    .collect();
                monitoring::bucket_pools(db, &pools).await?
            }
            MonitorCheck::Scheduler => monitoring::scheduled_tasks(db).await?,
            MonitorCheck::NodeCache => {
                // the walk reads a directory of up to the cache's cap, so it's off the runtime
                let cache = bucket.store().cache().clone();
                let node = node.to_owned();
                let io = |error: std::io::Error| {
                    ServiceError::Bucket(ace_core::bucket::BucketError::Store(error.into()))
                };
                tokio::task::spawn_blocking(move || monitoring::node_cache(&cache, &node))
                    .await
                    .map_err(|e| {
                        io(std::io::Error::other(format!(
                            "the cache walk stopped: {e}"
                        )))
                    })?
                    .map_err(io)?
            }
        };
        monitoring::emit(check.task(), &found.records);
        if found.left_out > 0 {
            tracing::warn!(
                task = check.task(),
                left_out = found.left_out,
                "a monitoring check found more than it emits records for"
            );
        }
        monitoring::replace(db, check.task(), &found.records).await?;
        Ok(MonitorReport {
            records: found.records.len(),
            left_out: found.left_out,
        })
    }

    /// The scheduled tasks' state, their runs (`task`'s, or every task's), newest first and at most
    /// `runs` of them, and the records the checks last emitted. It needs `monitoring:read`.
    pub async fn monitoring_state(
        &self,
        actor: &Actor,
        task: Option<&str>,
        runs: i64,
    ) -> Result<MonitoringState, ServiceError> {
        self.gate
            .read(actor, "monitoring_state", &MONITORING_READ, &|tx| {
                Box::pin(async move {
                    let tasks = ace_core::monitoring::task_states_with(tx.conn()).await?;
                    let runs = ace_core::scheduler::recent_runs(tx.conn(), task, runs).await?;
                    let records = ace_core::monitoring::stored(tx.conn(), MAX_MONITOR_RECORDS_READ)
                        .await?
                        .into_iter()
                        .map(|record| MonitorRecord {
                            task: record.task,
                            path: record.path,
                            identifier: record.identifier,
                            value: record.value,
                            emitted_at: record.emitted_at,
                        })
                        .collect();
                    Ok(MonitoringState {
                        tasks,
                        runs,
                        records,
                    })
                })
            })
            .await
    }
}
