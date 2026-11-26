//! The analysis still to run on an alert (PLAN.md 7.19): its tasks that haven't ended, so the alert
//! page can say which modules are queued, waiting or running and for how long, where "running" alone
//! can't tell an alert whose first task no pool claims from one that's nearly done; and how long its
//! analysis took, which only the per-root metrics event's log line said before.

use serde::Serialize;
use uuid::Uuid;

use crate::alerts::alert_in;
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most tasks `alert_work` lists; the counts cover all of them.
pub const MAX_WORK_ROWS: i64 = 25;

/// How many of the modules that ran longest `alert_work` names.
pub const MAX_SLOWEST: i64 = 5;

/// An alert's unfinished tasks.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AlertWork {
    pub queued: i64,
    pub delayed: i64,
    pub running: i64,
    /// Its tasks that failed, which won't run again.
    pub failed: i64,
    /// The oldest unfinished tasks, running ones first, at most `MAX_WORK_ROWS`.
    pub tasks: Vec<WorkTask>,
    /// While a pass runs, how long since it began, in seconds.
    pub running_for_seconds: Option<i64>,
    /// Once the alert's pass has completed, how long that pass took, in seconds. None for a pass that
    /// began before ace-rs recorded when passes begin.
    pub last_pass_seconds: Option<i64>,
    /// How long from its submission to its first pass's end, in seconds, once that pass has ended.
    pub first_pass_seconds: Option<i64>,
    /// How long after the pass began a worker first claimed one of its tasks, in seconds; None while
    /// none has been. The pass's wall-clock time includes this wait, which a pool that leases
    /// nothing makes long. It is the earliest claim the tasks hold, and a task keeps only its latest
    /// (`claimed_at`), so when the first task to run was claimed again later and nothing else was
    /// claimed before that, the wait reads longer than it was.
    pub first_claim_seconds: Option<i64>,
    /// How many passes have completed.
    pub completed_passes: i32,
    /// The modules that ran longest in the alert's current or last pass, at most `MAX_SLOWEST`, by
    /// their tasks' run time summed: a task's `run_seconds` holds only its current pass's runs.
    pub slowest: Vec<ModuleTime>,
}

/// How long a module's tasks on the alert ran, in all.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModuleTime {
    pub module: String,
    pub seconds: f64,
    /// How many runs that is: a task that was delayed and ran again counts each run.
    pub runs: i64,
}

impl AlertWork {
    /// How many tasks haven't ended.
    pub fn unfinished(&self) -> i64 {
        self.queued + self.delayed + self.running
    }
}

/// A task that hasn't ended.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WorkTask {
    pub id: i64,
    pub module: String,
    /// The observable's type and value.
    pub kind: String,
    pub value: String,
    /// `queued`, `delayed` or `running`.
    pub state: String,
    /// How long it has been in its state, in seconds: since its claim for a running task, since it
    /// last changed for the others. From the database's clock.
    pub for_seconds: i64,
    /// For a delayed task, how long until it runs again, in seconds; 0 when it's due.
    pub runs_in_seconds: Option<i64>,
    /// For a running task, the worker holding its lease.
    pub lease_owner: Option<String>,
    pub attempts: i32,
}

impl Service {
    /// The alert's tasks that haven't ended, counted by state, with the oldest of them, and its failed
    /// tasks' count, under `alert:read`. An alert that isn't there is `NotFound`.
    pub async fn alert_work(
        &self,
        actor: &crate::Actor,
        id: Uuid,
    ) -> Result<AlertWork, ServiceError> {
        self.gate
            .read(actor, "alert_work", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    alert_in(tx, id, false).await?;
                    let times = sqlx::query!(
                        r#"SELECT r.completed_pass,
                                  CASE WHEN r.pass > r.completed_pass THEN
                                      floor(extract(epoch FROM now() - r.pass_started_at))::bigint
                                  END AS running_for,
                                  CASE WHEN r.pass = r.completed_pass THEN
                                      (SELECT floor(extract(epoch FROM c.completed_at
                                                          - r.pass_started_at))::bigint
                                       FROM queue.root_completions c
                                       WHERE c.root_id = r.id AND c.pass = r.completed_pass)
                                  END AS last_pass,
                                  (SELECT floor(extract(epoch FROM c.completed_at - r.created_at))::bigint
                                   FROM queue.root_completions c
                                   WHERE c.root_id = r.id AND c.pass = 1) AS first_pass,
                                  (SELECT floor(extract(epoch FROM min(t.claimed_at)
                                                      - r.pass_started_at))::bigint
                                   FROM queue.tasks t
                                   WHERE t.root_id = r.id AND t.claimed_at >= r.pass_started_at)
                                      AS first_claim
                           FROM analysis.roots r WHERE r.id = $1"#,
                        id,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let slowest = sqlx::query_as!(
                        ModuleTime,
                        r#"SELECT module, sum(run_seconds) AS "seconds!", sum(runs)::bigint AS "runs!"
                           FROM queue.tasks
                           WHERE root_id = $1 AND run_seconds IS NOT NULL
                           GROUP BY module ORDER BY 2 DESC, module LIMIT $2"#,
                        id,
                        MAX_SLOWEST,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let mut work = AlertWork {
                        running_for_seconds: times.running_for,
                        last_pass_seconds: times.last_pass,
                        first_pass_seconds: times.first_pass,
                        first_claim_seconds: times.first_claim,
                        completed_passes: times.completed_pass,
                        slowest,
                        ..AlertWork::default()
                    };
                    let counts = sqlx::query!(
                        r#"SELECT state::text AS "state!", count(*) AS "count!"
                           FROM queue.tasks
                           WHERE root_id = $1 AND state IN ('queued', 'delayed', 'running', 'failed')
                           GROUP BY state"#,
                        id,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    for row in counts {
                        match row.state.as_str() {
                            "queued" => work.queued = row.count,
                            "delayed" => work.delayed = row.count,
                            "running" => work.running = row.count,
                            _ => work.failed = row.count,
                        }
                    }
                    if work.unfinished() > 0 {
                        work.tasks = sqlx::query_as!(
                            WorkTask,
                            r#"SELECT t.id, t.module, o.type::text AS "kind!", o.value,
                                      t.state::text AS "state!",
                                      floor(extract(epoch FROM now() - CASE WHEN t.state = 'running'
                                          THEN coalesce(t.claimed_at, t.updated_at)
                                          ELSE t.updated_at END))::bigint AS "for_seconds!",
                                      CASE WHEN t.state = 'delayed' THEN greatest(0, ceil(
                                          extract(epoch FROM t.run_after - now())))::bigint
                                      END AS runs_in_seconds,
                                      CASE WHEN t.state = 'running' THEN t.lease_owner END
                                          AS lease_owner,
                                      t.attempts
                               FROM queue.tasks t
                               JOIN analysis.observables o
                                 ON o.root_id = t.root_id AND o.id = t.observable_id
                               WHERE t.root_id = $1 AND t.state IN ('queued', 'delayed', 'running')
                               ORDER BY t.state = 'running' DESC, t.updated_at, t.id
                               LIMIT $2"#,
                            id,
                            MAX_WORK_ROWS,
                        )
                        .fetch_all(tx.conn())
                        .await?;
                    }
                    Ok(work)
                })
            })
            .await
    }
}
