//! The per-root metrics events: ace3's `EngineExecutionContext.record_execution_statistics`
//! (`saq/engine/execution_context.py`), whose root event ace3 emits once per work item since
//! `972058d1`, with the observable counts of `6a9cd43f`, followed by one event for each module that
//! ran.
//!
//! **When.** ace3's engine emits it when it has finished a work item: one run of the engine over a
//! root, which is a new root, a root whose mode changed, or one resumption of a delayed analysis. The
//! unit here is a root's pass (`crate::queue`): it begins when work is queued on an idle root and ends
//! when the root has no queued, delayed or running task left. So the transaction that ends a pass
//! (`queue::check_completion`) reads the event, and it is emitted once that transaction has committed
//! (`Tx::after_commit`): once for each row of `queue.root_completions`, never for a task's end that
//! left the pass open, and never for a transaction that rolled back or ran again. What ace3 splits
//! into a work item for each delayed resumption is one pass here, since a delayed task keeps its
//! pass open, so a root with a delayed module has one event where ace3 has several.
//!
//! **Where.** ace3 sends it to fluent-bit under the tag `metrics`, which writes it to a file its
//! logs are shipped from. ace4 has no fluent-bit: the event is a log record under the target
//! [`TARGET`], `ace_metrics`, at INFO, as a monitor record is one under `ace_monitor`
//! (`crate::monitoring`), so it goes where the process's logs go. Like any log record made inside a
//! span, it is also an event of that span in an exported trace. Its message is `METRICS (root): ` and the
//! event as JSON on one line, and each module event's is `METRICS (module): ` and its JSON. `ACE4_LOG=info,ace_metrics=off` turns it off, and then it isn't read
//! either: ace3's switch is `metrics_logging.enabled`. The binary's own default level, WARN, has it
//! off; the Compose stack sets `info`.
//!
//! **The fields of the root's event.** ace3's names where the value means the same, and a name of
//! its own where it doesn't:
//!
//! | ace3's field | here | from |
//! |---|---|---|
//! | `event_type`, `"root"` | `event_type`, `"root"` | a constant |
//! | `outcome`, `completed`, `cancelled`, `timed_out` or `failed` (since `91c3e6e4` and `24f94fda`) | `outcome`, `completed` or `cancelled` | `cancelled` when the root was cancelled by the pass's end (`analysis.roots.cancelled_at`), as ace3's is for a shutdown, a lost lock or a disposition stop. ace4 has neither of the other two: a task fails, never a pass, and no pass has a time limit as ace3's work item does |
//! | `timestamp`, the engine's local time as `%Y-%m-%d %H:%M:%S.%f` | `timestamp`, RFC 3339 in UTC | the pass's `queue.root_completions.completed_at` |
//! | `root_uuid` | `root_uuid` | the root's id |
//! | `total_time_seconds`, how long the engine's executor ran on the work item | not emitted under that name: `pass_open_seconds`, how long the pass was open | `completed_at` less `analysis.roots.pass_started_at` (migration 0066). It includes what ace3's leaves out, the time tasks waited for a worker and the waits of delayed tasks, and tasks run side by side, so it is no measure of the work done and is named so that nobody compares it with ace3's. Absent for a pass that began before migration 0066 |
//! | `total_analysis_time_seconds`, the sum of each module's run time in the work item | `total_analysis_time_seconds`, the sum of the run times of the root's tasks in the pass | the module events' `analysis_time_seconds`, summed. A run is defined below. ace3's sums its modules' time in one work item; a pass here may span several of ace3's work items (each delayed resumption is one there), so it is the sum over all of them. It includes the core's hooks task (ace3's hooks are modules whose time it counts), and 0 when no task ran |
//! | `alert_type` | `alert_type`, or null | the root's `origin ->> 'alert_type'`, what its submitter said (`crate::submit`). The API's own submissions name none |
//! | `is_alert`, whether the work item ran in correlation mode | `is_alert`, whether the root is an alert | `analysis.roots.alerted_at`. A root that becomes an alert does so in the pass that detects, so that pass's event says true; ace3's first says false and its next, in correlation mode, true |
//! | `queue` | `queue` | `analysis.roots.queue` |
//! | `observable_count`, the unique observables in the tree | `observable_count` | the root's rows of `analysis.observables`, one for each type and value |
//! | `observable_type_counts`, type to count | `observable_type_counts` | the same rows, by type |
//!
//! And three ace3 has no field for, since its unit differs: `pass`, which of the root's passes ended;
//! and `task_count` with
//! `failed_task_count`, the root's tasks at the pass's end and those that failed, without the core's
//! own hooks task. Since decision 23 the core queues no task a module's declaration declines, so
//! `task_count` counts the tasks that were queued to run: each ran, or was cancelled with its root
//! before it could. Under the audit setting (`ACE4_TAKES_AUDIT=1`, `crate::takes`) the declined tasks
//! are queued, leased and ended skipped as before, so they are counted again, and their runs are in
//! the run times. Those counts are the root's, not the pass's: a later pass's event counts the
//! earlier passes' observables and tasks too, as ace3's `observable_count` counts the whole tree. The
//! run times are the pass's alone, as ace3's are the work item's.
//!
//! **A task's run.** A run is one claim of a task, from the claim that takes its lease
//! (`Worker::claim_up_to`, `queue.tasks.claimed_at`) to the start of the transaction that ends the
//! task or delays it (`Worker::finish_in`, `Worker::delay_in`), both by the database's clock. Those
//! two statements add the run to the task's `run_seconds` and count it in `runs`, for the root's pass
//! it ended in (`run_pass`, migration 0068); a run in a later pass starts them over, so they hold the
//! current pass's runs only. A delayed task runs several times in one pass, since its delay keeps the
//! pass open, and its run time is the sum of its runs, not counting the waits between them; ace3
//! counts each resumption in the work item that runs it. A claim that comes back without an end adds
//! nothing: the core's hold of a file's first task or of a task that runs last, a release at shutdown,
//! a request given back before its answer, and a lease the reaper takes back, whose end nobody saw.
//!
//! A run is more than the module's own work. It includes the core's decision of the lease (the path
//! hold's check, the file's record and download URL, what the task reads of its tree) and, for a
//! request that leased several, the decisions of the others before it; the answer's way to the pool;
//! the task process's start and containment; fetching the file from the bucket; the module's
//! `analyze`; and writing its result and its files and sending them to the core. That is the right
//! thing to call a task's run time, for three reasons. It is the time a pool's slot was held for the
//! task, which is what bounds how much a pool can do, so it is what a run time is for when sizing
//! pools. It is what ace3's module time also is: the time from just before a module's `analyze` to
//! after its results were processed and the root saved, overhead included. And it is measured by one
//! clock that the core already writes at both ends, so it needs no clock in a pool, nothing new on the
//! wire and no statement more. A task that ends at its lease, before any pool has it (its file isn't
//! in the bucket, its root was cancelled), counts a run of the core's time alone; ace3 would count
//! none, since its module never started.
//!
//! The module's own time could be separated cheaply: the pool already times `analyze` in its `task`
//! span (`ace_sdk::task_span`), and could send that duration with the task's end, which the end's
//! statement would store in a column beside `run_seconds`. That changes the wire, so it isn't done
//! here. Until then the span is the module's own time, in the traces the collector receives.
//!
//! **The module events.** ace3 emits one event for each module that did anything in the work item
//! (`event_type` `module`), after the root's, with the same `root_uuid` and `timestamp`, which join
//! them. "Did anything" is a module ace3 ran at least once (its `analyze` called, whatever it
//! returned or raised) or that had a cache hit, miss or write. ace4 has no analysis cache, so here it
//! is a module with at least one run in the pass. Their message starts `METRICS (module): `.
//!
//! | ace3's field | here | from |
//! |---|---|---|
//! | `event_type`, `"module"` | `event_type`, `"module"` | a constant |
//! | `timestamp`, the root event's | `timestamp`, the root event's | |
//! | `root_uuid` | `root_uuid` | |
//! | `module`, the module's name | `module`, the module's name | `queue.tasks.module`; the core's hooks are one, `core_hooks` |
//! | `analysis_time_seconds`, the module's run time in the work item | `analysis_time_seconds`, the module's run time in the pass | the sum of its tasks' `run_seconds` in the pass |
//! | `percentage`, `analysis_time_seconds` as a percentage of the work item's `total_time_seconds`, 0 when that is 0 | `percentage`, `analysis_time_seconds` as a percentage of `total_analysis_time_seconds`, 0 when that is 0 | ace3's share is of the engine's time, which its modules ran one after another in; here tasks run side by side and the pass's open time includes waits, so a share of it could pass 100 and would move with the queue. A share of the run times is the module's share of the work, and the events of a pass add up to 100 |
//! | `exec_count`, the module's `analyze` calls, a delayed module's resumptions included | `exec_count` | the sum of its tasks' `runs` in the pass |
//! | `cache_hit_count`, `cache_miss_count`, `cache_write_count_insert`, `cache_lookup_*`, `cache_write_*` | not emitted | ace4 has no analysis cache. ace3 leaves them out too for a module that had no cache activity |
//!
//! And `pass`, as on the root's event.
//!
//! **A root that is cancelled or fails.** ace3's executor returns normally when a work item is
//! cancelled, so the events are emitted, with `outcome` `cancelled` since its `24f94fda`; here a
//! cancelled root's pass ends, at once or when its last running task has stopped, and its event's
//! `outcome` is `cancelled` too. Since `91c3e6e4` ace3 also emits the events when the executor
//! raises, which is the whole analysis timing out (`timed_out`) or failing (`failed`). ace4 has no
//! such failure: a task fails, never a pass, so a root whose tasks failed has its event, `completed`,
//! as ace3's does when a module raised and the engine caught it. A failed run counts in its module's run time and executions, as in ace3.
//!
//! **Cost.** One statement in the transaction that ends the pass, which reads the root's row, counts
//! its observables by type, and reads its tasks through their index by root once, grouped by module,
//! for the counts and the run times; nothing for a task's end that leaves the pass open. The lease
//! sets one column more, and a task's end and its delay three, in statements they already ran; the
//! root's lock they already took returns the pass. `docs/measurements/root-metrics.md` has the
//! measurements. The statement is a read: if it fails, the transaction fails as it would on any
//! statement's error, and the task's end is tried again as any is.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::db::{DbError, Tx};

/// The log target the events are emitted under.
pub const TARGET: &str = "ace_metrics";

/// ace3's `event_type` of the root's event.
pub const EVENT_TYPE_ROOT: &str = "root";

/// ace3's `event_type` of a module's event.
pub const EVENT_TYPE_MODULE: &str = "module";

/// ace3's `outcome` of a pass that ended with its root analyzed as far as it goes.
pub const OUTCOME_COMPLETED: &str = "completed";

/// ace3's `outcome` of a pass whose root was cancelled.
pub const OUTCOME_CANCELLED: &str = "cancelled";

/// What the root event's message starts with, before the event's JSON.
pub const MESSAGE_PREFIX: &str = "METRICS (root): ";

/// What a module event's message starts with, before the event's JSON.
pub const MODULE_MESSAGE_PREFIX: &str = "METRICS (module): ";

/// One pass's root event, with ace3's field names where they mean the same (the module's docs map
/// each), and the module events that follow it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RootMetrics {
    pub event_type: &'static str,
    /// When the pass completed.
    pub timestamp: DateTime<Utc>,
    pub root_uuid: Uuid,
    pub pass: i32,
    /// The sum of the run times of the root's tasks in the pass.
    pub total_analysis_time_seconds: f64,
    /// How long the pass was open, waits included. None when nothing recorded its start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pass_open_seconds: Option<f64>,
    pub alert_type: Option<String>,
    pub is_alert: bool,
    pub queue: String,
    pub observable_count: i64,
    pub observable_type_counts: BTreeMap<String, i64>,
    pub task_count: i64,
    pub failed_task_count: i64,
    /// ace3's `outcome`: `completed`, or `cancelled` for a root cancelled by the pass's end.
    pub outcome: &'static str,
    /// One event for each module that ran in the pass, by name. Emitted after this one, each a
    /// record of its own.
    #[serde(skip)]
    pub modules: Vec<ModuleMetrics>,
}

/// One module's event for a pass: ace3's `event_type` `module`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModuleMetrics {
    pub event_type: &'static str,
    /// The root event's.
    pub timestamp: DateTime<Utc>,
    pub root_uuid: Uuid,
    pub pass: i32,
    pub module: String,
    /// The sum of the run times of the module's tasks in the pass.
    pub analysis_time_seconds: f64,
    /// `analysis_time_seconds` as a percentage of the root event's `total_analysis_time_seconds`.
    pub percentage: f64,
    /// The module's runs in the pass.
    pub exec_count: i64,
}

/// Whether anything takes the events. When nothing does, a pass's end doesn't read them.
pub fn enabled() -> bool {
    tracing::enabled!(target: TARGET, tracing::Level::INFO)
}

/// Reads the events of the root's pass that this transaction ended at `completed_at`, with the root
/// locked. One statement.
pub async fn read(
    tx: &mut Tx<'_>,
    root: Uuid,
    pass: i32,
    completed_at: DateTime<Utc>,
) -> Result<Option<RootMetrics>, DbError> {
    // the tasks are read once, grouped by module: the counts leave out the core's hooks task, the
    // run times count only the runs that ended in this pass (`run_pass`, migration 0068)
    let row = sqlx::query!(
        r#"SELECT r.origin ->> 'alert_type' AS alert_type,
                  r.alerted_at IS NOT NULL AS "is_alert!",
                  r.queue::text AS "queue!",
                  r.cancelled_at IS NOT NULL AS "cancelled!",
                  EXTRACT(EPOCH FROM ($2::timestamptz - r.pass_started_at))::float8
                      AS pass_open_seconds,
                  o.types AS "types!", o.counts AS "counts!",
                  t.tasks AS "tasks!", t.failed AS "failed!",
                  t.modules AS "modules!", t.seconds AS "seconds!", t.runs AS "runs!"
           FROM analysis.roots r,
                LATERAL (SELECT COALESCE(array_agg(c.type ORDER BY c.type), '{}') AS types,
                                COALESCE(array_agg(c.n ORDER BY c.type), '{}') AS counts
                         FROM (SELECT type, count(*) AS n FROM analysis.observables
                               WHERE root_id = r.id GROUP BY type) c) o,
                LATERAL (SELECT COALESCE(sum(m.tasks) FILTER (WHERE m.module <> $3), 0)::int8
                                    AS tasks,
                                COALESCE(sum(m.failed) FILTER (WHERE m.module <> $3), 0)::int8
                                    AS failed,
                                COALESCE(array_agg(m.module ORDER BY m.module)
                                         FILTER (WHERE m.runs > 0), '{}') AS modules,
                                COALESCE(array_agg(m.seconds ORDER BY m.module)
                                         FILTER (WHERE m.runs > 0), '{}') AS seconds,
                                COALESCE(array_agg(m.runs ORDER BY m.module)
                                         FILTER (WHERE m.runs > 0), '{}') AS runs
                         FROM (SELECT module, count(*) AS tasks,
                                      count(*) FILTER (WHERE state = 'failed') AS failed,
                                      COALESCE(sum(run_seconds) FILTER (WHERE run_pass = $4),
                                               0)::float8 AS seconds,
                                      COALESCE(sum(runs) FILTER (WHERE run_pass = $4), 0)::int8
                                          AS runs
                               FROM queue.tasks WHERE root_id = r.id GROUP BY module) m) t
           WHERE r.id = $1"#,
        root,
        completed_at,
        crate::hooks::HOOKS_MODULE,
        pass,
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(row.map(|row| {
        let observable_type_counts: BTreeMap<String, i64> =
            row.types.into_iter().zip(row.counts).collect();
        let total: f64 = row.seconds.iter().sum();
        let modules = row
            .modules
            .into_iter()
            .zip(row.seconds)
            .zip(row.runs)
            .map(|((module, seconds), runs)| ModuleMetrics {
                event_type: EVENT_TYPE_MODULE,
                timestamp: completed_at,
                root_uuid: root,
                pass,
                module,
                analysis_time_seconds: seconds,
                percentage: if total > 0.0 {
                    seconds / total * 100.0
                } else {
                    0.0
                },
                exec_count: runs,
            })
            .collect();
        RootMetrics {
            event_type: EVENT_TYPE_ROOT,
            timestamp: completed_at,
            root_uuid: root,
            pass,
            total_analysis_time_seconds: total,
            // a clock that stepped back between the two can't make a pass shorter than nothing
            pass_open_seconds: row.pass_open_seconds.map(|seconds| seconds.max(0.0)),
            alert_type: row.alert_type,
            is_alert: row.is_alert,
            queue: row.queue,
            observable_count: observable_type_counts.values().sum(),
            observable_type_counts,
            task_count: row.tasks,
            failed_task_count: row.failed,
            outcome: if row.cancelled {
                OUTCOME_CANCELLED
            } else {
                OUTCOME_COMPLETED
            },
            modules,
        }
    }))
}

impl RootMetrics {
    /// The root's event as JSON on one line, as its log record's message carries it.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            // every field is a string, a number, a bool or a map of them
            format!(
                r#"{{"event_type":"root","root_uuid":"{}","error":"{e}"}}"#,
                self.root_uuid
            )
        })
    }

    /// Writes the root's event to the log, under [`TARGET`], and then each module's.
    pub fn emit(&self) {
        tracing::info!(
            target: TARGET,
            event_type = self.event_type,
            root_uuid = %self.root_uuid,
            pass = self.pass,
            "{MESSAGE_PREFIX}{}",
            self.to_json()
        );
        for module in &self.modules {
            module.emit();
        }
    }
}

impl ModuleMetrics {
    /// The module's event as JSON on one line, as its log record's message carries it.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            format!(
                r#"{{"event_type":"module","root_uuid":"{}","error":"{e}"}}"#,
                self.root_uuid
            )
        })
    }

    /// Writes the module's event to the log, under [`TARGET`].
    pub fn emit(&self) {
        tracing::info!(
            target: TARGET,
            event_type = self.event_type,
            root_uuid = %self.root_uuid,
            pass = self.pass,
            module = %self.module,
            "{MODULE_MESSAGE_PREFIX}{}",
            self.to_json()
        );
    }
}

/// Reads the events of the pass this transaction ended and has them emitted once the transaction
/// has committed. Does nothing when nothing takes them.
pub(crate) async fn record(
    tx: &mut Tx<'_>,
    root: Uuid,
    pass: i32,
    completed_at: DateTime<Utc>,
) -> Result<(), DbError> {
    if !enabled() {
        return Ok(());
    }
    if let Some(metrics) = read(tx, root, pass, completed_at).await? {
        tx.after_commit(move || metrics.emit());
    }
    Ok(())
}
