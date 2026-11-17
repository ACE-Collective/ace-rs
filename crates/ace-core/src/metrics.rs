//! The per-root metrics event: ace3's `EngineExecutionContext.record_execution_statistics`
//! (`saq/engine/execution_context.py`), whose root event ace3 emits once per work item since
//! `972058d1`, with the observable counts of `6a9cd43f`.
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
//! event as JSON on one line. `ACE4_LOG=info,ace_metrics=off` turns it off, and then it isn't read
//! either: ace3's switch is `metrics_logging.enabled`. The binary's own default level, WARN, has it
//! off; the Compose stack sets `info`.
//!
//! **The fields.** ace3's names, where the value means the same:
//!
//! | ace3's field | here | from |
//! |---|---|---|
//! | `event_type`, `"root"` | `event_type`, `"root"` | a constant |
//! | `timestamp`, the engine's local time as `%Y-%m-%d %H:%M:%S.%f` | `timestamp`, RFC 3339 in UTC | the pass's `queue.root_completions.completed_at` |
//! | `root_uuid` | `root_uuid` | the root's id |
//! | `total_time_seconds`, how long the engine's executor ran on the work item | `total_time_seconds`, how long the pass was open | `completed_at` less `analysis.roots.pass_started_at` (migration 0066). It includes what ace3's leaves out: the time tasks waited for a worker, and the waits of delayed tasks. Absent for a pass that began before migration 0066 |
//! | `total_analysis_time_seconds`, the sum of each module's run time in the work item | not emitted | the core keeps no run time for a task. A module's run is a span, `task` (`ace_sdk::task_span`) inside the pool's `pool.task`, with its root, observable, module and duration, in the traces the collector receives (`ace_pool::telemetry`). That is a module's time for whoever reads traces, not a number on this event |
//! | `alert_type` | `alert_type`, or null | the root's `origin ->> 'alert_type'`, what its submitter said (`crate::submit`). The API's own submissions name none |
//! | `is_alert`, whether the work item ran in correlation mode | `is_alert`, whether the root is an alert | `analysis.roots.alerted_at`. A root that becomes an alert does so in the pass that detects, so that pass's event says true; ace3's first says false and its next, in correlation mode, true |
//! | `queue` | `queue` | `analysis.roots.queue` |
//! | `observable_count`, the unique observables in the tree | `observable_count` | the root's rows of `analysis.observables`, one for each type and value |
//! | `observable_type_counts`, type to count | `observable_type_counts` | the same rows, by type |
//!
//! And three ace3 has no field for, since its unit differs: `pass`, which of the root's passes ended;
//! `cancelled`, whether the root was cancelled when it ended (ace3 emits the same event for a
//! cancelled work item, with nothing saying so); and `task_count` with `failed_task_count`, the root's
//! tasks at the pass's end and those that failed, without the core's own hooks task. The counts are
//! the root's, not the pass's: a later pass's event counts the earlier passes' observables and tasks
//! too, as ace3's `observable_count` counts the whole tree.
//!
//! ace3 also emits an event for each module that did anything in the work item (`event_type`
//! `module`: its run time, its share of the total, its executions and its analysis cache's counters).
//! None is emitted here: the core keeps no timing for a task, and ace4 has no analysis cache. The
//! spans are what stand in for them.
//!
//! **A root that is cancelled or fails.** ace3's executor returns normally when a work item is
//! cancelled, so the event is emitted; here a cancelled root's pass ends, at once or when its last
//! running task has stopped, and its event has `cancelled`. ace3 emits nothing when the executor
//! raises, which is the whole analysis timing out. ace4 has no such failure: a task fails, never a
//! pass, so a root whose tasks failed has its event, as ace3's does when a module raised and the
//! engine caught it.
//!
//! **Cost.** One statement in the transaction that ends the pass, which reads the root's row and
//! counts its observables and tasks through their indexes by root, and nothing for a task's end that
//! leaves the pass open: 0.3 to 0.45 ms on a root with 3,600 tasks, nine tenths of it the task
//! counts (`docs/measurements/root-metrics.md`). The statement is a read: if it fails, the transaction
//! fails as it would on any statement's error, and the task's end is tried again as any is.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::db::{DbError, Tx};

/// The log target the event is emitted under.
pub const TARGET: &str = "ace_metrics";

/// ace3's `event_type` of the root's event.
pub const EVENT_TYPE_ROOT: &str = "root";

/// What the message starts with, before the event's JSON.
pub const MESSAGE_PREFIX: &str = "METRICS (root): ";

/// One pass's event, with ace3's field names (the module's docs map each).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RootMetrics {
    pub event_type: &'static str,
    /// When the pass completed.
    pub timestamp: DateTime<Utc>,
    pub root_uuid: Uuid,
    pub pass: i32,
    /// How long the pass was open. None when nothing recorded its start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_time_seconds: Option<f64>,
    pub alert_type: Option<String>,
    pub is_alert: bool,
    pub queue: String,
    pub observable_count: i64,
    pub observable_type_counts: BTreeMap<String, i64>,
    pub task_count: i64,
    pub failed_task_count: i64,
    pub cancelled: bool,
}

/// Whether anything takes the event. When nothing does, a pass's end doesn't read it.
pub fn enabled() -> bool {
    tracing::enabled!(target: TARGET, tracing::Level::INFO)
}

/// Reads the event of the root's pass that this transaction ended at `completed_at`, with the root
/// locked. One statement.
pub async fn read(
    tx: &mut Tx<'_>,
    root: Uuid,
    pass: i32,
    completed_at: DateTime<Utc>,
) -> Result<Option<RootMetrics>, DbError> {
    let row = sqlx::query!(
        r#"SELECT r.origin ->> 'alert_type' AS alert_type,
                  r.alerted_at IS NOT NULL AS "is_alert!",
                  r.queue::text AS "queue!",
                  r.cancelled_at IS NOT NULL AS "cancelled!",
                  EXTRACT(EPOCH FROM ($2::timestamptz - r.pass_started_at))::float8
                      AS total_time_seconds,
                  o.types AS "types!", o.counts AS "counts!",
                  t.tasks AS "tasks!", t.failed AS "failed!"
           FROM analysis.roots r,
                LATERAL (SELECT COALESCE(array_agg(c.type ORDER BY c.type), '{}') AS types,
                                COALESCE(array_agg(c.n ORDER BY c.type), '{}') AS counts
                         FROM (SELECT type, count(*) AS n FROM analysis.observables
                               WHERE root_id = r.id GROUP BY type) c) o,
                LATERAL (SELECT count(*) AS tasks,
                                count(*) FILTER (WHERE state = 'failed') AS failed
                         FROM queue.tasks WHERE root_id = r.id AND module <> $3) t
           WHERE r.id = $1"#,
        root,
        completed_at,
        crate::hooks::HOOKS_MODULE,
    )
    .fetch_optional(tx.conn())
    .await?;
    Ok(row.map(|row| {
        let observable_type_counts: BTreeMap<String, i64> =
            row.types.into_iter().zip(row.counts).collect();
        RootMetrics {
            event_type: EVENT_TYPE_ROOT,
            timestamp: completed_at,
            root_uuid: root,
            pass,
            // a clock that stepped back between the two can't make a pass shorter than nothing
            total_time_seconds: row.total_time_seconds.map(|seconds| seconds.max(0.0)),
            alert_type: row.alert_type,
            is_alert: row.is_alert,
            queue: row.queue,
            observable_count: observable_type_counts.values().sum(),
            observable_type_counts,
            task_count: row.tasks,
            failed_task_count: row.failed,
            cancelled: row.cancelled,
        }
    }))
}

impl RootMetrics {
    /// The event as JSON on one line, as the log record's message carries it.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            // every field is a string, a number, a bool or a map of them
            format!(
                r#"{{"event_type":"root","root_uuid":"{}","error":"{e}"}}"#,
                self.root_uuid
            )
        })
    }

    /// Writes the event to the log, under [`TARGET`].
    pub fn emit(&self) {
        tracing::info!(
            target: TARGET,
            event_type = self.event_type,
            root_uuid = %self.root_uuid,
            pass = self.pass,
            "{MESSAGE_PREFIX}{}",
            self.to_json()
        );
    }
}

/// Reads the event of the pass this transaction ended and has it emitted once the transaction has
/// committed. Does nothing when nothing takes the event.
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
