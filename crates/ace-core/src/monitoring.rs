//! Monitoring (PLAN.md 7.12): ace3's `monitoring` service (`saq/monitoring/`), whose monitors each
//! read some shared state on a timer and emit it as monitor records (`saq/monitor.py`), and its
//! hourly `ace cas node-stats` cron task, which emits the same kind of record.
//!
//! Each of ace3's monitors is a check here: a function that reads what the monitor reads and returns
//! its records, which the scheduler (6.7) runs as a task of its own (`ace_app::scheduler`). ace3's
//! records go to fluent-bit, and optionally to its log, stdout or an in-memory cache. ace4 has no
//! fluent-bit: a record is a log line (`emit`, under the target `ace_monitor`, so `ACE4_LOG` can
//! filter them), which is where ace4's logs are shipped from, and a row of `monitoring.records`,
//! where a check's run replaces its last run's rows (`replace`), so the administration area shows
//! each check's state as of its last run.
//!
//! | ace3 monitor | path | here |
//! |---|---|---|
//! | `distributed_workload`, every 5 s | `workload.distributed` | `workload`: the roots with a pass in progress, by analysis mode |
//! | `distributed_delayed_analysis`, 5 s | `workload.distributed.delayed_analysis` | `delayed_analysis`: the delayed tasks, by root and module |
//! | `distributed_locks`, 5 s | `workload.distributed.locks` | `leases`: the running tasks' leases. ace3 locks a root while a worker analyzes it; a task's lease is what a worker holds here |
//! | `local_workload`, 5 s | `workload.local` | none: ace3 counts what its collectors have collected on this node and not yet delivered (`incoming_workload`). A submission here is one transaction that makes the root and its tasks, so nothing waits between the two |
//! | `node_status`, 30 s | `node.status` | replaced by `queue` (`workload.queue`): ace4 keeps no table of nodes, no heartbeat and no drain. A pool is a set of processes that lease tasks, and one that is gone shows as its modules' tasks waiting longer and its leases expiring, which is what `queue` reports for each module |
//! | `cas_pools`, 300 s | `cas.pool` | `bucket_pools`: the bucket's index, by pool |
//! | cron `hourly/cas-node-stats` | `cas.node` | `node_cache`: the read cache of the node that runs it |
//! | fluent-bit's `cron-jobs` records, one per cron run | | `scheduled_tasks` (`scheduler.task`): each scheduled task's state from `scheduler.tasks` and `scheduler.runs`, which 6.7 left for this step to read |
//!
//! What differs from ace3's:
//! - A check runs on a cron schedule, whose grain is a minute, where ace3's monitors run every 5, 30
//!   or 300 seconds.
//! - A check that emits a record for each of something (a delayed task's root, a lease) emits at most
//!   `MAX_RECORDS`, the ones most worth seeing first, and says how many it left out. ace3 emits one
//!   for every row, however many there are.
//! - ace3's emitter gates a record by its path's definition (`monitor.definitions`: enabled, a
//!   suppression window, dedup). A check here is turned off or slowed by its task's entry in the
//!   overlay's `scheduler:` section, and there are no definitions.
//! - The records name no company: ace4 has none.
//!
//! ace3's other record of this kind isn't a monitor's: the engine's per-root metrics event, which it
//! sends to fluent-bit under the tag `metrics` when it has finished a work item. Here it is
//! `crate::metrics`: a log record under the target `ace_metrics`, one for each pass a root completes,
//! emitted by the transaction that ends the pass and not by a scheduled check, so it has no row in
//! `monitoring.records`.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::bucket::Retention;
use crate::db::{Db, DbError};

/// The most records one run of a check emits.
pub const MAX_RECORDS: i64 = 500;

/// ace3's `gc_overdue_seconds`: how far past its pool's grace an unheld object is before the pool's
/// record counts it as overdue, which an hourly GC should never let happen.
pub const GC_OVERDUE_SECONDS: f64 = 7200.0;

pub const WORKLOAD_DISTRIBUTED: &str = "workload.distributed";
pub const WORKLOAD_DELAYED_ANALYSIS: &str = "workload.distributed.delayed_analysis";
pub const WORKLOAD_LOCKS: &str = "workload.distributed.locks";
pub const WORKLOAD_QUEUE: &str = "workload.queue";
pub const CAS_POOL: &str = "cas.pool";
pub const CAS_NODE: &str = "cas.node";
pub const SCHEDULER_TASK: &str = "scheduler.task";

/// A monitor record: ace3's `emit_monitor(monitor, value, identifier)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    /// ace3's monitor path.
    pub path: &'static str,
    /// What the record is about, when a check emits several.
    pub identifier: Option<String>,
    pub value: Value,
}

impl Record {
    fn new(path: &'static str, identifier: Option<String>, value: Value) -> Record {
        Record {
            path,
            identifier,
            value,
        }
    }
}

/// What a check found: its records, and how many more it would have emitted without the bound.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Found {
    pub records: Vec<Record>,
    pub left_out: i64,
}

impl Found {
    fn all(records: Vec<Record>) -> Found {
        Found {
            records,
            left_out: 0,
        }
    }
}

/// ace3's `DistributedWorkloadMonitor`: how many roots are being analyzed, by analysis mode, as one
/// record. ace3 counts its `workload` rows, a root's from when it's queued until an engine has
/// finished with it; here that is a root whose pass hasn't completed.
pub async fn workload(db: &Db) -> Result<Found, DbError> {
    let rows = sqlx::query!(
        r#"SELECT analysis_mode, count(*) AS "count!" FROM analysis.roots
           WHERE completed_pass < pass GROUP BY analysis_mode ORDER BY analysis_mode"#
    )
    .fetch_all(db.pool())
    .await?;
    let workload: Vec<Value> = rows
        .into_iter()
        .map(|row| json!({"analysis_mode": row.analysis_mode, "count": row.count}))
        .collect();
    Ok(Found::all(vec![Record::new(
        WORKLOAD_DISTRIBUTED,
        None,
        json!({"workload": workload}),
    )]))
}

/// ace3's `DistributedDelayedAnalysisMonitor`: one record for each root and module with delayed
/// tasks, the most first. ace3's record names the node holding the delayed analysis; a delayed task
/// here waits in the queue, held by no node, so it names when the first is due instead.
pub async fn delayed_analysis(db: &Db) -> Result<Found, DbError> {
    let rows = sqlx::query!(
        r#"SELECT root_id, module, count(*) AS "count!", min(run_after) AS "next_run!",
                  count(*) OVER () AS "groups!"
           FROM queue.tasks WHERE state = 'delayed'
           GROUP BY root_id, module
           ORDER BY count(*) DESC, root_id, module LIMIT $1"#,
        MAX_RECORDS,
    )
    .fetch_all(db.pool())
    .await?;
    let groups = rows.first().map_or(0, |row| row.groups);
    let records: Vec<Record> = rows
        .into_iter()
        .map(|row| {
            Record::new(
                WORKLOAD_DELAYED_ANALYSIS,
                Some(format!("{}:{}", row.root_id, row.module)),
                json!({
                    "uuid": row.root_id,
                    "module": row.module,
                    "count": row.count,
                    "next_run": row.next_run,
                }),
            )
        })
        .collect();
    Ok(Found {
        left_out: groups - records.len() as i64,
        records,
    })
}

/// ace3's `DistributedLocksMonitor`: one record for each lease a worker holds, the soonest to expire
/// first, so the expired ones, whose worker went away, come first. ace3's lock is on a root, by a
/// worker of a node; a lease is on a task, by the pool process that claimed it (`lock_owner`).
pub async fn leases(db: &Db) -> Result<Found, DbError> {
    let rows = sqlx::query!(
        r#"SELECT id, root_id, module, lease_owner AS "lease_owner!",
                  lease_expires_at AS "lease_expires_at!", updated_at, attempts,
                  lease_expires_at <= now() AS "expired!",
                  (SELECT count(*) FROM queue.tasks WHERE state = 'running') AS "running!"
           FROM queue.tasks WHERE state = 'running'
           ORDER BY lease_expires_at, id LIMIT $1"#,
        MAX_RECORDS,
    )
    .fetch_all(db.pool())
    .await?;
    let running = rows.first().map_or(0, |row| row.running);
    let records: Vec<Record> = rows
        .into_iter()
        .map(|row| {
            Record::new(
                WORKLOAD_LOCKS,
                Some(row.id.to_string()),
                json!({
                    "uuid": row.root_id,
                    "task": row.id,
                    "module": row.module,
                    "lock_owner": row.lease_owner,
                    // when the task was claimed, or its lease last extended
                    "lock_time": row.updated_at,
                    "lease_expires_at": row.lease_expires_at,
                    "expired": row.expired,
                    "attempts": row.attempts,
                }),
            )
        })
        .collect();
    Ok(Found {
        left_out: running - records.len() as i64,
        records,
    })
}

/// What stands in for ace3's `NodeStatusMonitor`: for each module with tasks that aren't finished,
/// how many are queued, delayed and running, how long the oldest claimable one has waited, and how
/// many leases have expired. A pool that is down or too small shows as its modules' tasks waiting
/// longer, and one that died as expired leases. The modules with the longest wait come first.
pub async fn queue(db: &Db) -> Result<Found, DbError> {
    let rows = sqlx::query!(
        r#"SELECT module,
                  count(*) FILTER (WHERE state = 'queued') AS "queued!",
                  count(*) FILTER (WHERE state = 'delayed') AS "delayed!",
                  count(*) FILTER (WHERE state = 'running') AS "running!",
                  count(*) FILTER (WHERE state = 'running' AND lease_expires_at <= now())
                      AS "expired_leases!",
                  COALESCE(EXTRACT(EPOCH FROM now() - min(run_after)
                      FILTER (WHERE state IN ('queued', 'delayed') AND run_after <= now())), 0)::float8
                      AS "oldest_waiting_seconds!",
                  count(*) OVER () AS "modules!"
           FROM queue.tasks WHERE state IN ('queued', 'delayed', 'running')
           GROUP BY module
           ORDER BY 6 DESC, module LIMIT $1"#,
        MAX_RECORDS,
    )
    .fetch_all(db.pool())
    .await?;
    let modules = rows.first().map_or(0, |row| row.modules);
    let records: Vec<Record> = rows
        .into_iter()
        .map(|row| {
            Record::new(
                WORKLOAD_QUEUE,
                Some(row.module.clone()),
                json!({
                    "module": row.module,
                    "queued": row.queued,
                    "delayed": row.delayed,
                    "running": row.running,
                    "expired_leases": row.expired_leases,
                    "oldest_waiting_seconds": row.oldest_waiting_seconds.round() as i64,
                }),
            )
        })
        .collect();
    Ok(Found {
        left_out: modules - records.len() as i64,
        records,
    })
}

/// ace3's `CASPoolMonitor` (`saq/cas/health.py`'s `pool_health`): one record for each pool the bucket
/// is configured with, and for each pool that still has rows in the index and isn't configured.
/// `gc_overdue` is the field to alert on: unheld objects further past their grace than the hourly GC
/// should ever let them get, which stays above zero when GC is failing or isn't running.
///
/// ace3's `stored_bytes`, `backend`, `encryption`, `legal_holds` and `purges_last_24h` have no field:
/// the bucket stores an object's bytes as they are in one S3 bucket, and has no legal hold and no
/// forced purge.
pub async fn bucket_pools(db: &Db, pools: &[(String, Retention)]) -> Result<Found, DbError> {
    let mut records: std::collections::BTreeMap<String, serde_json::Map<String, Value>> =
        std::collections::BTreeMap::new();
    let blank = || {
        let mut entry = serde_json::Map::new();
        for field in [
            "objects_present",
            "objects_deleting",
            "size_bytes",
            "never_verified",
            "verified_last_7d",
            "holds_live",
            "holds_expired",
            "objects_held",
        ] {
            entry.insert(field.to_owned(), json!(0));
        }
        entry
    };
    for (name, _) in pools {
        records.insert(name.clone(), blank());
    }
    let objects = sqlx::query!(
        r#"SELECT pool, state::text AS "state!", count(*) AS "count!",
                  COALESCE(sum(size), 0)::bigint AS "size!",
                  count(*) FILTER (WHERE verified_at IS NULL) AS "never_verified!",
                  count(*) FILTER (WHERE verified_at > now() - interval '7 days')
                      AS "verified_recently!"
           FROM store.objects GROUP BY pool, state"#
    )
    .fetch_all(db.pool())
    .await?;
    let add = |entry: &mut serde_json::Map<String, Value>, field: &str, by: i64| {
        let now = entry.get(field).and_then(Value::as_i64).unwrap_or(0);
        entry.insert(field.to_owned(), json!(now + by));
    };
    for row in objects {
        let entry = records.entry(row.pool).or_insert_with(blank);
        let field = if row.state == "present" {
            "objects_present"
        } else {
            "objects_deleting"
        };
        add(entry, field, row.count);
        add(entry, "size_bytes", row.size);
        add(entry, "never_verified", row.never_verified);
        add(entry, "verified_last_7d", row.verified_recently);
    }
    let holds = sqlx::query!(
        r#"SELECT pool,
                  count(*) FILTER (WHERE expires_at IS NULL OR expires_at > now()) AS "live!",
                  count(*) FILTER (WHERE expires_at <= now()) AS "expired!",
                  count(DISTINCT sha256) FILTER (WHERE expires_at IS NULL OR expires_at > now())
                      AS "held!"
           FROM store.holds GROUP BY pool"#
    )
    .fetch_all(db.pool())
    .await?;
    for row in holds {
        let entry = records.entry(row.pool).or_insert_with(blank);
        entry.insert("holds_live".to_owned(), json!(row.live));
        entry.insert("holds_expired".to_owned(), json!(row.expired));
        entry.insert("objects_held".to_owned(), json!(row.held));
    }
    let mut found = Vec::new();
    for (name, mut entry) in records {
        let configured = pools.iter().find(|(pool, _)| *pool == name);
        let (retention, gc_overdue) = match configured {
            Some((_, Retention::Held { grace })) => {
                // present, unheld, and further past the pool's grace than GC should let them get:
                // GC's own candidates (`Bucket::gc`), with the margin added
                let overdue = sqlx::query_scalar!(
                    r#"SELECT count(*) AS "count!" FROM store.objects o
                       WHERE o.pool = $1 AND o.state = 'present'
                         AND o.last_held_at < now() - make_interval(secs => $2)
                         AND NOT EXISTS (
                             SELECT 1 FROM store.holds h
                             WHERE h.pool = o.pool AND h.sha256 = o.sha256
                               AND (h.expires_at IS NULL OR h.expires_at > now()))"#,
                    name,
                    grace.as_secs_f64() + GC_OVERDUE_SECONDS,
                )
                .fetch_one(db.pool())
                .await?;
                (json!("held"), json!(overdue))
            }
            Some((_, Retention::Permanent)) => (json!("permanent"), Value::Null),
            None => (Value::Null, Value::Null),
        };
        entry.insert("pool".to_owned(), json!(name));
        entry.insert("configured".to_owned(), json!(configured.is_some()));
        entry.insert("retention".to_owned(), retention);
        entry.insert("gc_overdue".to_owned(), gc_overdue);
        found.push(Record::new(CAS_POOL, Some(name), Value::Object(entry)));
    }
    // a pool is a name the configuration or a put gave, so there are few; the bound still holds
    let left_out = (found.len() as i64 - MAX_RECORDS).max(0);
    found.truncate(MAX_RECORDS as usize);
    Ok(Found {
        records: found,
        left_out,
    })
}

/// ace3's `node_stats` (`ace cas node-stats`, hourly on every node): this node's read cache, how many
/// entries and bytes it holds against its cap, and the free and total space of the filesystem it is
/// on. ace3 also reports the filesystem under each local-backend pool; the bucket is S3, so there is
/// none. It walks the cache directory, so it's for a blocking thread.
pub fn node_cache(cache: &ace_store::NodeCache, node: &str) -> std::io::Result<Found> {
    let usage = cache.usage()?;
    let (free, total) = match disk(cache.dir()) {
        Some((free, total)) => (json!(free), json!(total)),
        None => (Value::Null, Value::Null),
    };
    Ok(Found::all(vec![Record::new(
        CAS_NODE,
        Some(node.to_owned()),
        json!({
            "node": node,
            "kind": "read_cache",
            "path": cache.dir().display().to_string(),
            "entries": usage.entries,
            "bytes": usage.bytes,
            "max_bytes": cache.max_bytes(),
            "fs_free_bytes": free,
            "fs_total_bytes": total,
        }),
    )]))
}

/// The free and total bytes of the filesystem `path` is on, as ace3's `_disk` (`shutil.disk_usage`:
/// what an unprivileged process may use, and the whole).
fn disk(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `path` is a NUL-terminated string and `stats` is room for one statvfs, which the call
    // fills in when it returns 0.
    let stats = unsafe {
        if libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) != 0 {
            return None;
        }
        stats.assume_init()
    };
    let block = stats.f_frsize as u64;
    Some((
        (stats.f_bavail as u64).saturating_mul(block),
        (stats.f_blocks as u64).saturating_mul(block),
    ))
}

/// A scheduled task as `scheduler.tasks` and its runs have it.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskState {
    pub name: String,
    pub schedule: String,
    pub due_at: DateTime<Utc>,
    /// A run holds the task now.
    pub running: bool,
    /// How long ago it was due, when no run holds it: a task nothing runs falls behind.
    pub overdue_seconds: i64,
    /// The last run that ended.
    pub last_outcome: Option<String>,
    pub last_started_at: Option<DateTime<Utc>>,
    pub last_ended_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_node: Option<String>,
    /// How many runs have ended otherwise than `succeeded` since the last that did.
    pub failures_since_success: i64,
}

/// Every scheduled task's state, by name: what ace3's `cron-jobs` records say one run at a time.
pub async fn task_states(db: &Db) -> Result<Vec<TaskState>, DbError> {
    task_states_with(db.pool()).await
}

/// `task_states`, on a connection or in a transaction the caller holds.
pub async fn task_states_with<'c>(
    executor: impl sqlx::PgExecutor<'c>,
) -> Result<Vec<TaskState>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT t.name, t.schedule, t.due_at,
                  (t.run_id IS NOT NULL AND t.lease_until > now()) AS "running!",
                  GREATEST(EXTRACT(EPOCH FROM now() - t.due_at), 0)::float8 AS "overdue!",
                  last.outcome AS "outcome?", last.started_at AS "started_at?",
                  last.ended_at AS "ended_at?", last.error AS "error?", last.node AS "node?",
                  (SELECT count(*) FROM scheduler.runs r
                   WHERE r.task = t.name AND r.outcome IS NOT NULL AND r.outcome <> 'succeeded'
                     AND r.id > COALESCE((SELECT max(s.id) FROM scheduler.runs s
                                          WHERE s.task = t.name AND s.outcome = 'succeeded'), 0))
                      AS "failures!"
           FROM scheduler.tasks t
           LEFT JOIN LATERAL (
               SELECT outcome, started_at, ended_at, error, node FROM scheduler.runs r
               WHERE r.task = t.name AND r.ended_at IS NOT NULL ORDER BY r.id DESC LIMIT 1
           ) last ON true
           ORDER BY t.name LIMIT $1"#,
        MAX_RECORDS,
    )
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| TaskState {
            name: row.name,
            schedule: row.schedule,
            due_at: row.due_at,
            running: row.running,
            overdue_seconds: if row.running {
                0
            } else {
                row.overdue.round() as i64
            },
            last_outcome: row.outcome,
            last_started_at: row.started_at,
            last_ended_at: row.ended_at,
            last_error: row.error,
            last_node: row.node,
            failures_since_success: row.failures,
        })
        .collect())
}

/// One record for each scheduled task: when it's due and how far behind it is, whether it's running,
/// how its last run ended, and how many runs have failed since one succeeded. ace3 writes each cron
/// run's outcome to fluent-bit's `cron-jobs` tag; `scheduler.runs` keeps them here, and this is what
/// reads it (PLAN.md 6.7).
pub async fn scheduled_tasks(db: &Db) -> Result<Found, DbError> {
    let records = task_states(db)
        .await?
        .into_iter()
        .map(|task| {
            Record::new(
                SCHEDULER_TASK,
                Some(task.name.clone()),
                json!({
                    "task": task.name,
                    "schedule": task.schedule,
                    "due_at": task.due_at,
                    "running": task.running,
                    "overdue_seconds": task.overdue_seconds,
                    "last_outcome": task.last_outcome,
                    "last_started_at": task.last_started_at,
                    "last_ended_at": task.last_ended_at,
                    "last_error": task.last_error,
                    "last_node": task.last_node,
                    "failures_since_success": task.failures_since_success,
                }),
            )
        })
        .collect();
    Ok(Found::all(records))
}

/// A record's line, as ace3's emitter writes it to its log and to stdout (`_format_message`).
pub fn format_message(record: &Record) -> String {
    match &record.identifier {
        Some(identifier) => format!(
            "MONITOR ({}) <{identifier}> : {}",
            record.path, record.value
        ),
        None => format!("MONITOR ({}): {}", record.path, record.value),
    }
}

/// Writes each record to the log, under the target `ace_monitor`: ace3's `emit_monitor`, whose
/// records go to fluent-bit. The value is JSON on one line.
pub fn emit(task: &str, records: &[Record]) {
    for record in records {
        tracing::info!(
            target: "ace_monitor",
            task,
            path = record.path,
            identifier = record.identifier.as_deref(),
            value = %record.value,
            "{}",
            format_message(record)
        );
    }
}

/// Replaces `task`'s records with these, in one transaction, so a reader sees one run's records or
/// the next's, never a mix, and a thing a check no longer finds has no record left.
pub async fn replace(db: &Db, task: &str, records: &[Record]) -> Result<(), DbError> {
    let paths: Vec<String> = records.iter().map(|r| r.path.to_owned()).collect();
    let identifiers: Vec<Option<String>> = records.iter().map(|r| r.identifier.clone()).collect();
    let values: Vec<Value> = records.iter().map(|r| r.value.clone()).collect();
    let mut tx = db.begin().await?;
    sqlx::query!("DELETE FROM monitoring.records WHERE task = $1", task)
        .execute(tx.conn())
        .await?;
    sqlx::query!(
        "INSERT INTO monitoring.records (task, path, identifier, value)
         SELECT $1, path, identifier, value
         FROM unnest($2::text[], $3::text[], $4::jsonb[]) WITH ORDINALITY AS r(path, identifier, value, n)
         ORDER BY n",
        task,
        &paths,
        &identifiers as &[Option<String>],
        &values,
    )
    .execute(tx.conn())
    .await?;
    tx.commit().await?;
    Ok(())
}

/// A record as `monitoring.records` keeps it.
#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub id: i64,
    pub task: String,
    pub path: String,
    pub identifier: Option<String>,
    pub value: Value,
    pub emitted_at: DateTime<Utc>,
}

/// The records each check last emitted, by check and in the order it emitted them, at most `limit`.
pub async fn stored<'c>(
    executor: impl sqlx::PgExecutor<'c>,
    limit: i64,
) -> Result<Vec<Stored>, DbError> {
    Ok(sqlx::query_as!(
        Stored,
        "SELECT id, task, path, identifier, value, emitted_at
         FROM monitoring.records ORDER BY task, id LIMIT $1",
        limit,
    )
    .fetch_all(executor)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ace3's `test_emit_monitor_logging_with_identifier`, `test_emit_monitor_stdout` and
    /// `test_emit_monitor_stderr`: a record's line, with and without what it's about.
    #[test]
    fn a_record_s_line_is_ace3_s() {
        let with = Record::new(
            CAS_POOL,
            Some("alerts".to_owned()),
            json!({"objects_present": 3}),
        );
        assert_eq!(
            format_message(&with),
            "MONITOR (cas.pool) <alerts> : {\"objects_present\":3}"
        );
        let without = Record::new(WORKLOAD_DISTRIBUTED, None, json!({"workload": []}));
        assert_eq!(
            format_message(&without),
            "MONITOR (workload.distributed): {\"workload\":[]}"
        );
    }

    /// ace3's `node_stats`: the read cache's entries and bytes against its cap, and the filesystem it's
    /// on. The walk counts and removes nothing, over the cap or not.
    #[test]
    fn a_node_s_cache_is_counted_and_left_alone() {
        let dir = tempfile::tempdir().expect("a directory");
        let cache = ace_store::NodeCache::new(dir.path(), 10).expect("a cache");
        let pool = dir.path().join("alerts").join("ab");
        std::fs::create_dir_all(&pool).expect("a pool's directory");
        std::fs::write(pool.join("one"), b"twelve bytes").expect("an entry");
        std::fs::write(pool.join("two"), b"five!").expect("an entry");
        let found = node_cache(&cache, "host/1").expect("walks");
        assert_eq!(found.left_out, 0);
        let record = &found.records[0];
        assert_eq!(
            (record.path, record.identifier.as_deref()),
            (CAS_NODE, Some("host/1"))
        );
        let value = &record.value;
        assert_eq!(
            (
                &value["node"],
                &value["kind"],
                &value["entries"],
                &value["bytes"],
                &value["max_bytes"]
            ),
            (
                &json!("host/1"),
                &json!("read_cache"),
                &json!(2),
                &json!(17),
                &json!(10)
            )
        );
        assert_eq!(value["path"], dir.path().display().to_string());
        let (free, total) = (
            value["fs_free_bytes"].as_u64().expect("free"),
            value["fs_total_bytes"].as_u64().expect("total"),
        );
        assert!(free > 0 && free <= total, "{value}");
        // over its cap, and still there
        assert!(pool.join("one").exists() && pool.join("two").exists());
        assert_eq!(disk(std::path::Path::new("/no/such/path/at/all")), None);
    }
}
