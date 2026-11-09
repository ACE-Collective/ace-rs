//! Failed tasks (PLAN.md 2.19), for 5.6's `crashes` router: ace3's analysis module crash reports.
//!
//! ace3 writes a crash report directory on the node where a module raised, hung or was killed, and indexes
//! it in `analysis_module_crashes`. ace4's equivalent is a `queue.tasks` row in state `failed`: its error,
//! its attempts and the sha256 of each input it read, whose bytes are in the bucket's `alert_files` pool.
//! Any node can serve any of them, so there's nothing like ace3's `wrong_node` or its replication.
//!
//! Each read needs `crash:read`, ace3's name, so a grant made for ace3 carries over. A list or one task
//! writes no row. A download goes through `Gate::write` with a row that says what was read, as ace3 logs
//! its download, because the archive holds the file the module failed on.
//!
//! Nothing here writes to the queue. ace3's router has no write, and ace3's `ace crash prune` is retention
//! of report directories, which the bucket's GC is here. `ace task replay` (2.20) runs a failed task again
//! on a laptop through the lease API's admin route, which changes nothing.
//!
//! A task's error is text a module or a hostile file wrote, such as a file name, so it's data: nothing here
//! reads it, and the adapters return it as a string.

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use ace_core::bucket::ALERT_FILES;
use ace_core::db::Tx;

use crate::gate::{Audited, Change, Recorded, TITLE_LIMIT, Target};
use crate::permission::CRASH_READ;
use crate::{Service, ServiceError};

/// The most failed tasks one page holds, as ace3's listing.
pub const MAX_CRASHES_PAGE: u32 = 500;
/// A page's size when none is asked for, as ace3's.
const DEFAULT_CRASHES_PAGE: u32 = 50;

/// Which failed tasks to list. Every filter that's set must match.
#[derive(Debug, Clone, Default)]
pub struct CrashFilter {
    /// Only this root's tasks, an alert or not.
    pub root: Option<Uuid>,
    /// Only this module's tasks, by its key, such as `yara`.
    pub module: Option<String>,
}

/// One failed task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash {
    /// The task's id, which `ace task replay` takes.
    pub id: i64,
    pub root: Uuid,
    /// Whether the root is an alert. Most failed tasks are on roots that never became one.
    pub alerted: bool,
    pub module: String,
    pub observable_id: i64,
    pub observable_type: String,
    pub observable_value: String,
    /// Claims since its last normal run, and how many it was allowed.
    pub attempts: i32,
    pub max_attempts: i32,
    /// Why it failed, as the pool or the core wrote it.
    pub error: String,
    /// The sha256 of each input it read from the bucket.
    pub input_hashes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub failed_at: DateTime<Utc>,
}

/// One page of failed tasks, newest first, and the cursor for the next, None on the last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashPage {
    pub crashes: Vec<Crash>,
    pub next: Option<i64>,
}

/// One input of a failed task, and its object in the bucket when it's still there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrashInput {
    pub sha256: String,
    /// None when the bucket no longer has it, as after its alert's retention.
    pub size: Option<i64>,
    pub mime_type: Option<String>,
}

/// Everything recorded about a failed task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashDetail {
    pub crash: Crash,
    /// The root's description, up to 1024 characters.
    pub root_title: String,
    pub analysis_mode: String,
    /// The paths a file observable has in its root, the one it was analyzed under first.
    pub paths: Vec<String>,
    pub inputs: Vec<CrashInput>,
}

/// A download's audit row: what was read.
#[derive(Serialize)]
struct CrashRead<'a> {
    root: Uuid,
    module: &'a str,
    inputs: &'a [String],
}

impl Recorded for CrashRead<'_> {}

fn no_crash(id: i64) -> ServiceError {
    ServiceError::NotFound(format!("no failed task {id}"))
}

/// The failed task, and the rest of what's recorded about it.
async fn detail_in(tx: &mut Tx<'_>, id: i64) -> Result<CrashDetail, ServiceError> {
    let row = sqlx::query!(
        r#"SELECT t.id, t.root_id, r.alerted_at IS NOT NULL AS "alerted!", t.module,
                  t.observable_id, o.type, o.value, t.attempts, t.max_attempts,
                  coalesce(t.error, '') AS "error!", t.input_hashes, t.created_at,
                  t.updated_at, left(r.description, $2) AS "title!", r.analysis_mode
           FROM queue.tasks t
           JOIN analysis.observables o ON o.root_id = t.root_id AND o.id = t.observable_id
           JOIN analysis.roots r ON r.id = t.root_id
           WHERE t.id = $1 AND t.state = 'failed'"#,
        id,
        TITLE_LIMIT,
    )
    .fetch_optional(tx.conn())
    .await?
    .ok_or_else(|| no_crash(id))?;
    let paths = sqlx::query_scalar!(
        r#"SELECT path FROM analysis.files WHERE root_id = $1 AND observable_id = $2
           ORDER BY analyzed DESC, depth, path COLLATE "C""#,
        row.root_id,
        row.observable_id,
    )
    .fetch_all(tx.conn())
    .await?;
    let inputs = sqlx::query!(
        r#"SELECT h.sha256 AS "sha256!", s.size AS "size?", s.mime_type AS "mime_type?"
           FROM unnest($1::text[]) WITH ORDINALITY AS h(sha256, n)
           LEFT JOIN store.objects s
             ON s.pool = $2 AND s.sha256 = h.sha256 AND s.state = 'present'
           ORDER BY h.n"#,
        &row.input_hashes,
        ALERT_FILES,
    )
    .fetch_all(tx.conn())
    .await?
    .into_iter()
    .map(|input| CrashInput {
        sha256: input.sha256,
        size: input.size,
        mime_type: input.mime_type,
    })
    .collect();
    Ok(CrashDetail {
        crash: Crash {
            id: row.id,
            root: row.root_id,
            alerted: row.alerted,
            module: row.module,
            observable_id: row.observable_id,
            observable_type: row.r#type,
            observable_value: row.value,
            attempts: row.attempts,
            max_attempts: row.max_attempts,
            error: row.error,
            input_hashes: row.input_hashes,
            created_at: row.created_at,
            failed_at: row.updated_at,
        },
        root_title: row.title,
        analysis_mode: row.analysis_mode,
        paths,
        inputs,
    })
}

impl Service {
    /// A page of failed tasks, newest failure first, of up to `limit` (50 when None, at most
    /// `MAX_CRASHES_PAGE`), after the task `after` names, as ace3 lists its crash reports.
    pub async fn crashes(
        &self,
        actor: &crate::Actor,
        filter: &CrashFilter,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<CrashPage, ServiceError> {
        let limit = match limit.unwrap_or(DEFAULT_CRASHES_PAGE) {
            limit @ 1..=MAX_CRASHES_PAGE => i64::from(limit),
            limit => {
                return Err(ServiceError::InvalidRequest(format!(
                    "a page holds 1 to {MAX_CRASHES_PAGE}, not {limit}"
                )));
            }
        };
        let (root, module) = (filter.root, filter.module.as_deref());
        self.gate
            .read(actor, "crashes", &CRASH_READ, &|tx| {
                Box::pin(async move {
                    if let Some(after) = after {
                        let known = sqlx::query_scalar!(
                            r#"SELECT EXISTS (SELECT FROM queue.tasks
                                              WHERE id = $1 AND state = 'failed') AS "known!""#,
                            after,
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        if !known {
                            return Err(ServiceError::InvalidRequest(format!(
                                "the cursor {after} names no failed task"
                            )));
                        }
                    }
                    let mut crashes: Vec<Crash> = sqlx::query!(
                        r#"SELECT t.id, t.root_id, r.alerted_at IS NOT NULL AS "alerted!", t.module,
                                  t.observable_id, o.type, o.value, t.attempts, t.max_attempts,
                                  coalesce(t.error, '') AS "error!", t.input_hashes, t.created_at,
                                  t.updated_at
                           FROM queue.tasks t
                           JOIN analysis.observables o
                             ON o.root_id = t.root_id AND o.id = t.observable_id
                           JOIN analysis.roots r ON r.id = t.root_id
                           WHERE t.state = 'failed'
                             AND ($2::uuid IS NULL OR t.root_id = $2)
                             AND ($3::text IS NULL OR t.module = $3)
                             AND ($4::bigint IS NULL OR (t.updated_at, t.id) <
                                  (SELECT a.updated_at, a.id FROM queue.tasks a WHERE a.id = $4))
                           ORDER BY t.updated_at DESC, t.id DESC
                           LIMIT $1"#,
                        limit + 1,
                        root,
                        module,
                        after,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| Crash {
                        id: row.id,
                        root: row.root_id,
                        alerted: row.alerted,
                        module: row.module,
                        observable_id: row.observable_id,
                        observable_type: row.r#type,
                        observable_value: row.value,
                        attempts: row.attempts,
                        max_attempts: row.max_attempts,
                        error: row.error,
                        input_hashes: row.input_hashes,
                        created_at: row.created_at,
                        failed_at: row.updated_at,
                    })
                    .collect();
                    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
                    let more = crashes.len() > limit;
                    crashes.truncate(limit);
                    let next = if more {
                        crashes.last().map(|crash| crash.id)
                    } else {
                        None
                    };
                    Ok(CrashPage { crashes, next })
                })
            })
            .await
    }

    /// One failed task, with its root's title, its file's paths and whether the bucket still has each
    /// input.
    pub async fn crash(&self, actor: &crate::Actor, id: i64) -> Result<CrashDetail, ServiceError> {
        self.gate
            .read(actor, "crash", &CRASH_READ, &|tx| {
                Box::pin(async move { detail_in(tx, id).await })
            })
            .await
    }

    /// Lets an actor download what's recorded about a failed task with its inputs, and records that they
    /// did, as ace3 logs a crash report's download. It needs `crash:read`, as ace3's does. The caller
    /// fetches each input from the bucket by its hash; the row is written whether or not the bytes arrive.
    pub async fn download_crash(
        &self,
        actor: &crate::Actor,
        id: i64,
    ) -> Result<CrashDetail, ServiceError> {
        self.gate
            .write(actor, "download_crash", &CRASH_READ, &|tx| {
                Box::pin(async move {
                    let detail = detail_in(tx, id).await?;
                    let change = Change::read(
                        Target::task(id),
                        &CrashRead {
                            root: detail.crash.root,
                            module: &detail.crash.module,
                            inputs: &detail.crash.input_hashes,
                        },
                    )?;
                    Ok(Audited::changed(detail, change))
                })
            })
            .await
    }
}
