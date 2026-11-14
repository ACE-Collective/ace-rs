//! The scheduler (PLAN.md 6.7): ace3's maintenance tasks, which `ace cron run <cadence>`
//! (`ace3/saq/cron_tasks.py`, `ace3/docs/CRON.md`) runs from `etc/cron/<cadence>/` on yacron's
//! schedules in `etc/cron.yaml`, here as tasks of `ace serve`.
//!
//! **What runs.** Of ace3's 25 core tasks (3 hourly, 20 daily, 2 weekly), seven have a counterpart in
//! ace4 now, and run here on ace3's cadence (`Task::builtin`), with one of the cron jobs ace3 runs
//! outside them, `nrd-refresh` (PLAN.md 7.4, `crate::nrd`). `daily/partitions` keeps the email
//! archive's weekly partitions and ace3's analysis result cache's daily ones; ace4 has no result
//! cache, so only the archive's half runs, a run that drops and makes nothing for the cache. A table
//! that needs attention fails the run, with why, as ace3's exits 1:
//!
//! | task | ace3 | schedule | timeout | component and grant |
//! |---|---|---|---|---|
//! | `bucket_gc` | `hourly/cas-gc`, `ace cas gc` | `0 * * * *` | 50 min | `scheduler:bucket_gc`, `bucket:gc` |
//! | `yara_qa_prune` | `daily/yara-qa-prune`, `ace yara-qa prune` | `0 5 * * *` | 1 h | `scheduler:yara_qa_prune`, `signature:qa_purge` |
//! | `bucket_orphans` | `weekly/cas-orphans`, `ace cas orphans` | `0 5 * * 1` | 4 h | `scheduler:bucket_orphans`, `bucket:gc` |
//! | `bucket_verify` | `weekly/cas-verify`, `ace cas verify` | `0 5 * * 1` | 4 h | `scheduler:bucket_verify`, `bucket:verify` |
//! | `email_archive_partitions` | `daily/partitions`, `ace partitions maintain`, its email archive half (PLAN.md 7.5 batch 9) | `0 5 * * *` | 1 h | `scheduler:email_archive_partitions`, `email_archive:maintain` |
//! | `file_collection_prune` | `daily/file-collection-prune`, `ace file-collection prune` (PLAN.md 7.9) | `0 5 * * *` | 1 h | `scheduler:file_collection_prune`, `file_collection:prune` |
//! | `svs_validations_prune` | `daily/svs-validations-prune`, `ace svs yara prune` (PLAN.md 7.10 batch 3) | `0 5 * * *` | 1 h | `scheduler:svs_validations_prune`, `svs:validation_prune` |
//! | `svs_catalog_refresh` | `service_svs`'s catalog refresher, every `svs.catalog.refresh_interval_seconds` (300), `ace svs catalog refresh` (PLAN.md 7.10 batch 4) | `*/5 * * * *` | 25 min | `scheduler:svs_catalog_refresh`, `svs:catalog_refresh` |
//! | `svs_run_timers` | `service_svs`'s run timer, every `svs.runs.timer_interval_seconds` (30), and its maintenance windows' expiry (PLAN.md 7.10 batch 5) | `* * * * *` | 10 min | `scheduler:svs_run_timers`, `svs:run_timers` |
//! | `nrd_refresh` | `etc/cron.yaml`'s `nrd-refresh`, `ace nrd refresh` | `*/30 * * * *` | 25 min | `scheduler:nrd_refresh`, `nrd:refresh` |
//!
//! The rest, and a site's one, wait for the step that brings what they maintain, or mean nothing in
//! ace4; PLAN.md 6.7 lists each with why. ace3's other cron jobs, outside `cron_tasks.py` in `etc/cron.yaml`, are listed
//! there too.
//!
//! **One run across replicas.** ace3 runs every task on every node, and a task that changes shared
//! state does nothing unless `ACE_IS_PRIMARY_NODE` is 1. Here every replica of `ace serve` runs this
//! loop, and a run is claimed in Postgres (`ace_core::scheduler`): a due task's row is taken with
//! `FOR UPDATE SKIP LOCKED`, and the claim moves its due time past now and leases it for the run, so
//! one replica runs each due time, two never run a task at once (yacron's `concurrencyPolicy:
//! Forbid`), and due times missed while the stack was down run once, not once each. A run whose
//! process died keeps its lease for its timeout and a minute, and the next claim marks it
//! `abandoned`. Each run is a row of `scheduler.runs`: when it was due, the node, its start and end,
//! its outcome (`succeeded`, `failed`, `timed_out`, `stopped`, `abandoned`), its error and what it did.
//! ace3 writes each task's outcome to fluent-bit's `cron-jobs` tag and shows it nowhere in its GUI or
//! API, so there's no route for the table; 7.12's monitoring reads it.
//!
//! **Bounds.** Each task runs as a tokio task of its own, so a hung one holds up no other, and each
//! run is stopped at its timeout, which is `timed_out`. At shutdown the running tasks are stopped and
//! recorded `stopped`, and the loop returns within `STOP_WAIT`. Each task's work is in bounded steps
//! (the bucket's batches, S3's and Postgres's own timeouts), so stopping one between them leaves
//! nothing half done that the next run doesn't finish: GC resumes the objects it left `deleting`.
//!
//! **Who acts.** Each task acts as its own internal component, `scheduler:<task>`, through the service
//! layer, holding only the grant migration 0036 gives it (PLAN.md 5.2). The QA prune deletes rows people
//! read, so each of its batches has an audit row; the bucket's tasks have none, and
//! `ace_service`'s `maintenance` docs say why.
//!
//! **Configuration.** The overlay's `scheduler:` section, by task name: `schedule` (five-field cron,
//! UTC, as ace3's containers run with `TZ=UTC`), `timeout_seconds` and `enabled`, each key refused when
//! unknown and each left out keeping the default. A task this build doesn't have logs a warning and is
//! skipped (2.23), and a schedule that doesn't parse stops startup. Replicas should share one overlay:
//! a replica with another schedule for a task works its due time out again.
//!
//! ace3's integrations add tasks with their own `etc/cron/<cadence>/`; a site's binary adds one with
//! `App::scheduled_task`. Its component, `scheduler:<name>`, holds what a grant gives it, and until a
//! site can grant a component (only the core's migrations do now) it holds nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ace_core::bucket::Bucket;
use ace_core::db::Db;
use ace_core::scheduler::{self, Outcome};
use ace_sdk::ScheduledTaskSection;
use ace_service::{Actor, Component, Service};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// How long the loop waits between looking for due tasks: ace3's cron has a minute's grain.
pub const POLL: Duration = Duration::from_secs(15);
/// How long a run's lease outlasts its timeout, for recording its end.
pub const LEASE_MARGIN: Duration = Duration::from_secs(60);
/// How long shutdown waits for the running tasks to stop and their ends to be recorded.
pub const STOP_WAIT: Duration = Duration::from_secs(10);
/// How long recording a run's end may take.
const RECORD_TIMEOUT: Duration = Duration::from_secs(5);

/// What a task's run did: its summary for the run's row, and an error when it found something wrong
/// though it ran to the end, such as a corrupt object, which makes the run `failed`.
#[derive(Debug, Clone, PartialEq)]
pub struct Done {
    pub summary: Value,
    pub error: Option<String>,
}

impl Done {
    pub fn ok(summary: Value) -> Done {
        Done {
            summary,
            error: None,
        }
    }
}

/// What a task gets to run with: the service, the bucket, the component it acts as and the site
/// overlay, such as `nrd_refresh`'s feeds.
#[derive(Clone)]
pub struct TaskContext {
    pub service: Service,
    pub bucket: Bucket,
    pub actor: Actor,
    pub overlay: Arc<ace_sdk::Overlay>,
    /// The email archive's retention, which `email_archive_partitions` keeps.
    pub archive: ace_core::email_archive::ArchiveConfig,
}

/// A run's future.
pub type Run = Pin<Box<dyn Future<Output = Result<Done, String>> + Send>>;

/// A task's body.
pub type Job = Arc<dyn Fn(TaskContext) -> Run + Send + Sync>;

/// A scheduled task with its defaults.
#[derive(Clone)]
pub struct Task {
    /// Its name in the overlay and in `scheduler.tasks`: lowercase letters, digits and `_`.
    pub name: String,
    /// The default schedule, five-field cron in UTC.
    pub schedule: String,
    /// The default timeout.
    pub timeout: Duration,
    pub job: Job,
}

impl Task {
    pub fn new(
        name: &str,
        schedule: &str,
        timeout: Duration,
        job: impl Fn(TaskContext) -> Run + Send + Sync + 'static,
    ) -> Task {
        Task {
            name: name.to_owned(),
            schedule: schedule.to_owned(),
            timeout,
            job: Arc::new(job),
        }
    }

    /// The component the task acts as.
    pub fn component(&self) -> Result<Component, String> {
        Component::new(format!("scheduler:{}", self.name)).map_err(|e| e.to_string())
    }

    /// The core's tasks, on ace3's schedules (the module's docs).
    pub fn builtin() -> Vec<Task> {
        vec![
            Task::new(
                "bucket_gc",
                "0 * * * *",
                Duration::from_secs(50 * 60),
                |ctx| {
                    Box::pin(async move {
                        let done = ctx
                            .service
                            .collect_bucket_garbage(&ctx.actor, &ctx.bucket)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(Done::ok(summary(&done)))
                    })
                },
            ),
            Task::new(
                "yara_qa_prune",
                "0 5 * * *",
                Duration::from_secs(3600),
                |ctx| {
                    Box::pin(async move {
                        let done = ctx
                            .service
                            .prune_qa_matches(&ctx.actor)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(Done::ok(summary(&done)))
                    })
                },
            ),
            Task::new(
                "bucket_orphans",
                "0 5 * * 1",
                Duration::from_secs(4 * 3600),
                |ctx| {
                    Box::pin(async move {
                        let done = ctx
                            .service
                            .remove_bucket_orphans(&ctx.actor, &ctx.bucket)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(Done::ok(summary(&done)))
                    })
                },
            ),
            Task::new(
                "bucket_verify",
                "0 5 * * 1",
                Duration::from_secs(4 * 3600),
                |ctx| {
                    Box::pin(async move {
                        let done = ctx
                            .service
                            .verify_bucket(&ctx.actor, &ctx.bucket)
                            .await
                            .map_err(|e| e.to_string())?;
                        let failed: Vec<String> = done
                            .iter()
                            .filter(|(_, stats)| stats.failed())
                            .map(|(pool, stats)| {
                                format!(
                                    "{pool}: {} missing, {} corrupt",
                                    stats.missing.len(),
                                    stats.corrupt.len()
                                )
                            })
                            .collect();
                        Ok(Done {
                            summary: summary(&done),
                            error: (!failed.is_empty()).then(|| failed.join("; ")),
                        })
                    })
                },
            ),
            Task::new(
                "email_archive_partitions",
                "0 5 * * *",
                Duration::from_secs(3600),
                |ctx| {
                    Box::pin(async move {
                        let done = ctx
                            .service
                            .maintain_email_archive(&ctx.actor, &ctx.archive, Utc::now())
                            .await
                            .map_err(|e| e.to_string())?;
                        let problems: Vec<String> = done
                            .iter()
                            .flat_map(|table| {
                                table
                                    .problems
                                    .iter()
                                    .map(move |p| format!("{}: {p}", table.table))
                            })
                            .collect();
                        Ok(Done {
                            summary: summary(&done),
                            error: (!problems.is_empty()).then(|| problems.join("; ")),
                        })
                    })
                },
            ),
            Task::new(
                "file_collection_prune",
                "0 5 * * *",
                Duration::from_secs(3600),
                |ctx| {
                    Box::pin(async move {
                        let done = ctx
                            .service
                            .prune_file_collections(&ctx.actor)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(Done::ok(summary(&done)))
                    })
                },
            ),
            Task::new(
                "svs_validations_prune",
                "0 5 * * *",
                Duration::from_secs(3600),
                |ctx| {
                    Box::pin(async move {
                        let done = ctx
                            .service
                            .prune_svs_validations(&ctx.actor)
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(Done::ok(summary(&done)))
                    })
                },
            ),
            Task::new(
                "svs_catalog_refresh",
                "*/5 * * * *",
                Duration::from_secs(25 * 60),
                |ctx| {
                    Box::pin(async move {
                        let results = ctx
                            .service
                            .refresh_svs_catalog(&ctx.actor, None, false)
                            .await
                            .map_err(|e| e.to_string())?;
                        // one repository's failure is on its row and in this run's error; the others
                        // were still read
                        let failed: Vec<String> = results
                            .iter()
                            .filter_map(|r| {
                                r.error
                                    .as_ref()
                                    .map(|error| format!("{}: {error}", r.repository))
                            })
                            .collect();
                        let count = |keep: fn(&ace_service::CatalogRefresh) -> bool| {
                            results.iter().filter(|r| keep(r)).count()
                        };
                        Ok(Done {
                            summary: json!({
                                "repositories": count(|r| !r.retired),
                                "refreshed": count(|r| r.refreshed),
                                "retired": count(|r| r.retired && r.error.is_none()),
                                "failed": failed.len(),
                                "added": results.iter().map(|r| r.added).sum::<i64>(),
                                "changed": results.iter().map(|r| r.changed).sum::<i64>(),
                                "removed": results.iter().map(|r| r.removed).sum::<i64>(),
                            }),
                            error: (!failed.is_empty()).then(|| failed.join("; ")),
                        })
                    })
                },
            ),
            Task::new(
                "svs_run_timers",
                "* * * * *",
                Duration::from_secs(10 * 60),
                |ctx| {
                    Box::pin(async move {
                        let done = ctx
                            .service
                            .run_svs_timers(&ctx.actor, chrono::Utc::now())
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok(Done {
                            summary: summary(&done),
                            // each failed move is in the log; the next pass tries it again
                            error: done.first_error.as_ref().map(|first| {
                                format!("{} moves failed, the first: {first}", done.failed)
                            }),
                        })
                    })
                },
            ),
            Task::new(
                "nrd_refresh",
                "*/30 * * * *",
                Duration::from_secs(25 * 60),
                |ctx| {
                    Box::pin(async move {
                        let refresher = crate::nrd::Refresher::new(&ctx.overlay.nrd)?;
                        let done = refresher
                            .refresh(&ctx.service, &ctx.actor, &ctx.overlay.nrd)
                            .await?;
                        Ok(Done::ok(done.summary()))
                    })
                },
            ),
        ]
    }
}

fn summary(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).unwrap_or_else(|e| json!({"unencodable": e.to_string()}))
}

/// A task as the overlay leaves it.
#[derive(Clone)]
pub struct Configured {
    pub task: Task,
    pub schedule: String,
    cron: Arc<croner::Cron>,
    pub timeout: Duration,
    pub enabled: bool,
    actor: Actor,
}

impl Configured {
    /// The schedule's next time after `now`.
    pub fn next(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        self.cron.find_next_occurrence(&now, false).ok()
    }
}

/// The tasks with the overlay's `scheduler:` section over their defaults. A section for a task the
/// binary doesn't have is logged and skipped; a bad name, schedule or timeout is an error.
pub fn configure(
    tasks: &[Task],
    overlay: &BTreeMap<String, ScheduledTaskSection>,
) -> Result<Vec<Configured>, String> {
    for name in overlay.keys() {
        if !tasks.iter().any(|t| &t.name == name) {
            tracing::warn!(
                task = %name,
                "the overlay has a scheduler section for a task this build doesn't have; skipping it"
            );
        }
    }
    let mut seen = BTreeSet::new();
    let mut configured = Vec::new();
    for task in tasks {
        let valid = !task.name.is_empty()
            && task
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !valid || !seen.insert(task.name.as_str()) {
            return Err(format!(
                "scheduled task {:?}: a name is lowercase letters, digits and _, and names one task",
                task.name
            ));
        }
        let section = overlay.get(&task.name).cloned().unwrap_or_default();
        let schedule = section.schedule.unwrap_or_else(|| task.schedule.clone());
        let cron = croner::parser::CronParser::new()
            .parse(&schedule)
            .map_err(|e| format!("scheduler.{}.schedule {schedule:?}: {e}", task.name))?;
        let timeout = match section.timeout_seconds {
            Some(0) => {
                return Err(format!(
                    "scheduler.{}.timeout_seconds: a run needs at least a second",
                    task.name
                ));
            }
            Some(seconds) => Duration::from_secs(seconds),
            None => task.timeout,
        };
        configured.push(Configured {
            actor: Actor::Internal {
                id: task.component()?,
            },
            task: task.clone(),
            schedule,
            cron: Arc::new(cron),
            timeout,
            enabled: section.enabled.unwrap_or(true),
        });
    }
    Ok(configured)
}

/// The loop every `ace serve` replica runs.
pub struct Scheduler {
    pub db: Db,
    pub service: Service,
    pub bucket: Bucket,
    pub tasks: Vec<Configured>,
    /// This process, as its runs' rows name it.
    pub node: String,
    pub poll: Duration,
    pub stop_wait: Duration,
    /// The site overlay the tasks read, such as `nrd_refresh`'s feeds.
    pub overlay: Arc<ace_sdk::Overlay>,
    /// The email archive's retention, for `email_archive_partitions`.
    pub archive: ace_core::email_archive::ArchiveConfig,
}

impl Scheduler {
    pub fn new(db: Db, service: Service, bucket: Bucket, tasks: Vec<Configured>) -> Scheduler {
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "core".to_owned());
        Scheduler {
            db,
            service,
            bucket,
            tasks,
            node: format!("{host}/{}", std::process::id()),
            poll: POLL,
            stop_wait: STOP_WAIT,
            overlay: Arc::default(),
            archive: ace_core::email_archive::ArchiveConfig::default(),
        }
    }

    /// The scheduler with the email archive's retention (`email_archive_partitions`).
    pub fn with_archive(mut self, archive: ace_core::email_archive::ArchiveConfig) -> Scheduler {
        self.archive = archive;
        self
    }

    /// The scheduler with the site overlay its tasks read.
    pub fn with_overlay(mut self, overlay: ace_sdk::Overlay) -> Scheduler {
        self.overlay = Arc::new(overlay);
        self
    }

    /// Runs the due tasks until `stop` fires, then stops the running ones and waits at most
    /// `stop_wait` for their ends to be recorded.
    pub async fn run(self, stop: CancellationToken) {
        let enabled: Vec<Configured> = self.tasks.iter().filter(|t| t.enabled).cloned().collect();
        for task in self.tasks.iter().filter(|t| !t.enabled) {
            tracing::info!(task = %task.task.name, "the overlay turned this scheduled task off");
        }
        let mut ensured = BTreeSet::new();
        let mut running: BTreeSet<String> = BTreeSet::new();
        let mut runs: JoinSet<String> = JoinSet::new();
        let stopping = CancellationToken::new();
        loop {
            for task in &enabled {
                let name = &task.task.name;
                if !ensured.contains(name) {
                    match scheduler::ensure(&self.db, name, &task.schedule, &|now| task.next(now))
                        .await
                    {
                        Ok(()) => {
                            ensured.insert(name.clone());
                        }
                        Err(e) => {
                            tracing::error!(task = %name, "the scheduler can't record the task: {e}");
                            continue;
                        }
                    }
                }
                if running.contains(name) {
                    continue;
                }
                let lease = task.timeout + LEASE_MARGIN;
                let claimed =
                    scheduler::claim(&self.db, name, &self.node, lease, &|now| task.next(now))
                        .await;
                match claimed {
                    Ok(Some(claimed)) => {
                        tracing::info!(
                            task = %name,
                            run = claimed.run,
                            scheduled_for = %claimed.scheduled_for,
                            next_due = %claimed.next_due,
                            "running a scheduled task"
                        );
                        running.insert(name.clone());
                        let context = TaskContext {
                            service: self.service.clone(),
                            bucket: self.bucket.clone(),
                            actor: task.actor.clone(),
                            overlay: self.overlay.clone(),
                            archive: self.archive.clone(),
                        };
                        runs.spawn(run_one(
                            self.db.clone(),
                            task.clone(),
                            claimed.run,
                            context,
                            stopping.clone(),
                        ));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!(task = %name, "claiming a scheduled task failed: {e}")
                    }
                }
            }
            tokio::select! {
                () = stop.cancelled() => break,
                () = tokio::time::sleep(self.poll) => {}
                Some(ended) = runs.join_next(), if !runs.is_empty() => {
                    match ended {
                        Ok(name) => { running.remove(&name); }
                        Err(e) => tracing::error!("a scheduled run's task failed: {e}"),
                    }
                }
            }
            while let Some(ended) = runs.try_join_next() {
                if let Ok(name) = ended {
                    running.remove(&name);
                }
            }
        }
        stopping.cancel();
        let waited = tokio::time::timeout(self.stop_wait, async {
            while runs.join_next().await.is_some() {}
        })
        .await;
        if waited.is_err() {
            tracing::warn!(
                running = ?running,
                "scheduled runs were still recording their ends at the shutdown deadline"
            );
            runs.abort_all();
        }
    }
}

/// Runs one claimed run to its end, its timeout or the stop, and records how it ended. The job runs
/// as a tokio task of its own, so a panic in it is the run's failure, and it's aborted at the
/// timeout or the stop.
async fn run_one(
    db: Db,
    task: Configured,
    run: i64,
    context: TaskContext,
    stop: CancellationToken,
) -> String {
    let name = task.task.name.clone();
    let mut job = tokio::spawn((task.task.job)(context));
    let ended = tokio::select! {
        ended = tokio::time::timeout(task.timeout, &mut job) => match ended {
            Ok(Ok(Ok(done))) => match done.error {
                None => (Outcome::Succeeded, None, Some(done.summary)),
                Some(error) => (Outcome::Failed, Some(error), Some(done.summary)),
            },
            Ok(Ok(Err(error))) => (Outcome::Failed, Some(error), None),
            Ok(Err(e)) => (Outcome::Failed, Some(format!("the task panicked or was cancelled: {e}")), None),
            Err(_) => (
                Outcome::TimedOut,
                Some(format!("it ran past its timeout of {} s", task.timeout.as_secs())),
                None,
            ),
        },
        () = stop.cancelled() => (
            Outcome::Stopped,
            Some("the process was shutting down".to_owned()),
            None,
        ),
    };
    job.abort();
    let (outcome, error, summary) = ended;
    match outcome {
        Outcome::Succeeded => {
            tracing::info!(task = %name, run, summary = %summary.clone().unwrap_or_default(), "a scheduled task succeeded")
        }
        _ => {
            tracing::error!(task = %name, run, outcome = outcome.as_str(), error = error.as_deref().unwrap_or(""), "a scheduled task didn't succeed")
        }
    }
    let recorded = tokio::time::timeout(
        RECORD_TIMEOUT,
        scheduler::finish(&db, &name, run, outcome, error.as_deref(), summary.as_ref()),
    )
    .await;
    match recorded {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => {
            tracing::warn!(task = %name, run, "the run had been marked abandoned before it ended")
        }
        Ok(Err(e)) => tracing::error!(task = %name, run, "recording the run's end failed: {e}"),
        Err(_) => tracing::error!(task = %name, run, "recording the run's end timed out"),
    }
    name
}

#[cfg(test)]
mod tests;
