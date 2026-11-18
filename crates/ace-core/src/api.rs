//! The lease API (PLAN.md 2.14): what a worker calls to lease, renew and end tasks, and to get
//! presigned bucket URLs for its inputs and outputs. A worker holds an API token and nothing
//! else: no database URL and no bucket key.
//!
//! - `POST /api/worker/v1/lease`: tasks of the pool's modules, as a list, or 204 after waiting up
//!   to `wait_seconds` (at most `ApiConfig::max_wait`) for one. The request says how many the
//!   worker can start now (`max`, one when it doesn't say), and the answer holds the oldest that
//!   are due, up to that many and up to `MAX_LEASED_AT_ONCE`. It comes as soon as one is leased
//!   and never waits to fill the list. The tasks are claimed together and each lease is decided
//!   for its task alone (`Api::leased_each`), so one that is held back, delayed, failed or
//!   cancelled there keeps no other out of the answer. A file task carries a presigned URL that
//!   downloads its input. A request that ends before its answer, as when its pool is stopped,
//!   gives back what it had claimed, but for the task whose lease it was deciding (`InHand`).
//! - `POST /api/worker/v1/tasks/<id>/renew`: extends the lease; the answer says whether the
//!   task was cancelled.
//! - `POST /api/worker/v1/tasks/<id>/uploads`: a presigned URL to upload one file the module
//!   wrote, under the task's own key in the bucket.
//! - `POST /api/worker/v1/tasks/<id>/end`: the task's end, a `TaskEnd`. A result's files must
//!   be uploaded first; the core checks each one's bytes against its sha256 and moves it into
//!   the `alert_files` pool, held by the root. A result that fails its check is answered 422 with
//!   each field that failed, and that ends the task as failed, because the same module would write
//!   the same result again. The row's error says why. A result or a skip also carries the writes
//!   to ACE's data the task made (PLAN.md 7.2, `writes.rs`), which land in the end's transaction;
//!   one the module doesn't declare, past its bound or about another email is refused with 403,
//!   and one that doesn't read with 400, failing the task with nothing written.
//!
//! - `POST /api/worker/v1/tasks/<id>/release`: gives the task back to the queue without
//!   counting the attempt, as a pool does at shutdown.
//! - `GET /api/worker/v1/yara/ruleset`: the ruleset YARA pools should scan with, the latest the
//!   core built (PLAN.md 2.26), with a presigned URL for its bytes; 204 before the first build.
//! - `POST /api/worker/v1/commands/lease`: a GUI command (PLAN.md 5.12), for a pool whose list in
//!   `ACE4_POOLS` has `@commands`, or 204 after waiting. Its claim starts its clock, and the answer says
//!   how long it has until its deadline.
//! - `POST /api/worker/v1/commands/<id>/report`: the command's output so far, which renews its lease; the
//!   answer says whether it was cancelled.
//! - `POST /api/worker/v1/commands/<id>/end`: how the command ended, with all it wrote.
//! - `POST /api/worker/v1/scans/lease`: a scan (PLAN.md 7.7, `scans.rs`) of a scanner the pool's list in
//!   `ACE4_POOLS` names as `@scan/<scanner>`, or 204 after waiting, with a presigned URL for each input.
//!   Its claim starts its clock, and the answer says how long it has until its deadline.
//! - `POST /api/worker/v1/scans/<id>/renew`: extends the scan's lease; the answer says whether its root
//!   was cancelled.
//! - `POST /api/worker/v1/scans/<id>/upload`: a presigned URL to upload the scan's output archive.
//! - `POST /api/worker/v1/scans/<id>/end`: how the scan ended, a `ScanEnd`. Its output archive must be
//!   uploaded first; the core checks its bytes against its sha256, puts it in `alert_files` held by
//!   the root, and wakes the task. A task's delay can carry the scan it waits for (`TaskEnd::Delay`):
//!   each input the module wrote is uploaded first, as a result's files are.
//! - `POST /api/worker/v1/actions/lease`: an action (PLAN.md 7.9, `actions.rs`) of a handler the pool's
//!   list in `ACE4_POOLS` names as `@<kind>/<name>`, or 204 after waiting. An action past its deadline,
//!   or a check another source confirmed first, is ended here without being handed out.
//! - `POST /api/worker/v1/actions/<id>/renew`: extends the action's lease; the answer says whether
//!   someone cancelled it, in which case the pool sends no end.
//! - `POST /api/worker/v1/actions/<id>/upload`: a presigned URL to upload the file a collection fetched.
//! - `POST /api/worker/v1/actions/<id>/end`: how the try went, an `ActionEnd`. A collected file must be
//!   uploaded first; the core checks its bytes against its sha256 and puts it in `alert_files`, held by
//!   the collection and by each alert it's for.
//! - `GET /api/admin/v1/tasks/<id>/replay`: any task in its leased form, with a fresh download
//!   URL, for `ace task replay`. It takes the admin token, and takes no lease.
//! - `GET /healthz`: 200 when the database answers, for the stack's healthcheck. It takes no
//!   token.
//!
//! Submissions moved to `ace-api` in PLAN.md 5.5, which serves people on a listener of its own.
//!
//! - `POST /api/worker/v1/tasks/<id>/reads/<read>`: a read of ACE's own data for a lookup module
//!   (PLAN.md 7.2), which ace3's modules query its databases for. `reads.md` beside this file is the
//!   contract, and `reads.rs` serves the reads built so far. 401 for an unknown token, 400 without
//!   a worker or with a body that doesn't read, 409 unless the task is leased to the worker now,
//!   403 for a read the module doesn't declare or a subject outside the task's root, 503 when the
//!   store behind it is down.
//! - `POST /api/admin/v1/tasks/<id>/reads/<read>`: the same for `ace task replay`, with the admin
//!   token and no lease.
//!
//! Every request carries `Authorization: Bearer <token>`, and the token says which pool the
//! worker is in. A task-scoped request also names the worker in `x-ace4-worker`. A task's lease
//! owner is `<pool>/<worker>`, so one pool's token can't touch another pool's tasks, and one
//! worker can't end another worker's.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ace_results::{AlertPath, ObservableKind, ObservableRef, ResultEnvelope, Sha256, YaraMeta};
use ace_sdk::wire::{
    ApiError, COMMANDS, CarryingEmail, CommandEnd, CommandLeaseRequest, CommandOutcome,
    CommandReply, CommandReport, CurrentRuleset, EmailBodyPart, FieldError as WireFieldError,
    LeaseRequest, LeasedCommand, LeasedTask, MAX_LEASED_AT_ONCE, Presigned, Renewal, TaskEnd,
    TaskFile, TaskObservable, UploadRequest, paths,
};
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use opentelemetry::propagation::{Extractor, TextMapPropagator};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use serde_json::Value;
use sha2::Digest;
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::actions::{ActionCatalog, ActionError, ActionWorker};
use crate::bucket::{ALERT_FILES, Bucket, BucketError, Hold};
use crate::commands::{CommandState, CommandWorker};
use crate::db::{Db, DbError, Isolation, Retryable};
use crate::lists::ListCache;
use crate::orchestrator::{Orchestrator, OrchestratorError, Rejected};
use crate::queue::{HELD_BACK_BY, QueueError, TASKS_CHANNEL, Task, TaskId, Worker};
use crate::scans::{EndedScan, ScanRowState, ScanWorker};
use crate::tree;

/// What a pool's list in `ACE4_POOLS` names a scanner it runs with (`ace_sdk::scanners::pool_entry`).
const SCAN_PREFIX: &str = "@scan/";

/// The header a task-scoped request names its worker in.
pub const WORKER_HEADER: &str = "x-ace4-worker";

/// How long a task that runs last first waits for the rest of its root, doubling up to 32 s while the
/// same thing holds it back (`tree::HeldBack`). Every file has one, so it starts low: most roots are
/// done in a moment. A task that waits for every other module is also woken when the last of them
/// ends (`queue::check_completion`), so this is how soon it asks again while they run, and the
/// fallback when nothing wakes it.
const OTHERS_PENDING_DELAY: Duration = Duration::from_millis(250);

/// How long a file's first task is held, at most, while something nearer the root that could add
/// the file under another path is pending (`Api::held_for_path`). Past it the file is analyzed under
/// the best path it has, so a slow module can't stall the root. Most holds end in under a second.
const PATH_HOLD_LIMIT: Duration = Duration::from_secs(60);

/// A held task waits half as long again as its file has, within these bounds, so a quick root
/// goes on at once and a slow one isn't polled for nothing.
const PATH_HOLD_MIN: Duration = Duration::from_millis(100);
const PATH_HOLD_MAX: Duration = Duration::from_secs(2);

/// Whether reading a file task's record settles the file's path (`Api::task_file`).
#[derive(Debug, Clone, Copy)]
enum Choose {
    Settle,
    Read,
}

/// The target of the lease's timing events: one a claimed task from the core and one a lease request
/// from a pool, at debug, so `ACE4_LOG=info,ace_lease=debug` turns them on
/// (`docs/measurements/lease.md`).
pub const LEASE_TIMING: &str = "ace_lease";

/// Where the core's time went on one claimed task, in microseconds, for its timing event.
#[derive(Debug, Default, Clone, Copy)]
struct LeaseTimes {
    /// The path hold's decision.
    path: u64,
    /// The file's record, its path settled, and its download URL.
    file: u64,
    /// Whether a task that runs last is held back, and its delay when it is.
    last: u64,
    /// The carrying email and everything the task reads of its root's tree.
    reads: u64,
}

/// The tasks a lease request has claimed and not answered with yet. Dropped with any left, it
/// gives them back to the queue, each claim uncounted, as a pool gives its leases back when it
/// stops (`Worker::release`): the request ended before its answer, so no pool holds them.
///
/// All but the task whose lease was being decided when the request ended. That one keeps its
/// lease until it runs out, as the one task of a request that ended did before, with its claim
/// counted: a request also ends when a decision panics, and a task whose decision panics every
/// time must use up its attempts and fail, not be claimed again for ever ahead of the others.
struct InHand {
    worker: Worker,
    tasks: Vec<TaskId>,
    deciding: Option<TaskId>,
}

impl Drop for InHand {
    fn drop(&mut self) {
        let mut tasks = std::mem::take(&mut self.tasks);
        tasks.retain(|task| Some(*task) != self.deciding);
        if tasks.is_empty() {
            return;
        }
        let worker = self.worker.clone();
        // outside a runtime, as when the server is torn down, their leases run out instead
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            for task in tasks {
                match worker.release(task).await {
                    Ok(()) => {
                        tracing::info!(%task, "gave back a task its lease request never answered with");
                    }
                    // the core held it back, delayed it or failed it before the request ended
                    Err(QueueError::LeaseLost(_)) => {}
                    Err(e) => tracing::warn!(%task, "giving back an unanswered task failed: {e}"),
                }
            }
        });
    }
}

/// The microseconds since `since`, and `since` moved to now.
fn lap(since: &mut std::time::Instant) -> u64 {
    let now = std::time::Instant::now();
    let micros = u64::try_from(now.duration_since(*since).as_micros()).unwrap_or(u64::MAX);
    *since = now;
    micros
}

/// A pool's access to the API: its name, the hash of its token and the modules it may lease.
#[derive(Clone)]
pub struct PoolAccess {
    pub name: String,
    token_sha256: [u8; 32],
    pub modules: Vec<String>,
    /// It runs GUI commands (PLAN.md 5.12): its list has `@commands` (`ace_sdk::wire::COMMANDS`).
    pub commands: bool,
    /// The scanners it runs (PLAN.md 7.7): its list has `@scan/<scanner>` for each.
    pub scanners: Vec<String>,
    /// The action handlers it runs (PLAN.md 7.9): its list has `@<kind>/<name>` for each.
    pub actions: Vec<(ace_sdk::actions::ActionKind, String)>,
}

impl PoolAccess {
    /// A pool that runs `modules`, and GUI commands when they include `@commands`.
    pub fn new(name: impl Into<String>, token: &str, mut modules: Vec<String>) -> Self {
        let commands = modules.iter().any(|m| m == COMMANDS);
        modules.retain(|m| m != COMMANDS);
        let scanners = modules
            .iter()
            .filter_map(|m| m.strip_prefix(SCAN_PREFIX))
            .map(str::to_owned)
            .collect();
        modules.retain(|m| !m.starts_with(SCAN_PREFIX));
        let actions = modules
            .iter()
            .filter_map(|m| ace_sdk::actions::parse_pool_entry(m))
            .collect();
        modules.retain(|m| ace_sdk::actions::parse_pool_entry(m).is_none());
        PoolAccess {
            name: name.into(),
            token_sha256: sha256(token),
            modules,
            commands,
            scanners,
            actions,
        }
    }
}

impl std::fmt::Debug for PoolAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolAccess")
            .field("name", &self.name)
            .field("modules", &self.modules)
            .field("commands", &self.commands)
            .field("scanners", &self.scanners)
            .field("actions", &self.actions)
            .finish_non_exhaustive()
    }
}

fn sha256(token: &str) -> [u8; 32] {
    sha2::Sha256::digest(token.as_bytes()).into()
}

/// The pools and limits the API serves.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub pools: Vec<PoolAccess>,
    /// The hash of the token for admin calls, such as `ace task replay`. None turns them off.
    admin_token_sha256: Option<[u8; 32]>,
    /// The largest task end, a result's details and text included. A file's bytes go to the bucket
    /// and don't count. A hostile file can choose how much text its result holds: a task past this
    /// fails at once, and its row says why.
    pub max_end_bytes: usize,
    /// How long a lease, and each renewal, lasts.
    pub lease: Duration,
    /// The longest a lease request waits for a task.
    pub max_wait: Duration,
    /// How long a presigned URL works.
    pub url_expiry: Duration,
    /// The snort and suricata rules the `snort-signature` read answers from (PLAN.md 7.4), ace3's
    /// `data/snort/snort.rules`. None answers every one with no rule.
    pub snort_rules: Option<std::path::PathBuf>,
    /// The email archive's key and retention (PLAN.md 7.5 batch 9), which its reads and its write
    /// use. The default has no key: the core archives and opens nothing.
    pub archive: crate::email_archive::ArchiveConfig,
    /// The action handlers the binary has (PLAN.md 7.9), which decide an action's tries.
    pub actions: ActionCatalog,
    /// The dispositions the site classifies `tp` or `fp`, which the `svs-capture-state` read answers
    /// with (PLAN.md 7.10). ace3's by default; `ace serve` sets the overlay's.
    pub classified: std::collections::BTreeSet<String>,
}

impl ApiConfig {
    pub fn new(pools: Vec<PoolAccess>) -> Self {
        ApiConfig {
            pools,
            admin_token_sha256: None,
            max_end_bytes: 64 << 20,
            lease: Duration::from_secs(60),
            max_wait: Duration::from_secs(20),
            url_expiry: Duration::from_secs(900),
            snort_rules: None,
            archive: crate::email_archive::ArchiveConfig::default(),
            actions: ActionCatalog::default(),
            classified: ace_sdk::ACE3_DISPOSITION_CLASSES
                .iter()
                .map(|(name, _)| (*name).to_owned())
                .collect(),
        }
    }

    /// The dispositions the site classifies `tp` or `fp` (`ace_service`'s `Dispositions`).
    pub fn classified(mut self, names: impl IntoIterator<Item = String>) -> Self {
        self.classified = names.into_iter().collect();
        self
    }

    pub fn actions(mut self, actions: ActionCatalog) -> Self {
        self.actions = actions;
        self
    }

    pub fn archive(mut self, archive: crate::email_archive::ArchiveConfig) -> Self {
        self.archive = archive;
        self
    }

    pub fn snort_rules(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.snort_rules = Some(path.into());
        self
    }

    pub fn admin_token(mut self, token: &str) -> Self {
        self.admin_token_sha256 = Some(sha256(token));
        self
    }

    pub fn lease(mut self, lease: Duration) -> Self {
        self.lease = lease;
        self
    }

    /// The pools in `ACE4_POOLS`, as `<pool>:<module>,<module>;<pool>:...`, each with the
    /// token in `ACE4_POOL_TOKEN_<POOL>`, the admin token in `ACE4_ADMIN_TOKEN`, and the lease's
    /// length in `ACE4_LEASE_SECONDS` (60), and the snort rules in `ACE4_SNORT_RULES`. Each has a
    /// dev default: `default_pools`, the binary's own pools and their modules in the same form,
    /// and tokens named `ace4-dev-<pool>-token`.
    pub fn from_env(default_pools: &str) -> Self {
        let pools = std::env::var("ACE4_POOLS").unwrap_or_else(|_| default_pools.to_owned());
        let pools = pools
            .split(';')
            .filter_map(|pool| pool.split_once(':'))
            .map(|(name, modules)| {
                let name = name.trim();
                let token = std::env::var(format!("ACE4_POOL_TOKEN_{}", name.to_uppercase()))
                    .unwrap_or_else(|_| format!("ace4-dev-{name}-token"));
                let modules = modules
                    .split(',')
                    .map(|m| m.trim().to_owned())
                    .filter(|m| !m.is_empty())
                    .collect();
                PoolAccess::new(name, &token, modules)
            })
            .collect();
        let admin =
            std::env::var("ACE4_ADMIN_TOKEN").unwrap_or_else(|_| "ace4-dev-admin-token".to_owned());
        let mut config = ApiConfig::new(pools).admin_token(&admin);
        if let Some(seconds) = std::env::var("ACE4_LEASE_SECONDS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            config = config.lease(Duration::from_secs(seconds));
        }
        if let Some(path) = std::env::var_os("ACE4_SNORT_RULES").filter(|p| !p.is_empty()) {
            config = config.snort_rules(path);
        }
        config
    }

    /// Lets each pool lease every instance of a module it lists (PLAN.md 2.23): a pool's list in
    /// `ACE4_POOLS` names module types, and an instance's tasks carry the instance's key.
    pub fn with_instances(mut self, catalog: &crate::eligibility::Catalog) -> Self {
        for pool in &mut self.pools {
            for component in catalog.iter() {
                if pool.modules.iter().any(|m| m == component.manifest.name)
                    && !pool.modules.contains(&component.key)
                {
                    pool.modules.push(component.key.clone());
                }
            }
        }
        self
    }
}

/// The lease API's state, cheap to clone into each request.
#[derive(Clone)]
pub struct Api {
    inner: Arc<Inner>,
}

struct Inner {
    db: Db,
    bucket: Bucket,
    orchestrator: Arc<Orchestrator>,
    config: ApiConfig,
    /// The module of each task that became claimable, or `*` when the listener reconnected and
    /// may have missed some.
    wakeups: broadcast::Sender<String>,
    listener: JoinHandle<()>,
    /// Fires at shutdown, so waiting lease requests answer at once.
    stopping: tokio_util::sync::CancellationToken,
    /// The analyst-edited lists, as of the newest version a lease has read (PLAN.md 5.14).
    lists: ListCache,
    /// What the reads read besides the database (PLAN.md 7.2).
    stores: crate::reads::ReadStores,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

impl Api {
    /// The API, with one listener on the queue's notifications for every waiting lease.
    pub async fn new(
        db: Db,
        bucket: Bucket,
        orchestrator: Orchestrator,
        config: ApiConfig,
    ) -> Result<Api, QueueError> {
        let config_snort_rules = config.snort_rules.clone();
        let classified = config.classified.clone();
        let archive = crate::email_archive::EmailArchive::new(
            db.clone(),
            bucket.clone(),
            config.archive.clone(),
        );
        let mut listener = PgListener::connect_with(db.pool()).await?;
        listener.listen(TASKS_CHANNEL).await?;
        let (wakeups, _) = broadcast::channel(1024);
        let sender = wakeups.clone();
        let listener = tokio::spawn(async move {
            loop {
                let module = match listener.try_recv().await {
                    Ok(Some(notification)) => notification.payload().to_owned(),
                    Ok(None) => "*".to_owned(),
                    Err(e) => {
                        tracing::warn!("the lease API's queue listener failed: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        "*".to_owned()
                    }
                };
                // no receivers is fine: nobody is waiting
                if sender.send(module).is_err() {
                    tracing::trace!("a wakeup with no lease waiting");
                }
            }
        });
        Ok(Api {
            inner: Arc::new(Inner {
                db,
                bucket,
                orchestrator: Arc::new(orchestrator),
                config,
                wakeups,
                listener,
                stopping: tokio_util::sync::CancellationToken::new(),
                lists: ListCache::default(),
                stores: crate::reads::ReadStores::new(config_snort_rules)
                    .with_archive(archive)
                    .with_classified(classified),
            }),
        })
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    /// Ends every waiting lease request with no task, as at shutdown, so the server's
    /// graceful stop doesn't wait out their waits.
    pub fn shut_down(&self) {
        self.inner.stopping.cancel();
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route(paths::LEASE, post(lease))
            .route("/api/worker/v1/tasks/{id}/renew", post(renew))
            .route("/api/worker/v1/tasks/{id}/uploads", post(uploads))
            .route(
                "/api/worker/v1/tasks/{id}/end",
                post(end).layer(axum::extract::DefaultBodyLimit::max(
                    self.inner.config.max_end_bytes,
                )),
            )
            .route("/api/worker/v1/tasks/{id}/release", post(release))
            .route("/api/worker/v1/tasks/{id}/reads/{read}", post(read))
            .route("/api/admin/v1/tasks/{id}/reads/{read}", post(replay_read))
            .route(paths::COMMAND_LEASE, post(lease_command))
            .route(
                "/api/worker/v1/commands/{id}/report",
                post(report_command).layer(axum::extract::DefaultBodyLimit::max(MAX_COMMAND_BODY)),
            )
            .route(
                "/api/worker/v1/commands/{id}/end",
                post(end_command).layer(axum::extract::DefaultBodyLimit::max(MAX_COMMAND_BODY)),
            )
            .route(ace_sdk::scanners::paths::LEASE, post(lease_scan))
            .route("/api/worker/v1/scans/{id}/renew", post(renew_scan))
            .route("/api/worker/v1/scans/{id}/upload", post(upload_scan))
            .route("/api/worker/v1/scans/{id}/end", post(end_scan))
            .route(ace_sdk::actions::paths::LEASE, post(lease_action))
            .route("/api/worker/v1/actions/{id}/renew", post(renew_action))
            .route("/api/worker/v1/actions/{id}/upload", post(upload_action))
            .route(
                "/api/worker/v1/actions/{id}/end",
                post(end_action).layer(axum::extract::DefaultBodyLimit::max(MAX_ACTION_END_BYTES)),
            )
            .route(paths::RULESET, get(current_ruleset))
            .route("/api/admin/v1/tasks/{id}/replay", get(replay))
            .route("/healthz", get(health))
            .with_state(self.clone())
    }

    fn pool(&self, headers: &HeaderMap) -> Result<&PoolAccess, Failure> {
        let token = bearer(headers).ok_or(Failure::Unauthorized)?;
        let hash = sha256(token);
        self.inner
            .config
            .pools
            .iter()
            .find(|pool| pool.token_sha256 == hash)
            .ok_or(Failure::Unauthorized)
    }

    /// The worker a task-scoped request comes from, owning tasks as `<pool>/<worker>`.
    fn worker(&self, headers: &HeaderMap) -> Result<Worker, Failure> {
        let pool = self.pool(headers)?;
        let name = headers
            .get(WORKER_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| Failure::BadRequest(format!("no {WORKER_HEADER} header")))?;
        Ok(self.pool_worker(pool, name, pool.modules.clone()))
    }

    fn pool_worker(&self, pool: &PoolAccess, name: &str, modules: Vec<String>) -> Worker {
        Worker::new(
            self.inner.db.clone(),
            format!("{}/{name}", pool.name),
            modules,
            self.inner.config.lease,
        )
        .with_type_step(self.inner.orchestrator.clone())
    }

    /// The orchestrator, as what follows a file's type step for the reaper (`queue::run_reaper`).
    pub fn type_step_ended(&self) -> Arc<dyn crate::queue::TypeStepEnded> {
        self.inner.orchestrator.clone()
    }

    /// The pool a command request comes from, as a command worker named by `x-ace4-worker` or `name`.
    fn command_worker(
        &self,
        headers: &HeaderMap,
        name: Option<&str>,
    ) -> Result<CommandWorker, Failure> {
        let pool = self.pool(headers)?;
        if !pool.commands {
            return Err(Failure::Forbidden(format!(
                "pool {} doesn't run commands",
                pool.name
            )));
        }
        let name = match name {
            Some(name) => name,
            None => headers
                .get(WORKER_HEADER)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Failure::BadRequest(format!("no {WORKER_HEADER} header")))?,
        };
        if name.is_empty() {
            return Err(Failure::BadRequest("no worker name".to_owned()));
        }
        Ok(CommandWorker::new(
            self.inner.db.clone(),
            format!("{}/{name}", pool.name),
            self.inner.config.lease,
        ))
    }

    /// The pool a scan request comes from, as a scan worker named by `x-ace4-worker` or `name`, and
    /// the scanners it runs.
    fn scan_worker(
        &self,
        headers: &HeaderMap,
        name: Option<&str>,
    ) -> Result<(ScanWorker, Vec<String>), Failure> {
        let pool = self.pool(headers)?;
        if pool.scanners.is_empty() {
            return Err(Failure::Forbidden(format!(
                "pool {} runs no scanner",
                pool.name
            )));
        }
        let name = match name {
            Some(name) => name,
            None => headers
                .get(WORKER_HEADER)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Failure::BadRequest(format!("no {WORKER_HEADER} header")))?,
        };
        if name.is_empty() {
            return Err(Failure::BadRequest("no worker name".to_owned()));
        }
        Ok((
            ScanWorker::new(
                self.inner.db.clone(),
                format!("{}/{name}", pool.name),
                self.inner.config.lease,
            ),
            pool.scanners.clone(),
        ))
    }

    /// The pool an action request comes from, as an action worker named by `x-ace4-worker` or `name`,
    /// and the handlers it runs.
    #[allow(clippy::type_complexity)]
    fn action_worker(
        &self,
        headers: &HeaderMap,
        name: Option<&str>,
    ) -> Result<(ActionWorker, Vec<(ace_sdk::actions::ActionKind, String)>), Failure> {
        let pool = self.pool(headers)?;
        if pool.actions.is_empty() {
            return Err(Failure::Forbidden(format!(
                "pool {} runs no action handler",
                pool.name
            )));
        }
        let name = match name {
            Some(name) => name,
            None => headers
                .get(WORKER_HEADER)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| Failure::BadRequest(format!("no {WORKER_HEADER} header")))?,
        };
        if name.is_empty() {
            return Err(Failure::BadRequest("no worker name".to_owned()));
        }
        Ok((
            ActionWorker::new(
                self.inner.db.clone(),
                format!("{}/{name}", pool.name),
                self.inner.config.lease,
                self.inner.config.actions.clone(),
            ),
            pool.actions.clone(),
        ))
    }

    /// Claims an action of `handlers` for `worker`, waiting up to `wait` for one.
    async fn lease_action_for(
        &self,
        worker: &ActionWorker,
        handlers: &[(ace_sdk::actions::ActionKind, String)],
        wait: Duration,
    ) -> Result<Option<ace_sdk::actions::LeasedAction>, Failure> {
        let mut wakeups = self.inner.wakeups.subscribe();
        let deadline = tokio::time::Instant::now() + wait;
        let payloads: Vec<String> = handlers
            .iter()
            .map(|(kind, name)| ace_sdk::actions::pool_entry(*kind, name))
            .collect();
        loop {
            if let Some(action) = worker.claim(handlers).await? {
                return Ok(Some(action));
            }
            if self.inner.stopping.is_cancelled() {
                return Ok(None);
            }
            let sleep = tokio::time::sleep_until(deadline);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    () = &mut sleep => return Ok(None),
                    () = self.inner.stopping.cancelled() => return Ok(None),
                    woken = wakeups.recv() => match woken {
                        Ok(payload) if payload == "*" || payloads.contains(&payload) => break,
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => break,
                        Err(broadcast::error::RecvError::Closed) => {
                            (&mut sleep).await;
                            return Ok(None);
                        }
                    },
                }
            }
        }
    }

    /// Claims a scan of `scanners` for `worker`, waiting up to `wait` for one.
    async fn lease_scan_for(
        &self,
        worker: &ScanWorker,
        scanners: &[String],
        wait: Duration,
    ) -> Result<Option<ace_sdk::scanners::LeasedScan>, Failure> {
        let mut wakeups = self.inner.wakeups.subscribe();
        let deadline = tokio::time::Instant::now() + wait;
        let payloads: Vec<String> = scanners
            .iter()
            .map(|s| ace_sdk::scanners::pool_entry(s))
            .collect();
        loop {
            if let Some(scan) = worker.claim(scanners).await? {
                let mut inputs = Vec::new();
                for input in scan.inputs {
                    let download = self
                        .inner
                        .bucket
                        .store()
                        .presign_get(ALERT_FILES, &input.sha256, self.inner.config.url_expiry)
                        .await
                        .map_err(BucketError::from)?;
                    inputs.push(ace_sdk::scanners::LeasedScanInput {
                        name: input.name,
                        sha256: input.sha256,
                        size: input.size,
                        download: wire_presigned(download),
                    });
                }
                return Ok(Some(ace_sdk::scanners::LeasedScan {
                    id: scan.id,
                    scanner: scan.scanner,
                    args: scan.args,
                    inputs,
                    timeout_seconds: scan.timeout_seconds,
                    deadline_seconds: scan.deadline_in.as_secs_f64(),
                    lease_seconds: worker.lease().as_secs_f64(),
                }));
            }
            if self.inner.stopping.is_cancelled() {
                return Ok(None);
            }
            let sleep = tokio::time::sleep_until(deadline);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    () = &mut sleep => return Ok(None),
                    () = self.inner.stopping.cancelled() => return Ok(None),
                    woken = wakeups.recv() => match woken {
                        Ok(payload) if payload == "*" || payloads.contains(&payload) => break,
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => break,
                        Err(broadcast::error::RecvError::Closed) => {
                            (&mut sleep).await;
                            return Ok(None);
                        }
                    },
                }
            }
        }
    }

    /// The task's latest scan, as its lease carries it, with a download for its output.
    async fn task_scan(&self, task: &Task) -> Result<Option<ace_sdk::scanners::WireScan>, Failure> {
        let declares = self
            .inner
            .orchestrator
            .catalog()
            .get(&task.module)
            .is_some_and(|m| !m.scanners.is_empty());
        if !declares {
            return Ok(None);
        }
        let Some(scan) = crate::scans::latest_for_task(&self.inner.db, task.id).await? else {
            return Ok(None);
        };
        let output = match scan.output {
            Some((sha256, size)) => {
                let download = self
                    .inner
                    .bucket
                    .store()
                    .presign_get(ALERT_FILES, &sha256, self.inner.config.url_expiry)
                    .await
                    .map_err(BucketError::from)?;
                Some(ace_sdk::scanners::WireScanOutput {
                    sha256,
                    size,
                    download: wire_presigned(download),
                })
            }
            None => None,
        };
        Ok(Some(ace_sdk::scanners::WireScan {
            id: scan.id,
            scanner: scan.scanner,
            state: scan.state.for_module(),
            exit_code: scan.exit_code,
            error: scan.error,
            output,
        }))
    }

    /// Delays a task the worker owns and queues the scan it waits for (PLAN.md 7.7), in one
    /// transaction. The module must declare the scanner, the request must fit its spec, and each
    /// input must be the task's own file or one the worker uploaded for it, which goes into
    /// `alert_files` held by the root. A request that doesn't is refused, and fails the task.
    async fn delay_for_scan(
        &self,
        worker: &Worker,
        task: TaskId,
        after: Duration,
        state: &Value,
        request: &ace_sdk::scanners::ScanRequest,
    ) -> Result<(), Failure> {
        let owned = worker.owned(task).await?.ok_or(Failure::LeaseLost(task))?;
        let declared = self
            .inner
            .orchestrator
            .catalog()
            .get(&owned.module)
            .is_some_and(|m| m.scanners.contains(&request.scanner.as_str()));
        let refusal = if !declared {
            Some(format!(
                "{} doesn't declare the scanner {:?}",
                owned.module, request.scanner
            ))
        } else {
            match ace_sdk::scanners::find(ace_sdk::scanners::SCANNERS, &request.scanner) {
                None => Some(format!("no scanner is called {:?}", request.scanner)),
                Some(spec) if u64::from(request.timeout_seconds) > spec.max_timeout.as_secs() => {
                    Some(format!(
                        "a timeout of {} seconds, past {}'s {} seconds",
                        request.timeout_seconds,
                        spec.name,
                        spec.max_timeout.as_secs()
                    ))
                }
                Some(_) => request.refusal(),
            }
        };
        if let Some(why) = refusal {
            let error = format!("the scan request was refused: {why}");
            tracing::error!(%task, "{error}");
            worker.fail(task, &error).await?;
            return Err(Failure::Forbidden(error));
        }
        let own = (owned.observable.kind == ObservableKind::File)
            .then(|| owned.observable.value.parse::<Sha256>().ok())
            .flatten();
        let bucket = &self.inner.bucket;
        let mut files = Vec::new();
        for input in &request.inputs {
            if Some(input.sha256) == own || files.iter().any(|(sha, _)| *sha == input.sha256) {
                continue;
            }
            files.push((
                input.sha256,
                bucket.fetch_upload(task.0, &input.sha256).await?,
            ));
        }
        let hold = Hold::root(owned.root);
        let (files, hold) = (&files, &hold);
        let queued = self
            .inner
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    let Some((_, root)) = worker.delay_in(tx, task, after, state).await? else {
                        return Ok::<_, LandError>(None);
                    };
                    for (_, spooled) in files {
                        bucket.put_in(tx, ALERT_FILES, spooled, Some(hold)).await?;
                    }
                    Ok(Some(crate::scans::queue(tx, task, root, request).await?))
                })
            })
            .await?;
        for (sha256, _) in files {
            bucket.remove_upload(task.0, sha256).await?;
        }
        match queued {
            Some(scan) => {
                tracing::info!(%task, scan, scanner = %request.scanner, "queued a scan");
                Ok(())
            }
            None => Err(QueueError::Cancelled(task).into()),
        }
    }

    /// Claims a command for `worker`, waiting up to `wait` for one.
    async fn lease_command_for(
        &self,
        worker: &CommandWorker,
        wait: Duration,
    ) -> Result<Option<LeasedCommand>, Failure> {
        let mut wakeups = self.inner.wakeups.subscribe();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(command) = worker.claim().await? {
                return Ok(Some(LeasedCommand {
                    id: command.id,
                    argv: command.argv,
                    timeout_seconds: command.timeout_seconds,
                    deadline_seconds: command.deadline_in.as_secs_f64(),
                    lease_seconds: worker.lease().as_secs_f64(),
                }));
            }
            if self.inner.stopping.is_cancelled() {
                return Ok(None);
            }
            let sleep = tokio::time::sleep_until(deadline);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    () = &mut sleep => return Ok(None),
                    () = self.inner.stopping.cancelled() => return Ok(None),
                    woken = wakeups.recv() => match woken {
                        Ok(payload) if payload == "*" || payload == COMMANDS => break,
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => break,
                        Err(broadcast::error::RecvError::Closed) => {
                            (&mut sleep).await;
                            return Ok(None);
                        }
                    },
                }
            }
        }
    }

    /// Claims tasks for `worker`, `most` at most, waiting up to `wait` for the first. It answers as
    /// soon as one is leased, with as many as were due then, and never waits to fill the list: the
    /// worker asked for what it can start now, and a task that isn't due yet is for whoever is free
    /// when it is.
    async fn lease_for(
        &self,
        worker: &Worker,
        wait: Duration,
        most: usize,
    ) -> Result<Vec<LeasedTask>, Failure> {
        let mut wakeups = self.inner.wakeups.subscribe();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let mut clock = std::time::Instant::now();
            let claimed = worker.claim_up_to(most).await?;
            if !claimed.is_empty() {
                let since = clock;
                let claim = lap(&mut clock);
                let leased = self.leased_each(worker, claimed, since, claim).await?;
                if leased.is_empty() {
                    // each was held back, delayed, failed or cancelled: claim again
                    continue;
                }
                return Ok(leased);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline || self.inner.stopping.is_cancelled() {
                return Ok(Vec::new());
            }
            let mut until = deadline - now;
            if let Some(due) = worker.next_due().await? {
                let due_in = (due - Utc::now()).to_std().unwrap_or_default();
                until = until.min(due_in.max(Duration::from_millis(20)));
            }
            let sleep = tokio::time::sleep(until);
            tokio::pin!(sleep);
            loop {
                tokio::select! {
                    () = &mut sleep => break,
                    () = self.inner.stopping.cancelled() => return Ok(Vec::new()),
                    woken = wakeups.recv() => match woken {
                        Ok(module) if module == "*" || worker.modules().contains(&module) => break,
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => break,
                        Err(broadcast::error::RecvError::Closed) => {
                            (&mut sleep).await;
                            break;
                        }
                    },
                }
            }
        }
    }

    /// The leased form of each task claimed together, oldest first. Each task's lease is decided
    /// for it alone, by `leased`, as when it is claimed alone: one that is held back, delayed, failed
    /// or cancelled there is left out, and the others are leased. The decisions are made one after
    /// another. Made at once they were slower: nearly every one of a root's takes its root's row
    /// lock or waits behind a transaction that holds it, so they only queued there
    /// (`docs/measurements/lease.md`).
    ///
    /// A task whose decision fails with an error, such as a statement Postgres refused, is left
    /// out too when another was leased, and logged: its lease runs out and the reaper takes it
    /// back, which is what a request that failed did with its one task. When none was leased the
    /// first error is the request's answer.
    ///
    /// If the request is dropped before its answer, as when its pool stops or is killed while it
    /// waits, the tasks it had claimed are given back to the queue at once, their claims
    /// uncounted (`InHand`): no pool heard of them, so no pool will renew them.
    ///
    /// The tasks' leases all began at the claim, at `since`, and one decision that waits, as on a
    /// row lock, keeps the answer of those decided before it. So an answer that took more than a
    /// quarter of a lease renews what it holds first, and leaves out a task the worker no longer
    /// owns: what the pool is handed is its to run, with a whole lease ahead of it.
    async fn leased_each(
        &self,
        worker: &Worker,
        claimed: Vec<Task>,
        since: std::time::Instant,
        claim: u64,
    ) -> Result<Vec<LeasedTask>, Failure> {
        let batch = claimed.len();
        let mut in_hand = InHand {
            worker: worker.clone(),
            tasks: claimed.iter().map(|task| task.id).collect(),
            deciding: None,
        };
        let mut leased = Vec::with_capacity(batch);
        let mut failure = None;
        for task in claimed {
            let mut clock = std::time::Instant::now();
            let (id, module) = (task.id, task.module.clone());
            let mut times = LeaseTimes::default();
            in_hand.deciding = Some(id);
            let decided = self.leased(worker, task, &mut times).await;
            in_hand.deciding = None;
            tracing::debug!(
                target: LEASE_TIMING,
                task = id.0,
                module,
                leased = matches!(decided, Ok(Some(_))),
                batch,
                claim_us = claim,
                path_us = times.path,
                file_us = times.file,
                last_us = times.last,
                reads_us = times.reads,
                total_us = lap(&mut clock),
                "a claimed task"
            );
            match decided {
                Ok(Some(task)) => leased.push(task),
                // the core gave it up itself: it's no longer this request's
                Ok(None) => in_hand.tasks.retain(|task| *task != id),
                Err(e) => {
                    in_hand.tasks.retain(|task| *task != id);
                    tracing::error!(task = %id, "the lease's decision failed: {e:?}");
                    failure.get_or_insert(e);
                }
            }
        }
        if since.elapsed() > worker.lease() / 4 {
            let mut held = Vec::with_capacity(leased.len());
            for mut task in leased {
                let id = TaskId(task.id);
                match worker.renew(id).await {
                    Ok(lease) => {
                        task.lease_expires_at = lease.expires_at;
                        held.push(task);
                    }
                    // its lease ran out while the others were decided, and the reaper took it
                    Err(e) => {
                        in_hand.tasks.retain(|task| *task != id);
                        tracing::warn!(task = %id, "a task's lease didn't last until its answer: {e}");
                    }
                }
            }
            leased = held;
        }
        if leased.is_empty()
            && let Some(failure) = failure
        {
            return Err(failure);
        }
        // the answer has them now
        in_hand.tasks.clear();
        Ok(leased)
    }

    /// The leased form of a claimed task. A file task whose bytes aren't in the bucket fails,
    /// and None says to claim another.
    async fn leased(
        &self,
        worker: &Worker,
        task: Task,
        times: &mut LeaseTimes,
    ) -> Result<Option<LeasedTask>, Failure> {
        let mut clock = std::time::Instant::now();
        let file = if task.observable.kind == ObservableKind::File {
            let held = self.held_for_path(worker, &task).await;
            times.path = lap(&mut clock);
            if held? {
                return Ok(None);
            }
            let file = self.task_file(&task, Choose::Settle).await;
            times.file = lap(&mut clock);
            let file = match file? {
                Ok(file) => file,
                Err(why) => {
                    tracing::error!(task = %task.id, "{why}");
                    worker.fail(task.id, &why).await?;
                    return Ok(None);
                }
            };
            // a type step whose bytes were typed before, under a path whose questions the kept
            // type answers, ends here, with no pool (PLAN.md decision 25)
            if task.module == crate::type_step::TYPE_STEP
                && file
                    .facts
                    .as_ref()
                    .is_some_and(|facts| crate::type_step::answers(facts, file.path.as_str()))
            {
                self.end_kept_type(worker, &task).await?;
                return Ok(None);
            }
            Some(file)
        } else {
            None
        };
        let catalog = self.inner.orchestrator.catalog();
        let runs_last = catalog
            .iter()
            .any(|c| c.key == task.module && c.manifest.runs_last);
        // ace3's execute_final_analysis: what's below this file has all been found and scanned.
        // Modules that run last wait for each other only on the files below their observable, which
        // they read and the other can add to (`tree::held_back`); ace3 reruns its final analysis
        // until nothing more is added, and this runs each once. The wait doubles while the same
        // thing holds it back and starts low again when that changes, so a wait for xlmdeobfuscator
        // below, and then for what it added, isn't as long as the wait for the whole root was.
        if runs_last {
            let last: Vec<String> = catalog
                .iter()
                .filter(|c| c.manifest.runs_last)
                .map(|c| c.key.clone())
                .collect();
            let held =
                tree::held_back(self.inner.db.pool(), task.root, task.observable.id, &last).await;
            times.last = lap(&mut clock);
            if let Some(held) = held? {
                let before = task.delayed.as_ref().map(|d| &d.state);
                let step = match before {
                    Some(state) if state[HELD_BACK_BY] == held.as_str() => {
                        state["step"].as_u64().unwrap_or(0).saturating_add(1)
                    }
                    _ => 0,
                };
                let exponent = u32::try_from(step.min(7)).unwrap_or(7);
                let after = OTHERS_PENDING_DELAY.saturating_mul(2u32.saturating_pow(exponent));
                let state = serde_json::json!({HELD_BACK_BY: held.as_str(), "step": step});
                match worker.delay(task.id, after, &state).await {
                    Ok(_) => {}
                    Err(QueueError::Cancelled(_)) => return Ok(None),
                    Err(e) => return Err(e.into()),
                }
                // every other module has finished, and this task's delay isn't an end that would
                // wake the ones still waiting for that (`queue::check_completion`). They come back
                // when their waits end if this fails, so it doesn't fail the lease.
                if held == tree::HeldBack::ByLastBelow
                    && let Err(e) =
                        crate::queue::wake_held_back_now(&self.inner.db, task.root).await
                {
                    tracing::warn!(task = %task.id, "couldn't wake the tasks held back: {e}");
                }
                times.last = times.last.saturating_add(lap(&mut clock));
                return Ok(None);
            }
        }
        let reads_email = catalog
            .iter()
            .any(|c| c.key == task.module && c.manifest.reads_carrying_email);
        // The email module takes every file, so a root's email task is likely still pending when one
        // of its files is leased. Most files don't need the email, and the module knows which, so it
        // gets told and delays itself if it must.
        let emails_pending =
            reads_email && tree::emails_pending(self.inner.db.pool(), task.root).await?;
        let carrying_email = if reads_email && !emails_pending {
            match self.carrying_email(&task).await? {
                Ok(email) => email,
                Err(why) => {
                    tracing::error!(task = %task.id, "{why}");
                    worker.fail(task.id, &why).await?;
                    return Ok(None);
                }
            }
        } else {
            None
        };
        let redirection =
            tree::redirection(self.inner.db.pool(), task.root, task.observable.id).await?;
        let relationships =
            tree::relationships(self.inner.db.pool(), task.root, task.observable.id).await?;
        let yara_rules_below = if runs_last {
            tree::yara_rules_below(self.inner.db.pool(), task.root, task.observable.id).await?
        } else {
            Vec::new()
        };
        let (dependencies, observables_below) = self.tree_reads(&task, runs_last).await?;
        let (added_by, related_tags) = self.lineage_reads(&task).await?;
        let tree = self.tree_read(&task).await?;
        let scan = self.task_scan(&task).await?;
        // read after the claim, so an edit committed before it is in the task (`lists`' docs)
        let lists = self.lists_for(&task.module).await?;
        let mut leased = self.wire_task(task, file, redirection);
        leased.observable.relationships = relationships;
        leased.added_by = added_by;
        leased.related_tags = related_tags;
        leased.tree = tree;
        leased.carrying_email = carrying_email;
        leased.emails_pending = emails_pending;
        leased.yara_rules_below = yara_rules_below;
        leased.lists = lists;
        (leased.dependency_results, leased.dependency_errors) = by_module(dependencies);
        leased.observables_below = observables_below;
        leased.scan = scan;
        times.reads = lap(&mut clock);
        Ok(Some(leased))
    }

    /// What a task reads of its root's tree on the lease: its observable's results from the modules
    /// its module depends on, and for a module that runs last, the observables below of the types
    /// it reads there.
    async fn tree_reads(
        &self,
        task: &Task,
        runs_last: bool,
    ) -> Result<(Vec<tree::DependencyResult>, Vec<ObservableRef>), Failure> {
        let catalog = self.inner.orchestrator.catalog();
        let Some(manifest) = catalog.get(&task.module) else {
            return Ok(Default::default());
        };
        let pool = self.inner.db.pool();
        let results = if manifest.depends_on.is_empty() {
            Vec::new()
        } else {
            tree::results_of(pool, task.root, task.observable.id, manifest.depends_on).await?
        };
        let below = if runs_last && !manifest.reads_below.is_empty() {
            tree::observables_below(pool, task.root, task.observable.id, manifest.reads_below)
                .await?
        } else {
            Vec::new()
        };
        Ok((results, below))
    }

    /// What a task reads of where its observable came from, for a module that reads it: the modules
    /// whose results added it (`Module::READS_ADDED_BY`) and the tags of what it's related to
    /// (`Module::READS_RELATED_TAGS`).
    async fn lineage_reads(
        &self,
        task: &Task,
    ) -> Result<(Vec<String>, Vec<ace_sdk::wire::RelatedTags>), Failure> {
        let catalog = self.inner.orchestrator.catalog();
        let Some(manifest) = catalog.get(&task.module) else {
            return Ok(Default::default());
        };
        let pool = self.inner.db.pool();
        let added_by = if manifest.reads_added_by {
            tree::added_by(pool, task.root, task.observable.id).await?
        } else {
            Vec::new()
        };
        let related_tags = if manifest.reads_related_tags {
            tree::related_tags(pool, task.root, task.observable.id).await?
        } else {
            Vec::new()
        };
        Ok((added_by, related_tags))
    }

    /// The root's tree, for a module that walks it (`Module::READS_TREE`), with a download for each
    /// of its files the module reads (`Module::READS_TREE_FILES`).
    async fn tree_read(&self, task: &Task) -> Result<Option<ace_sdk::tree::TreeView>, Failure> {
        let catalog = self.inner.orchestrator.catalog();
        let Some(manifest) = catalog.get(&task.module).filter(|m| m.reads_tree) else {
            return Ok(None);
        };
        let (mut tree, wanted) = tree::tree_view(
            self.inner.db.pool(),
            task.root,
            task.observable.id,
            manifest.reads_tree_files,
            manifest.reads_tree_details,
        )
        .await?;
        for (index, value) in wanted {
            let Ok(sha256) = value.parse::<Sha256>() else {
                continue;
            };
            let download = self
                .inner
                .bucket
                .store()
                .presign_get(ALERT_FILES, &sha256, self.inner.config.url_expiry)
                .await
                .map_err(BucketError::from)?;
            tree.observables[index].download = Some(wire_presigned(download));
        }
        Ok(Some(tree))
    }

    /// The analyst-edited lists `module` reads, as they are now.
    async fn lists_for(&self, module: &str) -> Result<Vec<ace_sdk::lists::WireList>, Failure> {
        let specs = self
            .inner
            .orchestrator
            .catalog()
            .get(module)
            .map_or(&[][..], |manifest| manifest.lists);
        if specs.is_empty() {
            return Ok(Vec::new());
        }
        let snapshot = self.inner.lists.current(self.inner.db.pool()).await?;
        Ok(snapshot.wire(specs))
    }

    /// The email that carried a task's observable, or why the task can't run.
    async fn carrying_email(
        &self,
        task: &Task,
    ) -> Result<Result<Option<CarryingEmail>, String>, Failure> {
        let email =
            tree::carrying_email(self.inner.db.pool(), task.root, task.observable.id).await?;
        let Some(parts) = email else {
            return Ok(Ok(None));
        };
        let mut wire = Vec::with_capacity(parts.len());
        for part in parts {
            let Ok(sha256) = part.sha256.parse::<Sha256>() else {
                return Ok(Err(format!(
                    "the email body part's value {:?} isn't a sha256",
                    part.sha256
                )));
            };
            if self
                .inner
                .bucket
                .object(ALERT_FILES, &sha256)
                .await?
                .is_none()
            {
                return Ok(Err(format!("email body part {sha256} isn't in the bucket")));
            }
            let download = self
                .inner
                .bucket
                .store()
                .presign_get(ALERT_FILES, &sha256, self.inner.config.url_expiry)
                .await
                .map_err(BucketError::from)?;
            wire.push(EmailBodyPart {
                html: part.html,
                download: wire_presigned(download),
            });
        }
        Ok(Ok(Some(CarryingEmail { parts: wire })))
    }

    fn wire_task(
        &self,
        task: Task,
        file: Option<TaskFile>,
        redirection: Option<ObservableRef>,
    ) -> LeasedTask {
        LeasedTask {
            id: task.id.0,
            root: task.root,
            module: task.module,
            attempts: task.attempts,
            lease_expires_at: task.lease_expires_at,
            lease_seconds: self.inner.config.lease.as_secs_f64(),
            observable: TaskObservable {
                kind: task.observable.kind,
                value: task.observable.value,
                time: task.observable.time,
                directives: task.observable.directives,
                file,
                redirection,
                relationships: Vec::new(),
            },
            delayed: task.delayed,
            input_hashes: task.input_hashes,
            carrying_email: None,
            emails_pending: false,
            yara_rules_below: Vec::new(),
            lists: Vec::new(),
            dependency_results: Default::default(),
            dependency_errors: Default::default(),
            observables_below: Vec::new(),
            added_by: Vec::new(),
            related_tags: Vec::new(),
            tree: None,
            scan: None,
        }
    }

    /// Checks that a request carries the admin token.
    fn admin(&self, headers: &HeaderMap) -> Result<(), Failure> {
        let token = bearer(headers).ok_or(Failure::Unauthorized)?;
        match self.inner.config.admin_token_sha256 {
            Some(hash) if hash == sha256(token) => Ok(()),
            _ => Err(Failure::Unauthorized),
        }
    }

    /// Whether a file task is held for its file's path (PLAN.md decision 15). A file is analyzed
    /// once, under one of its paths, and its tasks name what they write after it, so the path is
    /// settled by a rule (`tree::choose_analysis_file`) rather than by which result landed first.
    /// Paths come from results, so the rule can only see them all once nothing that could add one
    /// is pending: the file's first task waits while a task nearer the root than the file is
    /// queued, delayed or running, for `PATH_HOLD_LIMIT` at most.
    ///
    /// Only nearer the root: a task as deep as the file or deeper, such as one on another file
    /// that's waiting the same way, never waits on this one, so two held files can't wait on each
    /// other. A path written from that deep isn't one the rule takes. Modules that run last are left
    /// out, since they wait for every other task, this one too, and what they write lands after the
    /// file's tasks have run.
    async fn held_for_path(&self, worker: &Worker, task: &Task) -> Result<bool, Failure> {
        let pool = self.inner.db.pool();
        let (chosen, waited) =
            tree::analysis_file_state(pool, task.root, task.observable.id).await?;
        if chosen {
            return Ok(false);
        }
        if waited >= PATH_HOLD_LIMIT {
            tracing::warn!(
                task = %task.id,
                "a file's path is settled while something nearer the root is still pending; a path it adds later won't be the one analyzed"
            );
            return Ok(false);
        }
        let depth = tree::depth(pool, task.root, task.observable.id).await?;
        let last: Vec<String> = self
            .inner
            .orchestrator
            .catalog()
            .iter()
            .filter(|c| c.manifest.runs_last)
            .map(|c| c.key.clone())
            .collect();
        if !tree::pending_above(pool, task.root, depth, &last).await? {
            return Ok(false);
        }
        let after = (waited / 2).clamp(PATH_HOLD_MIN, PATH_HOLD_MAX);
        worker.hold(task.id, after).await?;
        Ok(true)
    }

    /// A file task's record and its download URL, or why the task can't run. A lease settles the
    /// file's path (`tree::choose_analysis_file`); a replay only reads it.
    async fn task_file(
        &self,
        task: &Task,
        choose: Choose,
    ) -> Result<Result<TaskFile, String>, Failure> {
        let Ok(sha256) = task.observable.value.parse::<Sha256>() else {
            return Ok(Err(format!(
                "the file observable's value {:?} isn't a sha256",
                task.observable.value
            )));
        };
        let (root, observable) = (task.root, task.observable.id);
        let record = match choose {
            Choose::Settle => {
                self.inner
                    .db
                    .transaction(Isolation::ReadCommitted, |tx| {
                        Box::pin(
                            async move { tree::choose_analysis_file(tx, root, observable).await },
                        )
                    })
                    .await?
            }
            Choose::Read => tree::analysis_file(self.inner.db.pool(), root, observable).await?,
        };
        let object = self.inner.bucket.object(ALERT_FILES, &sha256).await?;
        let (Some(record), Some(object)) = (record, object) else {
            return Ok(Err(format!(
                "file {sha256} has no path in the root or isn't in the bucket"
            )));
        };
        let Ok(path) = AlertPath::new(record.path.clone()) else {
            return Ok(Err(format!(
                "file {sha256}'s path {:?} is invalid",
                record.path
            )));
        };
        let yara_meta = record
            .yara_meta
            .iter()
            .filter_map(|tag| tag.parse::<YaraMeta>().ok())
            .collect();
        let download = self
            .inner
            .bucket
            .store()
            .presign_get(ALERT_FILES, &sha256, self.inner.config.url_expiry)
            .await
            .map_err(BucketError::from)?;
        // the file's type, which every task but its type step's own is leased after
        let facts = crate::type_step::facts_for(self.inner.db.pool(), &sha256.to_hex()).await?;
        Ok(Ok(TaskFile {
            path,
            sha256,
            size: object.size,
            facts,
            role: record.role.as_deref().and_then(|role| role.parse().ok()),
            yara_meta,
            download: wire_presigned(download),
        }))
    }

    /// Lands a module's result (PLAN.md 2.15). It is checked against its type's schema before
    /// anything is written, which rejects it for good (`reject`), and each file it adds must have
    /// been uploaded with bytes that match its sha256. Then one transaction puts the files in the `alert_files` pool, held by
    /// the root, and writes the result, its observables, its file records and the tasks that
    /// became eligible. The uploads go once that has committed.
    async fn land(
        &self,
        worker: &Worker,
        task: TaskId,
        result: Value,
        writes: &[crate::writes::Checked],
    ) -> Result<(), Failure> {
        let task = worker.owned(task).await?.ok_or(Failure::LeaseLost(task))?;
        let orchestrator = &self.inner.orchestrator;
        if let Err(rejected) = orchestrator.check_result(&task.module, &result) {
            return Err(self.reject(worker, &task, &result, rejected).await);
        }
        if task.module == crate::type_step::TYPE_STEP {
            return self.land_type(worker, &task, &result).await;
        }
        let mut result: ResultEnvelope<Value> = serde_json::from_value(result)
            .map_err(|e| Failure::BadRequest(format!("the result doesn't read: {e}")))?;
        if let Some(error) = &result.error {
            // at INFO, as ace3 logs a failure a module reports itself: the module expected it, so
            // it is no failed task and leaves no crash to replay
            tracing::info!(
                task = %task.id, root = %task.root, module = %task.module,
                "the module said it failed: {error}"
            );
        }
        let bucket = &self.inner.bucket;
        let mut files = Vec::new();
        // what the result stores for its root without adding it (`ResultEnvelope::stored`) must
        // have been uploaded, as a file it adds must
        let mut stored = Vec::new();
        for file in &result.stored {
            if stored.contains(&file.sha256) || result.files.iter().any(|f| f.sha256 == file.sha256)
            {
                continue;
            }
            stored.push(file.sha256);
            files.push(bucket.fetch_upload(task.id.0, &file.sha256).await?);
        }
        for file in &mut result.files {
            match bucket.fetch_upload(task.id.0, &file.sha256).await {
                Ok(spooled) => files.push(spooled),
                Err(missing @ BucketError::Store(ace_store::StoreError::NotFound { .. })) => {
                    // a file a read put in the root, or another module's result stored there,
                    // comes with no upload (reads.md, `Module::ADDS_STORED_FILES`); any other
                    // missing upload could still be put right, so the task stays the worker's.
                    // Its size is the bucket's, which a module that didn't upload it may not know.
                    match self.read_file_in_root(&task, &file.sha256).await? {
                        Ok(size) => file.size = size,
                        Err(why) => {
                            tracing::warn!(task = %task.id, "{why}");
                            return Err(missing.into());
                        }
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        let hold = Hold::root(task.root);
        let archive = self.inner.stores.archive();
        let (task, files, hold) = (&task, &files, &hold);
        let result = &result;
        self.inner
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    for file in files {
                        bucket.put_in(tx, ALERT_FILES, file, Some(hold)).await?;
                    }
                    let applied = crate::writes::apply(tx, archive, bucket, task, writes).await?;
                    // the archive's id, which only the core knows, goes in the archiver's result
                    let mut result = std::borrow::Cow::Borrowed(result);
                    if let Some(archive_id) = applied.archive_id
                        && let Some(details) = result.to_mut().details.as_object_mut()
                    {
                        details.insert("archive_id".to_owned(), archive_id.into());
                    }
                    orchestrator.land_result(tx, worker, task, &result).await?;
                    Ok::<_, LandError>(())
                })
            })
            .await?;
        for file in files {
            bucket.remove_upload(task.id.0, &file.sha256).await?;
        }
        Ok(())
    }

    /// Ends a file's type step whose bytes already have a type kept (`Api::leased`), as its landing
    /// would: the task is done, and its end queues the file's other tasks in the same transaction
    /// (`queue::TypeStepEnded`).
    async fn end_kept_type(&self, worker: &Worker, task: &Task) -> Result<(), Failure> {
        self.inner
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    worker
                        .finish_in(tx, task.id, crate::queue::TaskState::Done, None)
                        .await?;
                    crate::queue::check_completion(tx, task.root).await?;
                    Ok::<_, LandError>(())
                })
            })
            .await?;
        tracing::debug!(task = %task.id, "a type step ended on the type kept for its bytes");
        Ok(())
    }

    /// Lands a file's type step (`crate::type_step`): keeps what it found in the file's bytes and
    /// ends the task, which queues the file's other tasks in the same transaction
    /// (`queue::TypeStepEnded`). Its output is no result in the tree.
    async fn land_type(&self, worker: &Worker, task: &Task, result: &Value) -> Result<(), Failure> {
        let facts: ace_results::types::file_type::TypeFacts =
            serde_json::from_value(result.get("details").cloned().unwrap_or_default())
                .map_err(|e| Failure::BadRequest(format!("the file's type doesn't read: {e}")))?;
        let (facts, sha256) = (&facts, task.observable.value.as_str());
        self.inner
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    crate::type_step::store_facts(tx, sha256, facts).await?;
                    worker
                        .finish_in(tx, task.id, crate::queue::TaskState::Done, None)
                        .await?;
                    crate::queue::check_completion(tx, task.root).await?;
                    Ok::<_, LandError>(())
                })
            })
            .await?;
        Ok(())
    }

    /// Whether a file a result adds with no upload is one a read put in the task's root, or one
    /// another result stored there: the module declares a read that does
    /// (`ace_sdk::reads::FILE_READS`) or that it adds stored files (`Module::ADDS_STORED_FILES`), and
    /// the bucket holds the file for the root. Its size there, or why not, which rejects the result.
    async fn read_file_in_root(
        &self,
        task: &Task,
        sha256: &Sha256,
    ) -> Result<Result<u64, String>, Failure> {
        let catalog = self.inner.orchestrator.catalog();
        let reads_files = catalog.get(&task.module).is_some_and(|manifest| {
            manifest.adds_stored_files
                || manifest
                    .reads
                    .iter()
                    .any(|r| ace_sdk::reads::FILE_READS.contains(r))
        });
        if !reads_files {
            return Ok(Err(format!(
                "the result adds file {sha256}, which wasn't uploaded, and {} declares no read that \
                 puts a file in the root and doesn't add stored files",
                task.module
            )));
        }
        let held = sqlx::query_scalar!(
            r#"SELECT o.size FROM store.holds h
               JOIN store.objects o ON o.pool = h.pool AND o.sha256 = h.sha256
               WHERE h.pool = $1 AND h.sha256 = $2 AND h.holder_kind = 'root'
                 AND h.holder_id = $3 AND o.state = 'present'
               LIMIT 1"#,
            ALERT_FILES,
            sha256.to_hex(),
            task.root.to_string(),
        )
        .fetch_optional(self.inner.db.pool())
        .await
        .map_err(|e| Failure::Internal(format!("the bucket's index: {e}")))?;
        if let Some(size) = held {
            Ok(Ok(size as u64))
        } else {
            Ok(Err(format!(
                "the result adds file {sha256}, which wasn't uploaded and the root doesn't hold"
            )))
        }
    }

    /// Checks the writes a task's end carries (PLAN.md 7.2, `writes.rs`). A refused write fails the
    /// task now, with why, as a result that fails its check does: the module would write the same
    /// on another attempt.
    async fn check_writes(
        &self,
        worker: &Worker,
        task: TaskId,
        writes: Vec<ace_sdk::writes::WireWrite>,
    ) -> Result<Vec<crate::writes::Checked>, Failure> {
        if writes.is_empty() {
            return Ok(Vec::new());
        }
        let owned = worker.owned(task).await?.ok_or(Failure::LeaseLost(task))?;
        let catalog = self.inner.orchestrator.catalog();
        let manifest = catalog.get(&owned.module);
        let writes = writes
            .into_iter()
            .map(|w| ace_sdk::writes::WireWrite {
                write: w.write,
                body: without_nul(w.body),
            })
            .collect();
        match crate::writes::check(
            &self.inner.db,
            self.inner.stores.archive(),
            &self.inner.bucket,
            manifest,
            &owned,
            writes,
        )
        .await
        {
            Ok(checked) => Ok(checked),
            Err(crate::writes::WriteFailure::Db(e)) => Err(e.into()),
            Err(refused) => {
                let (why, failure) = match refused {
                    crate::writes::WriteFailure::BadRequest(why) => {
                        (why.clone(), Failure::BadRequest(why))
                    }
                    crate::writes::WriteFailure::Forbidden(why) => {
                        (why.clone(), Failure::Forbidden(why))
                    }
                    crate::writes::WriteFailure::Db(_) => unreachable!("handled above"),
                };
                tracing::warn!(%task, module = %owned.module, "refused a task's writes: {why}");
                worker.fail(task, &why).await?;
                Err(failure)
            }
        }
    }

    /// Ends a skipped task and lands its writes in one transaction.
    async fn complete_with_writes(
        &self,
        worker: &Worker,
        task: TaskId,
        writes: &[crate::writes::Checked],
    ) -> Result<(), Failure> {
        let owned = worker.owned(task).await?.ok_or(Failure::LeaseLost(task))?;
        let owned = &owned;
        let archive = self.inner.stores.archive();
        let bucket = &self.inner.bucket;
        self.inner
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    let root = worker
                        .finish_in(tx, task, crate::queue::TaskState::Done, None)
                        .await?;
                    crate::writes::apply(tx, archive, bucket, owned, writes).await?;
                    crate::queue::check_completion(tx, root).await?;
                    Ok::<_, QueueError>(())
                })
            })
            .await?;
        Ok(())
    }

    /// Ends the task of a result that failed its check, whichever pool it came from. The module
    /// would write the same result on another attempt, so the task fails now, with the fields in
    /// its row, rather than waiting out its lease up to `max_attempts` times and failing with no
    /// reason. The result's uploads go too: no later attempt can use them. If the failure can't be
    /// written, the worker gets that error and the lease decides, as for any other.
    async fn reject(
        &self,
        worker: &Worker,
        task: &Task,
        result: &Value,
        rejected: Rejected,
    ) -> Failure {
        if let Err(e) = worker.fail(task.id, &rejected.error).await {
            return e.into();
        }
        tracing::warn!(task = %task.id, module = %task.module, "rejected a result: {}", rejected.error);
        let uploads = result["files"].as_array().into_iter().flatten();
        for sha256 in uploads.filter_map(|file| file["sha256"].as_str()?.parse::<Sha256>().ok()) {
            if let Err(e) = self.inner.bucket.remove_upload(task.id.0, &sha256).await {
                tracing::warn!(task = %task.id, "removing a rejected result's upload: {e}");
            }
        }
        Failure::Invalid(ApiError {
            error: rejected.error,
            fields: rejected
                .fields
                .into_iter()
                .map(|f| WireFieldError {
                    path: f.path,
                    message: f.message,
                })
                .collect(),
        })
    }
}

impl Api {
    /// A task end too big to read. Another attempt would write the same, so the task fails now,
    /// with a reason, like a result that fails its check. Nothing of it can be read, so it can't
    /// say which uploads it made, and those stay in the bucket.
    async fn end_too_large(&self, id: i64, headers: &HeaderMap) -> Result<StatusCode, Failure> {
        let worker = self.worker(headers)?;
        let error = format!(
            "the task's end is over the {} byte limit, so its result was not read",
            self.inner.config.max_end_bytes
        );
        worker.fail(TaskId(id), &error).await?;
        tracing::warn!(task = id, "{error}");
        Err(Failure::Invalid(ApiError {
            error,
            fields: Vec::new(),
        }))
    }
}

/// What can go wrong inside a result's transaction.
#[derive(Debug, thiserror::Error)]
enum LandError {
    #[error(transparent)]
    Bucket(#[from] BucketError),
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
    #[error(transparent)]
    Queue(#[from] QueueError),
}

impl From<DbError> for LandError {
    fn from(error: DbError) -> Self {
        LandError::Orchestrator(OrchestratorError::Db(error))
    }
}

impl Retryable for LandError {
    fn is_retryable(&self) -> bool {
        match self {
            LandError::Bucket(BucketError::Db(e)) => e.is_retryable(),
            LandError::Bucket(_) => false,
            LandError::Orchestrator(e) => e.is_retryable(),
            LandError::Queue(e) => e.is_retryable(),
        }
    }
}

impl From<LandError> for Failure {
    fn from(error: LandError) -> Self {
        match error {
            LandError::Bucket(e) => Failure::from(e),
            LandError::Orchestrator(e) => Failure::from(e),
            LandError::Queue(e) => Failure::from(e),
        }
    }
}

/// A span for one request, a child of the caller's span when the request carries a W3C
/// `traceparent` header (PLAN.md 2.22), so a task's spans in its pool and here share a trace.
fn request_span(name: &'static str, task: Option<i64>, headers: &HeaderMap) -> tracing::Span {
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let span = tracing::info_span!("lease_api", request = name, task);
    let parent = TraceContextPropagator::new().extract(&HeaderCarrier(headers));
    if let Err(e) = span.set_parent(parent) {
        tracing::debug!("no parent for the request's span: {e}");
    }
    span
}

struct HeaderCarrier<'a>(&'a HeaderMap);

impl Extractor for HeaderCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn wire_presigned(presigned: ace_store::Presigned) -> Presigned {
    Presigned {
        url: presigned.url,
        headers: presigned.headers,
    }
}

async fn lease(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(request): Json<LeaseRequest>,
) -> Result<Response, Failure> {
    let span = request_span("lease", None, &headers);
    lease_in(api, headers, request).instrument(span).await
}

async fn lease_in(
    api: Api,
    headers: HeaderMap,
    request: LeaseRequest,
) -> Result<Response, Failure> {
    let pool = api.pool(&headers)?;
    let modules = if request.modules.is_empty() {
        pool.modules.clone()
    } else if let Some(other) = request.modules.iter().find(|m| !pool.modules.contains(m)) {
        return Err(Failure::Forbidden(format!(
            "pool {} doesn't run {other}",
            pool.name
        )));
    } else {
        request.modules.clone()
    };
    if request.worker.is_empty() {
        return Err(Failure::BadRequest("no worker name".to_owned()));
    }
    let worker = api.pool_worker(pool, &request.worker, modules);
    let wait = Duration::from_secs(request.wait_seconds).min(api.inner.config.max_wait);
    let most = request.max.clamp(1, MAX_LEASED_AT_ONCE);
    let tasks = api
        .lease_for(&worker, wait, usize::try_from(most).unwrap_or(1))
        .await?;
    if tasks.is_empty() {
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Ok(Json(tasks).into_response())
    }
}

/// A command's report or end holds its output, up to `MAX_OUTPUT_BYTES`, which JSON's escapes of control
/// characters can make six times as long.
const MAX_COMMAND_BODY: usize = 8 * crate::commands::MAX_OUTPUT_BYTES;

/// The largest action end: a confirmation's events at most, each a few lines of a vendor's record.
const MAX_ACTION_END_BYTES: usize = 8 << 20;

async fn lease_command(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(request): Json<CommandLeaseRequest>,
) -> Result<Response, Failure> {
    let worker = api.command_worker(&headers, Some(&request.worker))?;
    let wait = Duration::from_secs(request.wait_seconds).min(api.inner.config.max_wait);
    match api.lease_command_for(&worker, wait).await? {
        Some(command) => Ok(Json(command).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn report_command(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(report): Json<CommandReport>,
) -> Result<Json<CommandReply>, Failure> {
    let worker = api.command_worker(&headers, None)?;
    let cancel_requested = worker
        .report(id, &report.output, report.output_truncated)
        .await?;
    Ok(Json(CommandReply { cancel_requested }))
}

async fn end_command(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(end): Json<CommandEnd>,
) -> Result<StatusCode, Failure> {
    let worker = api.command_worker(&headers, None)?;
    let (state, exit_code, error) = match &end.outcome {
        CommandOutcome::Completed { exit_code } => {
            (CommandState::Completed, Some(*exit_code), None)
        }
        CommandOutcome::TimedOut => (CommandState::TimedOut, None, None),
        CommandOutcome::Cancelled => (CommandState::Cancelled, None, None),
        CommandOutcome::Failed { error } => (CommandState::Failed, None, Some(error.as_str())),
        CommandOutcome::Abandoned { error } => {
            (CommandState::Abandoned, None, Some(error.as_str()))
        }
    };
    worker
        .end(
            id,
            state,
            exit_code,
            error,
            &end.output,
            end.output_truncated,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn lease_scan(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(request): Json<ace_sdk::scanners::ScanLeaseRequest>,
) -> Result<Response, Failure> {
    let (worker, scanners) = api.scan_worker(&headers, Some(&request.worker))?;
    let wait = Duration::from_secs(request.wait_seconds).min(api.inner.config.max_wait);
    match api.lease_scan_for(&worker, &scanners, wait).await? {
        Some(scan) => Ok(Json(scan).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn renew_scan(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<ace_sdk::scanners::ScanRenewal>, Failure> {
    let (worker, _) = api.scan_worker(&headers, None)?;
    let cancel_requested = worker.renew(id).await?;
    Ok(Json(ace_sdk::scanners::ScanRenewal { cancel_requested }))
}

/// A URL to upload a scan's output archive to, under its task's key in the bucket.
async fn upload_scan(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<ace_sdk::scanners::ScanUploadRequest>,
) -> Result<Json<Presigned>, Failure> {
    let (worker, _) = api.scan_worker(&headers, None)?;
    let (task, _) = worker
        .owned(id)
        .await?
        .ok_or(Failure::LeaseLost(TaskId(id)))?;
    let key = ace_store::Store::upload_key(task.0, &request.sha256);
    let presigned = api
        .inner
        .bucket
        .store()
        .presign_put(&key, request.size, api.inner.config.url_expiry)
        .await
        .map_err(BucketError::from)?;
    Ok(Json(wire_presigned(presigned)))
}

async fn end_scan(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(end): Json<ace_sdk::scanners::ScanEnd>,
) -> Result<StatusCode, Failure> {
    use ace_sdk::scanners::ScanOutcome;
    let (worker, _) = api.scan_worker(&headers, None)?;
    let (task, root) = worker
        .owned(id)
        .await?
        .ok_or(Failure::LeaseLost(TaskId(id)))?;
    let (state, exit_code, error) = match &end.outcome {
        ScanOutcome::Completed { exit_code } => (ScanRowState::Completed, Some(*exit_code), None),
        ScanOutcome::TimedOut { exit_code } => (ScanRowState::TimedOut, *exit_code, None),
        ScanOutcome::Cancelled => (ScanRowState::Cancelled, None, None),
        ScanOutcome::Failed { error } => (ScanRowState::Failed, None, Some(error.as_str())),
    };
    let bucket = &api.inner.bucket;
    let spooled = match &end.output {
        Some(output) => Some(bucket.fetch_upload(task.0, &output.sha256).await?),
        None => None,
    };
    let ended = EndedScan {
        state,
        exit_code,
        error,
        output: end.output.map(|o| (o.sha256, o.size)),
    };
    let hold = Hold::root(root);
    let (worker, ended, spooled, hold) = (&worker, &ended, &spooled, &hold);
    api.inner
        .db
        .transaction(Isolation::ReadCommitted, |tx| {
            Box::pin(async move {
                if let Some(spooled) = spooled {
                    bucket.put_in(tx, ALERT_FILES, spooled, Some(hold)).await?;
                }
                worker.end_in(tx, id, ended).await?;
                Ok::<_, LandError>(())
            })
        })
        .await?;
    if let Some(output) = &end.output {
        bucket.remove_upload(task.0, &output.sha256).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn lease_action(
    State(api): State<Api>,
    headers: HeaderMap,
    Json(request): Json<ace_sdk::actions::ActionLeaseRequest>,
) -> Result<Response, Failure> {
    let (worker, handlers) = api.action_worker(&headers, Some(&request.worker))?;
    let wait = Duration::from_secs(request.wait_seconds).min(api.inner.config.max_wait);
    match api.lease_action_for(&worker, &handlers, wait).await? {
        Some(action) => Ok(Json(action).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn renew_action(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<ace_sdk::actions::ActionRenewal>, Failure> {
    let (worker, _) = api.action_worker(&headers, None)?;
    let cancelled = worker.renew(id).await?;
    Ok(Json(ace_sdk::actions::ActionRenewal { cancelled }))
}

/// A URL to upload the file a collection fetched to, under the action's own key in the bucket.
async fn upload_action(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<ace_sdk::actions::ActionUploadRequest>,
) -> Result<Json<Presigned>, Failure> {
    let (worker, _) = api.action_worker(&headers, None)?;
    let (kind, _) = worker.owned(id).await?;
    if kind != ace_sdk::actions::ActionKind::FileCollection {
        return Err(Failure::BadRequest(format!(
            "action {id} is a {kind}, which uploads nothing"
        )));
    }
    let key = ace_store::Store::action_upload_key(id, &request.sha256);
    let presigned = api
        .inner
        .bucket
        .store()
        .presign_put(&key, request.size, api.inner.config.url_expiry)
        .await
        .map_err(BucketError::from)?;
    Ok(Json(wire_presigned(presigned)))
}

/// How a try of an action went. A collected file is fetched from its upload and checked before the
/// transaction that records the end puts it in `alert_files`, held by the collection and its alerts.
async fn end_action(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: Result<Json<ace_sdk::actions::ActionEnd>, JsonRejection>,
) -> Result<StatusCode, Failure> {
    let Json(end) = body.map_err(|e| Failure::BadRequest(e.body_text()))?;
    let (worker, _) = api.action_worker(&headers, None)?;
    // the lease first, so a stranger's end can't make the core read an upload
    worker.owned(id).await?;
    let file = match &end {
        ace_sdk::actions::ActionEnd::FileCollection {
            file: Some(file), ..
        } => Some(file.clone()),
        _ => None,
    };
    let bucket = &api.inner.bucket;
    let spooled = match &file {
        Some(file) => Some(bucket.fetch_action_upload(id, &file.sha256).await?),
        None => None,
    };
    let (worker, end, spooled, file) = (&worker, &end, &spooled, &file);
    api.inner
        .db
        .transaction(Isolation::ReadCommitted, |tx| {
            Box::pin(async move {
                if let Some(spooled) = spooled {
                    bucket
                        .put_in(
                            tx,
                            ALERT_FILES,
                            spooled,
                            Some(&crate::actions::collection_hold(id)),
                        )
                        .await?;
                }
                let roots = worker.end_in(tx, id, end).await?;
                if let Some(file) = file {
                    for root in roots {
                        bucket
                            .hold_in(tx, ALERT_FILES, &file.sha256, &Hold::root(root))
                            .await?;
                    }
                }
                Ok::<_, ActionLandError>(())
            })
        })
        .await?;
    if let Some(file) = file {
        bucket.remove_action_upload(id, &file.sha256).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// An action end's transaction failing: the action's rules or the bucket.
#[derive(Debug, thiserror::Error)]
enum ActionLandError {
    #[error(transparent)]
    Action(#[from] ActionError),
    #[error(transparent)]
    Bucket(#[from] BucketError),
}

impl Retryable for ActionLandError {
    fn is_retryable(&self) -> bool {
        match self {
            ActionLandError::Action(e) => e.is_retryable(),
            ActionLandError::Bucket(BucketError::Db(e)) => e.is_retryable(),
            ActionLandError::Bucket(_) => false,
        }
    }
}

impl From<DbError> for ActionLandError {
    fn from(error: DbError) -> Self {
        ActionLandError::Action(ActionError::Db(error))
    }
}

impl From<ActionLandError> for Failure {
    fn from(error: ActionLandError) -> Self {
        match error {
            ActionLandError::Action(e) => Failure::from(e),
            ActionLandError::Bucket(e) => Failure::from(e),
        }
    }
}

impl From<ActionError> for Failure {
    fn from(error: ActionError) -> Self {
        match error {
            ActionError::LeaseLost(id) => {
                Failure::Conflict(format!("action {id} is no longer leased to this worker"))
            }
            ActionError::Invalid(why) => Failure::BadRequest(why),
            ActionError::Db(e) => Failure::from(e),
        }
    }
}

async fn renew(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<Renewal>, Failure> {
    let span = request_span("renew", Some(id), &headers);
    let lease = async { Ok::<_, Failure>(api.worker(&headers)?.renew(TaskId(id)).await?) }
        .instrument(span)
        .await?;
    Ok(Json(Renewal {
        expires_at: lease.expires_at,
        cancel_requested: lease.cancel_requested,
    }))
}

/// Gives a task back to the queue without counting the attempt, as a pool does when it shuts
/// down with the task unfinished (PLAN.md 2.21).
async fn release(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<StatusCode, Failure> {
    api.worker(&headers)?.release(TaskId(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn uploads(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Json(request): Json<UploadRequest>,
) -> Result<Json<Presigned>, Failure> {
    let worker = api.worker(&headers)?;
    if worker.owned(TaskId(id)).await?.is_none() {
        return Err(Failure::LeaseLost(TaskId(id)));
    }
    let key = ace_store::Store::upload_key(id, &request.sha256);
    let presigned = api
        .inner
        .bucket
        .store()
        .presign_put(&key, request.size, api.inner.config.url_expiry)
        .await
        .map_err(BucketError::from)?;
    Ok(Json(wire_presigned(presigned)))
}

async fn end(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    end: Result<Json<TaskEnd>, JsonRejection>,
) -> Result<StatusCode, Failure> {
    // axum answers a body it can't read with 422, which here means only a rejected result
    let Json(end) = match end {
        Ok(end) => end,
        Err(e) if e.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return api.end_too_large(id, &headers).await;
        }
        Err(e) => return Err(Failure::BadRequest(e.body_text())),
    };
    let span = request_span("end", Some(id), &headers);
    end_in(api, id, headers, end).instrument(span).await
}

async fn end_in(
    api: Api,
    id: i64,
    headers: HeaderMap,
    end: TaskEnd,
) -> Result<StatusCode, Failure> {
    let worker = api.worker(&headers)?;
    let task = TaskId(id);
    match end {
        TaskEnd::Done { result, writes } => {
            let writes = api.check_writes(&worker, task, writes).await?;
            // checked as JSON, so each field that fails is named
            let result = serde_json::to_value(result)
                .map_err(|e| Failure::Internal(format!("re-encoding a result: {e}")))?;
            api.land(&worker, task, without_nul(result), &writes)
                .await?
        }
        TaskEnd::Skipped { reason, writes } => {
            tracing::info!(%task, "skipped: {reason}");
            let writes = api.check_writes(&worker, task, writes).await?;
            if writes.is_empty() {
                worker.complete(task).await?;
            } else {
                api.complete_with_writes(&worker, task, &writes).await?;
            }
        }
        TaskEnd::Delay {
            after_seconds,
            state,
            scan,
        } => {
            let after = Duration::try_from_secs_f64(after_seconds)
                .map_err(|e| Failure::BadRequest(format!("after_seconds: {e}")))?;
            match scan {
                Some(scan) => {
                    api.delay_for_scan(&worker, task, after, &without_nul(state), &scan)
                        .await?
                }
                None => {
                    worker.delay(task, after, &without_nul(state)).await?;
                }
            }
            return Ok(StatusCode::NO_CONTENT);
        }
        TaskEnd::Failed { error } => worker.fail(task, &text_without_nul(&error)).await?,
        TaskEnd::Cancelled => worker.cancelled(task).await?,
    }
    // a task that ends while its scan still runs doesn't wait for it (PLAN.md 7.7)
    let catalog = api.inner.orchestrator.catalog();
    if worker
        .modules()
        .iter()
        .any(|m| catalog.get(m).is_some_and(|m| !m.scanners.is_empty()))
    {
        crate::scans::cancel_for_task(&api.inner.db, task).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// A task's dependency results as the lease carries them: each one's details by module, and the
/// reasons of those whose modules said they failed.
fn by_module(
    results: Vec<tree::DependencyResult>,
) -> (BTreeMap<String, Value>, BTreeMap<String, String>) {
    let mut details = BTreeMap::new();
    let mut errors = BTreeMap::new();
    for result in results {
        if let Some(error) = result.error {
            errors.insert(result.module.clone(), error);
        }
        details.insert(result.module, result.details);
    }
    (details, errors)
}

/// A task's end can quote a hostile file, and Postgres refuses a NUL in text and in JSONB. Without
/// this one NUL in, say, an email's subject would stop its result landing on every attempt. Bytes
/// that matter are base64 in a result (ace3 #999), so nothing is lost but the character itself.
fn text_without_nul(text: &str) -> String {
    text.replace('\0', "\u{fffd}")
}

fn without_nul(value: Value) -> Value {
    match value {
        Value::String(text) if text.contains('\0') => Value::String(text_without_nul(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(without_nul).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (text_without_nul(&key), without_nul(value)))
                .collect(),
        ),
        other => other,
    }
}

/// The ruleset YARA pools should scan with, for any pool's token.
async fn current_ruleset(State(api): State<Api>, headers: HeaderMap) -> Result<Response, Failure> {
    api.pool(&headers)?;
    let Some(row) = crate::rulesets::current(&api.inner.db).await? else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let download = api
        .inner
        .bucket
        .store()
        .presign_get(
            crate::rulesets::RULESETS,
            &row.key,
            api.inner.config.url_expiry,
        )
        .await
        .map_err(BucketError::from)?;
    Ok(Json(CurrentRuleset {
        key: row.key,
        commit: row.commit,
        download: wire_presigned(download),
    })
    .into_response())
}

/// A task as a worker would lease it, with a fresh download URL for its input, for
/// `ace task replay` (PLAN.md 2.20). It takes no lease and changes nothing.
async fn replay(
    State(api): State<Api>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Result<Json<LeasedTask>, Failure> {
    api.admin(&headers)?;
    let task = crate::queue::find(&api.inner.db, TaskId(id))
        .await?
        .ok_or_else(|| Failure::NotFound(format!("no task {id}")))?;
    let file = if task.observable.kind == ObservableKind::File {
        Some(
            api.task_file(&task, Choose::Read)
                .await?
                .map_err(Failure::BadRequest)?,
        )
    } else {
        None
    };
    let redirection = tree::redirection(api.inner.db.pool(), task.root, task.observable.id).await?;
    let reads_email = api
        .inner
        .orchestrator
        .catalog()
        .iter()
        .any(|c| c.key == task.module && c.manifest.reads_carrying_email);
    let carrying_email = if reads_email {
        api.carrying_email(&task)
            .await?
            .map_err(Failure::BadRequest)?
    } else {
        None
    };
    let lists = api.lists_for(&task.module).await?;
    let runs_last = api
        .inner
        .orchestrator
        .catalog()
        .get(&task.module)
        .is_some_and(|manifest| manifest.runs_last);
    let (dependencies, observables_below) = api.tree_reads(&task, runs_last).await?;
    let (added_by, related_tags) = api.lineage_reads(&task).await?;
    let tree = api.tree_read(&task).await?;
    let mut leased = api.wire_task(task, file, redirection);
    leased.tree = tree;
    (leased.dependency_results, leased.dependency_errors) = by_module(dependencies);
    leased.observables_below = observables_below;
    leased.added_by = added_by;
    leased.related_tags = related_tags;
    // what the task read when it ran, if its email has been parsed by now, as it usually has
    leased.carrying_email = carrying_email;
    // the lists as they are now, which may have changed since it ran
    leased.lists = lists;
    Ok(Json(leased))
}

/// A read of ACE's own data for a leased task (PLAN.md 7.2, `reads.md`).
async fn read(
    State(api): State<Api>,
    Path((id, read)): Path<(i64, String)>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, Failure> {
    let span = request_span("read", Some(id), &headers);
    async {
        let worker = api.worker(&headers)?;
        let Json(request) = body.map_err(|e| Failure::BadRequest(e.body_text()))?;
        // Worker::owned doesn't look at the expiry: a lease past it may be claimed by another
        // worker at any moment, so it reads nothing
        let task = worker
            .owned(TaskId(id))
            .await?
            .filter(|task| task.lease_expires_at > Utc::now())
            .ok_or(Failure::LeaseLost(TaskId(id)))?;
        api.answer_read(&task, &read, request).await
    }
    .instrument(span)
    .await
}

/// A read for a task being replayed, with the admin token, whatever the task's state.
async fn replay_read(
    State(api): State<Api>,
    Path((id, read)): Path<(i64, String)>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, Failure> {
    api.admin(&headers)?;
    let Json(request) = body.map_err(|e| Failure::BadRequest(e.body_text()))?;
    let task = crate::queue::find(&api.inner.db, TaskId(id))
        .await?
        .ok_or_else(|| Failure::NotFound(format!("no task {id}")))?;
    api.answer_read(&task, &read, request).await
}

impl Api {
    /// Answers a read once the caller may make it for `task`: the task's module declares it.
    async fn answer_read(
        &self,
        task: &Task,
        read: &str,
        request: Value,
    ) -> Result<Json<Value>, Failure> {
        let declared = self
            .inner
            .orchestrator
            .catalog()
            .get(&task.module)
            .is_some_and(|manifest| manifest.reads.iter().any(|r| r.name == read));
        if !declared {
            return Err(Failure::Forbidden(format!(
                "{} doesn't declare the read {read}",
                task.module
            )));
        }
        let catalog = self.inner.orchestrator.catalog();
        crate::reads::answer(
            &self.inner.db,
            &self.inner.stores,
            catalog,
            task,
            read,
            request,
        )
        .await
        .map(Json)
        .map_err(|failure| match failure {
            crate::reads::ReadFailure::BadRequest(why) => Failure::BadRequest(why),
            crate::reads::ReadFailure::Forbidden(why) => Failure::Forbidden(why),
            crate::reads::ReadFailure::Unavailable(why) => Failure::Unavailable(why),
        })
    }
}

/// 200 when the database answers, for the stack's healthcheck.
async fn health(State(api): State<Api>) -> Result<StatusCode, Failure> {
    sqlx::query("SELECT 1")
        .execute(api.inner.db.pool())
        .await
        .map_err(|e| Failure::Unavailable(format!("the database: {e}")))?;
    Ok(StatusCode::OK)
}

/// Why a request failed, as the status and body the worker gets.
#[derive(Debug)]
pub enum Failure {
    Unauthorized,
    Forbidden(String),
    NotFound(String),
    BadRequest(String),
    /// The worker doesn't hold the task's lease any more.
    LeaseLost(TaskId),
    /// The task's root was cancelled.
    Cancelled(TaskId),
    /// The worker doesn't hold what it names any more, such as an action's lease.
    Conflict(String),
    /// A result that failed its check, with each field that failed. Its task has failed.
    Invalid(ApiError),
    /// Something to try again shortly.
    Unavailable(String),
    Internal(String),
}

impl From<QueueError> for Failure {
    fn from(error: QueueError) -> Self {
        match error {
            QueueError::LeaseLost(task) => Failure::LeaseLost(task),
            QueueError::Cancelled(task) => Failure::Cancelled(task),
            QueueError::Db(e) => Failure::from(e),
        }
    }
}

impl From<DbError> for Failure {
    fn from(error: DbError) -> Self {
        Failure::Internal(error.to_string())
    }
}

impl From<OrchestratorError> for Failure {
    fn from(error: OrchestratorError) -> Self {
        match error {
            OrchestratorError::Queue(e) => Failure::from(e),
            other => Failure::Internal(other.to_string()),
        }
    }
}

impl From<BucketError> for Failure {
    fn from(error: BucketError) -> Self {
        use ace_store::StoreError;
        match error {
            BucketError::Store(StoreError::NotFound { key }) => {
                Failure::BadRequest(format!("{key} wasn't uploaded"))
            }
            BucketError::Store(StoreError::Integrity { key, actual }) => {
                Failure::BadRequest(format!("the bytes uploaded to {key} have sha256 {actual}"))
            }
            BucketError::Deleting { pool, sha256 } => Failure::Unavailable(format!(
                "{pool}/{sha256} is being deleted; end the task again"
            )),
            other => Failure::Internal(other.to_string()),
        }
    }
}

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Failure::Unauthorized => (StatusCode::UNAUTHORIZED, api_error("unknown token")),
            Failure::Forbidden(why) => (StatusCode::FORBIDDEN, api_error(&why)),
            Failure::NotFound(why) => (StatusCode::NOT_FOUND, api_error(&why)),
            Failure::BadRequest(why) => (StatusCode::BAD_REQUEST, api_error(&why)),
            Failure::LeaseLost(task) => (
                StatusCode::CONFLICT,
                api_error(&format!("{task} is no longer leased to this worker")),
            ),
            Failure::Cancelled(task) => (
                StatusCode::GONE,
                api_error(&format!("{task} was cancelled")),
            ),
            Failure::Conflict(why) => (StatusCode::CONFLICT, api_error(&why)),
            Failure::Invalid(body) => (StatusCode::UNPROCESSABLE_ENTITY, body),
            Failure::Unavailable(why) => (StatusCode::SERVICE_UNAVAILABLE, api_error(&why)),
            Failure::Internal(why) => {
                tracing::error!("the lease API failed: {why}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    api_error("internal error"),
                )
            }
        };
        (status, Json(body)).into_response()
    }
}

fn api_error(error: &str) -> ApiError {
    ApiError {
        error: error.to_owned(),
        fields: Vec::new(),
    }
}

/// Serves the API on `listener` until `shutdown` completes.
pub async fn serve(
    listener: tokio::net::TcpListener,
    api: Api,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, api.router())
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eligibility::Catalog;

    /// A pool that lists a module leases the overlay's instances of it, which `ace serve`
    /// couldn't before: the default `ACE4_POOLS` names `splunk_api`, and an instance's tasks
    /// carry the instance's key.
    #[test]
    fn a_pool_leases_the_instances_of_its_modules() {
        let overlay = ace_sdk::Overlay::from_yaml(
            "modules:\n  splunk_api:\n    instances:\n      clicker_detection_splunk:\n        inputs: [fqdn]\n",
        )
        .expect("reads");
        let manifests = [ace_mod_splunk::MANIFEST, ace_mod_rdap::MANIFEST];
        let catalog = Catalog::of(overlay.components(&manifests).expect("components"));
        let config = ApiConfig::new(vec![
            PoolAccess::new(
                "lookups",
                "a",
                vec!["rdap_analyzer".to_owned(), "splunk_api".to_owned()],
            ),
            PoolAccess::new("parsers", "b", vec!["email_analyzer".to_owned()]),
        ])
        .with_instances(&catalog);
        assert_eq!(
            config.pools[0].modules,
            ["rdap_analyzer", "splunk_api", "clicker_detection_splunk"]
        );
        assert_eq!(config.pools[1].modules, ["email_analyzer"]);
    }

    /// A pool runs GUI commands (PLAN.md 5.12) only when its list has `@commands`, which isn't a module.
    #[test]
    fn a_pool_runs_commands_only_when_it_lists_them() {
        let config = ApiConfig::new(vec![
            PoolAccess::new(
                "parsers",
                "a",
                vec!["email_analyzer".to_owned(), COMMANDS.to_owned()],
            ),
            PoolAccess::new("lookups", "b", vec!["rdap_analyzer".to_owned()]),
        ]);
        assert!(config.pools[0].commands);
        assert_eq!(config.pools[0].modules, ["email_analyzer"]);
        assert!(!config.pools[1].commands);
    }
}
