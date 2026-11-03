//! The lease API (PLAN.md 2.14): what a worker calls to lease, renew and end tasks, and to get
//! presigned bucket URLs for its inputs and outputs. A worker holds an API token and nothing
//! else: no database URL and no bucket key.
//!
//! - `POST /api/worker/v1/lease`: a task of the pool's modules, or 204 after waiting up to
//!   `wait_seconds` (at most `ApiConfig::max_wait`) for one. A file task carries a presigned
//!   URL that downloads its input.
//! - `POST /api/worker/v1/tasks/<id>/renew`: extends the lease; the answer says whether the
//!   task was cancelled.
//! - `POST /api/worker/v1/tasks/<id>/uploads`: a presigned URL to upload one file the module
//!   wrote, under the task's own key in the bucket.
//! - `POST /api/worker/v1/tasks/<id>/end`: the task's end, a `TaskEnd`. A result's files must
//!   be uploaded first; the core checks each one's bytes against its sha256 and moves it into
//!   the `alert_files` pool, held by the root.
//!
//! - `POST /api/worker/v1/tasks/<id>/release`: gives the task back to the queue without
//!   counting the attempt, as a pool does at shutdown.
//! - `GET /api/worker/v1/yara/ruleset`: the ruleset YARA pools should scan with, the latest the
//!   core built (PLAN.md 2.26), with a presigned URL for its bytes; 204 before the first build.
//! - `GET /api/admin/v1/tasks/<id>/replay`: any task in its leased form, with a fresh download
//!   URL, for `ace task replay`. It takes the admin token, and takes no lease.
//!
//! Every request carries `Authorization: Bearer <token>`, and the token says which pool the
//! worker is in. A task-scoped request also names the worker in `x-ace4-worker`. A task's lease
//! owner is `<pool>/<worker>`, so one pool's token can't touch another pool's tasks, and one
//! worker can't end another worker's.

use std::sync::Arc;
use std::time::Duration;

use ace_results::{AlertPath, ObservableKind, ResultEnvelope, Sha256, YaraMeta};
use ace_sdk::wire::{
    ApiError, CurrentRuleset, FieldError as WireFieldError, LeaseRequest, LeasedTask, Presigned,
    Renewal, TaskEnd, TaskFile, TaskObservable, UploadRequest, paths,
};
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

use crate::bucket::{ALERT_FILES, Bucket, BucketError, Hold};
use crate::db::{Db, DbError, Isolation, Retryable};
use crate::orchestrator::{Orchestrator, OrchestratorError};
use crate::queue::{QueueError, TASKS_CHANNEL, Task, TaskId, Worker};
use crate::tree;

/// The header a task-scoped request names its worker in.
pub const WORKER_HEADER: &str = "x-ace4-worker";

/// A pool's access to the API: its name, the hash of its token and the modules it may lease.
#[derive(Clone)]
pub struct PoolAccess {
    pub name: String,
    token_sha256: [u8; 32],
    pub modules: Vec<String>,
}

impl PoolAccess {
    pub fn new(name: impl Into<String>, token: &str, modules: Vec<String>) -> Self {
        PoolAccess {
            name: name.into(),
            token_sha256: sha256(token),
            modules,
        }
    }
}

impl std::fmt::Debug for PoolAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolAccess")
            .field("name", &self.name)
            .field("modules", &self.modules)
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
    /// How long a lease, and each renewal, lasts.
    pub lease: Duration,
    /// The longest a lease request waits for a task.
    pub max_wait: Duration,
    /// How long a presigned URL works.
    pub url_expiry: Duration,
}

impl ApiConfig {
    pub fn new(pools: Vec<PoolAccess>) -> Self {
        ApiConfig {
            pools,
            admin_token_sha256: None,
            lease: Duration::from_secs(60),
            max_wait: Duration::from_secs(20),
            url_expiry: Duration::from_secs(900),
        }
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
    /// token in `ACE4_POOL_TOKEN_<POOL>`, and the admin token in `ACE4_ADMIN_TOKEN`. Each has a
    /// dev default: the parsers and lookups pools with the five ported modules, and tokens
    /// named `ace4-dev-<pool>-token`.
    pub fn from_env() -> Self {
        let pools = std::env::var("ACE4_POOLS").unwrap_or_else(|_| {
            "parsers:email_analyzer,archive,yara_scanner_v3_4;lookups:rdap_analyzer,splunk_api"
                .to_owned()
        });
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
        ApiConfig::new(pools).admin_token(&admin)
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
    orchestrator: Orchestrator,
    config: ApiConfig,
    /// The module of each task that became claimable, or `*` when the listener reconnected and
    /// may have missed some.
    wakeups: broadcast::Sender<String>,
    listener: JoinHandle<()>,
    /// Fires at shutdown, so waiting lease requests answer at once.
    stopping: tokio_util::sync::CancellationToken,
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
                orchestrator,
                config,
                wakeups,
                listener,
                stopping: tokio_util::sync::CancellationToken::new(),
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
            .route("/api/worker/v1/tasks/{id}/end", post(end))
            .route("/api/worker/v1/tasks/{id}/release", post(release))
            .route(paths::RULESET, get(current_ruleset))
            .route("/api/admin/v1/tasks/{id}/replay", get(replay))
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
    }

    /// Claims a task for `worker`, waiting up to `wait` for one.
    async fn lease_for(
        &self,
        worker: &Worker,
        wait: Duration,
    ) -> Result<Option<LeasedTask>, Failure> {
        let mut wakeups = self.inner.wakeups.subscribe();
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(task) = worker.claim().await? {
                match self.leased(worker, task).await? {
                    Some(leased) => return Ok(Some(leased)),
                    None => continue,
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline || self.inner.stopping.is_cancelled() {
                return Ok(None);
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
                    () = self.inner.stopping.cancelled() => return Ok(None),
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

    /// The leased form of a claimed task. A file task whose bytes aren't in the bucket fails,
    /// and None says to claim another.
    async fn leased(&self, worker: &Worker, task: Task) -> Result<Option<LeasedTask>, Failure> {
        let file = if task.observable.kind == ObservableKind::File {
            match self.task_file(&task).await? {
                Ok(file) => Some(file),
                Err(why) => {
                    tracing::error!(task = %task.id, "{why}");
                    worker.fail(task.id, &why).await?;
                    return Ok(None);
                }
            }
        } else {
            None
        };
        Ok(Some(self.wire_task(task, file)))
    }

    fn wire_task(&self, task: Task, file: Option<TaskFile>) -> LeasedTask {
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
            },
            delayed: task.delayed,
            input_hashes: task.input_hashes,
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

    /// A file task's record and its download URL, or why the task can't run.
    async fn task_file(&self, task: &Task) -> Result<Result<TaskFile, String>, Failure> {
        let Ok(sha256) = task.observable.value.parse::<Sha256>() else {
            return Ok(Err(format!(
                "the file observable's value {:?} isn't a sha256",
                task.observable.value
            )));
        };
        let record = tree::first_file(self.inner.db.pool(), task.root, task.observable.id).await?;
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
        Ok(Ok(TaskFile {
            path,
            sha256,
            size: object.size,
            mime_type: object.mime_type,
            yara_meta,
            download: wire_presigned(download),
        }))
    }

    /// Lands a module's result (PLAN.md 2.15). It is checked against its type's schema before
    /// anything is written, and each file it adds must have been uploaded with bytes that
    /// match its sha256. Then one transaction puts the files in the `alert_files` pool, held by
    /// the root, and writes the result, its observables, its file records and the tasks that
    /// became eligible. The uploads go once that has committed.
    async fn land(&self, worker: &Worker, task: TaskId, result: Value) -> Result<(), Failure> {
        let task = worker.owned(task).await?.ok_or(Failure::LeaseLost(task))?;
        let orchestrator = &self.inner.orchestrator;
        orchestrator
            .check_result(&task.module, &result)
            .map_err(|rejected| {
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
            })?;
        let result: ResultEnvelope<Value> = serde_json::from_value(result)
            .map_err(|e| Failure::BadRequest(format!("the result doesn't read: {e}")))?;
        let bucket = &self.inner.bucket;
        let mut files = Vec::new();
        for file in &result.files {
            files.push(bucket.fetch_upload(task.id.0, &file.sha256).await?);
        }
        let hold = Hold::root(task.root);
        let (task, result, files, hold) = (&task, &result, &files, &hold);
        self.inner
            .db
            .transaction(Isolation::ReadCommitted, |tx| {
                Box::pin(async move {
                    for file in files {
                        bucket.put_in(tx, ALERT_FILES, file, Some(hold)).await?;
                    }
                    orchestrator.land_result(tx, worker, task, result).await?;
                    Ok::<_, LandError>(())
                })
            })
            .await?;
        for file in files {
            bucket.remove_upload(task.id.0, &file.sha256).await?;
        }
        Ok(())
    }
}

/// What can go wrong inside a result's transaction.
#[derive(Debug, thiserror::Error)]
enum LandError {
    #[error(transparent)]
    Bucket(#[from] BucketError),
    #[error(transparent)]
    Orchestrator(#[from] OrchestratorError),
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
        }
    }
}

impl From<LandError> for Failure {
    fn from(error: LandError) -> Self {
        match error {
            LandError::Bucket(e) => Failure::from(e),
            LandError::Orchestrator(e) => Failure::from(e),
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
    match api.lease_for(&worker, wait).await? {
        Some(task) => Ok(Json(task).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
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
    Json(end): Json<TaskEnd>,
) -> Result<StatusCode, Failure> {
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
        TaskEnd::Done { result } => {
            // checked as JSON, so each field that fails is named
            let result = serde_json::to_value(result)
                .map_err(|e| Failure::Internal(format!("re-encoding a result: {e}")))?;
            api.land(&worker, task, result).await?
        }
        TaskEnd::Skipped { reason } => {
            tracing::info!(%task, "skipped: {reason}");
            worker.complete(task).await?;
        }
        TaskEnd::Delay {
            after_seconds,
            state,
        } => {
            let after = Duration::try_from_secs_f64(after_seconds)
                .map_err(|e| Failure::BadRequest(format!("after_seconds: {e}")))?;
            worker.delay(task, after, &state).await?;
        }
        TaskEnd::Failed { error } => worker.fail(task, &error).await?,
        TaskEnd::Cancelled => worker.cancelled(task).await?,
    }
    Ok(StatusCode::NO_CONTENT)
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
        Some(api.task_file(&task).await?.map_err(Failure::BadRequest)?)
    } else {
        None
    };
    Ok(Json(api.wire_task(task, file)))
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
    /// A result that failed its schema, with each field that failed.
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
