//! The AI investigation API (PLAN.md 7.15): ace3's `saq/ai_query/` and the service half of `aceapi_ai/`.
//!
//! **What it is.** ACE calls no language model. This is the other direction: read-only routes that an
//! AI agent, running somewhere else under an API key of its own, calls to investigate an alert. The
//! agent can run a query against a data source through a *backend* (ace3 ships one, Splunk), read an
//! alert and its observables, read an event, search past alerts, and export alerts for offline
//! analysis. Nothing here sends anything to a model or to any service but a configured backend.
//!
//! **Off by default.** A `Service` has no AI surface unless the binary gives it one
//! ([`Service::with_ai`]), which `ace serve-ai` does only when its overlay's `ai_api:` section says
//! `enabled: true`. `ace serve` never does: the routes are served by that process alone. Without one every route answers `NotFound` saying so, after the permission check,
//! so a key that holds nothing learns nothing.
//!
//! **Who may call.** Each route needs its own permission, ace3's: `ai:<backend>` for a backend's
//! query, `ai:alert`, `ai:event`, `ai:search` and `ai:export`. Listing the backends needs
//! `ai:backends`, which is ace4's: ace3 lets any authenticated key list them, and ace4 has no route but
//! the ping that asks for nothing. Only an API key may call, as in ace3, where no browser talks to the
//! app: a session is refused even if its user holds the permission.
//!
//! A key that holds only `ai:` permissions passes nothing on the main API, which `ace-api`'s tests
//! sweep. The reads of ACE's own data run as the component `ai_api` (migration 0062), which holds
//! `alert:read` and `event:read`, once the key has been found to hold the route's permission, so the
//! key itself never holds either. ace3's routes reuse its v2 services behind their own gate the same
//! way.
//!
//! **Bounds.** A query's text is at most [`MAX_QUERY_CHARS`]; its rows at most the backend's
//! `max_limit`, and [`MAX_RESPONSE_BYTES`] in all, with `truncated` and why when either cut it; its
//! time is the backend's. Each bucket (a backend, `search`, `export`) has ace3's three limits, enforced
//! across every node by rows in Postgres where ace3 uses Redis ([`limiter`]): queries at once, requests
//! a minute, requests an hour. A refusal is `RateLimited` with when to try again. When the limiter's
//! store can't be reached a request is refused, unless the site set `rate_limit_fail_open`.
//!
//! **Audit.** Every operation writes an audit row before it answers (`ai_record`, one row a request):
//! the key, the event (ace3's names: `query`, `query_rejected`, `query_error`, `rate_limited`,
//! `alert_read`, `event_read`, `search`, `similar`, `export_alerts` and their `_error`s), what was
//! asked and how much came back in counts and bytes. The query's text is recorded, as ace3 records it:
//! what an agent asked is the point of the trail. No row or alert content is. If the row can't be
//! written the request fails and returns nothing, so nothing an `ai:` key reaches can read without a
//! record. The same record goes to the log as `AI_AUDIT {json}`, ace3's line. A request refused for its
//! credential or its permission has the gate's warning and no row, as every refusal here.
//!
//! **What an agent's key can be made to do.** Alert text is whatever an attacker sent, and an agent
//! that reads it may follow instructions in it. What such an agent can then do is exactly what its
//! key's permissions allow: run read-only queries on the backends it holds (the backend's own
//! credential decides what "read-only" means there), and read alerts, events, search results and the
//! export. It can change nothing in ACE: there is no write among these routes, and its key holds
//! nothing on the main API. The limits bound how fast, and the audit shows what it asked.
//!
//! What differs from ace3, and what isn't here:
//! - ace3 runs this as a separate app in a container that holds no encryption key and no credential
//!   but its backends'. So does ace4: `ace serve-ai` (`ace-app`'s `serve_ai`), under a database role
//!   that can do only what these functions do ([`role`]), with ace3's startup custody checks
//!   (`ace-app`'s `ai::custody`). Where ace3's limiter keeps its state in Redis, whose password the
//!   container holds, this one's is in Postgres, under the same role.
//! - An alert has no version token, no `saq.log` and no whole-directory download (`ace-api`'s docs), so
//!   those three reads aren't here. An alert's observables come in pages.
//! - The export pages the alert list oldest first with the list's cursor: roots record no time they
//!   last changed, so there is no `changed_since`. A page is at most 200 alerts, and an alert's
//!   observables are in its row, up to 500, since
//!   ace4 has no index of observables to look ids up in; ace3's `POST /export/observables` has no
//!   counterpart.
//! - The backend's `python_module` and `python_class` are a type the binary registers
//!   (`ace_app::App::ai_backend_type`), named in the overlay.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_sdk::overlay::DispositionClass;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::alerts::{Alert, AlertQuery, AlertSort, AlertSummary, ObservablePage};
use crate::events::{Event, EventRef};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{
    AI_ALERT, AI_BACKENDS, AI_EVENT, AI_EXPORT, AI_SEARCH, ALERT_READ, PermissionName,
};
use crate::search::{SearchRequest, SearchResponse, SimilarRequest};
use crate::{Actor, Component, FilterEntry, Service, ServiceError};

pub mod limiter;
pub mod role;
pub mod testing;

pub use limiter::{AiLimiter, LimitError, LimitKind, PgLimiter, Slot};

/// The component the API reads ACE's own data as.
pub const AI_COMPONENT: &str = "ai_api";
/// The longest query text, in characters. ace3 has no limit but its body's size.
pub const MAX_QUERY_CHARS: usize = 16_384;
/// The most bytes of rows one query answers with, as JSON. Rows past it are left out and the answer
/// says `truncated` with the reason `size`.
pub const MAX_RESPONSE_BYTES: usize = 16 << 20;
/// What the awaiting request adds to a query's own timeout before it gives up: ace3's
/// `TIMEOUT_GRACE_SECONDS` for a query.
pub const QUERY_GRACE: Duration = Duration::from_secs(30);
/// The same for a search or an export, ace3's `aceapi_ai/limited.py`.
pub const READ_GRACE: Duration = Duration::from_secs(5);
/// The search routes' bucket.
pub const SEARCH_BUCKET: &str = "search";
/// The export routes' bucket.
pub const EXPORT_BUCKET: &str = "export";
/// The most alerts one export page holds. ace3's `MAX_ALERT_PAGE_SIZE` is 1,000, of rows that carry
/// ids; a row here carries its observables, so a page is smaller: at most 100,000 observables.
pub const MAX_EXPORT_PAGE: u32 = 200;
/// The most observables, and the most detections, one exported alert carries. An alert with more says
/// so; the alert's own pages have the rest.
pub const MAX_EXPORT_OBSERVABLES: i64 = 500;

/// A bucket's limits: ace3's `AIQueryBackendLimits`, with its defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiLimits {
    /// The most queries running at once, across every node.
    pub max_concurrency: u32,
    pub requests_per_minute: u32,
    pub hourly_budget: u32,
    /// The row limit when a request names none.
    pub default_limit: u32,
    /// The largest row limit a request may name.
    pub max_limit: u32,
    /// The widest time window a query may cover, in seconds.
    pub max_window_seconds: i64,
    /// The timeout when a request names none, in seconds.
    pub default_query_timeout: u32,
    /// The largest timeout a request may name, in seconds.
    pub max_query_timeout: u32,
}

impl Default for AiLimits {
    fn default() -> Self {
        AiLimits {
            max_concurrency: 2,
            requests_per_minute: 10,
            hourly_budget: 120,
            default_limit: 1000,
            max_limit: 5000,
            max_window_seconds: 90 * 86_400,
            default_query_timeout: 300,
            max_query_timeout: 600,
        }
    }
}

impl AiLimits {
    /// ace3's defaults for the export: more requests, since a first pull pages through every alert.
    pub fn export() -> Self {
        AiLimits {
            requests_per_minute: 60,
            hourly_budget: 1200,
            ..AiLimits::default()
        }
    }

    /// `max_window_seconds` as ace3 writes it, `DD:HH:MM:SS`.
    pub fn max_window(&self) -> String {
        let seconds = self.max_window_seconds;
        format!(
            "{:02}:{:02}:{:02}:{:02}",
            seconds / 86_400,
            seconds % 86_400 / 3600,
            seconds % 3600 / 60,
            seconds % 60
        )
    }

    /// A window as ace3 writes one, `[[DD:]HH:]MM:SS`, in seconds: its `create_timedelta`.
    pub fn parse_window(text: &str) -> Result<i64, String> {
        let parts: Vec<&str> = text.split(':').collect();
        let bad = || format!("{text:?} isn't a window: write DD:HH:MM:SS");
        if !(2..=4).contains(&parts.len()) {
            return Err(bad());
        }
        let mut seconds: i64 = 0;
        for (part, unit) in parts.iter().rev().zip([1, 60, 3600, 86_400]) {
            let value: i64 = part.parse().map_err(|_| bad())?;
            if !(0..=100_000).contains(&value) {
                return Err(bad());
            }
            seconds += value * unit;
        }
        if seconds == 0 {
            return Err(bad());
        }
        Ok(seconds)
    }

    /// Whether these can be used: nothing zero, and no default past its maximum.
    pub fn check(&self) -> Result<(), String> {
        let positive = [
            ("max_concurrency", self.max_concurrency),
            ("requests_per_minute", self.requests_per_minute),
            ("hourly_budget", self.hourly_budget),
            ("default_limit", self.default_limit),
            ("max_limit", self.max_limit),
            ("default_query_timeout", self.default_query_timeout),
            ("max_query_timeout", self.max_query_timeout),
        ];
        if let Some((name, _)) = positive.iter().find(|(_, value)| *value == 0) {
            return Err(format!("{name} has to be at least 1"));
        }
        if self.default_limit > self.max_limit {
            return Err("default_limit is over max_limit".to_owned());
        }
        if self.default_query_timeout > self.max_query_timeout {
            return Err("default_query_timeout is over max_query_timeout".to_owned());
        }
        if self.max_query_timeout > 3600 {
            return Err("max_query_timeout is at most 3600 seconds".to_owned());
        }
        if self.max_window_seconds <= 0 {
            return Err("max_window has to be longer than nothing".to_owned());
        }
        Ok(())
    }

    fn json(&self) -> Value {
        serde_json::json!({
            "max_concurrency": self.max_concurrency,
            "requests_per_minute": self.requests_per_minute,
            "hourly_budget": self.hourly_budget,
            "default_limit": self.default_limit,
            "max_limit": self.max_limit,
            "max_window": self.max_window(),
            "default_query_timeout": self.default_query_timeout,
            "max_query_timeout": self.max_query_timeout,
        })
    }
}

/// One query: ace3's `AIQueryRequest`.
#[derive(Debug, Clone, PartialEq)]
pub struct AiQueryRequest {
    pub query: String,
    /// The window's start; None exactly when the backend has no window.
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    /// None is the backend's `default_limit`.
    pub limit: Option<u32>,
    /// In seconds. The service fills in the backend's `default_query_timeout` before the backend
    /// sees the request.
    pub timeout_seconds: Option<u32>,
    /// What only this backend takes.
    pub extras: Map<String, Value>,
}

/// What a backend found: ace3's `AIQueryResult`. The row count is the rows'.
#[derive(Debug, Clone, PartialEq)]
pub struct AiQueryResult {
    /// The backend's own field names, untouched: a client's tooling keys on them.
    pub rows: Vec<Map<String, Value>>,
    /// Whether rows were cut. A capped result says so: it's never a silently short list.
    pub truncated: bool,
    /// `limit` or `backend_cap`; the service adds `size`.
    pub truncation_reason: Option<String>,
    /// The window the backend covered; None when it has none.
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    pub duration_ms: u64,
    pub meta: Map<String, Value>,
}

/// Why a backend gave no result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiQueryError {
    /// The backend refuses the request: ace3's `AIQueryRejected`, a 400.
    Rejected(String),
    /// The backend failed: ace3's `AIBackendError`, with the status the API answers, 502 or 504. The
    /// reason is shown to the caller and recorded, so it must hold no credential.
    Backend { status: u16, reason: String },
}

pub type AiFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One read-only query backend: ace3's `AIQueryBackend`. It wraps one data source's search API.
///
/// A backend is built once and `execute` is called by many requests at once, so what belongs to one
/// request stays in `execute`. Whatever it returns goes to the caller as it is: rows are the data
/// source's own.
pub trait AiQueryBackend: std::fmt::Debug + Send + Sync {
    /// False for a backend whose data has no time axis. The service then refuses a request that
    /// carries a window, so a reader never takes current state for a bounded search.
    fn windowed(&self) -> bool {
        true
    }

    /// The JSON schema of the `extras` it takes; None when it takes none, and then a request with
    /// any is refused.
    fn extras_schema(&self) -> Option<Value> {
        None
    }

    /// Checks a request's `extras`, when the backend takes any. The error is shown to the caller.
    fn check_extras(&self, _extras: &Map<String, Value>) -> Result<(), String> {
        Ok(())
    }

    /// What `GET /backends` says of it besides its name, window, limits and extras: its query
    /// language, time semantics and notes.
    fn describe(&self) -> Map<String, Value>;

    /// Refuses a request the backend won't run, before any limit is charged.
    fn validate(&self, request: &AiQueryRequest, limits: &AiLimits) -> Result<(), String>;

    /// Runs the query.
    fn execute<'a>(
        &'a self,
        request: &'a AiQueryRequest,
        limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<AiQueryResult, AiQueryError>>;
}

/// A backend with its limits.
#[derive(Debug, Clone)]
pub struct AiBackendEntry {
    pub backend: Arc<dyn AiQueryBackend>,
    pub limits: AiLimits,
}

/// The AI API as one server has it: its backends by name, the search and export limits, and the
/// limiter.
#[derive(Debug, Clone)]
pub struct AiSurface {
    backends: BTreeMap<String, AiBackendEntry>,
    search_limits: AiLimits,
    export_limits: AiLimits,
    limiter: Arc<dyn AiLimiter>,
    fail_open: bool,
    query_grace: Duration,
    read_grace: Duration,
}

impl AiSurface {
    /// A surface with no backend, ace3's default limits and a limiter that fails closed.
    pub fn new(limiter: Arc<dyn AiLimiter>) -> Self {
        AiSurface {
            backends: BTreeMap::new(),
            search_limits: AiLimits::default(),
            export_limits: AiLimits::export(),
            limiter,
            fail_open: false,
            query_grace: QUERY_GRACE,
            read_grace: READ_GRACE,
        }
    }

    /// How long a request waits past a query's own timeout, and past a search's or an export's, before
    /// it gives up: ace3's 30 and 5 seconds unless set.
    pub fn with_grace(mut self, query: Duration, read: Duration) -> Self {
        self.query_grace = query;
        self.read_grace = read;
        self
    }

    /// Adds a backend. Its name is its route and its permission's minor, `ai:<name>`, so it has to
    /// be a permission's part, and not one of the routes' own.
    pub fn with_backend(
        mut self,
        name: &str,
        backend: Arc<dyn AiQueryBackend>,
        limits: AiLimits,
    ) -> Result<Self, String> {
        let permission = PermissionName::new("ai", name).map_err(|e| e.to_string())?;
        if permission.minor() != name {
            return Err(format!("the backend name {name:?} has to be lowercase"));
        }
        if ["alert", "event", "search", "export", "backends"].contains(&name) {
            return Err(format!(
                "{name:?} can't name a backend: ai:{name} is a route's own permission"
            ));
        }
        limits
            .check()
            .map_err(|e| format!("backend {name}'s limits: {e}"))?;
        if self
            .backends
            .insert(name.to_owned(), AiBackendEntry { backend, limits })
            .is_some()
        {
            return Err(format!("two backends are named {name:?}"));
        }
        Ok(self)
    }

    pub fn with_search_limits(mut self, limits: AiLimits) -> Result<Self, String> {
        limits.check().map_err(|e| format!("search_limits: {e}"))?;
        self.search_limits = limits;
        Ok(self)
    }

    pub fn with_export_limits(mut self, limits: AiLimits) -> Result<Self, String> {
        limits.check().map_err(|e| format!("export_limits: {e}"))?;
        self.export_limits = limits;
        Ok(self)
    }

    /// Serve requests without limits when the limiter's store can't be reached, where the default is
    /// to refuse them: ace3's `ai_api.rate_limit_fail_open`.
    pub fn with_fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    /// The backends' names, in order.
    pub fn backend_names(&self) -> Vec<&str> {
        self.backends.keys().map(String::as_str).collect()
    }

    pub fn backend(&self, name: &str) -> Option<&AiBackendEntry> {
        self.backends.get(name)
    }
}

/// One backend as `GET /backends` lists it: ace3's `BackendDescriptor`.
#[derive(Debug, Clone, PartialEq)]
pub struct AiBackendDescription {
    pub name: String,
    /// Whether the caller's key holds `ai:<name>`.
    pub authorized: bool,
    pub describe: Map<String, Value>,
}

/// A query's answer: ace3's `AIQueryResponse`.
#[derive(Debug, Clone, PartialEq)]
pub struct AiQueryResponse {
    pub backend: String,
    pub rows: Vec<Map<String, Value>>,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    pub duration_ms: u64,
    pub meta: Map<String, Value>,
}

/// An observable of an exported alert. A file's value is its sha256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiExportObservable {
    pub id: i64,
    pub kind: String,
    pub value: String,
}

/// A detection of an exported alert: which signature fired, and the observable it's on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiExportDetection {
    pub signature_uuid: Option<String>,
    pub signature_version: Option<String>,
    pub signature_family: Option<String>,
    pub observable_type: String,
    pub observable_value: String,
}

/// One alert of the export: its row and what it maps to. ace3's `ExportAlert`.
#[derive(Debug, Clone, PartialEq)]
pub struct AiExportAlert {
    pub alert: AlertSummary,
    /// What its disposition says of its detections, by the site's classification; None for a
    /// disposition that says neither, and for none.
    pub disposition_class: Option<DispositionClass>,
    /// Its first observables, in the order they were added.
    pub observables: Vec<AiExportObservable>,
    /// It has more observables than `MAX_EXPORT_OBSERVABLES`.
    pub observables_truncated: bool,
    pub detections: Vec<AiExportDetection>,
    pub detections_truncated: bool,
    pub event_ids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AiExportPage {
    pub alerts: Vec<AiExportAlert>,
    /// Pass as `after` for the next page; None on the last.
    pub next: Option<String>,
}

/// An operation's audit row, which is also ace3's `AI_AUDIT` log line. Counts and sizes, the caller's
/// own query and what it named: no row a backend returned and nothing an alert holds.
#[derive(Debug, Default, Serialize)]
struct AiAudit<'a> {
    event: &'a str,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<&'a str>,
    /// The query's length in characters, when it was too long to keep.
    #[serde(skip_serializing_if = "Option::is_none")]
    query_chars: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_start: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_end: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    row_count: Option<usize>,
    /// How many bytes of rows were returned, as JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    /// Which limit refused: `concurrency`, `rate` or `budget`.
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alert: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    filters: Option<&'a [FilterEntry]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    include_test_alerts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    excluded_test_alerts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<u64>,
    /// The alerts a search answered with.
    #[serde(skip_serializing_if = "Option::is_none")]
    result_ids: Option<&'a [Uuid]>,
    /// The export's cursor, and whether there's a next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    more: Option<bool>,
}

impl Recorded for AiAudit<'_> {}

/// What an operation that failed inside its limits came to.
enum Limited<T> {
    Done(T),
    Refused(LimitKind, String, u64),
    Unavailable,
    TimedOut,
}

/// A held slot, given back when the request ends, however it ends: a request whose future is dropped
/// releases from a task of its own, and the limiter reaps what even that misses.
struct SlotGuard {
    limiter: Arc<dyn AiLimiter>,
    slot: Option<Slot>,
}

impl SlotGuard {
    async fn release(mut self) {
        if let Some(slot) = self.slot.take() {
            self.limiter.release(slot).await;
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let limiter = self.limiter.clone();
            runtime.spawn(async move { limiter.release(slot).await });
        }
    }
}

/// The actor the API reads ACE's own data as.
fn component() -> Actor {
    Actor::Internal {
        id: Component::new(AI_COMPONENT).expect("a valid component name"),
    }
}

fn elapsed(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl Service {
    /// The service with the AI investigation API turned on.
    pub fn with_ai(mut self, surface: AiSurface) -> Self {
        self.ai = Some(Arc::new(surface));
        self
    }

    /// The AI surface, when the binary set one.
    pub fn ai_surface(&self) -> Option<&Arc<AiSurface>> {
        self.ai.as_ref()
    }

    /// Lets `actor` onto a route that needs `permission`: it has to hold it, be an API key, and the
    /// surface has to be on, in that order, so a caller that may not ask learns nothing else.
    async fn ai_gate(
        &self,
        actor: &Actor,
        action: &'static str,
        permission: &PermissionName,
    ) -> Result<Arc<AiSurface>, ServiceError> {
        if !self.gate.allowed(actor, permission).await? {
            tracing::warn!(%actor, %permission, action, "permission denied");
            return Err(ServiceError::PermissionDenied {
                actor: actor.to_string(),
                permission: permission.clone(),
            });
        }
        if !matches!(actor, Actor::ApiKey { .. }) {
            return Err(ServiceError::Forbidden(
                "the AI investigation API takes an API key, not a session".to_owned(),
            ));
        }
        self.ai.clone().ok_or_else(|| {
            ServiceError::NotFound(
                "the AI investigation API isn't enabled on this server: the overlay's ai_api \
                 section turns it on"
                    .to_owned(),
            )
        })
    }

    /// Writes one operation's audit row, and its `AI_AUDIT` line once the row is committed. Every route
    /// calls it before it answers, so a failure to record fails the request.
    async fn ai_record(
        &self,
        actor: &Actor,
        permission: &PermissionName,
        target: Target,
        record: &AiAudit<'_>,
    ) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "ai_record", permission, &|_tx| {
                let target = target.clone();
                Box::pin(async move { Ok(Audited::changed((), Change::read(target, record)?)) })
            })
            .await?;
        // ace3's line, for a log pipeline that ships it off the node
        tracing::info!(
            %actor,
            "AI_AUDIT {}",
            serde_json::to_string(record).unwrap_or_default()
        );
        Ok(())
    }

    /// Runs `work` inside `bucket`'s limits: the slot first, since a request refused for concurrency
    /// must not use up the minute's count, then the counts, then the work, for at most `timeout`.
    async fn ai_limited<T>(
        &self,
        surface: &AiSurface,
        bucket: &str,
        limits: &AiLimits,
        timeout: Duration,
        work: impl Future<Output = T>,
    ) -> Limited<T> {
        let unavailable = |error: &str| {
            if surface.fail_open {
                tracing::warn!(
                    bucket,
                    "the AI rate limiter is unavailable, failing open: {error}"
                );
                false
            } else {
                tracing::error!(
                    bucket,
                    "the AI rate limiter is unavailable, refusing: {error}"
                );
                true
            }
        };
        let guard = match surface.limiter.acquire(bucket, limits).await {
            Ok(slot) => SlotGuard {
                limiter: surface.limiter.clone(),
                slot: Some(slot),
            },
            Err(LimitError::Exceeded {
                kind,
                detail,
                retry_after_seconds,
            }) => return Limited::Refused(kind, detail, retry_after_seconds),
            Err(LimitError::Unavailable(error)) => {
                if unavailable(&error) {
                    return Limited::Unavailable;
                }
                SlotGuard {
                    limiter: surface.limiter.clone(),
                    slot: None,
                }
            }
        };
        let outcome = match surface.limiter.check_request(bucket, limits).await {
            Err(LimitError::Exceeded {
                kind,
                detail,
                retry_after_seconds,
            }) => Limited::Refused(kind, detail, retry_after_seconds),
            Err(LimitError::Unavailable(error)) if unavailable(&error) => Limited::Unavailable,
            Ok(()) | Err(LimitError::Unavailable(_)) => {
                match tokio::time::timeout(timeout, work).await {
                    Ok(value) => Limited::Done(value),
                    Err(_) => Limited::TimedOut,
                }
            }
        };
        guard.release().await;
        outcome
    }

    /// Records what a limit, the limiter or the clock made of an operation and returns the error it
    /// answers with. `noun` names the work, as ace3's details do.
    #[allow(clippy::too_many_arguments)]
    async fn ai_refused<T>(
        &self,
        actor: &Actor,
        permission: &PermissionName,
        target: Target,
        event: &str,
        noun: &str,
        limited: Limited<T>,
        base: AiAudit<'_>,
    ) -> Result<T, ServiceError> {
        let failed = format!("{event}_error");
        match limited {
            Limited::Done(value) => Ok(value),
            Limited::Refused(kind, detail, retry_after_seconds) => {
                self.ai_record(
                    actor,
                    permission,
                    target,
                    &AiAudit {
                        event: "rate_limited",
                        status: 429,
                        kind: Some(kind.as_str()),
                        detail: Some(&detail),
                        ..base
                    },
                )
                .await?;
                Err(ServiceError::RateLimited {
                    detail,
                    retry_after_seconds,
                })
            }
            Limited::Unavailable => {
                let detail = "rate limiter unavailable";
                self.ai_record(
                    actor,
                    permission,
                    target,
                    &AiAudit {
                        event: &failed,
                        status: 503,
                        detail: Some(detail),
                        ..base
                    },
                )
                .await?;
                Err(ServiceError::Unavailable(format!(
                    "{detail}, refusing {noun}"
                )))
            }
            Limited::TimedOut => {
                let detail = format!("{noun} timed out");
                self.ai_record(
                    actor,
                    permission,
                    target,
                    &AiAudit {
                        event: &failed,
                        status: 504,
                        detail: Some(&detail),
                        ..base
                    },
                )
                .await?;
                Err(ServiceError::Upstream {
                    status: 504,
                    reason: detail,
                })
            }
        }
    }

    /// The enabled backends, each with whether the caller's key reaches it: ace3's `GET /backends`.
    /// Needs `ai:backends`. It reads nothing and isn't recorded.
    pub async fn ai_backends(
        &self,
        actor: &Actor,
    ) -> Result<Vec<AiBackendDescription>, ServiceError> {
        let surface = self.ai_gate(actor, "ai_backends", &AI_BACKENDS).await?;
        let mut described = Vec::new();
        for (name, entry) in &surface.backends {
            let permission = PermissionName::new("ai", name)?;
            let mut describe = Map::new();
            describe.insert("name".to_owned(), Value::String(name.clone()));
            describe.insert("windowed".to_owned(), Value::Bool(entry.backend.windowed()));
            describe.insert("limits".to_owned(), entry.limits.json());
            describe.insert(
                "extras_schema".to_owned(),
                entry.backend.extras_schema().unwrap_or(Value::Null),
            );
            describe.extend(entry.backend.describe());
            described.push(AiBackendDescription {
                name: name.clone(),
                authorized: self.gate.allowed(actor, &permission).await?,
                describe,
            });
        }
        Ok(described)
    }

    /// Runs a read-only query on a backend: ace3's `execute_query`. Needs `ai:<backend>`. A request
    /// the service or the backend refuses is `InvalidRequest`; a limit's refusal `RateLimited`; a
    /// backend's failure `Upstream`. Each is recorded.
    pub async fn ai_query(
        &self,
        actor: &Actor,
        backend: &str,
        request: AiQueryRequest,
    ) -> Result<AiQueryResponse, ServiceError> {
        // a name that can't be a permission's part names no backend
        let no_backend = || ServiceError::NotFound(format!("no AI query backend {backend:?}"));
        let permission = PermissionName::new("ai", backend).map_err(|_| no_backend())?;
        let surface = self.ai_gate(actor, "ai_query", &permission).await?;
        let entry = surface.backends.get(backend).ok_or_else(no_backend)?;
        let limits = &entry.limits;
        let target = Target::ai_backend(backend);
        let chars = request.query.chars().count();
        let too_long = chars > MAX_QUERY_CHARS;
        let base = || AiAudit {
            backend: Some(backend),
            query: (!too_long).then_some(request.query.as_str()),
            query_chars: too_long.then_some(chars),
            window_start: request.start_time,
            window_end: request.end_time,
            limit: request.limit,
            timeout_seconds: request.timeout_seconds,
            ..AiAudit::default()
        };

        // what ace3's service refuses before the backend sees the request, in its order
        let windowed = entry.backend.windowed();
        let has_window = (request.start_time.is_some(), request.end_time.is_some());
        let refusal = if too_long {
            Some(format!("a query has at most {MAX_QUERY_CHARS} characters"))
        } else if !request.extras.is_empty() && entry.backend.extras_schema().is_none() {
            Some(format!("backend {backend} accepts no extras"))
        } else if let Err(error) = entry.backend.check_extras(&request.extras) {
            Some(format!("invalid extras: {error}"))
        } else if windowed && has_window != (true, true) {
            Some(format!(
                "backend {backend} requires start_time and end_time"
            ))
        } else if !windowed && has_window != (false, false) {
            // refused, not ignored: an ignored window would read as a bounded search
            Some(format!(
                "backend {backend} has no time window; remove start_time and end_time and put any \
                 time filter in the query itself"
            ))
        } else if request.limit == Some(0) {
            Some("limit has to be at least 1".to_owned())
        } else if request.timeout_seconds == Some(0) {
            Some("timeout_seconds has to be at least 1".to_owned())
        } else if request
            .timeout_seconds
            .is_some_and(|timeout| timeout > limits.max_query_timeout)
        {
            Some(format!(
                "timeout_seconds exceeds the maximum of {}",
                limits.max_query_timeout
            ))
        } else {
            None
        };
        let timeout = request
            .timeout_seconds
            .unwrap_or(limits.default_query_timeout);
        let request = AiQueryRequest {
            timeout_seconds: Some(timeout),
            ..request.clone()
        };
        let refusal = refusal.or_else(|| entry.backend.validate(&request, limits).err());
        if let Some(detail) = refusal {
            return self
                .ai_rejected(actor, &permission, target, base(), detail)
                .await;
        }

        let limited = self
            .ai_limited(
                &surface,
                backend,
                limits,
                Duration::from_secs(u64::from(timeout)) + surface.query_grace,
                entry.backend.execute(&request, limits),
            )
            .await;
        let result = self
            .ai_refused(
                actor,
                &permission,
                target.clone(),
                "query",
                "query",
                limited,
                base(),
            )
            .await?;
        let mut result = match result {
            Ok(result) => result,
            Err(AiQueryError::Rejected(detail)) => {
                return self
                    .ai_rejected(actor, &permission, target, base(), detail)
                    .await;
            }
            Err(AiQueryError::Backend { status, reason }) => {
                // a backend names a failure of its own: never a 2xx, 3xx or 4xx of this API's
                let status = if (500..=599).contains(&status) {
                    status
                } else {
                    502
                };
                self.ai_record(
                    actor,
                    &permission,
                    target,
                    &AiAudit {
                        event: "query_error",
                        status,
                        detail: Some(&reason),
                        ..base()
                    },
                )
                .await?;
                return Err(ServiceError::Upstream { status, reason });
            }
        };

        // the bounds on what leaves: the row limit, then the bytes
        let cap = request
            .limit
            .unwrap_or(limits.default_limit)
            .min(limits.max_limit) as usize;
        if result.rows.len() > cap {
            result.rows.truncate(cap);
            result.truncated = true;
            result.truncation_reason.get_or_insert("limit".to_owned());
        }
        let mut bytes = 0;
        let mut kept = result.rows.len();
        for (index, row) in result.rows.iter().enumerate() {
            bytes += serde_json::to_vec(row)?.len();
            if bytes > MAX_RESPONSE_BYTES {
                kept = index;
                break;
            }
        }
        if kept < result.rows.len() {
            result.rows.truncate(kept);
            bytes = 0;
            for row in &result.rows {
                bytes += serde_json::to_vec(row)?.len();
            }
            result.truncated = true;
            result.truncation_reason = Some("size".to_owned());
        }

        self.ai_record(
            actor,
            &permission,
            target,
            &AiAudit {
                event: "query",
                status: 200,
                row_count: Some(result.rows.len()),
                bytes: Some(bytes),
                truncated: Some(result.truncated),
                duration_ms: Some(result.duration_ms),
                ..base()
            },
        )
        .await?;
        Ok(AiQueryResponse {
            backend: backend.to_owned(),
            rows: result.rows,
            truncated: result.truncated,
            truncation_reason: result.truncation_reason,
            window_start: result.window_start,
            window_end: result.window_end,
            duration_ms: result.duration_ms,
            meta: result.meta,
        })
    }

    /// Records a refused query and returns its error.
    async fn ai_rejected<T>(
        &self,
        actor: &Actor,
        permission: &PermissionName,
        target: Target,
        base: AiAudit<'_>,
        detail: String,
    ) -> Result<T, ServiceError> {
        self.ai_record(
            actor,
            permission,
            target,
            &AiAudit {
                event: "query_rejected",
                status: 400,
                detail: Some(&detail),
                ..base
            },
        )
        .await?;
        Err(ServiceError::InvalidRequest(detail))
    }

    /// One alert, with how much it holds: ace3's `GET /alerts/{uuid}`. Needs `ai:alert`, and records
    /// the read.
    pub async fn ai_alert(&self, actor: &Actor, id: Uuid) -> Result<Alert, ServiceError> {
        self.ai_gate(actor, "ai_alert", &AI_ALERT).await?;
        let alert = self.alert(&component(), id).await?;
        self.ai_record(
            actor,
            &AI_ALERT,
            Target::root(id),
            &AiAudit {
                event: "alert_read",
                status: 200,
                alert: Some(id),
                ..AiAudit::default()
            },
        )
        .await?;
        Ok(alert)
    }

    /// A page of an alert's observables, each with its results and detections: the alert's analysis,
    /// which ace3's alert read returns whole. Needs `ai:alert`, and records the read.
    pub async fn ai_alert_observables(
        &self,
        actor: &Actor,
        id: Uuid,
        limit: Option<u32>,
        after: Option<i64>,
    ) -> Result<ObservablePage, ServiceError> {
        self.ai_gate(actor, "ai_alert_observables", &AI_ALERT)
            .await?;
        let page = self
            .alert_observables(&component(), id, limit, after)
            .await?;
        self.ai_record(
            actor,
            &AI_ALERT,
            Target::root(id),
            &AiAudit {
                event: "alert_observables",
                status: 200,
                alert: Some(id),
                limit,
                result_count: Some(page.observables.len()),
                more: Some(page.next.is_some()),
                ..AiAudit::default()
            },
        )
        .await?;
        Ok(page)
    }

    /// One event, by its id or uuid, with its alerts: ace3's `GET /events/{id}`. Needs `ai:event`, and
    /// records the read.
    pub async fn ai_event(&self, actor: &Actor, event: EventRef) -> Result<Event, ServiceError> {
        self.ai_gate(actor, "ai_event", &AI_EVENT).await?;
        let found = self.event(&component(), event).await?;
        let named = match event {
            EventRef::Id(id) => id.to_string(),
            EventRef::Uuid(uuid) => uuid.to_string(),
        };
        self.ai_record(
            actor,
            &AI_EVENT,
            Target::event(found.id),
            &AiAudit {
                event: "event_read",
                status: 200,
                event_ref: Some(&named),
                ..AiAudit::default()
            },
        )
        .await?;
        Ok(found)
    }

    /// Searches alerts, as `search_alerts` does, under `ai:search`, in the search bucket's limits, with
    /// the query and the alerts it answered with recorded: ace3's `/search/alerts`.
    pub async fn ai_search(
        &self,
        actor: &Actor,
        request: &SearchRequest,
    ) -> Result<SearchResponse, ServiceError> {
        let surface = self.ai_gate(actor, "ai_search", &AI_SEARCH).await?;
        let base = || AiAudit {
            query: Some(request.query.as_str()),
            filters: Some(request.filters.as_slice()),
            limit: Some(request.limit),
            offset: Some(request.offset),
            include_test_alerts: Some(request.include_test_alerts),
            ..AiAudit::default()
        };
        let actor_inside = component();
        let response = self
            .ai_read(
                actor,
                &surface,
                "search",
                base,
                self.search_alerts(&actor_inside, request),
            )
            .await?;
        let ids = response.alert_ids();
        self.ai_record(
            actor,
            &AI_SEARCH,
            Target::ai_search(),
            &AiAudit {
                event: "search",
                status: 200,
                result_count: Some(ids.len()),
                total: Some(response.total),
                excluded_test_alerts: response.excluded_test_alerts,
                result_ids: Some(&ids),
                ..base()
            },
        )
        .await?;
        Ok(response)
    }

    /// The alerts most like one alert, as `similar_alerts` does, under `ai:search`: ace3's
    /// `/search/similar`.
    pub async fn ai_similar(
        &self,
        actor: &Actor,
        request: &SimilarRequest,
    ) -> Result<SearchResponse, ServiceError> {
        let surface = self.ai_gate(actor, "ai_similar", &AI_SEARCH).await?;
        let base = || AiAudit {
            alert: Some(request.alert),
            filters: Some(request.filters.as_slice()),
            limit: Some(request.limit),
            offset: Some(request.offset),
            include_test_alerts: Some(request.include_test_alerts),
            ..AiAudit::default()
        };
        let actor_inside = component();
        let response = self
            .ai_read(
                actor,
                &surface,
                "similar",
                base,
                self.similar_alerts(&actor_inside, request),
            )
            .await?;
        let ids = response.alert_ids();
        self.ai_record(
            actor,
            &AI_SEARCH,
            Target::ai_search(),
            &AiAudit {
                event: "similar",
                status: 200,
                result_count: Some(ids.len()),
                total: Some(response.total),
                excluded_test_alerts: response.excluded_test_alerts,
                result_ids: Some(&ids),
                ..base()
            },
        )
        .await?;
        Ok(response)
    }

    /// Runs a search inside the search bucket's limits. What the limits or the search refuse is
    /// recorded as `event`'s error.
    async fn ai_read<'a, T>(
        &self,
        actor: &Actor,
        surface: &AiSurface,
        event: &'a str,
        base: impl Fn() -> AiAudit<'a>,
        work: impl Future<Output = Result<T, ServiceError>>,
    ) -> Result<T, ServiceError> {
        let limits = &surface.search_limits;
        let timeout = Duration::from_secs(u64::from(limits.max_query_timeout)) + surface.read_grace;
        let limited = self
            .ai_limited(surface, SEARCH_BUCKET, limits, timeout, work)
            .await;
        let found = self
            .ai_refused(
                actor,
                &AI_SEARCH,
                Target::ai_search(),
                event,
                "search",
                limited,
                base(),
            )
            .await?;
        match found {
            Ok(value) => Ok(value),
            Err(error) => {
                self.ai_failed(
                    actor,
                    &AI_SEARCH,
                    Target::ai_search(),
                    event,
                    base(),
                    &error,
                )
                .await?;
                Err(error)
            }
        }
    }

    /// Records an operation the service itself refused, when the refusal is the caller's: a request it
    /// can't take, or one that names nothing. A failure that isn't the caller's is the log's.
    async fn ai_failed(
        &self,
        actor: &Actor,
        permission: &PermissionName,
        target: Target,
        event: &str,
        base: AiAudit<'_>,
        error: &ServiceError,
    ) -> Result<(), ServiceError> {
        let status = match error {
            ServiceError::InvalidRequest(_) => 400,
            ServiceError::NotFound(_) => 404,
            _ => return Ok(()),
        };
        let detail = error.to_string();
        self.ai_record(
            actor,
            permission,
            target,
            &AiAudit {
                event: &format!("{event}_error"),
                status,
                detail: Some(&detail),
                ..base
            },
        )
        .await
    }

    /// A page of every alert, oldest first, each with its observables, detections and events: ace3's
    /// `GET /export/alerts`. Needs `ai:export`, runs in the export bucket's limits, and records the
    /// page asked for and how much it held.
    pub async fn ai_export_alerts(
        &self,
        actor: &Actor,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> Result<AiExportPage, ServiceError> {
        let surface = self.ai_gate(actor, "ai_export_alerts", &AI_EXPORT).await?;
        let base = || AiAudit {
            limit,
            after,
            ..AiAudit::default()
        };
        let limits = &surface.export_limits;
        let timeout = Duration::from_secs(u64::from(limits.max_query_timeout)) + surface.read_grace;
        let limited = self
            .ai_limited(
                &surface,
                EXPORT_BUCKET,
                limits,
                timeout,
                self.export_page(limit, after),
            )
            .await;
        let page = self
            .ai_refused(
                actor,
                &AI_EXPORT,
                Target::ai_export(),
                "export_alerts",
                "export",
                limited,
                base(),
            )
            .await?;
        let page = match page {
            Ok(page) => page,
            Err(error) => {
                self.ai_failed(
                    actor,
                    &AI_EXPORT,
                    Target::ai_export(),
                    "export_alerts",
                    base(),
                    &error,
                )
                .await?;
                return Err(error);
            }
        };
        self.ai_record(
            actor,
            &AI_EXPORT,
            Target::ai_export(),
            &AiAudit {
                event: "export_alerts",
                status: 200,
                result_count: Some(page.alerts.len()),
                more: Some(page.next.is_some()),
                ..base()
            },
        )
        .await?;
        Ok(page)
    }

    /// One page of the export, read as the component.
    async fn export_page(
        &self,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> Result<AiExportPage, ServiceError> {
        let limit = match limit {
            None => MAX_EXPORT_PAGE,
            Some(limit) if (1..=MAX_EXPORT_PAGE).contains(&limit) => limit,
            Some(_) => {
                return Err(ServiceError::InvalidRequest(format!(
                    "a page of the export has 1 to {MAX_EXPORT_PAGE} alerts"
                )));
            }
        };
        let actor = component();
        let query = AlertQuery {
            sort: AlertSort::AlertDate,
            descending: false,
            ..AlertQuery::default()
        };
        let page = self.alerts(&actor, &query, Some(limit), after).await?;
        let ids: Vec<Uuid> = page.alerts.iter().map(|alert| alert.id).collect();
        let ids = &ids;
        let (observables, detections, events) = self
            .gate
            .read(&actor, "ai_export_alerts", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let observables = sqlx::query!(
                        r#"SELECT root_id AS "root_id!", id AS "id!", type AS "kind!", value AS "value!"
                           FROM (
                               SELECT root_id, id, type, value,
                                      row_number() OVER (PARTITION BY root_id ORDER BY id) AS place
                               FROM analysis.observables
                               WHERE root_id = ANY($1)
                           ) AS numbered
                           WHERE place <= $2
                           ORDER BY root_id, id"#,
                        ids,
                        MAX_EXPORT_OBSERVABLES + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let detections = sqlx::query!(
                        r#"SELECT root_id AS "root_id!", signature_uuid, signature_version,
                                  signature_family, kind AS "kind!", value AS "value!"
                           FROM (
                               SELECT d.root_id, d.id, d.signature_uuid, d.signature_version,
                                      d.signature_family, o.type AS kind, o.value,
                                      row_number() OVER (PARTITION BY d.root_id ORDER BY d.id) AS place
                               FROM analysis.detections d
                               JOIN analysis.observables o
                                 ON o.root_id = d.root_id AND o.id = d.observable_id
                               WHERE d.root_id = ANY($1)
                           ) AS numbered
                           WHERE place <= $2
                           ORDER BY root_id, id"#,
                        ids,
                        MAX_EXPORT_OBSERVABLES + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let events = sqlx::query!(
                        "SELECT root_id, event_id FROM events.event_alerts
                         WHERE root_id = ANY($1) ORDER BY root_id, event_id",
                        ids,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    Ok((observables, detections, events))
                })
            })
            .await?;

        let cap = usize::try_from(MAX_EXPORT_OBSERVABLES).unwrap_or(usize::MAX);
        let mut alerts: Vec<AiExportAlert> = page
            .alerts
            .into_iter()
            .map(|alert| AiExportAlert {
                disposition_class: alert
                    .disposition
                    .as_deref()
                    .and_then(|name| self.dispositions.class(name)),
                alert,
                observables: Vec::new(),
                observables_truncated: false,
                detections: Vec::new(),
                detections_truncated: false,
                event_ids: Vec::new(),
            })
            .collect();
        let place: BTreeMap<Uuid, usize> = alerts
            .iter()
            .enumerate()
            .map(|(index, exported)| (exported.alert.id, index))
            .collect();
        for row in observables {
            let Some(exported) = place.get(&row.root_id).map(|index| &mut alerts[*index]) else {
                continue;
            };
            if exported.observables.len() == cap {
                exported.observables_truncated = true;
            } else {
                exported.observables.push(AiExportObservable {
                    id: row.id,
                    kind: row.kind,
                    value: row.value,
                });
            }
        }
        for row in detections {
            let Some(exported) = place.get(&row.root_id).map(|index| &mut alerts[*index]) else {
                continue;
            };
            if exported.detections.len() == cap {
                exported.detections_truncated = true;
            } else {
                exported.detections.push(AiExportDetection {
                    signature_uuid: row.signature_uuid,
                    signature_version: row.signature_version,
                    signature_family: row.signature_family,
                    observable_type: row.kind,
                    observable_value: row.value,
                });
            }
        }
        for row in events {
            if let Some(exported) = place.get(&row.root_id).map(|index| &mut alerts[*index]) {
                exported.event_ids.push(row.event_id);
            }
        }
        Ok(AiExportPage {
            alerts,
            next: page.next,
        })
    }
}

/// How long ago a request started, for a backend's `duration_ms`.
pub fn duration_ms(since: Instant) -> u64 {
    elapsed(since)
}
