//! The AI investigation API as `ace serve` sets it up (PLAN.md 7.15): the overlay's `ai_api` section
//! made into `ace_service::ai`'s surface, the backend types a binary has, and ace3's Splunk backend
//! (`saq/ai_query/backends/splunk.py`).
//!
//! **Off by default.** With no `ai_api.enabled: true` there is no surface, no backend is built and no
//! secret is read: the routes say the API is off. A backend's own `enabled` is false by default too, as
//! in ace3, where a backend is defined for every process and enabled only for the one that serves it.
//!
//! **Backend types.** ace3's section names a Python module and class; here it names a type the binary
//! was built with (`App::ai_backend_type`), as an alert router's does. Every `App` has `splunk`, and
//! ace3's two testing backends `fake` and `fake_unwindowed`, which answer canned rows and reach
//! nothing.
//!
//! **Credentials.** A backend gets the secrets its entry lists and no other, read from the overlay's
//! `secrets:` as a pool reads a module's (PLAN.md 2.24): an environment variable or a file, never a
//! value in the overlay. A secret is held as `ace_sdk::Secret`, which doesn't print, and a backend's
//! errors name no credential. A backend whose credential isn't there fails to build, which stops `ace
//! serve`: ace3's `validate_startup`, so a missing token is a failure at boot and not a 502 at the
//! first query.
//!
//! What isn't here of ace3's startup checks (`aceapi_ai/startup_checks.py`): ace3 serves this API
//! from a container of its own and refuses to start it if the process holds the encryption password,
//! the GUI's signing key, the node-to-node key, the local overlay or a plaintext credential no
//! enabled backend declares. `ace serve` is one process that also serves the GUI and the lease API, so
//! there is nothing such a check could assert. What is kept is the part that is about a backend:
//! its credential has to resolve when the server starts, and it is handed only what it declared.
//!
//! **The Splunk backend.** One search for a query: the window as `earliest=` and `latest=` in the
//! instance's timezone and again as the job's range, `max_count` the row limit, and ace3's
//! `auto_append` (`| fields *`) after the query so the fields survive. Read-only is the Splunk
//! account's doing, not ACE's: its role has to leave out the commands that write (`| delete`,
//! `| outputlookup`, `| collect`), as ace3's notes say. What differs from ace3's: one client for the
//! backend, with its login kept, where ace3 makes one for each request because its client holds a
//! search's state; and a Splunk message among the rows never reaches here, since
//! `ace_mod_splunk::search` reads the results alone.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_core::Db;
use ace_hunt::splunk;
use ace_mod_splunk::search::{Connection, Limits, SearchClient, SearchError};
use ace_sdk::Secrets;
use ace_sdk::overlay::{AiLimitsSection, Overlay};
use ace_service::ai::testing::FakeBackend;
use ace_service::ai::{
    AiFuture, AiLimits, AiQueryBackend, AiQueryError, AiQueryRequest, AiQueryResult, AiSurface,
    PgLimiter,
};
use chrono::{DateTime, SecondsFormat, Utc};
use chrono_tz::Tz;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::hunter::SplunkInstance;

/// What a backend's builder is given: its entry's name and settings, and the secrets it lists.
#[derive(Debug, Clone, Default)]
pub struct AiBackendSetup {
    pub name: String,
    pub settings: Option<Value>,
    pub secrets: Secrets,
}

/// What builds a backend of one type, or says why it can't, which stops `ace serve`. The reason must
/// name no credential.
pub type AiBackendFactory =
    Arc<dyn Fn(&AiBackendSetup) -> Result<Arc<dyn AiQueryBackend>, String> + Send + Sync>;

/// The backend types every binary has.
pub(crate) fn builtin_types() -> BTreeMap<String, AiBackendFactory> {
    let mut types: BTreeMap<String, AiBackendFactory> = BTreeMap::new();
    types.insert(
        "splunk".to_owned(),
        Arc::new(|setup| Ok(Arc::new(SplunkBackend::new(setup)?) as Arc<dyn AiQueryBackend>)),
    );
    types.insert(
        "fake".to_owned(),
        Arc::new(|setup| {
            no_settings(setup)?;
            Ok(Arc::new(FakeBackend::new()) as Arc<dyn AiQueryBackend>)
        }),
    );
    types.insert(
        "fake_unwindowed".to_owned(),
        Arc::new(|setup| {
            no_settings(setup)?;
            Ok(Arc::new(FakeBackend::unwindowed()) as Arc<dyn AiQueryBackend>)
        }),
    );
    types
}

fn no_settings(setup: &AiBackendSetup) -> Result<(), String> {
    match &setup.settings {
        None | Some(Value::Null) => Ok(()),
        Some(_) => Err("this backend type takes no settings".to_owned()),
    }
}

/// Limits from a section, each key over `defaults`.
pub fn limits(section: &AiLimitsSection, defaults: AiLimits) -> Result<AiLimits, String> {
    let limits = AiLimits {
        max_concurrency: section.max_concurrency.unwrap_or(defaults.max_concurrency),
        requests_per_minute: section
            .requests_per_minute
            .unwrap_or(defaults.requests_per_minute),
        hourly_budget: section.hourly_budget.unwrap_or(defaults.hourly_budget),
        default_limit: section.default_limit.unwrap_or(defaults.default_limit),
        max_limit: section.max_limit.unwrap_or(defaults.max_limit),
        max_window_seconds: match &section.max_window {
            Some(window) => AiLimits::parse_window(window)?,
            None => defaults.max_window_seconds,
        },
        default_query_timeout: section
            .default_query_timeout
            .unwrap_or(defaults.default_query_timeout),
        max_query_timeout: section
            .max_query_timeout
            .unwrap_or(defaults.max_query_timeout),
    };
    limits.check()?;
    Ok(limits)
}

/// The surface the overlay's `ai_api` section asks for, with the limiter on `db`; None when the
/// section doesn't turn the API on. An entry that can't be used is an error whether or not the API is
/// on, but a backend is built, and its secrets read, only when both it and the API are enabled.
pub fn surface(
    types: &BTreeMap<String, AiBackendFactory>,
    overlay: &Overlay,
    db: Db,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<AiSurface>, String> {
    let section = &overlay.ai_api;
    let search = limits(&section.search_limits, AiLimits::default())
        .map_err(|e| format!("search_limits: {e}"))?;
    let export = limits(&section.export_limits, AiLimits::export())
        .map_err(|e| format!("export_limits: {e}"))?;
    let mut surface = AiSurface::new(Arc::new(PgLimiter::new(db)))
        .with_search_limits(search)?
        .with_export_limits(export)?
        .with_fail_open(section.rate_limit_fail_open);
    for (name, backend) in &section.backends {
        let entry_limits = limits(&backend.limits, AiLimits::default())
            .map_err(|e| format!("backends.{name}.limits: {e}"))?;
        let Some(factory) = types.get(&backend.kind) else {
            return Err(format!(
                "backends.{name}: this binary has no backend type {:?}; it has {}",
                backend.kind,
                types.keys().cloned().collect::<Vec<_>>().join(", ")
            ));
        };
        if !(section.enabled && backend.enabled) {
            continue;
        }
        let declared: Vec<&str> = backend.secrets.iter().map(String::as_str).collect();
        let setup = AiBackendSetup {
            name: name.clone(),
            settings: backend.settings.clone(),
            secrets: ace_pool::secrets::resolve_names("ai_api", &declared, overlay, env),
        };
        let built = factory(&setup).map_err(|e| format!("backends.{name}: {e}"))?;
        surface = surface.with_backend(name, built, entry_limits)?;
    }
    Ok(section.enabled.then_some(surface))
}

/// The Splunk backend's settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SplunkBackendSettings {
    /// The instance, as the hunter's `splunk` entries: ace3's `splunk_config_<name>`.
    splunk: SplunkInstance,
    /// Appended to every query so fields survive; a query must not end in a table command.
    #[serde(default = "default_auto_append")]
    auto_append: String,
}

fn default_auto_append() -> String {
    "| fields *".to_owned()
}

/// ace3's `SplunkAIQueryBackend`.
pub struct SplunkBackend {
    client: SearchClient,
    host: String,
    timezone: Tz,
    auto_append: String,
    dispatch_timeout: Duration,
    user_context: Option<String>,
    app_context: Option<String>,
    /// Between two reads of a job's status.
    poll: Duration,
}

impl std::fmt::Debug for SplunkBackend {
    /// Never the client, which holds the credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplunkBackend")
            .field("host", &self.host)
            .field("timezone", &self.timezone)
            .finish_non_exhaustive()
    }
}

impl SplunkBackend {
    /// Builds the backend from its entry. Its one secret is the account's password when the instance
    /// names a `username`, and its token otherwise. One that isn't there is an error, which stops the
    /// server: ace3's `validate_startup`.
    pub fn new(setup: &AiBackendSetup) -> Result<SplunkBackend, String> {
        let settings: SplunkBackendSettings =
            serde_json::from_value(setup.settings.clone().unwrap_or(Value::Null))
                .map_err(|e| format!("settings: {e}"))?;
        let instance = settings.splunk;
        let kind = if instance.username.is_some() {
            "password"
        } else {
            "token"
        };
        let names = setup.secrets.names();
        let credential = match names.as_slice() {
            [name] => setup
                .secrets
                .get(name)
                .map(|secret| secret.expose().to_owned()),
            [] => None,
            _ => {
                return Err(format!(
                    "the backend takes one secret, its splunk {kind}, and was given more"
                ));
            }
        };
        let Some(credential) = credential.filter(|credential| !credential.is_empty()) else {
            return Err(format!(
                "splunk {kind} is not set: name it in the backend's secrets, with a source in secrets:"
            ));
        };
        let timezone = Tz::from_str(&instance.timezone)
            .map_err(|e| format!("timezone {:?}: {e}", instance.timezone))?;
        let (password, token) = if instance.username.is_some() {
            (Some(credential), None)
        } else {
            (None, Some(credential))
        };
        let client = SearchClient::new(Connection {
            base_url: instance
                .base_url
                .clone()
                .unwrap_or_else(|| format!("https://{}:{}", instance.host, instance.port)),
            username: instance.username.clone(),
            password,
            token,
            ca_certificates: instance.ca_certificates.clone(),
            request_timeout: Duration::from_secs(instance.request_timeout_seconds),
        })?;
        Ok(SplunkBackend {
            client,
            host: instance.host,
            timezone,
            auto_append: settings.auto_append,
            dispatch_timeout: Duration::from_secs(instance.dispatch_timeout_seconds),
            user_context: instance.user_context,
            app_context: instance.app_context,
            poll: Duration::from_secs(1),
        })
    }

    /// The backend with another wait between reads of a job's status.
    pub fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// The form that creates the job: ace3's `SplunkClient.queue`. The window is in front of the
    /// query in the instance's timezone, after a `search` unless the query is a generating command,
    /// and again as the job's own range.
    fn form(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: u32,
    ) -> Vec<(String, String)> {
        let wall = |time: DateTime<Utc>| {
            time.with_timezone(&self.timezone)
                .format("%m/%d/%Y:%H:%M:%S")
                .to_string()
        };
        let iso = |time: DateTime<Utc>| {
            time.with_timezone(&self.timezone)
                .to_rfc3339_opts(SecondsFormat::Secs, false)
        };
        let trimmed = query.trim_start();
        let job = if trimmed.starts_with('|') {
            query.to_owned()
        } else {
            let rest = if trimmed.to_ascii_lowercase().starts_with("search") {
                &trimmed["search".len()..]
            } else {
                trimmed
            };
            format!(
                "search earliest={} latest={} {}",
                wall(start),
                wall(end),
                rest.trim_start()
            )
        };
        vec![
            ("search".to_owned(), job),
            ("max_count".to_owned(), limit.to_string()),
            ("exec_mode".to_owned(), "normal".to_owned()),
            ("earliest_time".to_owned(), iso(start)),
            ("latest_time".to_owned(), iso(end)),
        ]
    }
}

/// What a failed search is to the caller: ace3's mapping of its `RemoteApiError`. The text is
/// splunkd's status and messages, or the client's own, and holds no credential.
fn backend_error(error: SearchError) -> AiQueryError {
    match error {
        // a 401 from Splunk must not read as a failure of the caller's own key
        SearchError::Failed(text) if text.starts_with("HTTP 401") => AiQueryError::Backend {
            status: 502,
            reason: "splunk authentication failure".to_owned(),
        },
        SearchError::TimedOut { .. } => AiQueryError::Backend {
            status: 504,
            reason: error.to_string(),
        },
        other => AiQueryError::Backend {
            status: 502,
            reason: other.to_string(),
        },
    }
}

impl AiQueryBackend for SplunkBackend {
    fn describe(&self) -> Map<String, Value> {
        json!({
            "query_language": "SPL",
            "time_semantics": "start_time/end_time become the search window (earliest/latest); \
                               in-query time modifiers can only narrow it",
            "notes": format!(
                "'{}' is appended to every query, so queries must not end in a table command; \
                 rows carry raw splunk field names",
                self.auto_append
            ),
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }

    fn validate(&self, request: &AiQueryRequest, limits: &AiLimits) -> Result<(), String> {
        if request.query.trim().is_empty() {
            return Err("query must not be empty".to_owned());
        }
        let (Some(start), Some(end)) = (request.start_time, request.end_time) else {
            return Err("start_time and end_time are required".to_owned());
        };
        if start >= end {
            return Err("start_time must be before end_time".to_owned());
        }
        if (end - start).num_seconds() > limits.max_window_seconds {
            return Err(format!(
                "query window exceeds the maximum of {} (DD:HH:MM:SS)",
                limits.max_window()
            ));
        }
        if request.limit.is_some_and(|limit| limit > limits.max_limit) {
            return Err(format!("limit exceeds the maximum of {}", limits.max_limit));
        }
        Ok(())
    }

    fn execute<'a>(
        &'a self,
        request: &'a AiQueryRequest,
        limits: &'a AiLimits,
    ) -> AiFuture<'a, Result<AiQueryResult, AiQueryError>> {
        Box::pin(async move {
            let (Some(start), Some(end)) = (request.start_time, request.end_time) else {
                return Err(AiQueryError::Rejected(
                    "start_time and end_time are required".to_owned(),
                ));
            };
            let limit = request.limit.unwrap_or(limits.default_limit);
            let timeout = request
                .timeout_seconds
                .unwrap_or(limits.default_query_timeout);
            let query = if self.auto_append.is_empty() {
                request.query.clone()
            } else {
                format!("{} {}", request.query, self.auto_append)
            };
            let form = splunk::urlencode(&self.form(&query, start, end, limit));
            let started = Instant::now();
            let rows = self
                .client
                .search(
                    self.user_context.as_deref(),
                    self.app_context.as_deref(),
                    &form,
                    Limits {
                        poll: self.poll,
                        dispatch_timeout: self.dispatch_timeout,
                        query_timeout: Duration::from_secs(u64::from(timeout)),
                    },
                    std::future::pending(),
                )
                .await
                .map_err(backend_error)?;
            let truncated = rows.len() >= limit as usize;
            let link = splunk::link(
                &self.host,
                self.app_context.as_deref(),
                &request.query,
                start,
                end,
                self.timezone,
                false,
            );
            Ok(AiQueryResult {
                rows,
                truncated,
                truncation_reason: truncated.then(|| "limit".to_owned()),
                window_start: Some(start),
                window_end: Some(end),
                duration_ms: ace_service::ai::duration_ms(started),
                meta: json!({"search_link": link})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            })
        })
    }
}

#[cfg(test)]
mod tests;
