//! The Splunk module, a port of ace3's `SplunkAPIAnalyzer` (`saq/modules/splunk.py`) with
//! `BaseAPIAnalyzer`'s delay loop (`saq/modules/api_analysis.py:591-678`).
//!
//! It submits one search about the observable to splunkd's REST API and then asks for a delay,
//! as ace3 does. Each run after that reads the job's status once: while the job runs, the module
//! asks for another delay of `async_delay` seconds; once it's done, the module reads the rows,
//! deletes the job and turns the rows' mapped fields into observables. Past `query_timeout`
//! seconds from the first run, a job that hasn't finished ends the analysis with the error
//! `timed out`. With `correlation_delay`, the first run only waits.
//!
//! The requests are the ones splunk-sdk makes for ace3 (`saq/splunk.py`): a login, the server
//! info that picks the v2 or v1 search API, the job, its results with `output_mode=json`, and its
//! deletion, at the same paths. ace3 reads a job's status three times a poll; the port reads it
//! once.
//!
//! What isn't ported: the `<O_TIMESPEC>`, `<O_VALUEn>` and `<observable.*>` tokens and named
//! time ranges, with the `gui_link` they set; pivot links and summary details; and most
//! observable mapping options (see `ObservableMapping`). A query with an unfilled token fails at
//! init.

mod mapping;
mod rest;

use std::sync::Mutex;
use std::time::Duration;

use ace_results::types::splunk::SplunkApiAnalysis;
use ace_results::{ObservableKind, ResultEnvelope};
use ace_sdk::http::{HttpClient, HttpError};
use ace_sdk::{Delay, Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use crate::mapping::ObservableMapping;
use crate::mapping::{
    Mapping, add_observables, fill_query, parse_timespec, search_text, table_columns,
    unfilled_token, whole_value_patterns,
};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<SplunkAnalyzer>();

/// The secret that logs in as `username`.
pub const PASSWORD: &str = "splunk_password";
/// The secret sent as the session token when there's no `username`.
pub const TOKEN: &str = "splunk_token";

const FORM: &str = "application/x-www-form-urlencoded";

/// The Splunk module's settings: one search, as one of ace3's `SplunkAPIAnalyzer` blocks with
/// its `splunk_config_*` and `api_query_defaults_*` values in it.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct SplunkSettings {
    /// splunkd's management API, such as `https://splunk.example.com:8089`.
    pub base_url: String,
    /// The user to log in as, with the `splunk_password` secret. Without one, requests carry
    /// the `splunk_token` secret.
    pub username: Option<String>,
    /// The namespace searches run in, as ace3's `user_context` and `app_context`. With neither,
    /// they run under `/services/`.
    pub user_context: Option<String>,
    pub app_context: Option<String>,
    /// A PEM file of CA certificates to trust besides the platform's, such as the one that
    /// signed splunkd's certificate. Certificates are always verified.
    pub ca_certificates: Option<std::path::PathBuf>,
    /// The timeout of each request to splunkd.
    pub request_timeout_seconds: u64,
    /// The question the search answers, shown with the result.
    pub question: String,
    /// The summary's prefix, such as `Proxy correlation`.
    pub summary: String,
    /// The search. `<O_VALUE>` is replaced by the observable's value, with backslashes and
    /// quotes escaped, and `<O_TYPE>` by its type. The module puts `search ` in front unless it
    /// starts with `|`.
    pub query: String,
    /// The observable types the search is about. Empty means every type.
    pub valid_observable_types: Vec<ObservableKind>,
    /// The fields of the rows to turn into observables.
    pub observable_mapping: Vec<ObservableMapping>,
    /// Values no mapping turns into an observable, as regular expressions that match the whole
    /// value.
    pub ignored_values: Vec<String>,
    /// The most rows the search returns (splunkd's `max_count`).
    pub max_result_count: u64,
    /// Seconds from the first run after which the module stops waiting for the search.
    pub query_timeout: u64,
    /// Seconds between two reads of a running job's status.
    pub async_delay: u64,
    /// How long to wait before submitting the search, in ace3's `DD:HH:MM:SS` form read from
    /// the right, so `30` is 30 seconds.
    pub correlation_delay: Option<String>,
}

impl Default for SplunkSettings {
    /// ace3's `splunk_config_default` and `api_query_defaults_default`, with splunkd's own port.
    fn default() -> Self {
        SplunkSettings {
            base_url: "https://localhost:8089".to_owned(),
            username: None,
            user_context: None,
            app_context: None,
            ca_certificates: None,
            request_timeout_seconds: 60,
            question: String::new(),
            summary: String::new(),
            query: String::new(),
            valid_observable_types: Vec::new(),
            observable_mapping: Vec::new(),
            ignored_values: Vec::new(),
            max_result_count: 1000,
            query_timeout: 300,
            async_delay: 1,
            correlation_delay: None,
        }
    }
}

/// The Splunk module.
pub struct SplunkAnalyzer {
    client: HttpClient,
    /// `base_url` without a trailing slash.
    base_url: String,
    /// The path prefix of `user_context` and `app_context`, such as `/services`.
    namespace: String,
    /// The `Authorization` header of the last login, reused until splunkd answers 401.
    session: Mutex<Option<String>>,
    mappings: Vec<Mapping>,
    ignored: Vec<Regex>,
    correlation_delay: Option<Duration>,
}

impl Module for SplunkAnalyzer {
    const NAME: &'static str = "splunk_api";
    /// Every type: `valid_observable_types` narrows it, as in ace3.
    const INPUTS: &'static [ObservableKind] = ObservableKind::BUILTIN;
    const SECRETS: &'static [&'static str] = &[PASSWORD, TOKEN];
    /// A search needs its query, so the module runs only as the overlay's instances, as ace3's
    /// `SplunkAPIAnalyzer` runs only as its configured sections.
    const INSTANCES_ONLY: bool = true;
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        ..Resources::DEFAULT
    };
    type Output = SplunkApiAnalysis;
    type Settings = SplunkSettings;

    fn init(settings: &SplunkSettings) -> Result<Self, ModuleError> {
        if settings.query.trim().is_empty() {
            return Err(ModuleError::other("the Splunk module has no query"));
        }
        if let Some(token) = unfilled_token(&settings.query) {
            return Err(ModuleError::other(format!(
                "the query uses {token}, which the Splunk module doesn't fill"
            )));
        }
        let mut builder =
            HttpClient::builder().timeout(Duration::from_secs(settings.request_timeout_seconds));
        if let Some(path) = &settings.ca_certificates {
            let pem = std::fs::read(path)
                .map_err(|e| ModuleError::other(format!("{}: {e}", path.display())))?;
            builder = builder
                .add_root_certificates_pem(&pem)
                .map_err(ModuleError::other)?;
        }
        let mappings = settings
            .observable_mapping
            .iter()
            .map(Mapping::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ModuleError::other)?;
        let ignored = whole_value_patterns(&settings.ignored_values).map_err(ModuleError::other)?;
        let correlation_delay = settings
            .correlation_delay
            .as_deref()
            .map(parse_timespec)
            .transpose()
            .map_err(ModuleError::other)?;
        Ok(SplunkAnalyzer {
            client: builder.build().map_err(ModuleError::other)?,
            base_url: settings.base_url.trim_end_matches('/').to_owned(),
            namespace: rest::namespace(
                settings.user_context.as_deref(),
                settings.app_context.as_deref(),
            ),
            session: Mutex::new(None),
            mappings,
            ignored,
            correlation_delay,
        })
    }
}

/// What a delayed run needs from the runs before it. ace3 keeps the same in the analysis's
/// details between delays.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Search {
    /// The query with the observable in it.
    query: String,
    /// `search/v2/jobs` or `search/jobs`, from the server's version.
    jobs_path: Option<String>,
    search_id: Option<String>,
    dispatch_state: Option<String>,
    start_time: Option<String>,
    running_start_time: Option<String>,
    end_time: Option<String>,
}

/// Where a run left the search.
enum Step {
    /// The job is queued or running.
    Waiting,
    /// The job is done and these are its rows.
    Rows(Vec<Map<String, Value>>),
}

/// How the analysis ends.
enum Ending {
    Rows(Vec<Map<String, Value>>),
    Error(String),
}

/// Why a run couldn't go on.
enum Failure {
    /// The task fails, such as when splunkd can't be reached, so it runs again later.
    Task(ModuleError),
    /// The search failed. As in ace3, the analysis ends with this as its `query_error`.
    Search(String),
}

impl From<ModuleError> for Failure {
    fn from(error: ModuleError) -> Self {
        Failure::Task(error)
    }
}

impl From<HttpError> for Failure {
    fn from(error: HttpError) -> Self {
        if error.is_unavailable() {
            Failure::Task(error.into())
        } else {
            Failure::Search(error.to_string())
        }
    }
}

/// splunkd's answer: any status but the ones that say it's down or busy.
struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    /// The body of a successful answer, or the search failure an error status is.
    fn into_body(self) -> Result<Vec<u8>, Failure> {
        if self.status.is_success() {
            Ok(self.body)
        } else {
            Err(Failure::Search(status_text(self.status, &self.body)))
        }
    }
}

/// An error status as splunklib's `HTTPError` words it: `HTTP 400 Bad Request -- <messages>`.
fn status_text(status: StatusCode, body: &[u8]) -> String {
    let mut text = format!(
        "HTTP {} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or_default()
    );
    if let Some(messages) = rest::messages(&String::from_utf8_lossy(body)) {
        text.push_str(" -- ");
        text.push_str(&messages);
    }
    text
}

/// A time as ace3's `format_iso8601` writes a UTC one: `2026-11-02T18:06:05.296-00:00`.
fn iso8601(time: DateTime<Utc>) -> String {
    format!(
        "{}.{:03}-00:00",
        time.format("%Y-%m-%dT%H:%M:%S"),
        time.timestamp_subsec_millis()
    )
}

/// Seconds since the epoch, as Python's `time.time()`.
fn epoch_seconds(time: DateTime<Utc>) -> f64 {
    time.timestamp() as f64 + f64::from(time.timestamp_subsec_micros()) / 1_000_000.0
}

impl Lookup for SplunkAnalyzer {
    const TCP_PORTS: &'static [u16] = &[8089, 443];

    async fn analyze(
        &self,
        ctx: &TaskContext<SplunkSettings>,
    ) -> Result<Outcome<SplunkApiAnalysis>, ModuleError> {
        let settings = ctx.settings();
        let observable = ctx.observable();
        if !settings.valid_observable_types.is_empty()
            && !settings
                .valid_observable_types
                .iter()
                .any(|kind| observable.kind.is_subtype_of(*kind))
        {
            return Ok(Outcome::Skipped(format!(
                "{} isn't one of valid_observable_types",
                observable.kind
            )));
        }
        // ace3 times the query from the analysis's first run, which asks for the first delay
        let now = ctx.now();
        let started = ctx.delayed().map_or(now, |d| d.first_delayed_at);
        let elapsed = (now - started).to_std().unwrap_or_default();

        let mut search = match ctx.delay_state::<Search>()? {
            Some(search) => search,
            None => {
                let search = Search {
                    query: fill_query(&settings.query, observable.kind, &observable.value),
                    ..Search::default()
                };
                if let Some(wait) = self.correlation_delay {
                    return self.delay(settings, wait, &search);
                }
                search
            }
        };

        let ending = match self.step(ctx, &mut search).await {
            Ok(Step::Waiting) if elapsed < Duration::from_secs(settings.query_timeout) => {
                return self.delay(settings, Duration::from_secs(settings.async_delay), &search);
            }
            Ok(Step::Waiting) => {
                // as in ace3, the job is left to splunkd's own expiry
                tracing::warn!("splunk query timed out: {}", search.query);
                Ending::Error("timed out".to_owned())
            }
            Ok(Step::Rows(rows)) => Ending::Rows(rows),
            Err(Failure::Task(error)) => return Err(error),
            Err(Failure::Search(error)) => {
                tracing::error!("splunk query {} failed: {error}", search.query);
                if let (Some(jobs), Some(sid)) = (&search.jobs_path, &search.search_id) {
                    let url = format!(
                        "{}{}/{jobs}/{}/",
                        self.base_url,
                        self.namespace,
                        rest::segment(sid)
                    );
                    self.delete_job(ctx, &url).await;
                }
                // ace3's RemoteApiError(500, "Splunk search failed: ...") as text
                Ending::Error(format!("HTTP 500: Splunk search failed: {error}"))
            }
        };
        Ok(Outcome::Done(self.result(ctx, &search, started, ending)))
    }
}

impl SplunkAnalyzer {
    /// Run again after `run_after`. The module ends the wait itself at `query_timeout`, with a
    /// result, so the SDK's timeout is only a backstop past it.
    fn delay(
        &self,
        settings: &SplunkSettings,
        run_after: Duration,
        search: &Search,
    ) -> Result<Outcome<SplunkApiAnalysis>, ModuleError> {
        let timeout = Duration::from_secs(
            settings
                .query_timeout
                .saturating_add(settings.async_delay)
                .saturating_add(60),
        )
        .saturating_add(self.correlation_delay.unwrap_or_default());
        Ok(Outcome::Delay(
            Delay::new(run_after, timeout).with_state(search)?,
        ))
    }

    /// Submits the search, or reads the job's status once and, when it's done, its rows.
    async fn step(
        &self,
        ctx: &TaskContext<SplunkSettings>,
        search: &mut Search,
    ) -> Result<Step, Failure> {
        let now = ctx.now();
        let (Some(jobs), Some(sid)) = (search.jobs_path.clone(), search.search_id.clone()) else {
            self.submit(ctx, search).await?;
            return Ok(Step::Waiting);
        };
        let url = format!(
            "{}{}/{jobs}/{}",
            self.base_url,
            self.namespace,
            rest::segment(&sid)
        );
        let reply = self.call(ctx, Method::GET, &url, None).await?;
        if reply.status == StatusCode::NOT_FOUND {
            // the job expired or splunkd lost it; ace3 submits the search again
            tracing::info!("splunk search {sid} is gone; submitting it again");
            self.submit(ctx, search).await?;
            return Ok(Step::Waiting);
        }
        if reply.status == StatusCode::NO_CONTENT {
            return Ok(Step::Waiting);
        }
        let body = reply.into_body()?;
        let job = rest::entry_content(&String::from_utf8_lossy(&body)).map_err(Failure::Search)?;
        let text = |key: &str| job.get(key).and_then(Value::as_str).unwrap_or_default();
        let state = text("dispatchState");
        if matches!(state, "QUEUED" | "PARSING") {
            tracing::info!("splunk search {sid} is not ready yet ({state})");
            return Ok(Step::Waiting);
        }
        search.dispatch_state = Some(state.to_owned());
        if state == "RUNNING" && search.running_start_time.is_none() {
            search.running_start_time = Some(iso8601(now));
        }
        tracing::info!(
            "{sid} dispatch state {state} done progress: {} is failed {} event count {} run duration {}",
            text("doneProgress"),
            text("isFailed"),
            text("eventCount"),
            text("runDuration"),
        );
        if text("isDone") != "1" {
            return Ok(Step::Waiting);
        }

        // splunklib reads and deletes a job in the namespace of its acl
        let job_url = format!(
            "{}{}/{jobs}/{}",
            self.base_url,
            rest::job_namespace(job.get("eai:acl"), &self.namespace),
            rest::segment(&sid)
        );
        let query = [
            ("count", "0"),
            ("output_mode", "json"),
            ("segmentation", "none"),
        ];
        let reply = if jobs == "search/v2/jobs" {
            let url = format!("{job_url}/results");
            self.call(ctx, Method::POST, &url, Some(rest::form(&query)))
                .await?
        } else {
            let url = format!("{job_url}/results?{}", rest::form(&query));
            self.call(ctx, Method::GET, &url, None).await?
        };
        let rows = rest::result_rows(&reply.into_body()?).map_err(Failure::Search)?;
        tracing::info!("got results for {sid}");
        search.end_time = Some(iso8601(now));
        self.delete_job(ctx, &format!("{job_url}/")).await;
        Ok(Step::Rows(rows))
    }

    /// Submits the search as a new job, on the search API the server's version allows.
    async fn submit(
        &self,
        ctx: &TaskContext<SplunkSettings>,
        search: &mut Search,
    ) -> Result<(), Failure> {
        let url = format!("{}/services/server/info", self.base_url);
        let body = self.call(ctx, Method::GET, &url, None).await?.into_body()?;
        let info = rest::entry_content(&String::from_utf8_lossy(&body)).map_err(Failure::Search)?;
        let jobs = rest::jobs_path(&info);

        let text = search_text(&search.query);
        let max_count = ctx.settings().max_result_count.to_string();
        let form = rest::form(&[
            ("search", &text),
            ("max_count", &max_count),
            ("exec_mode", "normal"),
        ]);
        let url = format!("{}{}/{jobs}/", self.base_url, self.namespace);
        let body = self
            .call(ctx, Method::POST, &url, Some(form))
            .await?
            .into_body()?;
        let sid = rest::element_text(&String::from_utf8_lossy(&body), "sid")
            .filter(|sid| !sid.is_empty())
            .ok_or_else(|| Failure::Search("splunkd answered a new search without a sid".into()))?;
        tracing::info!("submitted splunk search {sid}");
        *search = Search {
            query: std::mem::take(&mut search.query),
            jobs_path: Some(jobs.to_owned()),
            search_id: Some(sid),
            start_time: Some(iso8601(ctx.now())),
            ..Search::default()
        };
        Ok(())
    }

    /// Deletes a job, logging a failure, as ace3's `delete_search_job`.
    async fn delete_job(&self, ctx: &TaskContext<SplunkSettings>, url: &str) {
        let failure = match self.call(ctx, Method::DELETE, url, None).await {
            Ok(reply) if reply.status.is_success() => return,
            Ok(reply) => status_text(reply.status, &reply.body),
            Err(Failure::Task(error)) => error.to_string(),
            Err(Failure::Search(error)) => error,
        };
        tracing::warn!("unable to delete splunk search job: {failure}");
    }

    /// Sends a request with the session's or the token's `Authorization`. A 401 logs in again
    /// once, as splunklib's autologin does. A 429, 502, 503 or 504 fails the task.
    async fn call(
        &self,
        ctx: &TaskContext<SplunkSettings>,
        method: Method,
        url: &str,
        form: Option<String>,
    ) -> Result<Reply, Failure> {
        let mut fresh = false;
        loop {
            let authorization = self.authorization(ctx, fresh).await?;
            let mut request = self
                .client
                .request(method.clone(), url)
                .header(AUTHORIZATION, authorization);
            if let Some(body) = &form {
                request = request.header(CONTENT_TYPE, FORM).body(body.clone());
            }
            let response = self.client.send(request).await?;
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED && !fresh && ctx.settings().username.is_some() {
                fresh = true;
                continue;
            }
            // splunkd down or busy fails the task, classified as the SDK does it
            if let Err(error) = response.error_for_status_ref() {
                let error = HttpError::from_reqwest(error);
                if error.is_unavailable() {
                    return Err(Failure::Task(error.into()));
                }
            }
            let body = response.bytes().await.map_err(HttpError::from_reqwest)?;
            return Ok(Reply {
                status,
                body: body.to_vec(),
            });
        }
    }

    /// The `Authorization` header: the token, or the session of a login as `username`, which
    /// is reused until `fresh` asks for a new one.
    async fn authorization(
        &self,
        ctx: &TaskContext<SplunkSettings>,
        fresh: bool,
    ) -> Result<String, Failure> {
        let settings = ctx.settings();
        let Some(username) = settings.username.as_deref() else {
            let token = ctx.secret(TOKEN)?.expose();
            // splunklib sends a token as `Splunk <token>` unless it says its scheme
            return Ok(
                if token.starts_with("Splunk ") || token.starts_with("Bearer ") {
                    token.to_owned()
                } else {
                    format!("Splunk {token}")
                },
            );
        };
        if !fresh && let Some(session) = self.session.lock().ok().and_then(|s| s.clone()) {
            return Ok(session);
        }
        let password = ctx.secret(PASSWORD)?;
        let url = format!("{}/services/auth/login", self.base_url);
        let request = self
            .client
            .post(&url)
            .header(CONTENT_TYPE, FORM)
            .body(rest::form(&[
                ("username", username),
                ("password", password.expose()),
            ]));
        let response = self.client.send(request).await?;
        let status = response.status();
        if let Err(error) = response.error_for_status_ref() {
            let error = HttpError::from_reqwest(error);
            if error.is_unavailable() {
                return Err(Failure::Task(error.into()));
            }
        }
        let body = response.bytes().await.map_err(HttpError::from_reqwest)?;
        if !status.is_success() {
            return Err(Failure::Task(ModuleError::other(format!(
                "the Splunk login as {username} failed: {}",
                status_text(status, &body)
            ))));
        }
        let key = rest::element_text(&String::from_utf8_lossy(&body), "sessionKey")
            .filter(|key| !key.is_empty())
            .ok_or_else(|| ModuleError::other("splunkd answered the login without a sessionKey"))?;
        let session = format!("Splunk {key}");
        if let Ok(mut cached) = self.session.lock() {
            *cached = Some(session.clone());
        }
        Ok(session)
    }

    /// The result: the rows and the observables their mapped fields give, or the error.
    fn result(
        &self,
        ctx: &TaskContext<SplunkSettings>,
        search: &Search,
        started: DateTime<Utc>,
        ending: Ending,
    ) -> ResultEnvelope<SplunkApiAnalysis> {
        let settings = ctx.settings();
        let mut details = SplunkApiAnalysis {
            query: Some(search.query.clone()),
            question: Some(settings.question.clone()),
            query_summary: Some(settings.summary.clone()),
            query_start: Some(epoch_seconds(started)),
            search_id: search.search_id.clone(),
            dispatch_state: search.dispatch_state.clone(),
            start_time: search.start_time.clone(),
            running_start_time: search.running_start_time.clone(),
            end_time: search.end_time.clone(),
            ..SplunkApiAnalysis::default()
        };
        let mut observables = Vec::new();
        // BaseAPIAnalysis.generate_summary: no summary for no rows
        let summary = match ending {
            Ending::Error(error) => {
                let summary = format!("{}: ERROR: {error}", settings.summary);
                details.query_error = Some(error);
                Some(summary)
            }
            Ending::Rows(rows) => {
                details.table_columns = table_columns(&search.query);
                for row in &rows {
                    add_observables(
                        row,
                        &self.mappings,
                        &self.ignored,
                        ctx.now(),
                        &mut observables,
                    );
                }
                let summary = (!rows.is_empty())
                    .then(|| format!("{}: ({} results)", settings.summary, rows.len()));
                details.query_results = Some(rows);
                summary
            }
        };
        let mut result = ResultEnvelope::new(details);
        result.summary = summary;
        result.observables = observables;
        result
    }
}
