//! `ace hunter`: ace3's hunter for query hunts (PLAN.md 6.4), with Splunk as its one source.
//!
//! It loads the hunts of each type it has rule directories for from the signatures checkout
//! (`ace_hunt::load_hunts`, 6.2), records them for the `hunt` router (`Service::sync_hunts`), and
//! every tick runs each hunt ace3's `HuntManager.execute` would run: enabled, for this instance type,
//! not suppressed, and ready by its frequency. A run searches the hunt's window
//! (`ace_hunt::query::schedule::window`) with the hunt's Splunk search (`ace_hunt::splunk`) through
//! `ace_mod_splunk::search`, turns the rows into submissions as ace3's `QueryHunt` does
//! (`ace_hunt::query::process`), and records them and the hunt's new state in one transaction
//! (`Service::record_hunt_run`), as the internal component `hunter`, which migration 0034 grants
//! `alert:create`, `hunt:read` and `hunt:write`. The state lives in Postgres, so a restart neither
//! searches a window again nor skips one. Hunts reload every `reload_seconds`.
//!
//! Each hit a suppression drops is a row (PLAN.md 6.5, [`run_of`]): a group a grouped hunt's
//! `suppression` drops, decided here, and a duplicate of a dedup key, which ace3's collector drops and
//! `Service::record_hunt_run` drops here, in the run's transaction (`ace_service`'s `hunts` docs).
//!
//! **Where it runs.** Its own process of the `ace` binary, as ace3's hunter is its own service. A
//! search needs the Splunk instance's credentials, and 2.24 holds a process to the secrets it
//! declares: `ace serve` holds the API's and none of a data source's, so the hunter isn't part of
//! it. A pool reaches only the lease API and the bucket, while a hunt writes roots through the
//! service layer, so it isn't a pool either. 6.7's scheduler takes `ace3/saq/cron_tasks.py`, which
//! has no hunts; a hunt has its own frequency, window and state, which this keeps. So `ace hunter`
//! resolves `splunk_<instance>_password` or `splunk_<instance>_token` for each Splunk instance its
//! configuration names, from the site overlay's secrets, and no others.
//!
//! **Bounded waits** (2.21): each request to Splunk by the instance's `request_timeout_seconds`, a
//! job by `dispatch_timeout_seconds` until it starts and the hunt's `query_timeout` once it runs,
//! each database call by the pool's acquire and statement timeouts (`DbConfig`), and a stop ends
//! a run's wait at once, cancelling its job; the run's window is then left to the next start.
//!
//! It reads `ACE4_HUNTER`, a JSON file ([`HunterConfig`]), `ACE4_DATABASE_URL`, the `ACE4_BUCKET_*`
//! variables and the overlay at `ACE4_OVERLAY`.
//!
//! **Correlation** (PLAN.md 6.6). A hunt with a `correlate` block has its rows run through
//! `ace_hunt::correlate::engine` before they're processed, on the run's thread, with every wait
//! bounded and a stop ending it ([`Hunter::correlate`]). Its `query` commands go to the query sources
//! the configuration names ([`QuerySourceConfig`]), by default `splunk` on the `default` instance,
//! as ace3's `hunter.correlation.query_sources` does: [`SplunkQuery`] runs one as ace3's
//! `SplunkQuerySource` does. Its custom command types are the binary's (`App::command_type`), a
//! command's `cache:` is kept in memory (`correlation_cache_bytes`), and what the run logs and the
//! trace holds is scrubbed of the Splunk credentials the hunter holds, which no template can read.
//! A `type: executable` command runs no script (PLAN.md decision 16): one of the signatures' hunt
//! scripts runs as the script command type the binary registers for its path (`App::hunt_script`),
//! built over the hunter's network ([`net`]) with its settings in the configuration's `scripts`, and
//! its `files:` are read from the signatures checkout. Any other executable fails its step.
//!
//! What waits: LogScale and Rapid7 hunts for their clients in 7.8 (their hunts load, and the
//! hunter skips them, saying so), and their correlation sources with them; a file mapping's files
//! (three of the signatures' Splunk hunts have one), which are logged and dropped until the hunter
//! spools files for submission.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ace_core::submit::{Origin, Submission};
use ace_hunt::correlate::action::{Level, LogLine};
use ace_hunt::correlate::cache::MemoryCache;
use ace_hunt::correlate::command::CommandTypes;
use ace_hunt::correlate::engine::{Correlated, Engine, EngineError, HuntRun, Runtime};
use ace_hunt::correlate::source::{QuerySource, Sources};
use ace_hunt::correlate::time::Time;
use ace_hunt::query::schedule::{self, Ran, State, Window};
use ace_hunt::query::{self, Context, EventTimeSource, Processed};
use ace_hunt::render::Renderer;
use ace_hunt::splunk::{self, Instance, Search};
use ace_hunt::{Hunt, HuntType, LoadOptions};
use ace_mod_splunk::search::{Connection, Limits, SearchClient};
use ace_results::{Detection, NewObservable, ObservableKind, ObservableRef, Relationship};
use ace_sdk::Secrets;
use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as Json};
use tokio_util::sync::CancellationToken;

use crate::App;

/// The hunter's configuration, the file `ACE4_HUNTER` names.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HunterConfig {
    /// The signatures checkout.
    pub signatures: PathBuf,
    /// Each hunt type's rule directories, relative to `signatures`.
    pub rule_dirs: BTreeMap<String, Vec<PathBuf>>,
    /// The Splunk instances hunts name in `splunk_config`.
    #[serde(default)]
    pub splunk: BTreeMap<String, SplunkInstance>,
    /// ace3's `global_settings.instance_type`, which a hunt's `instance_types` names.
    pub instance_type: String,
    #[serde(default = "default_tick")]
    pub tick_seconds: u64,
    #[serde(default = "default_reload")]
    pub reload_seconds: u64,
    /// Between two reads of a job's status, as ace3's hunter waits.
    #[serde(default = "default_poll")]
    pub poll_seconds: f64,
    /// How many hunts run at once.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// The sources a correlation's `query` commands name, ace3's
    /// `hunter.correlation.query_sources`: by default `splunk` on the `default` instance.
    #[serde(default = "default_query_sources")]
    pub query_sources: BTreeMap<String, QuerySourceConfig>,
    /// The bytes of correlation command outputs kept for their `cache:`.
    #[serde(default = "default_cache_bytes")]
    pub correlation_cache_bytes: usize,
    /// Each script command type's settings, by its name (`App::hunt_script`), such as
    /// `removed_hunt_three`'s home tenant (PLAN.md decision 16).
    #[serde(default)]
    pub scripts: BTreeMap<String, Json>,
}

/// A correlation query source: a Splunk instance of [`HunterConfig::splunk`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuerySourceConfig {
    Splunk { instance: String },
}

fn default_query_sources() -> BTreeMap<String, QuerySourceConfig> {
    BTreeMap::from([(
        "splunk".to_owned(),
        QuerySourceConfig::Splunk {
            instance: "default".to_owned(),
        },
    )])
}

fn default_cache_bytes() -> usize {
    64 << 20
}

fn default_tick() -> u64 {
    5
}
fn default_reload() -> u64 {
    60
}
fn default_poll() -> f64 {
    3.0
}
fn default_concurrency() -> usize {
    4
}

/// A Splunk instance, ace3's `splunk_config_<name>`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplunkInstance {
    /// The host, which the web UI link and a root's `tool_instance` name.
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// The management API, by default `https://<host>:<port>`.
    #[serde(default)]
    pub base_url: Option<String>,
    /// The user to log in as with `splunk_<name>_password`; without one, `splunk_<name>_token`.
    #[serde(default)]
    pub username: Option<String>,
    /// The timezone searches are written in, such as `GMT`.
    pub timezone: String,
    #[serde(default)]
    pub ca_certificates: Option<PathBuf>,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
    #[serde(default = "default_dispatch_timeout")]
    pub dispatch_timeout_seconds: u64,
    /// The owner and app a correlation's searches run as, ace3's `user_context` and
    /// `app_context`; a hunt's own search takes them from the hunt.
    #[serde(default)]
    pub user_context: Option<String>,
    #[serde(default)]
    pub app_context: Option<String>,
}

fn default_port() -> u16 {
    8089
}
fn default_request_timeout() -> u64 {
    60
}
fn default_dispatch_timeout() -> u64 {
    900
}

/// The secret names an instance's credentials are under.
pub fn secret_names(instance: &str) -> [String; 2] {
    [
        format!("splunk_{instance}_password"),
        format!("splunk_{instance}_token"),
    ]
}

struct Source {
    instance: Instance,
    client: Arc<SearchClient>,
    dispatch_timeout: Duration,
    user_context: Option<String>,
    app_context: Option<String>,
}

/// The hunter without its database: what decides, searches and processes a run.
pub struct Hunter {
    config: HunterConfig,
    sources: BTreeMap<String, Source>,
    renderer: Renderer,
    /// Where `<include:PATH>` reads from, ace3's working directory.
    home: PathBuf,
    /// A correlation's own renderer, without `fromjson`, as ace3's.
    correlation_renderer: Renderer,
    command_types: CommandTypes,
    cache: MemoryCache,
    /// The credentials' text, scrubbed from what a correlation records.
    secrets: Vec<String>,
}

/// What one tick did with one hunt.
#[derive(Debug)]
pub struct Tick {
    /// Why it didn't run, in ace3's manager's words.
    pub skipped: Option<String>,
    pub window: Option<Window>,
    pub search: Option<Search>,
    pub processed: Processed,
    /// Why the run failed, as ace3 logs it.
    pub error: Option<String>,
    /// The state after the tick.
    pub state: State,
}

impl Hunter {
    pub fn new(config: HunterConfig, secrets: &Secrets) -> Result<Hunter> {
        let mut sources = BTreeMap::new();
        let mut held = Vec::new();
        for (name, instance) in &config.splunk {
            let [password, token] = secret_names(name);
            let secret = |n: &str| secrets.get(n).map(|s| s.expose().to_owned());
            held.extend(secret(&password));
            held.extend(secret(&token));
            let timezone = chrono_tz::Tz::from_str(&instance.timezone).map_err(|e| {
                anyhow::anyhow!(
                    "splunk instance {name}: timezone {:?}: {e}",
                    instance.timezone
                )
            })?;
            let client = SearchClient::new(Connection {
                base_url: instance
                    .base_url
                    .clone()
                    .unwrap_or_else(|| format!("https://{}:{}", instance.host, instance.port)),
                username: instance.username.clone(),
                password: secret(&password),
                token: secret(&token),
                ca_certificates: instance.ca_certificates.clone(),
                request_timeout: Duration::from_secs(instance.request_timeout_seconds),
            })
            .map_err(|e| anyhow::anyhow!("splunk instance {name}: {e}"))?;
            sources.insert(
                name.clone(),
                Source {
                    instance: Instance {
                        host: instance.host.clone(),
                        timezone,
                    },
                    client: Arc::new(client),
                    dispatch_timeout: Duration::from_secs(instance.dispatch_timeout_seconds),
                    user_context: instance.user_context.clone(),
                    app_context: instance.app_context.clone(),
                },
            );
        }
        Ok(Hunter {
            home: config.signatures.clone(),
            cache: MemoryCache::new(config.correlation_cache_bytes, Box::new(Utc::now)),
            config,
            sources,
            renderer: Renderer::default(),
            correlation_renderer: Renderer::correlation(ace_hunt::render::Limits::default()),
            command_types: CommandTypes::new(),
            secrets: held,
        })
    }

    /// The correlation command types the binary has (`App::command_types`).
    pub fn with_command_types(mut self, types: CommandTypes) -> Hunter {
        self.command_types = types;
        self
    }

    /// The query sources a correlation can name, for a run that stops on `stop`: each configured
    /// source whose instance the hunter has. One whose instance it hasn't fails to load, as ace3's
    /// source that fails to build, and a query naming it fails its step.
    fn query_sources(&self, stop: &CancellationToken) -> Sources {
        let mut sources = Sources::new();
        for (name, source) in &self.config.query_sources {
            let QuerySourceConfig::Splunk { instance } = source;
            let Some(splunk) = self.sources.get(instance) else {
                tracing::error!(
                    source = name,
                    "failed to load query source {name}: splunk config for {instance} not found"
                );
                continue;
            };
            sources.register(
                name,
                Arc::new(SplunkQuery {
                    client: splunk.client.clone(),
                    timezone: splunk.instance.timezone,
                    user_context: splunk.user_context.clone(),
                    app_context: splunk.app_context.clone(),
                    dispatch_timeout: splunk.dispatch_timeout,
                    poll: Duration::from_secs_f64(self.config.poll_seconds.max(0.0)),
                    stop: stop.clone(),
                    handle: tokio::runtime::Handle::current(),
                }),
            );
        }
        sources
    }

    /// Runs a hunt's correlation over its rows (ace3's `CorrelationEngine.execute` in
    /// `process_query_results`), anchored to the window it searched, on this thread: the run
    /// blocks it while a query waits, so the runtime moves its other tasks off it. The run's log
    /// lines go to the hunter's log.
    pub fn correlate(
        &self,
        hunt: &Hunt,
        rows: &[JsonMap<String, Json>],
        window: &Window,
        stop: &CancellationToken,
    ) -> Result<Correlated, EngineError> {
        let config = &hunt.config;
        let Some(correlate) = &config.correlate else {
            return Ok(Correlated::default());
        };
        let events = rows
            .iter()
            .map(
                |r| match ace_hunt::query::extract::to_loaded(&Json::Object(r.clone())) {
                    ace_hunt::value::Value::Map(m) => m,
                    _ => ace_hunt::value::Map::new(),
                },
            )
            .collect();
        let sources = self.query_sources(stop);
        let clock = Utc::now;
        let stopped = || stop.is_cancelled();
        let rt = Runtime {
            renderer: &self.correlation_renderer,
            sources: &sources,
            command_types: &self.command_types,
            cache: &self.cache,
            secrets: &self.secrets,
            clock: &clock,
            stopped: &stopped,
            limits: Default::default(),
        };
        let run = HuntRun {
            start: Time::from(window.start),
            end: Some(Time::from(window.end)),
            source_type: Some(config.kind.clone()),
            name: Some(config.name.clone()),
            uuid: Some(config.uuid.clone()),
            replay: Vec::new(),
        };
        let result = tokio::task::block_in_place(|| {
            Engine::new(&rt, correlate, &hunt.commands, run).execute(events)
        });
        if let Ok(correlated) = &result {
            log_correlation(config, correlated);
        }
        result
    }

    /// Where `<include:PATH>` in a query reads from.
    pub fn with_home(mut self, home: PathBuf) -> Hunter {
        self.home = home;
        self
    }

    /// The Splunk instances hunts may name, for `ace_hunt::types::Splunk`'s check at load.
    pub fn instances(&self) -> Vec<String> {
        self.sources.keys().cloned().collect()
    }

    /// Loads the hunts of `kind` from its rule directories.
    pub fn load(&self, kind: &dyn HuntType) -> Vec<ace_hunt::LoadedHunt> {
        let dirs: Vec<PathBuf> = self
            .config
            .rule_dirs
            .get(kind.name())
            .into_iter()
            .flatten()
            .map(|d| self.config.signatures.join(d))
            .collect();
        let options = LoadOptions {
            home: self.home.clone(),
            ..LoadOptions::default()
        };
        ace_hunt::load_hunts(kind, &dirs, &options)
    }

    /// One tick for one hunt at `now`: whether ace3's manager would run it, and the run.
    pub async fn tick(
        &self,
        hunt: &Hunt,
        state: &State,
        signature_version: &str,
        now: DateTime<Utc>,
        stop: &CancellationToken,
    ) -> Tick {
        let config = &hunt.config;
        let mut tick = Tick {
            skipped: None,
            window: None,
            search: None,
            processed: Processed::default(),
            error: None,
            state: state.clone(),
        };
        let instance_type = self.config.instance_type.to_lowercase();
        let ready = schedule::ready(config, state, now);
        tick.skipped = if !config.enabled {
            Some("disabled".to_owned())
        } else if !config
            .instance_types
            .iter()
            .any(|t| t.to_lowercase() == instance_type)
        {
            Some("invalid instance type".to_owned())
        } else if schedule::suppressed(config, state, now) {
            Some("suppressed".to_owned())
        } else if config.kind != "splunk" {
            Some(format!(
                "{} hunts wait for their client (PLAN.md 7.8)",
                config.kind
            ))
        } else {
            match ready {
                Ok(true) => None,
                Ok(false) => Some("not ready".to_owned()),
                Err(e) => {
                    tick.error = Some(e);
                    Some("not ready".to_owned())
                }
            }
        };
        if tick.skipped.is_some() {
            return tick;
        }
        let window = match schedule::window(config, state, now) {
            Ok(window) => window,
            Err(e) => return self.failed(tick, config, None, e, now),
        };
        tick.window = Some(window);
        let name = splunk::splunk_config(hunt);
        let Some(source) = self.sources.get(name) else {
            return self.failed(
                tick,
                config,
                Some(window),
                format!("splunk config for {name} not found"),
                now,
            );
        };
        let search = match splunk::query(hunt, &self.home)
            .and_then(|q| splunk::search(hunt, &q, window.start, window.end, &source.instance))
        {
            Ok(search) => search,
            Err(e) => return self.failed(tick, config, Some(window), e, now),
        };
        let query_timeout = config
            .query_timeout
            .as_deref()
            .and_then(|t| schedule::timedelta(t).ok())
            .and_then(|t| t.to_std().ok())
            .unwrap_or(Duration::from_secs(1800));
        let limits = Limits {
            poll: Duration::from_secs_f64(self.config.poll_seconds.max(0.0)),
            dispatch_timeout: source.dispatch_timeout,
            query_timeout,
        };
        let form = splunk::urlencode(&search.form);
        let rows = source
            .client
            .search(
                splunk::user_context(hunt),
                splunk::app_context(hunt),
                &form,
                limits,
                stop.clone().cancelled_owned(),
            )
            .await;
        tick.search = Some(search.clone());
        let rows = match rows {
            Ok(rows) => rows,
            Err(e) => return self.failed(tick, config, Some(window), e.to_string(), now),
        };
        let correlated = match &config.correlate {
            None => None,
            Some(_) => match self.correlate(hunt, &rows, &window, stop) {
                Ok(correlated) => Some(correlated),
                Err(e) => return self.failed(tick, config, Some(window), e.to_string(), now),
            },
        };
        let event_time = |row: &JsonMap<String, Json>| Some(splunk::event_time(row, now));
        let valid_type = |t: &str| ObservableKind::from_str(t).is_ok();
        let ctx = Context {
            renderer: &self.renderer,
            now,
            signature_version,
            tool_instance: &source.instance.host,
            query: Some(search.query.clone()),
            search_id: None,
            search_link: Some(search.link.clone()),
            event_time: &event_time,
            valid_type: &valid_type,
            email: ace_mod_email::py::normalize_email_address,
            state,
            manual: false,
            correlated: correlated.as_ref(),
        };
        match query::process(config, &rows, &ctx) {
            Ok(processed) => {
                let keys: Vec<Option<String>> = processed
                    .submissions
                    .iter()
                    .map(|s| {
                        s.suppression_key
                            .clone()
                            .or_else(|| s.group_value.as_ref().map(query::group_key))
                    })
                    .collect();
                schedule::record_run(
                    config,
                    &mut tick.state,
                    &window,
                    &Ran::Searched { submitted: &keys },
                    now,
                );
                tick.processed = processed;
                tick
            }
            Err(e) => self.failed(tick, config, Some(window), e.to_string(), now),
        }
    }

    fn failed(
        &self,
        mut tick: Tick,
        config: &ace_hunt::HuntConfig,
        window: Option<Window>,
        error: String,
        now: DateTime<Utc>,
    ) -> Tick {
        tracing::warn!(hunt = %config.name, uuid = %config.uuid, "hunt failed: {error}");
        let window = window.unwrap_or(Window {
            target_start: now,
            target_end: now,
            start: now,
            end: now,
        });
        schedule::record_run(config, &mut tick.state, &window, &Ran::Failed, now);
        tick.error = Some(error);
        tick
    }
}

/// ace3's `SplunkQuerySource`: a correlation's query run as a job on a Splunk instance
/// (`ace_hunt::splunk::correlation_form`), its wait bounded by the instance's dispatch timeout and
/// the command's `timeout`, and ended by the run's stop.
pub struct SplunkQuery {
    client: Arc<SearchClient>,
    timezone: chrono_tz::Tz,
    user_context: Option<String>,
    app_context: Option<String>,
    dispatch_timeout: Duration,
    poll: Duration,
    stop: CancellationToken,
    handle: tokio::runtime::Handle,
}

impl QuerySource for SplunkQuery {
    fn default_time_field(&self) -> Option<&str> {
        Some("_time")
    }

    fn default_time_format(&self) -> Option<&str> {
        Some("iso8601")
    }

    fn execute_query(
        &self,
        query: &str,
        start: Time,
        end: Time,
        timeout: chrono::TimeDelta,
        _source_options: &JsonMap<String, Json>,
    ) -> Result<Vec<JsonMap<String, Json>>, String> {
        // ace3's Splunk source has no per-call options, and takes them to ignore
        let form = splunk::urlencode(&splunk::correlation_form(query, start, end));
        let limits = Limits {
            poll: self.poll,
            dispatch_timeout: self.dispatch_timeout,
            query_timeout: timeout.to_std().unwrap_or(Duration::ZERO),
        };
        self.handle
            .block_on(self.client.search(
                self.user_context.as_deref(),
                self.app_context.as_deref(),
                &form,
                limits,
                self.stop.clone().cancelled_owned(),
            ))
            .map_err(|e| e.to_string())
    }

    fn format_timespec_for_display(
        &self,
        start: Time,
        end: Time,
    ) -> Result<Option<String>, String> {
        Ok(Some(splunk::correlation_timespec(
            start,
            end,
            self.timezone,
        )))
    }
}

/// Writes what a correlation logged, and ace3's line for each event's trace and stream event.
fn log_correlation(config: &ace_hunt::HuntConfig, correlated: &Correlated) {
    for LogLine { level, message } in &correlated.logs {
        let (hunt, uuid) = (&config.name, &config.uuid);
        match level {
            Level::Debug => tracing::debug!(hunt, uuid, "{message}"),
            Level::Info => tracing::info!(hunt, uuid, "{message}"),
            Level::Warning => tracing::warn!(hunt, uuid, "{message}"),
            Level::Error | Level::Critical => tracing::error!(hunt, uuid, "{message}"),
        }
    }
    for et in &correlated.trace.event_traces {
        tracing::info!(
            hunt = %config.name,
            uuid = %config.uuid,
            event_index = et.event_index,
            outcome = %et.outcome,
            steps = et.steps.len(),
            duration_ms = et.duration_ms,
            "correlation trace"
        );
    }
    for se in &correlated.trace.stream_events {
        tracing::info!(
            hunt = %config.name,
            uuid = %config.uuid,
            event_type = %se.event_type,
            at_event_index = se.at_event_index,
            detail = se.detail.as_deref(),
            "correlation stream event"
        );
    }
}

/// A hunt's submission as the core takes it: the root's description, mode and event time, and the
/// rest as its origin (`ace_core::submit::Origin`). The hunt's detection is on its `signature_id`
/// observable, since ace4's detections are on an observable; ace3's is on the root.
pub fn to_core(submission: &query::Submission) -> (Submission, Origin) {
    let mut observables = Vec::new();
    for observable in &submission.observables {
        let Ok(kind) = ObservableKind::from_str(&observable.kind) else {
            tracing::warn!(kind = %observable.kind, "a hunt mapped a type ace doesn't have; it's in the root's origin only");
            continue;
        };
        let mut new = NewObservable::new(kind, observable.value.clone());
        new.time = observable.time;
        new.tags = observable.tags.clone();
        new.directives = observable.directives.clone();
        new.display_type = observable.display_type.clone();
        for relationship in &observable.relationships {
            let (Ok(rk), Ok(target)) = (
                serde_json::from_value(Json::String(relationship.kind.clone())),
                ObservableKind::from_str(&relationship.target.kind),
            ) else {
                continue;
            };
            new.relationships.push(Relationship::new(
                rk,
                ObservableRef {
                    kind: target,
                    value: relationship.target.value.clone(),
                },
            ));
        }
        if kind == ObservableKind::SignatureId {
            for detection in &submission.detections {
                new.detections.push(Detection {
                    description: detection.description.clone(),
                    details: None,
                    queue: None,
                    signature_uuid: Some(detection.signature_uuid.clone()),
                    signature_version: Some(detection.signature_version.clone()),
                    signature_family: Some(detection.signature_family.clone()),
                });
            }
        }
        observables.push(new);
    }
    if !submission.files.is_empty() {
        tracing::warn!(
            files = submission.files.len(),
            "a hunt's file mappings made files, which the hunter doesn't submit yet"
        );
    }
    let core = Submission {
        description: submission.description.clone(),
        analysis_mode: Some(submission.analysis_mode.clone()),
        event_time: Some(submission.event_time),
        observables: Vec::new(),
        file_yara_meta: BTreeMap::new(),
    };
    let origin = Origin {
        event_time_from_query: submission.event_time_source == EventTimeSource::QueryTime,
        observables,
        details: serde_json::to_value(submission).ok(),
    };
    (core, origin)
}

/// A tick that ran, as the service records it: its submissions with their dedup and suppression keys,
/// and a row's worth for each submission a group's suppression dropped (PLAN.md 6.5).
pub fn run_of(
    hunt: &Hunt,
    read: ace_service::HuntState,
    tick: &Tick,
    now: DateTime<Utc>,
) -> ace_service::HuntRun {
    let config = &hunt.config;
    let state = from_service(read.clone());
    let submissions = tick
        .processed
        .submissions
        .iter()
        .map(|s| {
            let (submission, origin) = to_core(s);
            ace_service::HuntSubmission {
                submission,
                origin,
                dedup_key: s.key.clone(),
                suppression_key: s
                    .suppression_key
                    .clone()
                    .or_else(|| s.group_value.as_ref().map(query::group_key)),
                group_value: s.group_value.clone(),
                events: s.rows.len(),
            }
        })
        .collect();
    let suppressed = tick
        .processed
        .suppressed
        .iter()
        .filter_map(|(s, key)| {
            let Some((since, until)) = schedule::group_suppression(config, &state, key, now) else {
                tracing::error!(hunt = %config.name, key, "a suppressed group has no suppression window");
                return None;
            };
            tracing::info!(hunt = %config.name, key, %until, "suppressed a group's alert");
            Some(ace_service::GroupSuppressed {
                key: key.clone(),
                group_value: s.group_value.clone(),
                description: s.description.clone(),
                event_time: s.event_time,
                events: s.rows.len(),
                since,
                until,
            })
        })
        .collect();
    ace_service::HuntRun {
        kind: config.kind.clone(),
        name: config.name.clone(),
        uuid: config.uuid.clone(),
        at: now,
        read,
        state: to_service(&tick.state),
        window_start: tick.window.map(|w| w.start),
        window_end: tick.window.map(|w| w.end),
        submissions,
        suppressed,
    }
}

fn to_service(state: &State) -> ace_service::HuntState {
    ace_service::HuntState {
        last_executed_time: state.last_executed_time,
        last_end_time: state.last_end_time,
        last_alert_time: state.last_alert_time,
        last_alert_times: state.last_alert_times.clone(),
    }
}

fn from_service(state: ace_service::HuntState) -> State {
    State {
        last_executed_time: state.last_executed_time,
        last_end_time: state.last_end_time,
        last_alert_time: state.last_alert_time,
        last_alert_times: state.last_alert_times,
    }
}

/// The commit the signatures checkout is at, ace3's `signature_version`, or `unknown`.
fn signature_version(checkout: &Path) -> String {
    let git = checkout.join(".git");
    let head = std::fs::read_to_string(git.join("HEAD")).unwrap_or_default();
    let head = head.trim();
    let commit = match head.strip_prefix("ref: ") {
        Some(reference) => std::fs::read_to_string(git.join(reference)).unwrap_or_default(),
        None => head.to_owned(),
    };
    let commit = commit.trim();
    if commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        commit.to_owned()
    } else {
        "unknown".to_owned()
    }
}

pub fn run(app: &App, telemetry: &mut ace_pool::telemetry::Telemetry) -> Result<ExitCode> {
    telemetry.start_export().context("starting span export")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    let code = runtime.block_on(hunt(app));
    runtime.shutdown_timeout(Duration::from_secs(5));
    code
}

async fn hunt(app: &App) -> Result<ExitCode> {
    use ace_core::bucket::{Bucket, BucketSettings};
    use ace_core::db::{Db, DbConfig};
    use ace_core::eligibility::Catalog;
    use ace_core::orchestrator::Orchestrator;
    use ace_store::{BucketConfig, DEFAULT_CACHE_MAX_BYTES, NodeCache, Store};

    let path =
        std::env::var_os("ACE4_HUNTER").context("ACE4_HUNTER names no hunter configuration")?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("{}", Path::new(&path).display()))?;
    let config: HunterConfig =
        serde_json::from_str(&text).context("reading the hunter's configuration")?;
    let overlay = crate::cli::overlay()?;
    let names: Vec<String> = config.splunk.keys().flat_map(|n| secret_names(n)).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let secrets = ace_pool::secrets::resolve_names(
        "hunter",
        &names,
        &overlay,
        &ace_pool::secrets::process_env,
    );
    let mut command_types = app.command_types();
    app.build_hunt_scripts(&mut command_types, &net::net()?, &config.scripts)
        .map_err(anyhow::Error::msg)?;
    // a script's `files:` are read from the signatures checkout, as ace3 stages them from its hunt
    // repositories
    command_types
        .scripts_mut()
        .set_roots(vec![config.signatures.clone()]);
    let hunter = Arc::new(Hunter::new(config.clone(), &secrets)?.with_command_types(command_types));

    let db = Db::connect(&DbConfig::from_env("ace-hunter")?)
        .await
        .context("connecting to Postgres")?;
    let cache_dir = std::env::temp_dir().join("ace4-hunter-cache");
    let store = Store::new(
        &BucketConfig::from_env()?,
        NodeCache::new(&cache_dir, DEFAULT_CACHE_MAX_BYTES)
            .with_context(|| format!("the cache in {}", cache_dir.display()))?,
    );
    let bucket = Bucket::new(db.clone(), store, BucketSettings::default());
    let components = crate::cli::components(&app.registry(), &overlay)?;
    let modes = app.modes_with(&components);
    let orchestrator = Orchestrator::new(Catalog::of(components), modes);
    let service = ace_service::Service::new(db, orchestrator);
    let actor = ace_service::Actor::Internal {
        id: ace_service::Component::new("hunter")?,
    };
    let stop = tokio_util::sync::CancellationToken::new();
    let stopping = stop.clone();
    tokio::spawn(async move {
        crate::serve::wait_for_stop().await;
        stopping.cancel();
    });

    let mut hunts: Vec<(Hunt, String)> = Vec::new();
    let mut loaded_at: Option<std::time::Instant> = None;
    let limit = Arc::new(tokio::sync::Semaphore::new(config.concurrency.max(1)));
    while !stop.is_cancelled() {
        if loaded_at.is_none_or(|at| at.elapsed() >= Duration::from_secs(config.reload_seconds)) {
            hunts = reload(app, &hunter, &service, &actor, &config).await;
            loaded_at = Some(std::time::Instant::now());
        }
        let mut runs = tokio::task::JoinSet::new();
        for (hunt, version) in hunts.clone() {
            let (hunter, service, actor, bucket, stop, limit) = (
                hunter.clone(),
                service.clone(),
                actor.clone(),
                bucket.clone(),
                stop.clone(),
                limit.clone(),
            );
            runs.spawn(async move {
                let Ok(_permit) = limit.acquire().await else {
                    return;
                };
                let config = &hunt.config;
                let read = match service.hunt_state(&actor, &config.kind, &config.name).await {
                    Ok(state) => state,
                    Err(e) => {
                        tracing::error!(hunt = %config.name, "reading the hunt's state: {e}");
                        return;
                    }
                };
                let state = from_service(read.clone());
                let now = Utc::now();
                let tick = hunter.tick(&hunt, &state, &version, now, &stop).await;
                if tick.skipped.is_some() || matches!(&tick.error, Some(e) if e.contains("stopped"))
                {
                    return;
                }
                let run = run_of(&hunt, read, &tick, now);
                match service.record_hunt_run(&actor, &bucket, &run).await {
                    Ok(recorded) => tracing::info!(
                        hunt = %config.name,
                        roots = recorded.roots.len(),
                        suppressed = recorded.suppressions.len(),
                        "recorded a hunt's run"
                    ),
                    Err(e) => tracing::error!(hunt = %config.name, "recording the hunt's run: {e}"),
                }
            });
        }
        while runs.join_next().await.is_some() {}
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(config.tick_seconds)) => {}
            () = stop.cancelled() => {}
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Loads every type's hunts, records them, and returns the ones that loaded with their signatures
/// version.
async fn reload(
    app: &App,
    hunter: &Hunter,
    service: &ace_service::Service,
    actor: &ace_service::Actor,
    config: &HunterConfig,
) -> Vec<(Hunt, String)> {
    let version = signature_version(&config.signatures);
    let mut hunts = Vec::new();
    for kind in app.hunt_types() {
        if !config.rule_dirs.contains_key(kind.name()) {
            continue;
        }
        let checked;
        let kind: &dyn HuntType = if kind.name() == "splunk" {
            checked = ace_hunt::types::Splunk {
                instances: Some(hunter.instances()),
            };
            &checked
        } else {
            kind.as_ref()
        };
        let mut rows = Vec::new();
        for loaded in hunter.load(kind) {
            let path = loaded
                .path
                .strip_prefix(&config.signatures)
                .unwrap_or(&loaded.path)
                .to_string_lossy()
                .into_owned();
            match loaded.result {
                Ok(hunt) => {
                    rows.push(ace_service::LoadedHuntRow {
                        kind: kind.name().to_owned(),
                        path,
                        name: Some(hunt.config.name.clone()),
                        uuid: Some(hunt.config.uuid.clone()),
                        enabled: Some(hunt.config.enabled),
                        frequency: Some(hunt.config.frequency.clone()),
                        error: None,
                    });
                    hunts.push((hunt, version.clone()));
                }
                Err(e) => {
                    tracing::warn!(path, "a hunt didn't load: {e}");
                    rows.push(ace_service::LoadedHuntRow {
                        kind: kind.name().to_owned(),
                        path,
                        name: None,
                        uuid: None,
                        enabled: None,
                        frequency: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }
        if let Err(e) = service.sync_hunts(actor, kind.name(), &rows).await {
            tracing::error!(kind = kind.name(), "recording the loaded hunts: {e}");
        }
    }
    hunts
}

pub mod net;
#[cfg(test)]
mod tests;
