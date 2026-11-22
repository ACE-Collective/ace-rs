//! `ace hunter`: ace3's hunter for query hunts (PLAN.md 6.4), with Splunk as its own hunt type and
//! a site's hunt types beside it (decision 40).
//!
//! It loads the hunts of each type it has rule directories for from the signatures checkout
//! (`ace_hunt::load_hunts`, 6.2), records them for the `hunt` router (`Service::sync_hunts`), and
//! every tick runs each hunt ace3's `HuntManager.execute` would run: enabled, for this instance type,
//! not suppressed, and ready by its frequency. A run searches the hunt's window
//! (`ace_hunt::query::schedule::window`) with its hunt type's search (`ace_hunt::search::HuntSearch`),
//! turns the rows into submissions as ace3's `QueryHunt` does (`ace_hunt::query::process`), and
//! records them and the hunt's new state in one transaction (`Service::record_hunt_run`), as the
//! internal component `hunter`, which migration 0034 grants `alert:create`, `hunt:read` and
//! `hunt:write`. The state lives in Postgres, so a restart neither searches a window again nor skips
//! one. Hunts reload every `reload_seconds`.
//!
//! **Hunt types' searches** (decision 40, docs/decisions/0005-site-hunt-types.md). A hunt type's
//! search is what `App::hunt_searches` has for its name: every `App` has Splunk's ([`splunk`]: the
//! hunt's search on the instance its `splunk_config` names, built by `ace_hunt::splunk` and run by
//! `ace_mod_splunk::search`), and a site adds its own with `App::hunt_search`, built from the
//! overlay's `hunt_types.<type>` (its settings and the shared connections it binds). A hunt of a type
//! the binary has no search for loads and is skipped, saying so. Splunk's instances are the overlay's
//! connections of type `splunk` (PLAN.md decision 41), each named as ace3 names the instance, which
//! Splunk's search takes by name. A row's event time is the hunt type's (`HuntType::event_time`,
//! decision 43), not its search's, so a validation run through `ace serve`, which has no search,
//! times the rows as the hunter does.
//!
//! Each hit a suppression drops is a row (PLAN.md 6.5, [`run_of`]): a group a grouped hunt's
//! `suppression` drops, decided here, and a duplicate of a dedup key, which ace3's collector drops and
//! `Service::record_hunt_run` drops here, in the run's transaction (`ace_service`'s `hunts` docs).
//!
//! **Where it runs.** Its own process of the `ace` binary, as ace3's hunter is its own service. A
//! search needs a data source's credentials, and 2.24 holds a process to the secrets it declares:
//! `ace serve` holds the API's and none of a data source's, so the hunter isn't part of it. A pool
//! reaches only the lease API and the bucket, while a hunt writes roots through the service layer, so
//! it isn't a pool either. 6.7's scheduler takes `ace3/saq/cron_tasks.py`, which has no hunts; a hunt
//! has its own frequency, window and state, which this keeps. So `ace hunter` resolves the secrets
//! of the connections its components take: those the overlay's `command_types:`, `hunt_types:` and
//! `query_sources:` bind, and every Splunk instance, which Splunk's search takes by name (with
//! ace3's secret names, `splunk_<instance>_password` or `splunk_<instance>_token`), and no others.
//!
//! **Bounded waits** (2.21): a search by its type's own bounds and the hunt's `query_timeout`
//! (Splunk's: each request by the instance's `request_timeout_seconds`, a job by
//! `dispatch_timeout_seconds` until it starts and the hunt's `query_timeout` once it runs), each
//! database call by the pool's acquire and statement timeouts (`DbConfig`), and a stop ends a run's
//! wait at once, cancelling its job; the run's window is then left to the next start.
//!
//! It reads `ACE4_HUNTER`, a JSON file ([`HunterConfig`]), `ACE4_DATABASE_URL`, the `ACE4_BUCKET_*`
//! variables and the overlay at `ACE4_OVERLAY`.
//!
//! **Correlation** (PLAN.md 6.6). A hunt with a `correlate` block has its rows run through
//! `ace_hunt::correlate::engine` before they're processed, on the run's thread, with every wait
//! bounded and a stop ending it ([`Hunter::correlate`]). Its `query` commands go to the overlay's
//! `query_sources:`, by default `splunk` on the `default` instance, as ace3's
//! `hunter.correlation.query_sources` does, each of a type `App::query_source_types` has: every `App`
//! has `splunk` ([`SplunkQuery`], as ace3's `SplunkQuerySource` runs one), and a site adds its own
//! with `App::query_source_type`. Its custom command types are the binary's (`App::command_type`), a
//! command's `cache:` is kept in memory (`correlation_cache_bytes`), and what the run logs and the
//! trace holds is scrubbed of the credentials the hunter holds, which no template can read.
//! A `type: executable` command runs no script (PLAN.md decision 16): a hunt script runs as the
//! script command type the site's binary registers for its path (`App::hunt_script`),
//! built over the hunter's network ([`net`]) with its settings in the configuration's `scripts`, and
//! its `files:` are read from the signatures checkout. Any other executable fails its step.
//!
//! **A type that isn't schedulable** (PLAN.md decision 42, ace3's `hunt_type_<name>.schedulable`):
//! the overlay's `hunt_types.<type>.schedulable: false` keeps a type's hunts off the schedule, for a
//! data source whose query quota must stay under people's control. The hunter refuses to start when
//! its `rule_dirs` names such a type, as ace3's configuration refuses it, so it loads none of the
//! type's hunts; it builds no search for the type and resolves none of that search's secrets. The
//! type's hunts still validate through `ace serve`'s `hunt` router.
//!
//! What waits: a type the binary lacks, such as `rapid7`, has no hunts loaded, whatever `rule_dirs`
//! names, and the hunter warns of each such type when it starts (`unknown_types`); a file mapping's
//! files (three of the signatures' Splunk hunts have one), which are logged and dropped until the
//! hunter spools files for submission.

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
use ace_hunt::search::{HuntSearch, STOPPED, SearchLimits};
use ace_hunt::{Hunt, HuntType, LoadOptions};
use ace_results::{Detection, NewObservable, ObservableKind, ObservableRef, Relationship};
use ace_sdk::Secrets;
use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as Json};
use tokio_util::sync::CancellationToken;

use crate::App;

pub use splunk::{SplunkQuery, SplunkSearch};

/// The hunter's configuration, the file `ACE4_HUNTER` names.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HunterConfig {
    /// The signatures checkout.
    pub signatures: PathBuf,
    /// Each hunt type's rule directories, relative to `signatures`.
    pub rule_dirs: BTreeMap<String, Vec<PathBuf>>,
    /// ace3's `global_settings.instance_type`, which a hunt's `instance_types` names.
    pub instance_type: String,
    #[serde(default = "default_tick")]
    pub tick_seconds: u64,
    #[serde(default = "default_reload")]
    pub reload_seconds: u64,
    /// Between two reads of a search job's status, as ace3's hunter waits.
    #[serde(default = "default_poll")]
    pub poll_seconds: f64,
    /// How many hunts run at once.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    /// The bytes of correlation command outputs kept for their `cache:`.
    #[serde(default = "default_cache_bytes")]
    pub correlation_cache_bytes: usize,
    /// Each script command type's settings, by its name (`App::hunt_script`), such as a site's own
    /// values a script holds in its code (PLAN.md decision 16).
    #[serde(default)]
    pub scripts: BTreeMap<String, Json>,
}

/// ace3's default query sources when the overlay names none: `splunk` on the `default` instance,
/// the connection `default`.
pub fn default_query_sources() -> BTreeMap<String, ace_sdk::overlay::QuerySourceSection> {
    BTreeMap::from([(
        "splunk".to_owned(),
        ace_sdk::overlay::QuerySourceSection {
            kind: "splunk".to_owned(),
            settings: None,
            connections: BTreeMap::from([(
                ace_mod_splunk::connection::SLOT.name.to_owned(),
                "default".to_owned(),
            )]),
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

/// What a hunt type's search or a query source's builder is given (PLAN.md decision 40): its
/// name (the hunt type's, or the source's as a correlation's `source:` names it), its settings
/// from the overlay's `hunt_types.<type>.settings` or `query_sources.<name>.settings`, the shared
/// connections its entry binds to its slots, with their secrets where the process holds them, and
/// the hunter's poll interval. `ace serve` builds query sources with no secrets, to validate hunts,
/// and never runs a query on them. A test builds one with `SearchSetup::new` and the methods after
/// it, so a field added here doesn't break it.
#[derive(Clone)]
#[non_exhaustive]
pub struct SearchSetup {
    pub name: String,
    pub settings: Option<Json>,
    pub connections: ace_sdk::Connections,
    /// Between two reads of a search job's status, the hunter's `poll_seconds`.
    pub poll: Duration,
    stop: CancellationToken,
    handle: Option<tokio::runtime::Handle>,
}

impl std::fmt::Debug for SearchSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchSetup")
            .field("name", &self.name)
            .field("settings", &self.settings)
            .field("connections", &self.connections.slots())
            .finish_non_exhaustive()
    }
}

impl SearchSetup {
    /// The setup of `name` with `settings`, no connections, a 3 second poll, never stopped, on the
    /// runtime it is made in, if any.
    pub fn new(name: impl Into<String>, settings: Option<Json>) -> SearchSetup {
        SearchSetup {
            name: name.into(),
            settings,
            connections: ace_sdk::Connections::new(),
            poll: Duration::from_secs(3),
            stop: CancellationToken::new(),
            handle: tokio::runtime::Handle::try_current().ok(),
        }
    }

    pub fn with_connections(mut self, connections: ace_sdk::Connections) -> SearchSetup {
        self.connections = connections;
        self
    }

    pub fn with_poll(mut self, poll: Duration) -> SearchSetup {
        self.poll = poll;
        self
    }

    /// A query source built with this setup ends its queries when `stop` is cancelled.
    pub fn with_stop(mut self, stop: CancellationToken) -> SearchSetup {
        self.stop = stop;
        self
    }

    /// How a query source, which the correlation engine calls on a thread it may block, runs its
    /// async client and ends on the run's stop.
    pub fn blocking(&self) -> Blocking {
        Blocking {
            stop: self.stop.clone(),
            handle: self.handle.clone(),
        }
    }
}

/// Runs a query source's async work to its end on the hunter's runtime from the correlation's
/// thread, which `ace hunter` runs under `block_in_place`, ending it with [`STOPPED`] when the run
/// stops.
#[derive(Clone)]
pub struct Blocking {
    stop: CancellationToken,
    handle: Option<tokio::runtime::Handle>,
}

impl Blocking {
    /// A future that ends when the run stops, for a client that takes one.
    pub fn stop(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        self.stop.clone().cancelled_owned()
    }

    /// Whether the run has stopped.
    pub fn stopped(&self) -> bool {
        self.stop.is_cancelled()
    }

    /// Runs `work` to its end, or until the run stops.
    pub fn run<T>(
        &self,
        work: impl std::future::Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        let handle = self
            .handle
            .as_ref()
            .ok_or_else(|| "a query source runs only on the hunter's runtime".to_owned())?;
        let stop = self.stop.clone();
        handle.block_on(async move {
            tokio::select! {
                done = work => done,
                () = stop.cancelled() => Err(STOPPED.to_owned()),
            }
        })
    }
}

/// What builds a hunt type's search from its setup, or says why it can't: the reason a hunt of
/// the type is skipped with.
pub type HuntSearchFactory =
    Arc<dyn Fn(&SearchSetup) -> Result<Arc<dyn HuntSearch>, String> + Send + Sync>;

/// What builds a query source from its setup, or says why it can't.
pub type QuerySourceFactory =
    Arc<dyn Fn(&SearchSetup) -> Result<Arc<dyn QuerySource>, String> + Send + Sync>;

/// A search or query source type: the slots its entries bind, and what builds one.
#[derive(Clone)]
pub struct SearchType<F> {
    pub connections: &'static [ace_sdk::ConnectionSlot],
    pub build: F,
}

/// A query source of the overlay's, ready to build for a run.
struct SourceEntry {
    kind: String,
    settings: Option<Json>,
    connections: ace_sdk::Connections,
    build: QuerySourceFactory,
}

/// The hunter without its database: what decides, searches and processes a run.
pub struct Hunter {
    config: HunterConfig,
    /// The binary's hunt types by name, which time a search's rows (`HuntType::event_time`).
    types: BTreeMap<String, Arc<dyn HuntType>>,
    /// Each hunt type's search, or why it didn't build.
    searches: BTreeMap<String, Result<Arc<dyn HuntSearch>, String>>,
    sources: BTreeMap<String, SourceEntry>,
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
    /// What the hunt type's search ran, once it got that far.
    pub search: Option<ace_hunt::search::Ran>,
    pub processed: Processed,
    /// Why the run failed, as ace3 logs it.
    pub error: Option<String>,
    /// The state after the tick.
    pub state: State,
}

impl Hunter {
    /// A hunter with Splunk's hunt type and every `App`'s built-in Splunk search and source over
    /// `overlay`'s Splunk instances and its query sources, and no site types: `Hunter::for_app` is
    /// the hunter `ace hunter` runs.
    pub fn new(
        config: HunterConfig,
        secrets: &Secrets,
        overlay: &ace_sdk::Overlay,
    ) -> Result<Hunter> {
        let app = App::new().hunt_type(ace_hunt::types::Splunk::default());
        Hunter::for_app(config, secrets, &app, overlay)
    }

    /// The hunter of `app`'s hunt type searches and query source types, built with `overlay`'s
    /// `hunt_types:` and `query_sources:` and the connections they take, whose secrets are those
    /// of `secrets`.
    pub fn for_app(
        config: HunterConfig,
        secrets: &Secrets,
        app: &App,
        overlay: &ace_sdk::Overlay,
    ) -> Result<Hunter> {
        // ace3's HuntTypeConfig refuses this pairing when its configuration loads: hunts in a rule
        // directory of a type that isn't schedulable would look live and never run
        if let Some(kind) = config
            .rule_dirs
            .keys()
            .find(|kind| !overlay.hunt_type_schedulable(kind))
        {
            anyhow::bail!(
                "hunt type {kind} defines rule_dirs but is not schedulable; those hunts would never \
                 load, so remove rule_dirs or set schedulable to true"
            );
        }
        let mut held = Vec::new();
        let poll = Duration::from_secs_f64(config.poll_seconds.max(0.0));
        let setup = |name: &str, settings: Option<Json>, connections: ace_sdk::Connections| {
            SearchSetup::new(name, settings)
                .with_connections(connections)
                .with_poll(poll)
        };
        let mut searches = BTreeMap::new();
        for (kind, search) in app.hunt_searches() {
            let section = overlay.hunt_types.get(&kind).cloned().unwrap_or_default();
            if !section.schedulable {
                // never built, so the hunter holds none of its secrets
                searches.insert(
                    kind.clone(),
                    Err(format!(
                        "the {kind} hunt type isn't schedulable (the overlay's \
                         hunt_types.{kind}.schedulable)"
                    )),
                );
                continue;
            }
            let built = overlay
                .bind(
                    &format!("hunt_types.{kind}.connections"),
                    search.connections,
                    &section.connections,
                )
                .map_err(|e| e.to_string())
                .and_then(|bindings| {
                    let connections = ace_sdk::Connections::resolve(&bindings, secrets);
                    held.extend(held_secrets(&connections));
                    (search.build)(&setup(&kind, section.settings.clone(), connections))
                });
            if let Err(e) = &built {
                tracing::error!(
                    hunt_type = kind,
                    "the {kind} hunt type's search failed to load: {e}"
                );
            }
            searches.insert(kind, built);
        }
        let types = app.query_source_types();
        let mut sources = BTreeMap::new();
        let entries = overlay
            .query_sources
            .clone()
            .unwrap_or_else(default_query_sources);
        for (name, entry) in entries {
            let Some(kind) = types.get(&entry.kind) else {
                tracing::error!(
                    source = name,
                    "failed to load query source {name}: this binary has no query source type {}",
                    entry.kind
                );
                continue;
            };
            match overlay.bind(
                &format!("query_sources.{name}.connections"),
                kind.connections,
                &entry.connections,
            ) {
                Ok(bindings) => {
                    let connections = ace_sdk::Connections::resolve(&bindings, secrets);
                    held.extend(held_secrets(&connections));
                    sources.insert(
                        name,
                        SourceEntry {
                            kind: entry.kind.clone(),
                            settings: entry.settings.clone(),
                            connections,
                            build: kind.build.clone(),
                        },
                    );
                }
                Err(e) => tracing::error!(source = name, "failed to load query source {name}: {e}"),
            }
        }
        Ok(Hunter {
            home: config.signatures.clone(),
            cache: MemoryCache::new(config.correlation_cache_bytes, Box::new(Utc::now)),
            config,
            types: app
                .hunt_types()
                .iter()
                .map(|kind| (kind.name().to_owned(), kind.clone()))
                .collect(),
            searches,
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
    /// source that builds. One that fails to build is logged and left out, as ace3's source that
    /// fails to build, and a query naming it fails its step.
    fn query_sources(&self, stop: &CancellationToken) -> Sources {
        let mut sources = Sources::new();
        for (name, entry) in &self.sources {
            let setup = SearchSetup::new(name, entry.settings.clone())
                .with_connections(entry.connections.clone())
                .with_poll(Duration::from_secs_f64(self.config.poll_seconds.max(0.0)))
                .with_stop(stop.clone());
            match (entry.build)(&setup) {
                Ok(source) => {
                    sources.register(name, source);
                }
                Err(e) => tracing::error!(
                    source = name,
                    kind = entry.kind,
                    "failed to load query source {name}: {e}"
                ),
            }
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

    /// The search of the hunt type `kind`, or why there is none.
    fn search_of(&self, kind: &str) -> Result<&Arc<dyn HuntSearch>, String> {
        match self.searches.get(kind) {
            Some(Ok(search)) => Ok(search),
            Some(Err(e)) => Err(format!("{kind} hunts' search failed to load: {e}")),
            None => Err(format!("this binary has no search for {kind} hunts")),
        }
    }

    /// The hunt type `kind` and its search, or why a hunt of it can't run.
    fn runner_of(&self, kind: &str) -> Result<(&dyn HuntType, &dyn HuntSearch), String> {
        let search = self.search_of(kind)?;
        let kind = self
            .types
            .get(kind)
            .ok_or_else(|| format!("this binary has no {kind} hunt type"))?;
        Ok((kind.as_ref(), search.as_ref()))
    }

    /// Loads the hunts of `kind` from its rule directories, each checked as its search checks it
    /// when it is made (Splunk: the instance it names).
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
        match self.search_of(kind.name()) {
            Ok(search) => {
                let checked = ace_hunt::search::Checked {
                    kind,
                    search: search.as_ref(),
                };
                ace_hunt::load_hunts(&checked, &dirs, &options)
            }
            Err(_) => ace_hunt::load_hunts(kind, &dirs, &options),
        }
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
        let search = self.runner_of(&config.kind);
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
        } else if let Err(why) = &search {
            Some(why.clone())
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
        let Ok((kind, search)) = search else {
            return tick;
        };
        if tick.skipped.is_some() {
            return tick;
        }
        let window = match schedule::window(config, state, now) {
            Ok(window) => window,
            Err(e) => return self.failed(tick, config, None, e, now),
        };
        tick.window = Some(window);
        let query_timeout = config
            .query_timeout
            .as_deref()
            .and_then(|t| schedule::timedelta(t).ok())
            .and_then(|t| t.to_std().ok())
            .unwrap_or(Duration::from_secs(1800));
        let limits = SearchLimits {
            poll: Duration::from_secs_f64(self.config.poll_seconds.max(0.0)),
            query_timeout,
        };
        let searched = search
            .search(
                hunt,
                &self.home,
                &window,
                limits,
                Box::pin(stop.clone().cancelled_owned()),
            )
            .await;
        tick.search = searched.ran.clone();
        let rows = match searched.rows {
            Ok(rows) => rows,
            Err(e) => return self.failed(tick, config, Some(window), e, now),
        };
        let Some(ran) = searched.ran else {
            return self.failed(
                tick,
                config,
                Some(window),
                format!("the {} search said nothing of what it ran", config.kind),
                now,
            );
        };
        let correlated = match &config.correlate {
            None => None,
            Some(_) => match self.correlate(hunt, &rows, &window, stop) {
                Ok(correlated) => Some(correlated),
                Err(e) => return self.failed(tick, config, Some(window), e.to_string(), now),
            },
        };
        let event_time = |row: &JsonMap<String, Json>| kind.event_time(config, row, now);
        let valid_type = |t: &str| ObservableKind::from_str(t).is_ok();
        let ctx = Context {
            renderer: &self.renderer,
            now,
            signature_version,
            tool_instance: &ran.tool_instance,
            query: Some(ran.query.clone()),
            search_id: ran.search_id.clone(),
            search_link: ran.link.clone(),
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

/// The text of every secret `connections` hold, which a correlation's output is scrubbed of.
fn held_secrets(connections: &ace_sdk::Connections) -> Vec<String> {
    connections
        .all()
        .into_iter()
        .flat_map(|connection| {
            connection
                .secret_roles()
                .into_iter()
                .filter_map(|role| connection.secret(role))
                .map(|secret| secret.expose().to_owned())
                .collect::<Vec<_>>()
        })
        .filter(|text| !text.is_empty())
        .collect()
}

/// The query sources `ace serve` validates hunts with (PLAN.md decision 40): each of `overlay`'s,
/// built with its connections' settings and none of their secrets, and refusing to run a query,
/// so a validation has each source's time field and its display of a window, and reaches no data
/// source.
pub fn validation_sources(app: &App, overlay: &ace_sdk::Overlay) -> Sources {
    let (sources, failed) = validation_sources_and_failures(app, overlay);
    for (name, e) in failed {
        tracing::debug!(
            source = name,
            "a query source isn't there to validate hunts with: {e}"
        );
    }
    sources
}

/// `validation_sources`, and each of the overlay's sources that didn't build, with why: a type the
/// binary hasn't, a binding its slots refuse, or its builder's error.
pub fn validation_sources_and_failures(
    app: &App,
    overlay: &ace_sdk::Overlay,
) -> (Sources, Vec<(String, String)>) {
    let types = app.query_source_types();
    let mut sources = Sources::new();
    let mut failed = Vec::new();
    let entries = overlay
        .query_sources
        .clone()
        .unwrap_or_else(default_query_sources);
    for (name, entry) in entries {
        let Some(kind) = types.get(&entry.kind) else {
            failed.push((
                name,
                format!("this binary has no query source type {}", entry.kind),
            ));
            continue;
        };
        let built = overlay
            .bind(
                &format!("query_sources.{name}.connections"),
                kind.connections,
                &entry.connections,
            )
            .map_err(|e| e.to_string())
            .and_then(|bindings| {
                let connections = ace_sdk::Connections::resolve(&bindings, &Secrets::new());
                (kind.build)(
                    &SearchSetup::new(&name, entry.settings.clone()).with_connections(connections),
                )
            });
        match built {
            Ok(source) => {
                sources.register(&name, Arc::new(ValidationOnly(source)));
            }
            Err(e) => failed.push((name, e)),
        }
    }
    (sources, failed)
}

/// A query source `ace serve` holds: what it says of its times, and no query.
struct ValidationOnly(Arc<dyn QuerySource>);

impl QuerySource for ValidationOnly {
    fn default_time_field(&self) -> Option<&str> {
        self.0.default_time_field()
    }

    fn default_time_format(&self) -> Option<&str> {
        self.0.default_time_format()
    }

    fn execute_query(
        &self,
        _query: &str,
        _start: Time,
        _end: Time,
        _timeout: chrono::TimeDelta,
        _source_options: &JsonMap<String, Json>,
    ) -> Result<Vec<JsonMap<String, Json>>, String> {
        Err("a query runs only in ace hunter; send its saved results to validate it".to_owned())
    }

    fn format_timespec_for_display(
        &self,
        start: Time,
        end: Time,
    ) -> Result<Option<String>, String> {
        self.0.format_timespec_for_display(start, end)
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
        // the hunt's queue, ace3's `RootAnalysis.queue` (PLAN.md 7.13)
        queue: Some(submission.queue.clone()),
        // the links the hunt rendered for its alert, ace3's root pivot links (decision 32 part
        // (b)); one ace4 can't show (not https://, or an icon that isn't a name) is left out
        pivot_links: submission
            .pivot_links
            .iter()
            .take(ace_results::MAX_PIVOT_LINKS)
            .filter_map(|link| {
                let mut pivot = ace_results::PivotLink::new(link.url.clone(), link.text.clone());
                pivot.icon = link.icon.clone();
                match pivot.refusal() {
                    None => Some(pivot),
                    Some(why) => {
                        tracing::warn!("a hunt's pivot link is left out: {why}");
                        None
                    }
                }
            })
            .collect(),
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
            let (submission, origin) = to_core(s);
            Some(ace_service::GroupSuppressed {
                key: key.clone(),
                group_value: s.group_value.clone(),
                description: s.description.clone(),
                event_time: s.event_time,
                events: s.rows.len(),
                since,
                until,
                hit: ace_service::HuntSubmission {
                    submission,
                    origin,
                    dedup_key: s.key.clone(),
                    suppression_key: Some(key.clone()),
                    group_value: s.group_value.clone(),
                    events: s.rows.len(),
                },
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
        // only a grouped hunt's suppression is per group, which is what an SVS run keys
        suppression: config
            .group_by
            .as_ref()
            .and_then(|_| schedule::suppression(config)),
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

/// The hunt types `config`'s `rule_dirs` names that `app` doesn't have, whose hunts the hunter never
/// loads (`reload` takes only the binary's types), such as one a site's binary would add.
pub fn unknown_types<'c>(app: &App, config: &'c HunterConfig) -> Vec<&'c str> {
    let known: Vec<&str> = app.hunt_types().iter().map(|kind| kind.name()).collect();
    config
        .rule_dirs
        .keys()
        .map(String::as_str)
        .filter(|kind| !known.contains(kind))
        .collect()
}

async fn hunt(app: &App) -> Result<ExitCode> {
    use ace_core::db::{Db, DbConfig};

    let path =
        std::env::var_os("ACE4_HUNTER").context("ACE4_HUNTER names no hunter configuration")?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("{}", Path::new(&path).display()))?;
    let config: HunterConfig =
        serde_json::from_str(&text).context("reading the hunter's configuration")?;
    for kind in unknown_types(app, &config) {
        tracing::warn!(
            hunt_type = kind,
            "rule_dirs names a hunt type this binary doesn't have, so none of its hunts load"
        );
    }
    let overlay = crate::cli::overlay(app)?;
    // the secrets of the connections the command types, the hunt types' searches and the query
    // sources take, which run here, Splunk's instances among them, and no others
    let names = app.hunter_secret_names(&overlay);
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let secrets = ace_pool::secrets::resolve_names(
        "hunter",
        &names,
        &overlay,
        &ace_pool::secrets::process_env,
    );
    let mut command_types = app.command_types_for(&overlay, &secrets);
    app.build_hunt_scripts(&mut command_types, &net::net()?, &config.scripts)
        .map_err(anyhow::Error::msg)?;
    // a script's `files:` are read from the signatures checkout, as ace3 stages them from its hunt
    // repositories
    command_types
        .scripts_mut()
        .set_roots(vec![config.signatures.clone()]);
    let hunter = Arc::new(
        Hunter::for_app(config.clone(), &secrets, app, &overlay)?.with_command_types(command_types),
    );

    let db = Db::connect(&DbConfig::from_env("ace-hunter")?)
        .await
        .context("connecting to Postgres")?;
    let bucket = crate::cli::submitting_bucket(&db, "ace4-hunter-cache").await?;
    let service = crate::cli::submitting_service(app, &overlay, db)?;
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
                if tick.skipped.is_some() || tick.error.as_deref() == Some(STOPPED) {
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
        let kind: &dyn HuntType = kind.as_ref();
        let mut rows = Vec::new();
        let now = chrono::Utc::now();
        for loaded in hunter.load(kind) {
            // what SVS's run windows and results need of the file, loaded as a hunt or not (PLAN.md 7.10
            // batch 5): `ace serve` reads it from the row, since only this process has the hunt files
            let svs = ace_core::svs::windows::read_hunt_file(&loaded.path, now)
                .map(|info| ace_core::svs::windows::RecordedHunt::from(&info));
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
                        svs,
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
                        svs,
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
pub mod splunk;
#[cfg(test)]
mod tests;
