//! The clicker detection module, a port of ace3's `SplunkClickerDetectionAnalyzer`
//! (`saq/modules/clicker_detection.py`) with the source-agnostic orchestration it mixes in
//! (`ClickerDetectionMixin`, `saq/clicker_detection/analyzer.py`) and the config it reads
//! (`saq/clicker_detection/config.py`).
//!
//! It answers "did anyone click this URL or visit this domain?" for a url or fqdn that carries the
//! `clicker_detection` directive, which an analyst's "Check for clickers" adds. Each search the
//! analysts configured for the source and the observable's type runs in turn, as its own Splunk job,
//! through the Splunk module's client (`Splunkd`) and its delay loop (PLAN.md 1.28): the module asks
//! for a delay while a job runs, and each run after reads its status once. The plan of searches is
//! fixed at the first run, as ace3 keeps it in the analysis's details, and the searches' state goes
//! from run to run in the delay's state. Past `query_timeout` from the first run, a search that
//! hasn't finished is `timed out` in the result's error, so silence doesn't read as "no clicks"; the
//! searches after it then time out too, as in ace3, whose clock is the analysis's.
//!
//! A search's rows become `clicker_events` and the observables its `observable_mapping` names. A
//! hit, a row whose `action_type` is one of `escalate_action_types` or any row with
//! `escalate_on_any`, adds the detection point `URL clicker identified via <search> (<users>)`
//! with ace3's `URL_CLICKER` signature when `add_detection_point`, and with `crawl_clicked_url`
//! adds the `crawl` directive to a URL, or the clicked URLs, uncrawled, to a domain.
//!
//! The config is ace3's `clicker_detection.yaml`, at `config_path`, read as PyYAML's `safe_load`
//! reads it and again whenever its modification time or size changes, as ace3's `watch_file` does.
//! A missing or unreadable file is no searches, which, as ace3's `custom_requirement`, skips the
//! observable.
//!
//! What isn't ported: urlfinderlib's child URLs. ace3 matches a URL and every child URL
//! urlfinderlib finds in it (a URL in its query, a base64 one, a Proofpoint or Mandrill wrapper);
//! here a URL matches itself alone, as a domain does in both. urlfinderlib's URL comes with 7.5's
//! `url_extraction`. A search's time ranges are around the observable's time, else the root's event
//! time (`Module::READS_EVENT_TIME`), else the first run's clock, as ace3's. Nor are `<O_TIMESPEC>`
//! (a time range around the observable's own time), `<O_VALUEn>` and `<observable.*>` tokens other
//! than `<observable.value>` and `<observable.type>`:
//! a search using one fails the task. ace3 also clears a skipped Phishkit analysis when it crawls,
//! which ace4 has no Phishkit for. `tests/clicker_differences.md` lists the rest.
//!
//! What doesn't depend on Splunk is public (PLAN.md decision 51), for a site's clicker on another
//! source, such as a LogScale one: the watched config ([`ClickerConfig`]), the searches that
//! apply ([`searches_for`]), the values a search matches ([`match_values`]), a time range's
//! durations ([`durations`]), what a search's rows add ([`collect`], into [`Findings`], with the
//! search's console link and each row's time from the caller) and the summary ([`summary_text`]).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use ace_results::types::splunk::{ClickerEvent, SplunkClickerDetectionAnalysis};
use ace_results::{Detection, NewObservable, ObservableKind, ResultEnvelope};
use ace_sdk::{Delay, Lookup, Manifest, Module, ModuleError, Outcome, Resources, TaskContext};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::mapping::{Mapping, ObservableMapping, add_observables, event_time, parse_timespec};
use crate::{Connection, Failure, Search, Splunkd, Step, connection};

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::lookup::<ClickerDetection>();

/// The directive an analyst's "Check for clickers" adds, which the module needs.
pub const DIRECTIVE: &str = "clicker_detection";
/// The directive a clicked URL gets, so it's crawled.
pub const CRAWL: &str = "crawl";
/// ace3's `URL_CLICKER` built-in signature.
pub const URL_CLICKER: &str = "a764126b-443d-4991-a554-72d86125382d";

/// The module's settings: ace3's `analysis_module_clicker_detection_splunk` with the
/// `api_query_defaults` it falls back on.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ClickerSettings {
    /// The Splunk instance, from the connection bound to the slot `splunk` (ace3's `api_name`):
    /// its timezone is what a search's time range is written in, and the web links go to its host
    /// on HTTPS's port, as ace3's do.
    pub splunk: connection::Instance,
    /// The namespace, where the instance names none, as the Splunk module's.
    pub user_context: Option<String>,
    pub app_context: Option<String>,
    pub question: String,
    pub summary: String,
    /// The top-level key of the clicker config holding this module's searches.
    pub source: String,
    /// ace3's `clicker_detection.yaml`. None is no searches.
    pub config_path: Option<PathBuf>,
    pub max_result_count: u64,
    /// Seconds from the first run after which a search that hasn't finished has timed out.
    pub query_timeout: u64,
    /// Seconds between two reads of a running job's status.
    pub async_delay: u64,
    /// How long to wait before the first search, in ace3's `DD:HH:MM:SS` form.
    pub correlation_delay: Option<String>,
}

impl Default for ClickerSettings {
    /// ace3's section and `api_query_defaults_default`, on the default instance's settings.
    fn default() -> Self {
        ClickerSettings {
            splunk: connection::Instance::default(),
            user_context: None,
            app_context: None,
            question: "Did anyone click this URL or visit this domain?".to_owned(),
            summary: "URL Clicks".to_owned(),
            source: "splunk".to_owned(),
            config_path: None,
            max_result_count: 1000,
            query_timeout: 300,
            async_delay: 1,
            correlation_delay: None,
        }
    }
}

/// The config file as it was last read, with what identifies that version of it.
#[derive(Default)]
struct Loaded {
    version: Option<(SystemTime, u64)>,
    config: Option<Yaml>,
}

/// A value of the config, as PyYAML loads it, its mappings in the file's order.
pub type Yaml = ace_hunt::value::Value;

/// ace3's clicker config file, read again whenever its modification time or size changes, as
/// ace3's `watch_file` does.
#[derive(Default)]
pub struct ClickerConfig {
    loaded: Mutex<Loaded>,
}

impl ClickerConfig {
    pub fn new() -> ClickerConfig {
        ClickerConfig::default()
    }

    /// The config at `path`, read as PyYAML's `safe_load` reads it, again when the file changed.
    /// None, a missing file or one that doesn't load is no config, which is no searches.
    pub fn get(&self, path: Option<&Path>) -> Option<Yaml> {
        let path = path?;
        let version = std::fs::metadata(path)
            .ok()
            .map(|m| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()));
        let mut loaded = self.loaded.lock().ok()?;
        if loaded.version.is_some() && loaded.version == version {
            return loaded.config.clone();
        }
        let config = match std::fs::read_to_string(path) {
            Ok(text) => {
                let mut budget = ace_hunt::yaml::Budget::new(ace_hunt::yaml::Limits::default());
                match ace_hunt::yaml::load(&text, &path.display().to_string(), &mut budget) {
                    Ok(value) => Some(value),
                    Err(e) => {
                        tracing::warn!(
                            "failed to load clicker detection config {}: {e:?}",
                            path.display()
                        );
                        None
                    }
                }
            }
            Err(e) => {
                tracing::debug!(
                    "clicker detection config not found: {}: {e}",
                    path.display()
                );
                None
            }
        };
        loaded.version = version;
        loaded.config = config.clone();
        config
    }
}

/// The clicker detection module.
pub struct ClickerDetection {
    splunkd: Splunkd,
    tz: chrono_tz::Tz,
    /// The web links. host: the instance.s.
    host: String,
    correlation_delay: Option<Duration>,
    config: ClickerConfig,
}

impl Module for ClickerDetection {
    const NAME: &'static str = "clicker_detection_splunk";
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Url, ObservableKind::Fqdn];
    /// Its searches' time ranges are around the root's event time when the observable has no time
    /// of its own.
    const READS_EVENT_TIME: bool = true;
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &[DIRECTIVE];
    const CONNECTIONS: &'static [ace_sdk::ConnectionSlot] = &[connection::SLOT];
    /// ace3 ships it disabled, with no searches.
    const ENABLED_BY_DEFAULT: bool = false;
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(120),
        ..Resources::DEFAULT
    };
    type Output = SplunkClickerDetectionAnalysis;
    type Settings = ClickerSettings;

    fn init(settings: &ClickerSettings) -> Result<Self, ModuleError> {
        let splunkd = Splunkd::new(&Connection {
            instance: &settings.splunk,
            user_context: settings.user_context.as_deref(),
            app_context: settings.app_context.as_deref(),
            max_result_count: settings.max_result_count,
        })?;
        let tz = settings.splunk.tz().map_err(ModuleError::other)?;
        let host = settings.splunk.host.clone();
        let correlation_delay = settings
            .correlation_delay
            .as_deref()
            .map(parse_timespec)
            .transpose()
            .map_err(ModuleError::other)?;
        Ok(ClickerDetection {
            splunkd,
            tz,
            host,
            correlation_delay,
            config: ClickerConfig::new(),
        })
    }
}

/// The app searches run in, which the web links name: the instance's, else the module's, as
/// ace3's client takes it.
fn app_context(settings: &ClickerSettings) -> Option<&str> {
    settings
        .splunk
        .app_context
        .as_deref()
        .or(settings.app_context.as_deref())
}

/// What the searches found so far: their events, the observables their rows and clicks add, the
/// detections their hits raise, and whether a hit crawls the URL.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Findings {
    pub events: Vec<ClickerEvent>,
    pub observables: Vec<NewObservable>,
    pub detections: Vec<Detection>,
    pub crawl: bool,
}

/// What the runs before this one left, as ace3 keeps it in the analysis's details.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Progress {
    plan: Vec<String>,
    index: usize,
    error: Option<String>,
    gui_link: Option<String>,
    #[serde(flatten)]
    found: Findings,
    /// The job of the search running now.
    job: Option<Search>,
    /// Waiting out `correlation_delay`.
    waiting: bool,
    /// What the time ranges are around: the observable's time, else the root's event time, else
    /// the first run's, as ace3's `build_target_query` picks it, so every run of every search has
    /// the same window.
    anchor: Option<DateTime<Utc>>,
}

/// One search of the config, as `get_searches_for` lists it.
pub type SearchDef = Map<String, Value>;

/// `get_searches_for`: every enabled search of `source` whose `observable_types` has the type, in
/// the config's order.
pub fn searches_for(config: Option<&Yaml>, source: &str, kind: &str) -> Vec<(String, SearchDef)> {
    let Some(Yaml::Map(config)) = config else {
        return Vec::new();
    };
    let Some(Yaml::Map(source)) = config.get(source) else {
        return Vec::new();
    };
    if !truthy(source.get("enabled").map(Yaml::to_json).as_ref()) {
        return Vec::new();
    }
    let Some(Yaml::Map(searches)) = source.get("searches") else {
        return Vec::new();
    };
    searches
        .iter()
        .filter_map(|(name, def)| {
            let Yaml::Map(_) = def else {
                return None;
            };
            let def = def.to_json().as_object()?.clone();
            let types = def.get("observable_types").and_then(Value::as_array)?;
            types
                .iter()
                .any(|t| t.as_str() == Some(kind))
                .then(|| (name.key_text(), def.clone()))
        })
        .collect()
}

/// Python's truth of a YAML value.
pub fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

/// The searches' value escaping, `SplunkAPIAnalyzer._escape_value`.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\'', "\\'")
}

/// `splunk_value_expansion`: the values as a quoted OR-group.
fn value_clause(values: &[String]) -> String {
    let quoted: Vec<String> = values
        .iter()
        .map(|v| format!("\"{}\"", escape(v)))
        .collect();
    format!("({})", quoted.join(" OR "))
}

/// Python's `urllib.parse.quote(value, safe="")`.
pub fn quote_all(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(char::from(b))
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `clicker_match_values`: the values a search matches, with their percent-encoded forms after
/// them when it sets `match_url_encoded`. A URL's child URLs aren't found (the module's docs).
pub fn match_values(value: &str, def: &SearchDef) -> Vec<String> {
    let values = vec![value.to_owned()];
    if !truthy(def.get("match_url_encoded")) {
        return values;
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for v in values
        .iter()
        .cloned()
        .chain(values.iter().map(|v| quote_all(v)))
    {
        if seen.insert(v.clone()) {
            out.push(v);
        }
    }
    out
}

/// A time range's two durations, as `_prepare_search` reads `time_ranges`: a mapping with
/// `duration_before` and `duration_after`, or a bare `duration_before`.
pub fn durations(range: &Value) -> Result<(Duration, Duration), ModuleError> {
    let read = |v: Option<&Value>| -> Result<Duration, ModuleError> {
        match v {
            Some(Value::String(s)) if !s.is_empty() => {
                parse_timespec(s).map_err(ModuleError::other)
            }
            Some(Value::Number(n)) => parse_timespec(&n.to_string()).map_err(ModuleError::other),
            _ => Ok(Duration::ZERO),
        }
    };
    match range {
        Value::Object(o) => Ok((
            read(o.get("duration_before"))?,
            read(o.get("duration_after"))?,
        )),
        other => Ok((read(Some(other))?, Duration::ZERO)),
    }
}

impl ClickerDetection {
    /// `_prepare_search` and `build_target_query`: the search with its values, its type and its
    /// time ranges filled in.
    fn query(
        &self,
        ctx: &TaskContext<ClickerSettings>,
        def: &SearchDef,
        anchor: DateTime<Utc>,
    ) -> Result<String, ModuleError> {
        let observable = ctx.observable();
        let Some(base) = def.get("query").and_then(Value::as_str) else {
            return Err(ModuleError::other("a clicker search has no query"));
        };
        let values = match_values(&observable.value, def);
        let mut query = base.replace("<O_VALUE>", &value_clause(&values));
        query = query.replace("<O_TYPE>", observable.kind.as_str());
        query = query.replace("<observable.value>", &escape(&observable.value));
        query = query.replace("<observable.type>", &escape(observable.kind.as_str()));
        for token in ["<O_TIMESPEC>", "<observable.", "<O_VALUE"] {
            if query.contains(token) {
                return Err(ModuleError::other(format!(
                    "the clicker search uses {token}..., which the module doesn't fill"
                )));
            }
        }
        let use_index_time = truthy(def.get("use_index_time"));
        if let Some(ranges) = def.get("time_ranges").and_then(Value::as_object) {
            for (token, range) in ranges {
                let spec =
                    crate::mapping::time_spec(anchor, durations(range)?, self.tz, use_index_time)
                        .map_err(ModuleError::other)?;
                query = query.replace(&format!("<{token}>"), &spec);
            }
        }
        Ok(query)
    }

    /// `encoded_query_link(target_query)`: a Splunk web link with the query and no time range.
    fn link(&self, query: &str, app: Option<&str>) -> String {
        let mut query = ace_hunt::splunk::strip_comments(query);
        if !query.starts_with('|') && !query.trim_start().to_lowercase().starts_with("search") {
            query = format!("search {query}");
        }
        let path = match app {
            None | Some("-") => "en-US/app/search/search".to_owned(),
            Some(app) => format!("en-US/app/{app}/search"),
        };
        format!(
            "https://{}/{path}?{}",
            self.host,
            ace_hunt::splunk::urlencode(&[("q", query.as_str())])
        )
    }

    fn delay(
        &self,
        settings: &ClickerSettings,
        run_after: Duration,
        progress: &Progress,
    ) -> Result<Outcome<SplunkClickerDetectionAnalysis>, ModuleError> {
        let timeout = Duration::from_secs(
            settings
                .query_timeout
                .saturating_add(settings.async_delay)
                .saturating_add(60),
        )
        .saturating_add(self.correlation_delay.unwrap_or_default());
        Ok(Outcome::Delay(
            Delay::new(run_after, timeout).with_state(progress)?,
        ))
    }
}

/// A row's field as `event_mapping` maps it, or null.
fn mapped(row: &Map<String, Value>, mapping: Option<&Map<String, Value>>, key: &str) -> Value {
    mapping
        .and_then(|m| m.get(key))
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .and_then(|field| row.get(field))
        .cloned()
        .unwrap_or(Value::Null)
}

impl Lookup for ClickerDetection {
    const TCP_PORTS: &'static [u16] = &[8089, 443];

    async fn analyze(
        &self,
        ctx: &TaskContext<ClickerSettings>,
    ) -> Result<Outcome<SplunkClickerDetectionAnalysis>, ModuleError> {
        let settings = ctx.settings();
        let observable = ctx.observable();
        let kind = observable.kind.as_str();
        let config = self.config.get(settings.config_path.as_deref());
        let now = ctx.now();
        let started = ctx.delayed().map_or(now, |d| d.first_delayed_at);
        let elapsed = (now - started).to_std().unwrap_or_default();

        let mut progress = match ctx.delay_state::<Progress>()? {
            Some(progress) => progress,
            None => {
                // custom_requirement: nothing to do without a search for this source and type
                let plan: Vec<String> = searches_for(config.as_ref(), &settings.source, kind)
                    .into_iter()
                    .map(|(name, _)| name)
                    .collect();
                if plan.is_empty() {
                    return Ok(Outcome::Skipped(format!(
                        "the clicker config has no enabled {} search for {kind}",
                        settings.source
                    )));
                }
                // ace3's `source_event_time or observable.time or get_root().event_time`, and its
                // clock, with an error, when there is neither
                let anchor = observable.time.or(ctx.event_time()).unwrap_or_else(|| {
                    tracing::error!(
                        root = %ctx.root(),
                        observable = %observable,
                        "event_time is None! Using current time for TIMESPEC tokens instead"
                    );
                    now
                });
                let progress = Progress {
                    plan,
                    anchor: Some(anchor),
                    ..Progress::default()
                };
                if let Some(wait) = self.correlation_delay {
                    let progress = Progress {
                        waiting: true,
                        ..progress
                    };
                    return self.delay(settings, wait, &progress);
                }
                progress
            }
        };
        progress.waiting = false;

        while progress.index < progress.plan.len() {
            let name = progress.plan[progress.index].clone();
            let searches = searches_for(config.as_ref(), &settings.source, kind);
            let Some((_, def)) = searches.into_iter().find(|(n, _)| *n == name) else {
                // removed from the config while it was planned
                progress.job = None;
                progress.index += 1;
                continue;
            };
            let anchor = progress.anchor.unwrap_or(started);
            let query = self.query(ctx, &def, anchor)?;
            progress.gui_link = Some(self.link(&query, app_context(settings)));
            let mut job = progress.job.take().unwrap_or_else(|| Search {
                query: query.clone(),
                ..Search::default()
            });
            let ended = match self.splunkd.step(ctx, &mut job).await {
                Ok(Step::Waiting) if elapsed < Duration::from_secs(settings.query_timeout) => {
                    progress.job = Some(job);
                    return self.delay(
                        settings,
                        Duration::from_secs(settings.async_delay),
                        &progress,
                    );
                }
                Ok(Step::Waiting) => {
                    tracing::warn!("{} clicker search {name} timed out", settings.source);
                    Err("timed out".to_owned())
                }
                Ok(Step::Rows(rows)) => Ok(rows),
                Err(Failure::Task(error)) => return Err(error),
                Err(Failure::Search(error)) => {
                    tracing::error!(
                        "{} clicker search {name} failed for {}: {error}",
                        settings.source,
                        observable.value
                    );
                    self.splunkd.delete_search(ctx, &job).await;
                    Err(format!("HTTP 500: Splunk search failed: {error}"))
                }
            };
            match ended {
                Err(error) => {
                    let previous = progress
                        .error
                        .as_deref()
                        .map(|e| format!("{e}; "))
                        .unwrap_or_default();
                    progress.error = Some(format!("{previous}{name}: {error}"));
                }
                Ok(rows) => {
                    let portal_url = Some(self.link(&query, app_context(settings)));
                    collect(
                        &mut progress.found,
                        Clicked {
                            kind: observable.kind,
                            value: &observable.value,
                            source: &settings.source,
                            name: &name,
                            portal_url,
                        },
                        &def,
                        &rows,
                        &|row| event_time(row, now),
                    )?;
                }
            }
            progress.index += 1;
        }

        let details = SplunkClickerDetectionAnalysis {
            query: None,
            query_results: None,
            question: Some(settings.question.clone()),
            query_summary: Some(settings.summary.clone()),
            query_start: Some(
                started.timestamp() as f64 + f64::from(started.timestamp_subsec_micros()) / 1e6,
            ),
            gui_link: progress.gui_link.clone(),
            gui_link_label: progress
                .gui_link
                .as_ref()
                .map(|_| format!("Open in {}", capitalize(&settings.source))),
            search_id: None,
            dispatch_state: None,
            start_time: None,
            running_start_time: None,
            end_time: None,
            clicker_plan: Some(progress.plan.clone()),
            clicker_index: Some(progress.index),
            clicker_source: Some(settings.source.clone()),
            clicker_events: Some(progress.found.events.clone()),
            matched_url_count: Some(1),
        };
        let summary = summary(&details, progress.error.as_deref());
        let mut result = ResultEnvelope::new(details);
        result.summary = Some(summary);
        // a search that never answered: the clicks the others found are kept beside it
        result.error = progress.error.clone().filter(|e| !e.trim().is_empty());
        result.observables = progress.found.observables;
        result.detections = progress.found.detections;
        if progress.found.crawl {
            result.analyzed.directives.push(CRAWL.to_owned());
        }
        Ok(Outcome::Done(result))
    }
}

/// Which search's rows `collect` reads: the observable searched for, the source and the search's
/// name (an event's `source` is `<source>:<name>`), and the search's console link, each event's
/// `portal_url`.
pub struct Clicked<'a> {
    pub kind: ObservableKind,
    pub value: &'a str,
    pub source: &'a str,
    pub name: &'a str,
    pub portal_url: Option<String>,
}

/// `_collect_search_events`, with the rows' observables: what one search's rows add to `found`. A
/// mapping with `time: true` gives its observables `row_time` of their row, the row's event time as
/// the source reads it.
pub fn collect(
    found: &mut Findings,
    clicked: Clicked<'_>,
    def: &SearchDef,
    rows: &[Map<String, Value>],
    row_time: &dyn Fn(&Map<String, Value>) -> DateTime<Utc>,
) -> Result<(), ModuleError> {
    let Clicked {
        kind,
        value,
        source,
        name,
        portal_url,
    } = clicked;
    // extract_result_observables, with this search's mappings
    let specs: Vec<ObservableMapping> = match def.get("observable_mapping") {
        Some(Value::Array(_)) => serde_json::from_value(def["observable_mapping"].clone())
            .map_err(|e| ModuleError::other(format!("search {name}'s observable_mapping: {e}")))?,
        _ => Vec::new(),
    };
    let mappings = specs
        .iter()
        .map(Mapping::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ModuleError::other)?;
    for row in rows {
        add_observables(row, &mappings, &[], row_time(row), &mut found.observables);
    }

    let event_mapping = def.get("event_mapping").and_then(Value::as_object);
    let source = format!("{source}:{name}");
    let events: Vec<ClickerEvent> = rows
        .iter()
        .map(|row| ClickerEvent {
            source: source.clone(),
            portal_url: portal_url.clone(),
            timestamp: mapped(row, event_mapping, "timestamp"),
            user: mapped(row, event_mapping, "user"),
            action_type: mapped(row, event_mapping, "action_type"),
            url: mapped(row, event_mapping, "url"),
            searched_value: value.to_owned(),
            network_message_id: mapped(row, event_mapping, "network_message_id"),
        })
        .collect();
    found.events.extend(events.iter().cloned());

    let on_hit = def.get("on_hit").and_then(Value::as_object);
    let flag = |key: &str| truthy(on_hit.and_then(|o| o.get(key)));
    let hits: Vec<&ClickerEvent> = if flag("escalate_on_any") {
        events.iter().collect()
    } else {
        let wanted: Vec<&Value> = on_hit
            .and_then(|o| o.get("escalate_action_types"))
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        events
            .iter()
            .filter(|e| wanted.contains(&&e.action_type))
            .collect()
    };
    if hits.is_empty() {
        return Ok(());
    }
    if flag("add_detection_point") {
        // a multivalue user field gives each of its users; ace3's set of them can't hold the list
        // and raises (tests/clicker_differences.md)
        let users: BTreeSet<String> = hits
            .iter()
            .flat_map(|e| match &e.user {
                Value::String(u) => vec![u.clone()],
                Value::Array(us) => us
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                _ => Vec::new(),
            })
            .filter(|u| !u.is_empty())
            .collect();
        let who = if users.is_empty() {
            "unknown user".to_owned()
        } else {
            users.into_iter().collect::<Vec<_>>().join(", ")
        };
        let mut detection = Detection::new(format!("URL clicker identified via {name} ({who})"));
        detection.signature_uuid = Some(URL_CLICKER.to_owned());
        found.detections.push(detection);
    }
    if flag("crawl_clicked_url") {
        if kind.is_subtype_of(ObservableKind::Url) {
            found.crawl = true;
        } else {
            // a busy domain's clicked URLs would flood the crawler, so they're added uncrawled
            let mut seen = BTreeSet::new();
            for url in hits.iter().filter_map(|e| e.url.as_str()) {
                if url.is_empty() || !seen.insert(url.to_owned()) {
                    continue;
                }
                let added = NewObservable::new(ObservableKind::Url, url);
                if !found
                    .observables
                    .iter()
                    .any(|o| o.kind == added.kind && o.value == added.value)
                {
                    found.observables.push(added);
                }
            }
        }
    }
    Ok(())
}

/// Python's `str.capitalize`.
pub fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect(),
        None => String::new(),
    }
}

/// `ClickerDetectionAnalysisMixin.generate_summary`, with the result's error.
fn summary(details: &SplunkClickerDetectionAnalysis, error: Option<&str>) -> String {
    summary_text(
        details.query_summary.as_deref(),
        details.clicker_source.as_deref(),
        details.clicker_events.as_ref().map_or(0, Vec::len),
        error,
    )
}

/// `ClickerDetectionAnalysisMixin.generate_summary` over a clicker result's summary, source and
/// count of events, with its error: `URL Clicks (Splunk): 2 clicks found, ERROR: ...`.
pub fn summary_text(
    query_summary: Option<&str>,
    source: Option<&str>,
    count: usize,
    error: Option<&str>,
) -> String {
    let mut label = query_summary
        .filter(|s| !s.is_empty())
        .unwrap_or("URL Clicks")
        .to_owned();
    if let Some(source) = source.filter(|s| !s.is_empty()) {
        label = format!("{label} ({})", capitalize(source));
    }
    let found = match count {
        0 => "no clicks found".to_owned(),
        1 => "1 click found".to_owned(),
        n => format!("{n} clicks found"),
    };
    match error.filter(|e| !e.is_empty()) {
        Some(error) => {
            let prefix = if count > 0 {
                format!("{found}, ")
            } else {
                String::new()
            };
            format!("{label}: {prefix}ERROR: {error}")
        }
        None => format!("{label}: {found}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn searches_apply_by_source_type_and_enabled() {
        let yaml = |text: &str| {
            let mut budget = ace_hunt::yaml::Budget::new(ace_hunt::yaml::Limits::default());
            ace_hunt::yaml::load(text, "test", &mut budget).expect("loads")
        };
        let config = yaml(
            "splunk:\n  enabled: yes\n  searches:\n    z: {observable_types: [url, fqdn], query: x}\n    \
             b: {observable_types: [fqdn], query: y}\n    c: not a mapping\n\
             logscale: {enabled: true, searches: {d: {observable_types: [url]}}}\n",
        );
        let names = |kind| {
            searches_for(Some(&config), "splunk", kind)
                .into_iter()
                .map(|(n, _)| n)
                .collect::<Vec<_>>()
        };
        assert_eq!(names("url"), ["z"]);
        // in the file's order
        assert_eq!(names("fqdn"), ["z", "b"]);
        let off = yaml("splunk: {enabled: false, searches: {a: {observable_types: [url]}}}");
        assert!(searches_for(Some(&off), "splunk", "url").is_empty());
        assert!(searches_for(None, "splunk", "url").is_empty());
    }

    #[test]
    fn values_are_quoted_escaped_and_encoded_as_ace3_does() {
        let def = json!({"match_url_encoded": true})
            .as_object()
            .cloned()
            .expect("a map");
        let values = match_values("https://a.example/x?q=\"1\"", &def);
        assert_eq!(
            values,
            [
                "https://a.example/x?q=\"1\"",
                "https%3A%2F%2Fa.example%2Fx%3Fq%3D%221%22"
            ]
        );
        assert_eq!(
            value_clause(&values),
            "(\"https://a.example/x?q=\\\"1\\\"\" OR \"https%3A%2F%2Fa.example%2Fx%3Fq%3D%221%22\")"
        );
    }

    #[test]
    fn the_summary_counts_clicks_and_keeps_errors_beside_them() {
        let mut details = SplunkClickerDetectionAnalysis {
            query_summary: Some("URL Clicks".into()),
            clicker_source: Some("splunk".into()),
            clicker_events: Some(vec![ClickerEvent::default()]),
            ..SplunkClickerDetectionAnalysis::default()
        };
        assert_eq!(
            summary(&details, None),
            "URL Clicks (Splunk): 1 click found"
        );
        let error = Some("proxy: timed out");
        assert_eq!(
            summary(&details, error),
            "URL Clicks (Splunk): 1 click found, ERROR: proxy: timed out"
        );
        details.clicker_events = Some(vec![]);
        assert_eq!(
            summary(&details, error),
            "URL Clicks (Splunk): ERROR: proxy: timed out"
        );
    }
}
