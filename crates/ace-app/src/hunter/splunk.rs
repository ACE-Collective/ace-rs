//! Splunk's hunt search and query source (PLAN.md 6.4, 6.6), on the path a site's hunt type takes
//! (decision 40): `ace_hunt::search::HuntSearch` and `ace_hunt::correlate::source::QuerySource`,
//! registered as every `App`'s built-in `splunk` types (`App::hunt_searches`,
//! `App::query_source_types`).
//!
//! What is Splunk's own is where they find their instances: the hunter configuration's `splunk:`,
//! ace3's global `splunk_config_<name>` sections, with ace3's secret names
//! (`splunk_<instance>_password`, `splunk_<instance>_token`), which the hunter resolves and hands
//! every setup as [`Instances`]. A process without them, such as `ace serve`, builds neither.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ace_hunt::Hunt;
use ace_hunt::correlate::source::QuerySource;
use ace_hunt::correlate::time::Time;
use ace_hunt::query::schedule::Window;
use ace_hunt::search::{BoxFuture, HuntSearch, Ran, STOPPED, SearchLimits, Searched, Stop};
use ace_hunt::splunk::{self, Instance};
use ace_mod_splunk::search::{Connection, Limits, SearchClient, SearchError};
use ace_sdk::Secrets;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Map as JsonMap, Value as Json};

use super::{Blocking, SearchSetup, SplunkInstance, secret_names};

/// One Splunk instance, ready to search.
pub(crate) struct Source {
    pub(crate) instance: Instance,
    client: Arc<SearchClient>,
    dispatch_timeout: Duration,
    user_context: Option<String>,
    app_context: Option<String>,
}

/// The hunter's Splunk instances, by name, and their credentials' text, which a correlation's
/// output is scrubbed of.
#[derive(Default)]
pub struct Instances {
    sources: BTreeMap<String, Source>,
    pub(crate) secrets: Vec<String>,
}

impl Instances {
    /// The instances of the hunter configuration's `splunk:`, each with its credentials of
    /// `secrets`.
    pub fn new(
        config: &BTreeMap<String, SplunkInstance>,
        secrets: &Secrets,
    ) -> anyhow::Result<Instances> {
        let mut sources = BTreeMap::new();
        let mut held = Vec::new();
        for (name, instance) in config {
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
        Ok(Instances {
            sources,
            secrets: held,
        })
    }

    /// The instances' names.
    pub fn names(&self) -> Vec<String> {
        self.sources.keys().cloned().collect()
    }
}

fn instances_of(setup: &SearchSetup) -> Result<Arc<Instances>, String> {
    setup
        .splunk
        .clone()
        .ok_or_else(|| "this process has no Splunk instances".to_owned())
}

/// Builds the `splunk` hunt type's search. It takes no settings.
pub(crate) fn build_search(setup: &SearchSetup) -> Result<Arc<dyn HuntSearch>, String> {
    if !matches!(setup.settings, None | Some(Json::Null)) {
        return Err(
            "the splunk search takes no settings; its instances are the hunter's splunk:"
                .to_owned(),
        );
    }
    Ok(Arc::new(SplunkSearch {
        instances: instances_of(setup)?,
    }))
}

/// ace3's `SplunkHunt`: a hunt's search on the instance its `splunk_config` names.
pub struct SplunkSearch {
    instances: Arc<Instances>,
}

impl HuntSearch for SplunkSearch {
    /// SplunkHunt's lookup of the instance a hunt names, which it fails without.
    fn on_load(&self, config: &ace_hunt::HuntConfig) -> Result<(), ace_hunt::HuntError> {
        use ace_hunt::HuntType;
        ace_hunt::types::Splunk {
            instances: Some(self.instances.names()),
        }
        .on_load(config)
    }

    fn search<'a>(
        &'a self,
        hunt: &'a Hunt,
        home: &'a Path,
        window: &'a Window,
        limits: SearchLimits,
        stop: Stop,
    ) -> BoxFuture<'a, Searched> {
        Box::pin(async move {
            let name = splunk::splunk_config(hunt);
            let Some(source) = self.instances.sources.get(name) else {
                return Searched::failed(format!("splunk config for {name} not found"));
            };
            let search = match splunk::query(hunt, home)
                .and_then(|q| splunk::search(hunt, &q, window.start, window.end, &source.instance))
            {
                Ok(search) => search,
                Err(e) => return Searched::failed(e),
            };
            let form = splunk::urlencode(&search.form);
            let rows = source
                .client
                .search(
                    splunk::user_context(hunt),
                    splunk::app_context(hunt),
                    &form,
                    Limits {
                        poll: limits.poll,
                        dispatch_timeout: source.dispatch_timeout,
                        query_timeout: limits.query_timeout,
                    },
                    stop,
                )
                .await
                .map_err(error_text);
            Searched {
                ran: Some(Ran {
                    query: search.query.clone(),
                    link: Some(search.link.clone()),
                    search_id: None,
                    tool_instance: source.instance.host.clone(),
                    sent: Some(Json::from(form)),
                }),
                rows,
            }
        })
    }

    /// `saq.splunk.extract_event_timestamp`: a row's `_time`, or the query's time.
    fn event_time(&self, row: &JsonMap<String, Json>, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        Some(splunk::event_time(row, now))
    }
}

fn error_text(error: SearchError) -> String {
    match error {
        SearchError::Stopped => STOPPED.to_owned(),
        other => other.to_string(),
    }
}

/// The `splunk` query source's settings, ace3's `SplunkQuerySource` kwargs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSettings {
    /// The Splunk instance, ace3's `config_name`.
    #[serde(default = "default_instance")]
    instance: String,
}

fn default_instance() -> String {
    "default".to_owned()
}

/// Builds a `splunk` query source on the instance its settings name.
pub(crate) fn build_source(setup: &SearchSetup) -> Result<Arc<dyn QuerySource>, String> {
    let settings: SourceSettings = serde_json::from_value(
        setup
            .settings
            .clone()
            .unwrap_or(Json::Object(JsonMap::new())),
    )
    .map_err(|e| format!("its settings: {e}"))?;
    let instances = instances_of(setup)?;
    let Some(splunk) = instances.sources.get(&settings.instance) else {
        return Err(format!("splunk config for {} not found", settings.instance));
    };
    Ok(Arc::new(SplunkQuery {
        client: splunk.client.clone(),
        timezone: splunk.instance.timezone,
        user_context: splunk.user_context.clone(),
        app_context: splunk.app_context.clone(),
        dispatch_timeout: splunk.dispatch_timeout,
        poll: setup.poll,
        blocking: setup.blocking(),
    }))
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
    blocking: Blocking,
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
        let stop = self.blocking.stop();
        self.blocking.run(async {
            self.client
                .search(
                    self.user_context.as_deref(),
                    self.app_context.as_deref(),
                    &form,
                    limits,
                    stop,
                )
                .await
                .map_err(error_text)
        })
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
