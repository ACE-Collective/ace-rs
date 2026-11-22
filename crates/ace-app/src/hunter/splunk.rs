//! Splunk's hunt search and query source (PLAN.md 6.4, 6.6), on the path a site's hunt type takes
//! (decision 40): `ace_hunt::search::HuntSearch` and `ace_hunt::correlate::source::QuerySource`,
//! registered as every `App`'s built-in `splunk` types (`App::hunt_searches`,
//! `App::query_source_types`).
//!
//! Their instances are the overlay's connections of type `splunk` (PLAN.md decision 41,
//! `ace_mod_splunk::connection`), ace3's global `splunk_config_<name>` sections, named as ace3 names
//! them and with ace3's secret names (`splunk_<instance>_password`, `splunk_<instance>_token`). The
//! search takes every instance by its name (`connection::BY_NAME`), since a hunt names its own in
//! `splunk_config`; a query source binds one to its slot `splunk` (`connection::SLOT`), as ace3's
//! source names one in `config_name`. `ace serve` builds a source with its instance's settings and
//! none of its secrets, to validate hunts.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ace_hunt::Hunt;
use ace_hunt::correlate::source::QuerySource;
use ace_hunt::correlate::time::Time;
use ace_hunt::query::schedule::Window;
use ace_hunt::search::{BoxFuture, HuntSearch, Ran, STOPPED, SearchLimits, Searched, Stop};
use ace_hunt::splunk::{self, Instance};
use ace_mod_splunk::connection;
use ace_mod_splunk::search::{Limits, SearchClient, SearchError};
use serde_json::{Map as JsonMap, Value as Json};

use super::{Blocking, SearchSetup};

/// One Splunk instance, ready to search.
pub(crate) struct Source {
    pub(crate) instance: Instance,
    client: Arc<SearchClient>,
    dispatch_timeout: Duration,
    user_context: Option<String>,
    app_context: Option<String>,
}

impl Source {
    /// The instance `connection`, with its secrets.
    fn of(connection: &ace_sdk::Connection) -> Result<Source, String> {
        let instance = connection::instance_of(connection)?;
        let timezone = instance
            .tz()
            .map_err(|e| format!("splunk instance {}: {e}", connection.name))?;
        let client = instance
            .client(connection)
            .map_err(|e| format!("splunk instance {}: {e}", connection.name))?;
        Ok(Source {
            instance: Instance {
                host: instance.host.clone(),
                timezone,
            },
            client: Arc::new(client),
            dispatch_timeout: Duration::from_secs(instance.dispatch_timeout_seconds),
            user_context: instance.user_context,
            app_context: instance.app_context,
        })
    }
}

/// The Splunk instances a hunt may name, by name: every connection of type `splunk`.
#[derive(Default)]
pub struct Instances {
    sources: BTreeMap<String, Source>,
}

impl Instances {
    /// The instances `setup`'s slot by name holds, each with its secrets.
    pub fn new(setup: &SearchSetup) -> Result<Instances, String> {
        let mut sources = BTreeMap::new();
        for connection in setup.connections.named(connection::BY_NAME.name) {
            sources.insert(connection.name.clone(), Source::of(connection)?);
        }
        Ok(Instances { sources })
    }

    /// The instances' names.
    pub fn names(&self) -> Vec<String> {
        self.sources.keys().cloned().collect()
    }
}

/// Builds the `splunk` hunt type's search over every Splunk instance. It takes no settings.
pub(crate) fn build_search(setup: &SearchSetup) -> Result<Arc<dyn HuntSearch>, String> {
    if !matches!(setup.settings, None | Some(Json::Null)) {
        return Err(
            "the splunk search takes no settings; its instances are the connections of type splunk"
                .to_owned(),
        );
    }
    Ok(Arc::new(SplunkSearch {
        instances: Arc::new(Instances::new(setup)?),
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
}

fn error_text(error: SearchError) -> String {
    match error {
        SearchError::Stopped => STOPPED.to_owned(),
        other => other.to_string(),
    }
}

/// Builds a `splunk` query source on the instance bound to its slot `splunk`, ace3's `config_name`.
/// It takes no settings.
pub(crate) fn build_source(setup: &SearchSetup) -> Result<Arc<dyn QuerySource>, String> {
    if !matches!(setup.settings, None | Some(Json::Null)) {
        return Err(format!(
            "the splunk query source takes no settings; bind its instance with connections: {{{}: <instance>}}",
            connection::SLOT.name
        ));
    }
    let Some(bound) = setup.connections.get(connection::SLOT.name) else {
        return Err(format!(
            "no Splunk instance is bound to its slot {}",
            connection::SLOT.name
        ));
    };
    let splunk = Source::of(bound)?;
    Ok(Arc::new(SplunkQuery {
        client: splunk.client,
        timezone: splunk.instance.timezone,
        user_context: splunk.user_context,
        app_context: splunk.app_context,
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
