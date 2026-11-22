//! The example site's hunt type and query source (PLAN.md decision 40): its hunts search its ticket
//! system, as a site's integration adds a hunt type for its own data source (a site's LogScale).
//!
//! - **The hunt type** `example_tickets` ([`TicketHunts`]): a hunt names the ticket `queue` it
//!   searches, and may name the ticket field its event time is read from (`timestamp_field`, by
//!   default `opened`), beside every query hunt's fields. Each ticket's `timestamp_field` is its
//!   event's time, as a site's mail_filter hunts read theirs, and the type reads it
//!   (`HuntType::event_time`, PLAN.md decision 43), so a validation run through `ace serve` times
//!   the tickets it is sent as `ace hunter` times those a search finds. Its search
//!   ([`TicketSearch`], `App::hunt_search`) asks the ticket system for the queue's tickets matching
//!   the hunt's query in the window. It reaches the system through the site's shared
//!   connection `example_ticket_system` in its slot `tickets`, which the overlay's
//!   `hunt_types.example_tickets.connections` binds, so only `ace hunter` holds the token.
//! - **The query source type** `example_tickets` ([`TicketSource`], `App::query_source_type`): a
//!   correlation's `source:` names an entry of the overlay's `query_sources:` of this type, whose
//!   settings name its queue and whose connection is the same system's.
//!
//! The ticket system's API, which the tests replay: `GET <url>/api/tickets/search` with `q` (the
//! query), `queue`, and `from` and `to` (the window, in epoch milliseconds), and the token as a
//! bearer token, answers `{"tickets": [...]}`, each ticket an object.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ace_app::hunter::{Blocking, SearchSetup};
use ace_hunt::correlate::source::QuerySource;
use ace_hunt::correlate::time::Time;
use ace_hunt::query::schedule::Window;
use ace_hunt::search::{BoxFuture, HuntSearch, Ran, STOPPED, SearchLimits, Searched, Stop};
use ace_hunt::validate::{Errors, Obj, string};
use ace_hunt::{Hunt, HuntConfig, HuntError, HuntType};
use ace_sdk::http::HttpClient;
use chrono::{DateTime, Utc};
use serde_json::{Map as JsonMap, Value as Json};

use crate::{TICKETS, TicketSystem, TicketSystemSettings};

/// The hunt type's name, and the query source type's.
pub const TICKET_HUNTS: &str = "example_tickets";

/// The most tickets one search reads.
pub const MAX_TICKETS: usize = 10_000;
/// The most bytes of one answer.
pub const MAX_ANSWER: usize = 16 << 20;

/// What a hunt of the type adds to a query hunt: the queue it searches, and the ticket field its
/// event time is read from.
#[derive(Debug, Clone, Default)]
pub struct TicketHunts;

/// The ticket field a hunt reads its event time from when it names none.
pub const DEFAULT_TIMESTAMP_FIELD: &str = "opened";

impl HuntType for TicketHunts {
    fn name(&self) -> &str {
        TICKET_HUNTS
    }

    fn model(&self) -> &str {
        "ExampleTicketHuntConfig"
    }

    fn settings(
        &self,
        o: &mut Obj<'_>,
        errs: &mut Errors,
    ) -> Result<Option<JsonMap<String, Json>>, HuntError> {
        let queue = o.required(errs, "queue", string)?;
        let field = o.default(
            errs,
            "timestamp_field",
            DEFAULT_TIMESTAMP_FIELD.to_owned(),
            string,
        )?;
        Ok(queue.zip(field).map(|(queue, field)| {
            JsonMap::from_iter([
                ("queue".to_owned(), Json::String(queue)),
                ("timestamp_field".to_owned(), Json::String(field)),
            ])
        }))
    }

    /// The ticket's time in the hunt's `timestamp_field`.
    fn event_time(
        &self,
        hunt: &HuntConfig,
        row: &JsonMap<String, Json>,
        _now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let field = hunt
            .settings
            .get("timestamp_field")
            .and_then(Json::as_str)
            .unwrap_or(DEFAULT_TIMESTAMP_FIELD);
        time_of(row, field)
    }
}

/// The slots the search and the source take.
pub const SLOTS: &[ace_sdk::ConnectionSlot] = &[TICKETS];

/// One ticket system, ready to search.
struct Client {
    settings: TicketSystemSettings,
    http: HttpClient,
    token: Option<String>,
}

impl Client {
    /// The client of the connection a setup binds to `tickets`: its settings, and its token when
    /// the process holds it.
    fn of(setup: &SearchSetup) -> Result<Client, String> {
        let settings = setup
            .connections
            .settings::<TicketSystem>(TICKETS.name)
            .map_err(|e| format!("{TICKET_HUNTS}: {e}"))?;
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(settings.request_timeout_seconds))
            .build()
            .map_err(|e| e.to_string())?;
        let token = setup
            .connections
            .secret(TICKETS.name, "token")
            .map(|t| t.expose().to_owned());
        Ok(Client {
            settings,
            http,
            token,
        })
    }

    fn search_url(
        &self,
        query: &str,
        queue: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> String {
        let pairs = [
            ("q", query.to_owned()),
            ("queue", queue.to_owned()),
            ("from", start.timestamp_millis().to_string()),
            ("to", end.timestamp_millis().to_string()),
        ];
        format!(
            "{}/api/tickets/search?{}",
            self.settings.url.trim_end_matches('/'),
            ace_hunt::splunk::urlencode(&pairs)
        )
    }

    /// The queue's tickets matching `query` from `start` to `end`.
    async fn tickets(&self, url: &str) -> Result<Vec<JsonMap<String, Json>>, String> {
        let token = self
            .token
            .as_deref()
            .ok_or_else(|| "the ticket system's token isn't held here".to_owned())?;
        let request = self
            .http
            .get(url)
            .header("Authorization", format!("Bearer {token}"));
        let response = self.http.send(request).await.map_err(|e| e.to_string())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!(
                "the ticket system answered HTTP {}",
                status.as_u16()
            ));
        }
        let bytes = response.bytes().await.map_err(|e| e.to_string())?;
        if bytes.len() > MAX_ANSWER {
            return Err(format!(
                "the ticket system's answer is over {MAX_ANSWER} bytes"
            ));
        }
        let body: Json = serde_json::from_slice(&bytes).map_err(|e| format!("its answer: {e}"))?;
        let tickets = body
            .get("tickets")
            .and_then(Json::as_array)
            .ok_or_else(|| "its answer has no tickets".to_owned())?;
        if tickets.len() > MAX_TICKETS {
            return Err(format!("the search found over {MAX_TICKETS} tickets"));
        }
        Ok(tickets
            .iter()
            .filter_map(|t| t.as_object().cloned())
            .collect())
    }
}

/// The ticket hunts' search.
pub struct TicketSearch {
    client: Client,
}

/// Builds the search from its setup (`App::hunt_search`).
pub fn build_search(setup: &SearchSetup) -> Result<Arc<dyn HuntSearch>, String> {
    Ok(Arc::new(TicketSearch {
        client: Client::of(setup)?,
    }))
}

/// A ticket's time in `field`, when it reads.
fn time_of(row: &JsonMap<String, Json>, field: &str) -> Option<DateTime<Utc>> {
    row.get(field)
        .and_then(Json::as_str)
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&Utc))
}

impl HuntSearch for TicketSearch {
    fn search<'a>(
        &'a self,
        hunt: &'a Hunt,
        _home: &'a Path,
        window: &'a Window,
        limits: SearchLimits,
        stop: Stop,
    ) -> BoxFuture<'a, Searched> {
        Box::pin(async move {
            let config = &hunt.config;
            let query = match ace_hunt::search::query(hunt) {
                Ok(query) => query,
                Err(e) => return Searched::failed(e),
            };
            let queue = config
                .settings
                .get("queue")
                .and_then(Json::as_str)
                .unwrap_or_default();
            let url = self
                .client
                .search_url(&query, queue, window.start, window.end);
            let ran = Ran {
                query: query.clone(),
                link: Some(format!(
                    "{}/search?{}",
                    self.client.settings.url.trim_end_matches('/'),
                    ace_hunt::splunk::urlencode(&[("q", query.as_str()), ("queue", queue)])
                )),
                search_id: None,
                tool_instance: self.client.settings.url.clone(),
                sent: Some(Json::String(url.clone())),
            };
            let rows = tokio::select! {
                rows = tokio::time::timeout(limits.query_timeout, self.client.tickets(&url)) => {
                    rows.unwrap_or_else(|_| Err(format!("the ticket search ran past its {:?}", limits.query_timeout)))
                }
                () = stop => Err(STOPPED.to_owned()),
            };
            Searched {
                ran: Some(ran),
                rows,
            }
        })
    }
}

/// A ticket query source's settings: the queue it searches.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSettings {
    queue: String,
}

/// The ticket query source.
pub struct TicketSource {
    client: Client,
    queue: String,
    blocking: Blocking,
}

/// Builds a source from its setup (`App::query_source_type`).
pub fn build_source(setup: &SearchSetup) -> Result<Arc<dyn QuerySource>, String> {
    let settings: SourceSettings =
        serde_json::from_value(setup.settings.clone().unwrap_or(Json::Null))
            .map_err(|e| format!("its settings: {e}"))?;
    Ok(Arc::new(TicketSource {
        client: Client::of(setup)?,
        queue: settings.queue,
        blocking: setup.blocking(),
    }))
}

impl QuerySource for TicketSource {
    fn default_time_field(&self) -> Option<&str> {
        Some(DEFAULT_TIMESTAMP_FIELD)
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
        let (start, end) = (start.utc(), end.utc());
        let url = self.client.search_url(query, &self.queue, start, end);
        let timeout = timeout.to_std().unwrap_or(Duration::ZERO);
        self.blocking.run(async {
            tokio::time::timeout(timeout, self.client.tickets(&url))
                .await
                .unwrap_or_else(|_| Err(format!("the ticket search ran past its {timeout:?}")))
        })
    }
}
