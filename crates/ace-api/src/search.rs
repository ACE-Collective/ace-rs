//! `/api/search/v1`: ace3's `search` router (PLAN.md 5.6, 7.11), over `ace_service::search`. Both routes
//! need `alert:read`, as ace3's do.
//!
//! | ace3 `/api/v2/search` | here |
//! |---|---|
//! | `POST /alerts` | `POST /api/search/v1/alerts` |
//! | `POST /similar` | `POST /api/search/v1/similar` |
//!
//! Each is a read that takes its question as a JSON body, as ace3's. The lib's docs say what differs
//! from ace3's bodies.

use std::collections::BTreeMap;

use ace_service::search::{
    SearchHit, SearchLane, SearchRequest, SearchResponse, SearchResult, SimilarRequest,
};
use ace_service::{FilterEntry, FilterValue};
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::Web;
use crate::alerts::AlertBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};

/// ace3's `SearchFiltersBody`. Lists match any of their values, and the filters are ANDed.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SearchFiltersRequest {
    /// Only alerts made at or after this time, with its UTC offset.
    #[serde(default)]
    insert_date_start: Option<DateTime<Utc>>,
    /// Only alerts made at or before this time.
    #[serde(default)]
    insert_date_end: Option<DateTime<Utc>>,
    /// Such as `OPEN`, `FALSE_POSITIVE`, `DELIVERY`.
    #[serde(default)]
    dispositions: Vec<String>,
    #[serde(default)]
    queues: Vec<String>,
    /// Exact tag names, whatever their case.
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    exclude_alert_uuids: Vec<Uuid>,
    /// Only alerts carrying all of these observables. A file's value is its sha256.
    #[serde(default)]
    observables: Vec<ObservablePair>,
    /// Only alerts with a detection from any of these signatures, each `<signature uuid>[:<version>]`.
    #[serde(default)]
    detection_points: Vec<String>,
    /// The rest of the alert list's filters, as `POST /api/filters/v1/screens/alerts/encode` takes them.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    filters: Value,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservablePair {
    r#type: String,
    value: String,
}

impl SearchFiltersRequest {
    /// The filters as entries of the alert screen's list, the alerts left out by id, and the window
    /// of its two times: ace3's `to_search_filters` and `to_filter_list`.
    fn parts(self) -> Result<Parts, ApiError> {
        let mut entries: Vec<FilterEntry> = match self.filters {
            Value::Null => Vec::new(),
            filters => serde_json::from_value(filters).map_err(|e| {
                ApiError::bad_request(format!(
                    "filters are entries {{\"name\", \"inverted\", \"values\"}}: {e}"
                ))
            })?,
        };
        let texts = |name: &str, values: Vec<String>| {
            FilterEntry::new(
                name,
                false,
                values.into_iter().map(FilterValue::Text).collect(),
            )
        };
        let window =
            (self.insert_date_start.is_some() || self.insert_date_end.is_some()).then(|| {
                (
                    self.insert_date_start
                        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH),
                    self.insert_date_end.unwrap_or(DateTime::<Utc>::MAX_UTC),
                )
            });
        if !self.dispositions.is_empty() {
            entries.push(texts("Disposition", self.dispositions));
        }
        if !self.queues.is_empty() {
            entries.push(texts("Queue", self.queues));
        }
        if !self.tags.is_empty() {
            entries.push(texts("Tag", self.tags));
        }
        // one entry for each pair: entries are ANDed, so an alert carries all of them
        for pair in self.observables {
            entries.push(FilterEntry::new(
                "Observable",
                false,
                vec![FilterValue::Pair(pair.r#type, pair.value)],
            ));
        }
        if !self.detection_points.is_empty() {
            entries.push(texts("Detection Point", self.detection_points));
        }
        Ok(Parts {
            filters: entries,
            exclude: self.exclude_alert_uuids,
            window,
        })
    }
}

/// What a request's filters come to.
struct Parts {
    filters: Vec<FilterEntry>,
    exclude: Vec<Uuid>,
    window: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

fn timezone(tz: Option<&str>) -> Result<chrono_tz::Tz, ApiError> {
    match tz {
        None => Ok(chrono_tz::Tz::UTC),
        Some(name) => Ok(ace_service::filters::timezone(name)?),
    }
}

fn default_true() -> bool {
    true
}

fn default_lanes() -> Vec<String> {
    vec!["semantic".to_owned(), "lexical".to_owned()]
}

/// ace3's `AlertSearchRequest`: a query, filters, or both.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertSearchRequest {
    /// Free text for the semantic lanes, and any number of `field:value` terms: `tag:phish`,
    /// `uuid:<alert id>`, `<observable type>:<value>` such as `ipv4:1.2.3.4`,
    /// `observable:<type>:<value>` for a value with colons in it, or a filter's slug such as
    /// `queue:default`, `disposition:DELIVERY` or `alert_date:-7d`. `-` before a term inverts it, quotes
    /// keep a value with a space or a comma whole, and commas separate ORed values. A prefix that names
    /// nothing is text. A bare word or indicator is searched by meaning only, never looked up exactly.
    /// At most 2,000 characters.
    query: Option<String>,
    #[serde(default)]
    filters: SearchFiltersRequest,
    /// The page's size, 1 to 100; 20 when left out.
    limit: Option<u32>,
    #[serde(default)]
    offset: u32,
    /// Whether each alert comes with the snippets that matched.
    #[serde(default = "default_true")]
    include_hits: bool,
    /// `semantic`, `lexical` or both.
    #[serde(default = "default_lanes")]
    lanes: Vec<String>,
    /// Whether SVS's test-run alerts are searched. They are left out unless the filters or the query
    /// name a queue, and `excluded_test_alerts` says how many were.
    #[serde(default)]
    include_test_alerts: bool,
    /// The IANA timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
}

/// ace3's `SimilarAlertsRequest`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SimilarAlertsRequest {
    alert_uuid: Uuid,
    #[serde(default)]
    filters: SearchFiltersRequest,
    /// The page's size, 1 to 50; 10 when left out.
    limit: Option<u32>,
    #[serde(default)]
    offset: u32,
    #[serde(default = "default_true")]
    include_hits: bool,
    #[serde(default)]
    include_test_alerts: bool,
    tz: Option<String>,
}

/// One snippet that matched: ace3's `SearchHitOut`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SearchHitBody {
    /// `semantic` or `lexical`.
    lane: &'static str,
    /// `alert`, `comment`, `detection`, `analysis` or `context` for a semantic hit; `observable`, `tag`
    /// or `uuid` for a lexical one.
    kind: String,
    title: Option<String>,
    /// What matched, as it was written. Show it as text.
    text: String,
    /// The lane's own score: 1 for an exact match. Not comparable between lanes.
    score: f64,
}

impl From<SearchHit> for SearchHitBody {
    fn from(hit: SearchHit) -> Self {
        SearchHitBody {
            lane: hit.lane.as_str(),
            kind: hit.kind,
            title: hit.title,
            text: hit.text,
            score: hit.score,
        }
    }
}

/// One alert a search found: ace3's `AlertSearchResultOut`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SearchResultBody {
    alert: AlertBody,
    rank: usize,
    /// The evidence behind the match: `exact` for a field term matched as written, `strong` for clearly
    /// similar text or similar text sharing terms with the query, `good` for similar text above the
    /// floor, `weak` for only a term in common. Null for a filter-only request, which is a listing.
    tier: Option<&'static str>,
    /// The fused rank score, for ordering only.
    score: f64,
    lanes: Vec<&'static str>,
    hits: Vec<SearchHitBody>,
}

impl From<SearchResult> for SearchResultBody {
    fn from(result: SearchResult) -> Self {
        SearchResultBody {
            alert: result.alert.into(),
            rank: result.rank,
            tier: result.tier.map(|tier| tier.as_str()),
            score: result.score,
            lanes: result.lanes.into_iter().map(SearchLane::as_str).collect(),
            hits: result.hits.into_iter().map(Into::into).collect(),
        }
    }
}

/// ace3's `AlertSearchResponse`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertSearchBody {
    query: String,
    /// How many alerts matched: for a search, within the 500 it ranks.
    total: u64,
    offset: u32,
    limit: u32,
    results: Vec<SearchResultBody>,
    lanes_used: Vec<&'static str>,
    timings_ms: BTreeMap<String, u64>,
    /// How many test-run alerts matched and were left out; null when none were left out, because the
    /// request named a queue or set `include_test_alerts`.
    excluded_test_alerts: Option<u64>,
    /// What the query language couldn't honor. When it isn't empty nothing was searched: a term that
    /// can't be honored is reported, since dropping it would return more alerts than were asked for.
    errors: Vec<String>,
    /// How to name a bare indicator so it's looked up exactly.
    hint: Option<String>,
    /// Lanes that didn't run or failed, so less came back than might have.
    warnings: Vec<String>,
}

impl From<SearchResponse> for AlertSearchBody {
    fn from(response: SearchResponse) -> Self {
        AlertSearchBody {
            query: response.query,
            total: response.total,
            offset: response.offset,
            limit: response.limit,
            results: response.results.into_iter().map(Into::into).collect(),
            lanes_used: response
                .lanes_used
                .into_iter()
                .map(SearchLane::as_str)
                .collect(),
            timings_ms: response.timings_ms,
            excluded_test_alerts: response.excluded_test_alerts,
            errors: response.errors,
            hint: response.hint,
            warnings: response.warnings,
        }
    }
}

/// Searches alerts by free text, indicator, tag or id.
///
/// Exact matches, an observable, a tag or an alert's id named by a `field:value` term, come first,
/// newest first, with the tier `exact`; matches by the meaning of the alert's text follow. The ranking
/// is made before the page is cut, so page one holds the best. With filters and no query the answer is
/// a listing, newest first, every tier null.
#[utoipa::path(
    post,
    path = "/api/search/v1/alerts",
    tag = "search",
    request_body = AlertSearchRequest,
    responses(
        (status = 200, description = "A page of the alerts found, or the query's errors with nothing searched", body = AlertSearchBody),
        (status = 400, description = "Neither a query nor a filter, a filter, lane, timezone, limit or offset that isn't one, a body that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn alerts(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<AlertSearchRequest>, JsonRejection>,
) -> Result<Json<AlertSearchBody>, ApiError> {
    let Json(body) = body?;
    let tz = timezone(body.tz.as_deref())?;
    let Parts {
        filters,
        exclude,
        window,
    } = body.filters.parts()?;
    let query = body.query.unwrap_or_default();
    if query.trim().is_empty() && filters.is_empty() && exclude.is_empty() && window.is_none() {
        return Err(ApiError::bad_request(
            "a query or at least one filter is required",
        ));
    }
    let mut semantic = false;
    let mut lexical = false;
    for lane in &body.lanes {
        match lane.as_str() {
            "semantic" => semantic = true,
            "lexical" => lexical = true,
            other => {
                return Err(ApiError::bad_request(format!(
                    "{other:?} isn't a lane: semantic or lexical"
                )));
            }
        }
    }
    let response = web
        .service
        .search_alerts(
            &actor,
            &SearchRequest {
                query,
                filters,
                exclude,
                window,
                tz,
                limit: body.limit.unwrap_or(20),
                offset: body.offset,
                include_hits: body.include_hits,
                semantic,
                lexical,
                include_test_alerts: body.include_test_alerts,
            },
        )
        .await?;
    Ok(Json(response.into()))
}

/// The alerts most like one alert, by its own indexed text, with their dispositions: "have we seen this
/// before?".
#[utoipa::path(
    post,
    path = "/api/search/v1/similar",
    tag = "search",
    request_body = SimilarAlertsRequest,
    responses(
        (status = 200, description = "A page of the alerts most like it, itself left out", body = AlertSearchBody),
        (status = 400, description = "A filter, timezone or limit that isn't one, a body that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No alert with that id", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn similar(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<SimilarAlertsRequest>, JsonRejection>,
) -> Result<Json<AlertSearchBody>, ApiError> {
    let Json(body) = body?;
    let tz = timezone(body.tz.as_deref())?;
    let Parts {
        filters,
        exclude,
        window,
    } = body.filters.parts()?;
    let response = web
        .service
        .similar_alerts(
            &actor,
            &SimilarRequest {
                alert: body.alert_uuid,
                filters,
                exclude,
                window,
                tz,
                limit: body.limit.unwrap_or(10),
                offset: body.offset,
                include_hits: body.include_hits,
                include_test_alerts: body.include_test_alerts,
            },
        )
        .await?;
    Ok(Json(response.into()))
}
