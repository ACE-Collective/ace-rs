//! Alert search (PLAN.md 7.11): ace3's `saq/search/`, its read path here and its index in `ace-search`.
//!
//! # What a search is
//!
//! A query is parsed first (`syntax`, ace3's `syntax.py`), and what it holds decides what runs:
//!
//! - **Field terms and no free text, or filters and no query**: a listing. The alert list's own query,
//!   newest first, with no ranking and no tier, paged by offset. It answers "every alert carrying this
//!   observable".
//! - **An exact term** (`ipv4:…`, `tag:…`, `uuid:…`, not inverted): the lexical lane, ace3's
//!   `lexical.py`. The alerts that hold the observable, the tag or the id, newest first, straight from
//!   the tree's own tables, so it's never stale.
//! - **Free text**: the semantic lanes, and only then, since an embedding of nothing still has a nearest
//!   neighbour. The dense lane is the cosine between the text's embedding and each chunk's, floored at
//!   `SearchConfig::score_threshold` so a nonsense query returns nothing; the sparse lane is the chunks
//!   that share a term with the text, rarer terms counting more. Both are the index's (`SearchIndex`).
//!
//! The lanes are fused by weighted reciprocal rank, exact matches go first in their own newest-first
//! order, the list is capped at `max_results`, filtered, and then paged, so `total` counts what was
//! found and page one holds the best. A result's tier is its evidence, never its place: `exact` for a
//! field term's match, `strong` for a dense score at `strong_threshold` or one above the floor with a
//! term in common, `good` for a dense score alone, `weak` for a term alone, and none for a listing.
//!
//! `similar_alerts` ranks other alerts by the alert's own chunks, ace3's `similar_alerts`.
//!
//! # Filters
//!
//! One filter list, `crate::filters`' for the alert screen: the request's entries and the query's
//! filter terms (`queue:…`, `-tag:…`, `alert_date:-7d`), ANDed. `in_scope` is the part of it every lane
//! applies before it ranks, so a lane's budget isn't spent on alerts the search can't return: the queue,
//! the disposition, the alert date and alerts left out by id. Everything found then goes through the
//! alert list's query with the whole list (`Service::alert_page`), which is the one place a filter is
//! decided, and which reads the alerts' rows for the page. ace3 splits its filters the same way, into a
//! Qdrant payload filter and a SQL post-filter.
//!
//! A term the query types narrows what the request's filters already say. Two entries of one filter
//! and polarity can't both be kept in one list, so they are joined where that means the same: inverted
//! entries become one (not this and not that), and entries of a filter an alert has one value of
//! (queue, disposition, owner, who dispositioned it) keep the values both name. Anything else is
//! reported and nothing is searched, as for any term that can't be honored. So is an Observable Pattern
//! that the list refuses for its bounds (`ServiceError::FilterRefused`, PLAN.md decision 39), as ace3's
//! `search_alerts` reports one. Each read of the list looks its patterns up again, at most four reads a
//! search, where ace3 reuses the query it built; a refusal is remembered (`filters::patterns`).
//!
//! **Test-run alerts are left out unless asked for**, as in ace3: a search whose filters say nothing
//! about queues leaves out SVS's test queue, and `excluded_test_alerts` counts what the same search
//! finds there, so "nothing seen before" can't hide three test alerts.
//!
//! # The index
//!
//! `SearchIndex` is what the read path asks of an index, and `ace-search`'s `PgIndex` is the one `ace
//! serve` runs: chunks, embeddings and terms in Postgres. The trait is here so this crate, the API and
//! the GUI don't link the embedding model, and so the retrieval comparison can put ace3's Qdrant behind
//! the same read path (`docs/decisions/0002-search-index.md`). With no index set, a search with free
//! text still runs its exact lane and says the semantic lanes are missing.
//!
//! **Indexing.** The transaction that completes an alert's pass adds or renews its row in `search.due`
//! (`ace_core::queue::check_completion`), and `ace serve`'s indexer (`run_worker`), woken by the
//! completion's notification or its poll, indexes each as the component `search_indexer`, which holds
//! `search:index` and nothing else. It writes no audit row: the chunks are derived from the alert,
//! nothing decides anything by them but a search's ranking, and indexing again replaces them.
//!
//! # What differs from ace3
//!
//! - No alert type, tool or node: ace4's roots have none, so there is no `alert_types` filter and no
//!   node scoping. The other typed filters of ace3's request are entries of the one filter list.
//! - A disposition, a move between queues or a tag needs no index task: the lanes read the alert's row.
//! - A listing is paged by offset up to `MAX_LISTING_OFFSET`; past that the alert list's cursor pages.
//! - `warnings` says when the semantic lanes didn't run or failed. ace3 logs it and returns less.
//! - The settings are ace3's defaults (`SearchConfig`), set by the binary, with no overlay section yet.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ace_core::db::DbError;
use ace_core::svs::SVS_QUEUE;
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::actor::{Actor, Component};
use crate::alerts::{AlertQuery, AlertSort, AlertSummary, Scope, no_alert};
use crate::filters::{self, FilterEntry, FilterScreen, FilterValue, Resolved, USER, USER_QUEUE};
use crate::permission::{ALERT_READ, SEARCH_INDEX};
use crate::{Service, ServiceError};

pub mod syntax;

use syntax::{ExactTerm, ParsedQuery};

/// The component the indexer acts as, which migration 0061 grants `search:index`.
pub const SEARCH_COMPONENT: &str = "search_indexer";
/// The longest query, in characters: ace3's `MAX_QUERY_LENGTH`.
pub const MAX_QUERY_CHARS: usize = 2000;
/// The largest page of a search: ace3's `MAX_PAGE_SIZE`.
pub const MAX_SEARCH_PAGE: u32 = 100;
/// The largest page of similar alerts: ace3's `MAX_SIMILAR_PAGE_SIZE`.
pub const MAX_SIMILAR_PAGE: u32 = 50;
/// The most alerts a request leaves out by id: ace3's `MAX_EXCLUDE_ALERT_UUIDS`.
pub const MAX_EXCLUDED: usize = 100;
/// How far a listing pages by offset.
pub const MAX_LISTING_OFFSET: u32 = 10_000;
/// The filters an alert has one value of, whose entries from the request and the query are joined by
/// keeping the values both name.
const SINGLE_VALUED: &[&str] = &[
    "Queue",
    "Disposition",
    "Owner",
    "Disposition By",
    "Unconfirmed Detections",
];

/// ace3's `search:` settings that the read path uses, with its defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchConfig {
    /// The most alerts a semantic lane returns.
    pub semantic_limit: usize,
    /// The most hits kept for one alert from a semantic lane.
    pub semantic_group_size: usize,
    /// The most alerts the lexical lane returns.
    pub lexical_limit: usize,
    /// Reciprocal rank fusion's constant.
    pub rrf_k: f64,
    pub semantic_weight: f64,
    /// Larger than the semantic lanes', so an exact match outranks them.
    pub lexical_weight: f64,
    /// The dense lane's floor: the lowest cosine that counts as a match.
    pub score_threshold: f64,
    /// The cosine at which a dense match alone is a strong one.
    pub strong_threshold: f64,
    /// The cap on the fused list, which a search pages within.
    pub max_results: usize,
}

impl Default for SearchConfig {
    fn default() -> Self {
        SearchConfig {
            semantic_limit: 100,
            semantic_group_size: 3,
            lexical_limit: 200,
            rrf_k: 60.0,
            semantic_weight: 1.0,
            lexical_weight: 2.0,
            score_threshold: 0.3,
            strong_threshold: 0.55,
            max_results: 500,
        }
    }
}

/// The filters every lane applies before it ranks (`search.in_scope`, migration 0061). None is a
/// filter that isn't set.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Scoped {
    pub queues: Option<Vec<String>>,
    pub not_queues: Option<Vec<String>>,
    /// With `OPEN` for an alert with no disposition.
    pub dispositions: Option<Vec<String>>,
    pub not_dispositions: Option<Vec<String>>,
    /// The alert date's windows, each a start and an end, both included: any of them.
    pub windows: Option<Vec<(DateTime<Utc>, DateTime<Utc>)>>,
    /// None of them.
    pub not_windows: Option<Vec<(DateTime<Utc>, DateTime<Utc>)>>,
    pub except: Option<Vec<Uuid>>,
}

/// A lane a result came from, as a caller sees it: ace3's `semantic` and `lexical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SearchLane {
    Lexical,
    Semantic,
}

impl SearchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            SearchLane::Lexical => "lexical",
            SearchLane::Semantic => "semantic",
        }
    }
}

/// One piece of evidence for why an alert matched: ace3's `SearchHit`.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub lane: SearchLane,
    /// `alert`, `comment`, `detection`, `analysis` or `context` from the index; `observable`, `tag` or
    /// `uuid` from the lexical lane.
    pub kind: String,
    /// What names the hit within its alert, so one chunk reached by two lanes is shown once.
    pub key: String,
    pub title: Option<String>,
    pub text: String,
    /// The lane's own score: 1 for an exact match. Not comparable between lanes.
    pub score: f64,
    /// The result and the observable the text came from, when it came from one.
    pub result_id: Option<i64>,
    pub observable_id: Option<i64>,
}

/// What one lane found: alerts best first, each with its hits best first.
pub type LaneResult = Vec<(Uuid, Vec<SearchHit>)>;

/// Why an index couldn't answer.
#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error(transparent)]
    Db(#[from] DbError),
    /// The index, its model or its store failed. Its message says which.
    #[error("{0}")]
    Failed(String),
}

impl From<sqlx::Error> for IndexError {
    fn from(error: sqlx::Error) -> Self {
        IndexError::Db(DbError::Sqlx(error))
    }
}

impl From<IndexError> for ServiceError {
    fn from(error: IndexError) -> Self {
        match error {
            IndexError::Db(error) => ServiceError::from(error),
            IndexError::Failed(message) => ServiceError::Unconfigured(message),
        }
    }
}

/// What the indexer did with one due alert: ace3's `search_index_task_complete` line.
#[derive(Debug, Clone, PartialEq)]
pub struct Indexed {
    pub root: Uuid,
    pub documents: usize,
    pub chunks: usize,
    /// Documents and chunks past the indexer's bounds.
    pub left_out: usize,
    /// Why nothing was written: the alert is gone, or isn't an alert.
    pub skipped: Option<String>,
    /// Why this try failed. The row stays due until it has failed three times.
    pub error: Option<String>,
}

pub type IndexFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, IndexError>> + Send + 'a>>;

/// What the read path and the indexer ask of an index. `ace-search` implements it.
pub trait SearchIndex: std::fmt::Debug + Send + Sync {
    /// The alerts whose chunks are nearest `text`'s embedding, none below `floor`: at most `limit`
    /// alerts, best first, each with its `group` best chunks.
    fn dense<'a>(
        &'a self,
        text: &'a str,
        scope: &'a Scoped,
        limit: usize,
        group: usize,
        floor: f64,
    ) -> IndexFuture<'a, LaneResult>;

    /// The alerts whose chunks share a term with `text`, rarer terms counting more, or None when the
    /// text has no term to search by, such as one that is all stopwords.
    fn sparse<'a>(
        &'a self,
        text: &'a str,
        scope: &'a Scoped,
        limit: usize,
        group: usize,
    ) -> IndexFuture<'a, Option<LaneResult>>;

    /// The alerts nearest `root`'s own chunks, itself left out.
    fn similar<'a>(
        &'a self,
        root: Uuid,
        scope: &'a Scoped,
        limit: usize,
        group: usize,
        floor: f64,
    ) -> IndexFuture<'a, LaneResult>;

    /// Indexes the next due alert, or None when nothing is due.
    fn index_next(&self) -> IndexFuture<'_, Option<Indexed>>;
}

/// A result's tier: the evidence behind the match, ace3's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Exact,
    Strong,
    Good,
    Weak,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Exact => "exact",
            Tier::Strong => "strong",
            Tier::Good => "good",
            Tier::Weak => "weak",
        }
    }
}

/// What to search for.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchRequest {
    /// Free text and field terms (`syntax`). Empty with filters is a listing.
    pub query: String,
    /// The alert screen's filters, ANDed with the query's own.
    pub filters: Vec<FilterEntry>,
    /// Alerts to leave out by id: ace3's `exclude_alert_uuids`.
    pub exclude: Vec<Uuid>,
    /// Only alerts made in this window, both ends included: ace3's `insert_date_start` and
    /// `insert_date_end`. The Alert Date filter says a window to the minute in the viewer's timezone;
    /// this is two instants.
    pub window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Where a date filter's wall clock is.
    pub tz: Tz,
    pub limit: u32,
    pub offset: u32,
    /// Whether each result carries its hits.
    pub include_hits: bool,
    pub semantic: bool,
    pub lexical: bool,
    /// Whether SVS's test-run alerts are searched when the filters name no queue.
    pub include_test_alerts: bool,
}

impl Default for SearchRequest {
    fn default() -> Self {
        SearchRequest {
            query: String::new(),
            filters: Vec::new(),
            exclude: Vec::new(),
            window: None,
            tz: Tz::UTC,
            limit: 20,
            offset: 0,
            include_hits: true,
            semantic: true,
            lexical: true,
            include_test_alerts: false,
        }
    }
}

/// What to find alerts like.
#[derive(Debug, Clone, PartialEq)]
pub struct SimilarRequest {
    pub alert: Uuid,
    pub filters: Vec<FilterEntry>,
    pub exclude: Vec<Uuid>,
    pub window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub tz: Tz,
    pub limit: u32,
    pub offset: u32,
    pub include_hits: bool,
    pub include_test_alerts: bool,
}

impl SimilarRequest {
    pub fn of(alert: Uuid) -> Self {
        SimilarRequest {
            alert,
            filters: Vec::new(),
            exclude: Vec::new(),
            window: None,
            tz: Tz::UTC,
            limit: 10,
            offset: 0,
            include_hits: true,
            include_test_alerts: false,
        }
    }
}

/// One alert a search found: ace3's `AlertSearchResult`, with the alert's row.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    pub alert: AlertSummary,
    pub rank: usize,
    /// None for a listing, which has no evidence to report.
    pub tier: Option<Tier>,
    /// The fused score, for ordering only.
    pub score: f64,
    pub lanes: Vec<SearchLane>,
    pub hits: Vec<SearchHit>,
    /// The alert's best dense and sparse scores, the evidence behind its tier.
    pub dense_score: Option<f64>,
    pub sparse_score: Option<f64>,
}

/// A page of what a search found: ace3's `SearchResponse`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SearchResponse {
    pub query: String,
    /// How many alerts matched: for a search, within `max_results`.
    pub total: u64,
    pub offset: u32,
    pub limit: u32,
    pub results: Vec<SearchResult>,
    pub lanes_used: Vec<SearchLane>,
    pub timings_ms: BTreeMap<String, u64>,
    /// How many test-run alerts matched and were left out; None when none were left out, because the
    /// request named a queue or asked for them.
    pub excluded_test_alerts: Option<u64>,
    /// What the query language couldn't honor. When it isn't empty nothing was searched.
    pub errors: Vec<String>,
    /// A "did you mean" line for a bare indicator.
    pub hint: Option<String>,
    /// Lanes that didn't run or failed, so less came back than might have.
    pub warnings: Vec<String>,
}

impl SearchResponse {
    pub fn alert_ids(&self) -> Vec<Uuid> {
        self.results.iter().map(|result| result.alert.id).collect()
    }
}

/// The actor the indexer acts as: the component `search_indexer`.
pub fn indexer_actor() -> Actor {
    Actor::Internal {
        id: Component::new(SEARCH_COMPONENT).expect("a valid component name"),
    }
}

/// Weighted reciprocal rank fusion: each alert's score is the sum over its lanes of `weight / (k +
/// rank)`. Ties keep the order alerts first appeared in.
pub fn fuse(lanes: &[(f64, Vec<Uuid>)], k: f64) -> Vec<(Uuid, f64)> {
    let mut order: Vec<Uuid> = Vec::new();
    let mut scores: HashMap<Uuid, f64> = HashMap::new();
    for (weight, ranked) in lanes {
        for (rank, alert) in ranked.iter().enumerate() {
            let score = scores.entry(*alert).or_insert_with(|| {
                order.push(*alert);
                0.0
            });
            *score += weight / (k + (rank + 1) as f64);
        }
    }
    let mut fused: Vec<(Uuid, f64)> = order
        .into_iter()
        .map(|alert| (alert, scores[&alert]))
        .collect();
    fused.sort_by(|a, b| b.1.total_cmp(&a.1));
    fused
}

/// Every exact match first, in the lexical lane's own newest-first order, then the rest as fused.
pub fn exact_first(fused: Vec<(Uuid, f64)>, lexical: &[Uuid]) -> Vec<(Uuid, f64)> {
    if lexical.is_empty() {
        return fused;
    }
    let scores: HashMap<Uuid, f64> = fused.iter().copied().collect();
    let exact: BTreeSet<Uuid> = lexical.iter().copied().collect();
    lexical
        .iter()
        .filter_map(|alert| scores.get(alert).map(|score| (*alert, *score)))
        .chain(
            fused
                .into_iter()
                .filter(|(alert, _)| !exact.contains(alert)),
        )
        .collect()
}

/// The tier a result's evidence earns.
pub fn assign_tier(
    config: &SearchConfig,
    lexical: bool,
    dense: Option<f64>,
    sparse: Option<f64>,
) -> Tier {
    if lexical {
        return Tier::Exact;
    }
    match dense {
        Some(dense)
            if dense >= config.strong_threshold
                || (sparse.is_some() && dense >= config.score_threshold) =>
        {
            Tier::Strong
        }
        Some(_) => Tier::Good,
        None => Tier::Weak,
    }
}

/// Exact hits first, then semantic hits by score; a chunk two lanes reached is there once, with its
/// best score.
pub fn merge_hits(lists: Vec<Vec<SearchHit>>) -> Vec<SearchHit> {
    let mut order: Vec<String> = Vec::new();
    let mut best: HashMap<String, SearchHit> = HashMap::new();
    for hit in lists.into_iter().flatten() {
        match best.get(&hit.key) {
            None => {
                order.push(hit.key.clone());
                best.insert(hit.key.clone(), hit);
            }
            Some(current) if hit.lane == current.lane && hit.score > current.score => {
                best.insert(hit.key.clone(), hit);
            }
            Some(_) => {}
        }
    }
    let mut hits: Vec<SearchHit> = order
        .into_iter()
        .filter_map(|key| best.remove(&key))
        .collect();
    hits.sort_by(|a, b| {
        (a.lane != SearchLane::Lexical)
            .cmp(&(b.lane != SearchLane::Lexical))
            .then(b.score.total_cmp(&a.score))
    });
    hits
}

/// The request's filters and the query's as one list, the query's narrowing the request's (the
/// module's docs say how), or why they can't be one. None when together they match nothing.
pub fn merge_filters(
    request: &[FilterEntry],
    typed: &[FilterEntry],
) -> Result<Option<Vec<FilterEntry>>, String> {
    let mut merged = filters::check(FilterScreen::Alerts, request).map_err(|e| e.to_string())?;
    for entry in typed {
        let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.name == entry.name && existing.inverted == entry.inverted)
        else {
            merged.push(entry.clone());
            continue;
        };
        if entry.inverted {
            for value in &entry.values {
                if !existing.values.contains(value) {
                    existing.values.push(value.clone());
                }
            }
            continue;
        }
        let slug = FilterScreen::Alerts
            .spec(&entry.name)
            .map_or(entry.name.as_str(), |spec| spec.slug);
        let stands_in = |value: &FilterValue| matches!(value, FilterValue::Text(text) if text == USER_QUEUE || text == USER);
        if !SINGLE_VALUED.contains(&entry.name.as_str())
            || existing.values.iter().chain(&entry.values).any(stands_in)
        {
            return Err(format!(
                "{slug}: is also one of the request's filters, and the two can't be combined: put the \
                 values in one of them"
            ));
        }
        existing.values.retain(|value| entry.values.contains(value));
        if existing.values.is_empty() {
            return Ok(None);
        }
    }
    Ok(Some(merged))
}

/// The part of a filter list every lane applies (`Scoped`): ace3's
/// `effective_filters_to_search_filters`. The rest, an owner, a tag, an observable, is the alert list's
/// query's alone. A queue filter that stands for the viewer's own is left to that query too, which
/// knows the viewer. A list `filters::check` refuses is `InvalidRequest`.
pub fn lane_scope(
    entries: &[FilterEntry],
    exclude: &[Uuid],
    window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    tz: Tz,
) -> Result<Scoped, ServiceError> {
    let f = Resolved::new(FilterScreen::Alerts, entries, Utc::now(), tz)?;
    let queues = |inverted| {
        f.names("queue", inverted)
            .filter(|names| !names.iter().any(|name| name == USER_QUEUE))
    };
    Ok(Scoped {
        queues: queues(false),
        not_queues: queues(true),
        dispositions: f.names("disposition", false),
        not_dispositions: f.names("disposition", true),
        // the request's own window and the Alert Date filter's are never both set (`one_window`)
        windows: match window {
            Some(window) => Some(vec![window]),
            None => f.windows("alert_date", false)?.map(pairs),
        },
        not_windows: f.windows("alert_date", true)?.map(pairs),
        except: (!exclude.is_empty()).then(|| exclude.to_vec()),
    })
}

fn pairs(
    (starts, ends): (Vec<DateTime<Utc>>, Vec<DateTime<Utc>>),
) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    starts.into_iter().zip(ends).collect()
}

impl Scoped {
    /// Windows as the text of a Postgres `tstzmultirange`, which `search.in_scope` takes: each window
    /// with both its ends included. An empty window, whose end is before its start, is left out.
    pub fn multirange(windows: &Option<Vec<(DateTime<Utc>, DateTime<Utc>)>>) -> Option<String> {
        windows.as_ref().map(|windows| {
            let ranges: Vec<String> = windows
                .iter()
                .filter(|(start, end)| start <= end)
                .map(|(start, end)| {
                    format!(
                        "[\"{}\",\"{}\"]",
                        start.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                        end.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
                    )
                })
                .collect();
            format!("{{{}}}", ranges.join(","))
        })
    }
}

fn names_queues(entries: &[FilterEntry]) -> bool {
    entries.iter().any(|entry| entry.name == "Queue")
}

/// The filters to search with, and those that select the test-run alerts they leave out, None when
/// none are: ace3's `leave_out_test_alerts`.
fn leave_out_test_alerts(
    entries: Vec<FilterEntry>,
    include: bool,
) -> (Vec<FilterEntry>, Option<Vec<FilterEntry>>) {
    if include || names_queues(&entries) {
        return (entries, None);
    }
    let with = |inverted| {
        let mut entries = entries.clone();
        entries.push(FilterEntry::text("Queue", inverted, &[SVS_QUEUE]));
        entries
    };
    (with(true), Some(with(false)))
}

/// What one run of the lanes needs.
struct Run<'a> {
    actor: &'a Actor,
    query: &'a str,
    parsed: &'a ParsedQuery,
    filters: &'a [FilterEntry],
    exclude: &'a [Uuid],
    window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    tz: Tz,
    limit: u32,
    offset: u32,
    include_hits: bool,
    semantic: bool,
    lexical: bool,
}

/// A request's own window and an Alert Date filter both say when, and one list can't hold both.
fn one_window(
    window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    entries: &[FilterEntry],
) -> Result<(), String> {
    if window.is_some()
        && entries
            .iter()
            .any(|entry| entry.name == "Alert Date" && !entry.inverted)
    {
        return Err(
            "alert_date: is also the request's own window, and the two can't be combined: give one"
                .to_owned(),
        );
    }
    Ok(())
}

/// What one run of a similar-alerts search is kept to.
struct Like<'a> {
    filters: &'a [FilterEntry],
    exclude: &'a [Uuid],
    window: Option<(DateTime<Utc>, DateTime<Utc>)>,
    tz: Tz,
    /// The page's size, its offset, and whether its results carry their hits.
    page: (u32, u32, bool),
}

/// What the semantic lanes found.
#[derive(Default)]
struct Semantic {
    dense: LaneResult,
    sparse: LaneResult,
}

fn best_scores(lane: &LaneResult) -> HashMap<Uuid, f64> {
    lane.iter()
        .filter_map(|(alert, hits)| {
            hits.iter()
                .map(|hit| hit.score)
                .fold(None, |best: Option<f64>, score| {
                    Some(best.map_or(score, |best| best.max(score)))
                })
                .map(|best| (*alert, best))
        })
        .collect()
}

fn elapsed(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl Service {
    /// The service with a search index (PLAN.md 7.11) and its settings.
    pub fn with_search(mut self, index: Arc<dyn SearchIndex>, config: SearchConfig) -> Self {
        self.search = Some(index);
        self.search_config = Arc::new(config);
        self
    }

    /// The search index, when the binary set one.
    pub fn search_index(&self) -> Option<&Arc<dyn SearchIndex>> {
        self.search.as_ref()
    }

    /// The search settings.
    pub fn search_config(&self) -> &SearchConfig {
        &self.search_config
    }

    async fn needs(&self, actor: &Actor, action: &'static str) -> Result<(), ServiceError> {
        if self.gate.allowed(actor, &ALERT_READ).await? {
            return Ok(());
        }
        tracing::warn!(%actor, permission = %ALERT_READ, action, "permission denied");
        Err(ServiceError::PermissionDenied {
            actor: actor.to_string(),
            permission: ALERT_READ.clone(),
        })
    }

    /// Searches alerts: ace3's `search_alerts`. It needs `alert:read`. A query the language can't honor
    /// comes back with `errors` and nothing searched; a request out of bounds is `InvalidRequest`.
    pub async fn search_alerts(
        &self,
        actor: &Actor,
        request: &SearchRequest,
    ) -> Result<SearchResponse, ServiceError> {
        self.needs(actor, "search_alerts").await?;
        let invalid = |message: String| Err(ServiceError::InvalidRequest(message));
        if request.query.chars().count() > MAX_QUERY_CHARS {
            return invalid(format!("a query has at most {MAX_QUERY_CHARS} characters"));
        }
        if request.limit == 0 || request.limit > MAX_SEARCH_PAGE {
            return invalid(format!(
                "a page of a search has 1 to {MAX_SEARCH_PAGE} alerts"
            ));
        }
        if request.exclude.len() > MAX_EXCLUDED {
            return invalid(format!(
                "a search leaves out at most {MAX_EXCLUDED} alerts by id"
            ));
        }
        if !request.semantic && !request.lexical {
            return invalid("a search runs at least one lane".to_owned());
        }
        let checked = filters::check(FilterScreen::Alerts, &request.filters)?;
        let query = request.query.trim();
        let parsed = syntax::parse(query);
        let empty = SearchResponse {
            query: query.to_owned(),
            offset: request.offset,
            limit: request.limit,
            ..SearchResponse::default()
        };
        if !parsed.errors.is_empty() {
            return Ok(SearchResponse {
                errors: parsed.errors,
                ..empty
            });
        }
        let merged = match merge_filters(&checked, &parsed.filters).and_then(|merged| {
            one_window(request.window, merged.as_deref().unwrap_or_default()).map(|()| merged)
        }) {
            Ok(Some(merged)) => merged,
            Ok(None) => return Ok(empty),
            Err(error) => {
                return Ok(SearchResponse {
                    errors: vec![error],
                    ..empty
                });
            }
        };
        if parsed.text.is_empty() && parsed.exact.is_empty() {
            if merged.is_empty() && request.exclude.is_empty() && request.window.is_none() {
                return Ok(empty);
            }
            if request.offset > MAX_LISTING_OFFSET {
                return invalid(format!(
                    "a listing pages by offset up to {MAX_LISTING_OFFSET}: the alert list's cursor pages past it"
                ));
            }
        }
        let (searched, test) = leave_out_test_alerts(merged, request.include_test_alerts);
        let run = |filters, limit, offset, include_hits| Run {
            actor,
            query,
            parsed: &parsed,
            filters,
            exclude: &request.exclude,
            window: request.window,
            tz: request.tz,
            limit,
            offset,
            include_hits,
            semantic: request.semantic,
            lexical: request.lexical,
        };
        // an Observable Pattern past its bounds is a term that can't be honored (`filters::patterns`)
        let refused = |why: String| SearchResponse {
            query: query.to_owned(),
            offset: request.offset,
            limit: request.limit,
            errors: vec![why],
            ..SearchResponse::default()
        };
        let mut response = match self
            .run_search(run(
                &searched,
                request.limit,
                request.offset,
                request.include_hits,
            ))
            .await
        {
            Err(ServiceError::FilterRefused(why)) => return Ok(refused(why)),
            searched => searched?,
        };
        response.hint = parsed.hint();
        if let Some(test) = test {
            response.excluded_test_alerts = Some(0);
            if self.any_test_alerts(actor).await? {
                // the same search over the test queue alone: its total is what was left out
                let started = Instant::now();
                let counted = match self.run_search(run(&test, 0, 0, false)).await {
                    Err(ServiceError::FilterRefused(why)) => return Ok(refused(why)),
                    counted => counted?,
                };
                response.excluded_test_alerts = Some(counted.total);
                response
                    .timings_ms
                    .insert("excluded_test_alerts".to_owned(), elapsed(started));
            }
        }
        Ok(response)
    }

    /// The alerts most like `request.alert`, itself left out: ace3's `similar_alerts`. It needs
    /// `alert:read`; an id that names no alert is `NotFound`.
    pub async fn similar_alerts(
        &self,
        actor: &Actor,
        request: &SimilarRequest,
    ) -> Result<SearchResponse, ServiceError> {
        self.needs(actor, "similar_alerts").await?;
        let invalid = |message: String| Err(ServiceError::InvalidRequest(message));
        if request.limit == 0 || request.limit > MAX_SIMILAR_PAGE {
            return invalid(format!(
                "a page of similar alerts has 1 to {MAX_SIMILAR_PAGE} alerts"
            ));
        }
        if request.exclude.len() > MAX_EXCLUDED {
            return invalid(format!(
                "a search leaves out at most {MAX_EXCLUDED} alerts by id"
            ));
        }
        let checked = filters::check(FilterScreen::Alerts, &request.filters)?;
        one_window(request.window, &checked).map_err(ServiceError::InvalidRequest)?;
        let root = request.alert;
        let known = self
            .gate
            .read(actor, "similar_alerts", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar!(
                        r#"SELECT EXISTS (SELECT FROM analysis.roots
                                          WHERE id = $1 AND alerted_at IS NOT NULL) AS "alert!""#,
                        root,
                    )
                    .fetch_one(tx.conn())
                    .await?)
                })
            })
            .await?;
        if !known {
            return Err(no_alert(root));
        }
        let query = format!("similar:{root}");
        let (searched, test) = leave_out_test_alerts(checked, request.include_test_alerts);
        let mut exclude = request.exclude.clone();
        exclude.push(root);
        let refused = |why: String| SearchResponse {
            query: query.clone(),
            offset: request.offset,
            limit: request.limit,
            errors: vec![why],
            ..SearchResponse::default()
        };
        let mut response = match self
            .run_similar(
                actor,
                &query,
                root,
                Like {
                    filters: &searched,
                    exclude: &exclude,
                    window: request.window,
                    tz: request.tz,
                    page: (request.limit, request.offset, request.include_hits),
                },
            )
            .await
        {
            // see search_alerts
            Err(ServiceError::FilterRefused(why)) => return Ok(refused(why)),
            similar => similar?,
        };
        if let Some(test) = test {
            response.excluded_test_alerts = Some(0);
            if self.any_test_alerts(actor).await? {
                let started = Instant::now();
                let counted = match self
                    .run_similar(
                        actor,
                        &query,
                        root,
                        Like {
                            filters: &test,
                            exclude: &exclude,
                            window: request.window,
                            tz: request.tz,
                            page: (0, 0, false),
                        },
                    )
                    .await
                {
                    Err(ServiceError::FilterRefused(why)) => return Ok(refused(why)),
                    counted => counted?,
                };
                response.excluded_test_alerts = Some(counted.total);
                response
                    .timings_ms
                    .insert("excluded_test_alerts".to_owned(), elapsed(started));
            }
        }
        Ok(response)
    }

    /// Whether any alert is in the test queue: the indexed check that spares a search its counting
    /// pass while there are no test runs.
    async fn any_test_alerts(&self, actor: &Actor) -> Result<bool, ServiceError> {
        self.gate
            .read(actor, "search_alerts", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    Ok(sqlx::query_scalar!(
                        r#"SELECT EXISTS (SELECT FROM analysis.roots
                                          WHERE alerted_at IS NOT NULL AND queue = $1) AS "any!""#,
                        SVS_QUEUE,
                    )
                    .fetch_one(tx.conn())
                    .await?)
                })
            })
            .await
    }

    async fn run_similar(
        &self,
        actor: &Actor,
        query: &str,
        root: Uuid,
        like: Like<'_>,
    ) -> Result<SearchResponse, ServiceError> {
        let Like {
            filters: entries,
            exclude,
            window,
            tz,
            page: (limit, offset, include_hits),
        } = like;
        let config = self.search_config.clone();
        let scope = lane_scope(entries, exclude, window, tz)?;
        let mut timings = BTreeMap::new();
        let mut warnings = Vec::new();
        let mut semantic = Semantic::default();
        let mut lanes_used = Vec::new();
        match &self.search {
            None => warnings.push(NO_INDEX.to_owned()),
            Some(index) => {
                let started = Instant::now();
                match index
                    .similar(
                        root,
                        &scope,
                        config.semantic_limit,
                        config.semantic_group_size,
                        config.score_threshold,
                    )
                    .await
                {
                    Ok(dense) => semantic.dense = dense,
                    Err(error) => {
                        tracing::error!(alert_uuid = %root, "the similar search failed: {error}");
                        warnings.push(LANES_FAILED.to_owned());
                    }
                }
                lanes_used.push(SearchLane::Semantic);
                timings.insert("semantic".to_owned(), elapsed(started));
            }
        }
        let run = Run {
            actor,
            query,
            parsed: &ParsedQuery::default(),
            filters: entries,
            exclude,
            window,
            tz,
            limit,
            offset,
            include_hits,
            semantic: true,
            lexical: false,
        };
        let mut response = self.assemble(&run, None, Some(semantic), timings).await?;
        response.lanes_used = lanes_used;
        response.warnings = warnings;
        Ok(response)
    }

    /// The lanes the parsed query calls for, under these filters, fused and paged: ace3's
    /// `_run_search`.
    async fn run_search(&self, run: Run<'_>) -> Result<SearchResponse, ServiceError> {
        let config = self.search_config.clone();
        let mut timings = BTreeMap::new();
        if run.parsed.text.is_empty() && run.parsed.exact.is_empty() {
            return self.listing(&run, timings).await;
        }
        let scope = lane_scope(run.filters, run.exclude, run.window, run.tz)?;
        let mut warnings = Vec::new();
        let mut lexical = None;
        if run.lexical && !run.parsed.exact.is_empty() {
            let started = Instant::now();
            lexical = Some(
                self.lexical_lane(run.actor, &run.parsed.exact, &scope, config.lexical_limit)
                    .await?,
            );
            timings.insert("lexical".to_owned(), elapsed(started));
        }
        let mut semantic = None;
        if run.semantic && !run.parsed.text.is_empty() {
            match &self.search {
                None => warnings.push(NO_INDEX.to_owned()),
                Some(index) => {
                    let started = Instant::now();
                    let mut found = Semantic::default();
                    let text = run.parsed.text.as_str();
                    let (limit, group) = (config.semantic_limit, config.semantic_group_size);
                    let lanes = async {
                        found.dense = index
                            .dense(text, &scope, limit, group, config.score_threshold)
                            .await?;
                        if let Some(sparse) = index.sparse(text, &scope, limit, group).await? {
                            found.sparse = sparse;
                        }
                        Ok::<(), IndexError>(())
                    };
                    if let Err(error) = lanes.await {
                        // a search degrades to what its other lanes found, as ace3's does
                        tracing::error!("the semantic search failed: {error}");
                        warnings.push(LANES_FAILED.to_owned());
                        found = Semantic::default();
                    }
                    semantic = Some(found);
                    timings.insert("semantic".to_owned(), elapsed(started));
                }
            }
        }
        let mut lanes_used = Vec::new();
        if lexical.is_some() {
            lanes_used.push(SearchLane::Lexical);
        }
        if semantic.is_some() {
            lanes_used.push(SearchLane::Semantic);
        }
        let mut response = self.assemble(&run, lexical, semantic, timings).await?;
        response.lanes_used = lanes_used;
        response.warnings = warnings;
        Ok(response)
    }

    /// The alerts the filters match, newest first, with no ranking and no tier: ace3's
    /// `filter_listing`.
    async fn listing(
        &self,
        run: &Run<'_>,
        mut timings: BTreeMap<String, u64>,
    ) -> Result<SearchResponse, ServiceError> {
        let started = Instant::now();
        let query = AlertQuery {
            filters: run.filters.to_vec(),
            sort: AlertSort::AlertDate,
            descending: true,
            tz: run.tz,
        };
        let except = (!run.exclude.is_empty()).then_some(run.exclude);
        let scope = |offset| Scope {
            only: None,
            except,
            offset,
            window: run.window,
        };
        let page = self
            .alert_page(
                run.actor,
                &query,
                i64::from(run.limit),
                None,
                scope(i64::from(run.offset)),
            )
            .await?;
        let total = if page.alerts.is_empty() && run.offset > 0 {
            // past the end no row carries the total, so the first page counts
            self.alert_page(run.actor, &query, 0, None, scope(0))
                .await?
                .total
        } else {
            page.total
        };
        timings.insert("listing".to_owned(), elapsed(started));
        let results = page
            .alerts
            .into_iter()
            .take(run.limit as usize)
            .enumerate()
            .map(|(index, alert)| SearchResult {
                alert,
                rank: run.offset as usize + index + 1,
                tier: None,
                score: 0.0,
                lanes: Vec::new(),
                hits: Vec::new(),
                dense_score: None,
                sparse_score: None,
            })
            .collect();
        Ok(SearchResponse {
            query: String::new(),
            total: u64::try_from(total).unwrap_or(0),
            offset: run.offset,
            limit: run.limit,
            results,
            timings_ms: timings,
            ..SearchResponse::default()
        })
    }

    /// Fuses the lanes, puts exact matches first, caps and filters the list, and pages it: ace3's
    /// `_assemble`.
    async fn assemble(
        &self,
        run: &Run<'_>,
        lexical: Option<LaneResult>,
        semantic: Option<Semantic>,
        mut timings: BTreeMap<String, u64>,
    ) -> Result<SearchResponse, ServiceError> {
        let config = self.search_config.clone();
        let ids = |lane: &LaneResult| lane.iter().map(|(alert, _)| *alert).collect::<Vec<_>>();
        let lexical_ids = lexical.as_ref().map(ids).unwrap_or_default();
        let (dense_scores, sparse_scores) = semantic.as_ref().map_or_else(Default::default, |s| {
            (best_scores(&s.dense), best_scores(&s.sparse))
        });
        let mut ranked = Vec::new();
        if lexical.is_some() {
            ranked.push((config.lexical_weight, lexical_ids.clone()));
        }
        if let Some(semantic) = &semantic {
            ranked.push((config.semantic_weight, ids(&semantic.dense)));
            ranked.push((config.semantic_weight, ids(&semantic.sparse)));
        }
        let mut fused = exact_first(fuse(&ranked, config.rrf_k), &lexical_ids);
        fused.truncate(config.max_results);

        // the whole filter list, by the alert list's own query, which also reads the rows
        let mut alerts: HashMap<Uuid, AlertSummary> = HashMap::new();
        if !fused.is_empty() {
            let started = Instant::now();
            let found: Vec<Uuid> = fused.iter().map(|(alert, _)| *alert).collect();
            let query = AlertQuery {
                filters: run.filters.to_vec(),
                sort: AlertSort::AlertDate,
                descending: true,
                tz: run.tz,
            };
            let page = self
                .alert_page(
                    run.actor,
                    &query,
                    i64::try_from(found.len()).unwrap_or(i64::MAX),
                    None,
                    Scope {
                        only: Some(&found),
                        except: (!run.exclude.is_empty()).then_some(run.exclude),
                        offset: 0,
                        window: run.window,
                    },
                )
                .await?;
            alerts = page
                .alerts
                .into_iter()
                .map(|alert| (alert.id, alert))
                .collect();
            timings.insert("post_filter".to_owned(), elapsed(started));
        }
        fused.retain(|(alert, _)| alerts.contains_key(alert));
        let total = fused.len();

        let exact: BTreeSet<Uuid> = lexical_ids.iter().copied().collect();
        let mut hits: HashMap<Uuid, Vec<Vec<SearchHit>>> = HashMap::new();
        let mut semantic_alerts: BTreeSet<Uuid> = BTreeSet::new();
        if run.include_hits {
            for (alert, found) in lexical.into_iter().flatten() {
                hits.entry(alert).or_default().push(found);
            }
        }
        if let Some(semantic) = semantic {
            for (alert, found) in semantic.dense.into_iter().chain(semantic.sparse) {
                semantic_alerts.insert(alert);
                if run.include_hits {
                    hits.entry(alert).or_default().push(found);
                }
            }
        }
        let results = fused
            .into_iter()
            .enumerate()
            .skip(run.offset as usize)
            .take(run.limit as usize)
            .filter_map(|(index, (id, score))| {
                let alert = alerts.remove(&id)?;
                let (dense, sparse) = (
                    dense_scores.get(&id).copied(),
                    sparse_scores.get(&id).copied(),
                );
                let mut lanes = Vec::new();
                if exact.contains(&id) {
                    lanes.push(SearchLane::Lexical);
                }
                if semantic_alerts.contains(&id) {
                    lanes.push(SearchLane::Semantic);
                }
                Some(SearchResult {
                    alert,
                    rank: index + 1,
                    tier: Some(assign_tier(&config, exact.contains(&id), dense, sparse)),
                    score,
                    lanes,
                    hits: merge_hits(hits.remove(&id).unwrap_or_default()),
                    dense_score: dense,
                    sparse_score: sparse,
                })
            })
            .collect();
        Ok(SearchResponse {
            query: run.query.to_owned(),
            total: total as u64,
            offset: run.offset,
            limit: run.limit,
            results,
            timings_ms: timings,
            ..SearchResponse::default()
        })
    }

    /// The lexical lane: the alerts that hold any of the observables, tags or ids the query named,
    /// newest first, each with one hit for each thing it matched. ace3's `lexical_search`.
    async fn lexical_lane(
        &self,
        actor: &Actor,
        terms: &[ExactTerm],
        scope: &Scoped,
        limit: usize,
    ) -> Result<LaneResult, ServiceError> {
        let mut types = Vec::new();
        let mut values = Vec::new();
        let mut tags: Vec<String> = Vec::new();
        let mut ids: Vec<Uuid> = Vec::new();
        let mut prefixes: Vec<String> = Vec::new();
        for term in terms {
            match term {
                ExactTerm::Observables(pairs) => {
                    for (kind, value) in pairs {
                        // any type, as the Observable filter's `Any`
                        types.push(if kind == filters::ANY_TYPE {
                            String::new()
                        } else {
                            kind.clone()
                        });
                        values.push(value.clone());
                    }
                }
                ExactTerm::Tags(names) => tags.extend(names.iter().map(|tag| tag.to_lowercase())),
                ExactTerm::Uuids(given) => {
                    for value in given {
                        match value.parse::<Uuid>() {
                            Ok(id) if value.len() == 36 => ids.push(id),
                            // hex and dashes only, so nothing in it is a LIKE wildcard
                            _ => prefixes.push(format!("{value}%")),
                        }
                    }
                }
            }
        }
        let many = i64::try_from(limit.saturating_mul(4)).unwrap_or(i64::MAX);
        let few = i64::try_from(limit).unwrap_or(i64::MAX);
        let windows = Scoped::multirange(&scope.windows);
        let not_windows = Scoped::multirange(&scope.not_windows);
        let (types, values, tags, ids, prefixes) = (&types, &values, &tags, &ids, &prefixes);
        let (windows, not_windows) = (&windows, &not_windows);
        let found = self
            .gate
            .read(actor, "search_alerts", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(crate::alerts::SET_LIST_TIMEOUT)
                        .execute(tx.conn())
                        .await?;
                    let mut found: Vec<(Uuid, DateTime<Utc>, SearchHit)> = Vec::new();
                    let hit = |kind: &str, key: String, title: &str, text: String| SearchHit {
                        lane: SearchLane::Lexical,
                        kind: kind.to_owned(),
                        key,
                        title: Some(title.to_owned()),
                        text,
                        score: 1.0,
                        result_id: None,
                        observable_id: None,
                    };
                    if !values.is_empty() {
                        let rows = sqlx::query!(
                            r#"SELECT r.id, r.alerted_at AS "alerted_at!", o.type, o.value
                               FROM unnest($1::text[], $2::text[]) p(t, v)
                               JOIN analysis.observables o
                                 ON (p.t = '' OR o.type = p.t)
                                AND o.value_hash = analysis.value_hash(p.v) AND o.value = p.v
                               JOIN analysis.roots r ON r.id = o.root_id
                               WHERE r.alerted_at IS NOT NULL
                                 AND search.in_scope(r.id, r.queue::text, r.disposition, r.alerted_at,
                                       $3, $4, $5, $6, $7::text::tstzmultirange,
                                       $8::text::tstzmultirange, $9)
                               ORDER BY r.alerted_at DESC, r.id DESC LIMIT $10"#,
                            types.as_slice(),
                            values.as_slice(),
                            scope.queues.as_deref(),
                            scope.not_queues.as_deref(),
                            scope.dispositions.as_deref(),
                            scope.not_dispositions.as_deref(),
                            windows.as_deref(),
                            not_windows.as_deref(),
                            scope.except.as_deref(),
                            many,
                        )
                        .fetch_all(tx.conn())
                        .await
                        .map_err(crate::alerts::timed_out)?;
                        for row in rows {
                            found.push((
                                row.id,
                                row.alerted_at,
                                hit(
                                    "observable",
                                    format!("{}:{}", row.r#type, row.value),
                                    &row.r#type,
                                    row.value,
                                ),
                            ));
                        }
                    }
                    if !tags.is_empty() {
                        // an alert's tags are its observables' and its results', as the Tag filter's
                        let rows = sqlx::query!(
                            r#"SELECT DISTINCT r.id AS "id!", r.alerted_at AS "alerted_at!", t.tag AS "tag!"
                               FROM analysis.roots r
                               JOIN LATERAL (
                                   SELECT tag FROM analysis.observables o, unnest(o.tags) tag
                                   WHERE o.root_id = r.id
                                   UNION
                                   SELECT tag FROM analysis.results x, unnest(x.tags) tag
                                   WHERE x.root_id = r.id
                               ) t ON lower(t.tag) = ANY ($1::text[])
                               WHERE r.alerted_at IS NOT NULL
                                 AND search.in_scope(r.id, r.queue::text, r.disposition, r.alerted_at,
                                       $2, $3, $4, $5, $6::text::tstzmultirange,
                                       $7::text::tstzmultirange, $8)
                               ORDER BY 2 DESC, 1 DESC LIMIT $9"#,
                            tags.as_slice(),
                            scope.queues.as_deref(),
                            scope.not_queues.as_deref(),
                            scope.dispositions.as_deref(),
                            scope.not_dispositions.as_deref(),
                            windows.as_deref(),
                            not_windows.as_deref(),
                            scope.except.as_deref(),
                            many,
                        )
                        .fetch_all(tx.conn())
                        .await
                        .map_err(crate::alerts::timed_out)?;
                        for row in rows {
                            found.push((
                                row.id,
                                row.alerted_at,
                                hit("tag", format!("tag:{}", row.tag), "tag", row.tag),
                            ));
                        }
                    }
                    if !ids.is_empty() || !prefixes.is_empty() {
                        let rows = sqlx::query!(
                            r#"SELECT r.id, r.alerted_at AS "alerted_at!"
                               FROM analysis.roots r
                               WHERE r.alerted_at IS NOT NULL
                                 AND (r.id = ANY ($1::uuid[]) OR r.id::text LIKE ANY ($2::text[]))
                                 AND search.in_scope(r.id, r.queue::text, r.disposition, r.alerted_at,
                                       $3, $4, $5, $6, $7::text::tstzmultirange,
                                       $8::text::tstzmultirange, $9)
                               ORDER BY r.alerted_at DESC, r.id DESC LIMIT $10"#,
                            ids.as_slice(),
                            prefixes.as_slice(),
                            scope.queues.as_deref(),
                            scope.not_queues.as_deref(),
                            scope.dispositions.as_deref(),
                            scope.not_dispositions.as_deref(),
                            windows.as_deref(),
                            not_windows.as_deref(),
                            scope.except.as_deref(),
                            few,
                        )
                        .fetch_all(tx.conn())
                        .await
                        .map_err(crate::alerts::timed_out)?;
                        for row in rows {
                            found.push((
                                row.id,
                                row.alerted_at,
                                hit(
                                    "uuid",
                                    format!("uuid:{}", row.id),
                                    "alert uuid",
                                    row.id.to_string(),
                                ),
                            ));
                        }
                    }
                    Ok(found)
                })
            })
            .await?;
        let mut order: Vec<(DateTime<Utc>, Uuid)> = Vec::new();
        let mut hits: HashMap<Uuid, Vec<SearchHit>> = HashMap::new();
        for (alert, alerted_at, hit) in found {
            let list = hits.entry(alert).or_insert_with(|| {
                order.push((alerted_at, alert));
                Vec::new()
            });
            if list.iter().all(|existing| existing.key != hit.key) {
                list.push(hit);
            }
        }
        order.sort_by(|a, b| b.cmp(a));
        Ok(order
            .into_iter()
            .take(limit)
            .filter_map(|(_, alert)| hits.remove(&alert).map(|hits| (alert, hits)))
            .collect())
    }

    /// Indexes the next alert whose index is out of date (`search.due`), or returns None when nothing
    /// is due. It needs `search:index`, which ACE's indexer holds (`indexer_actor`); `run_worker` calls
    /// it. A service with no index is `Unconfigured`.
    pub async fn index_due(&self, actor: &Actor) -> Result<Option<Indexed>, ServiceError> {
        if !self.gate.allowed(actor, &SEARCH_INDEX).await? {
            tracing::warn!(%actor, permission = %SEARCH_INDEX, action = "index_due", "permission denied");
            return Err(ServiceError::PermissionDenied {
                actor: actor.to_string(),
                permission: SEARCH_INDEX.clone(),
            });
        }
        let Some(index) = &self.search else {
            return Err(ServiceError::Unconfigured(
                "this node has no search index".to_owned(),
            ));
        };
        Ok(index.index_next().await?)
    }
}

const NO_INDEX: &str = "The text wasn't searched: this server has no search index.";
const LANES_FAILED: &str = "The text search failed, so its matches are missing. Try again.";

/// `ace serve`'s indexer: indexes every due alert (`Service::index_due`), then waits for the next
/// completion (`ace_core::queue::Completions`) or `poll`, in case a notification was lost, until
/// `stop` fires. Each alert it indexes is one log line, ace3's `search_index_task_complete`. A failure
/// of the index itself is logged and tried again after the wait.
pub async fn run_worker(service: Service, poll: Duration, stop: CancellationToken) {
    let actor = indexer_actor();
    let mut completions = None;
    loop {
        loop {
            if stop.is_cancelled() {
                return;
            }
            let started = Instant::now();
            match service.index_due(&actor).await {
                Ok(Some(indexed)) => match &indexed.error {
                    Some(error) => tracing::error!(
                        alert_uuid = %indexed.root,
                        elapsed_ms = elapsed(started),
                        "indexing an alert for search failed: {error}"
                    ),
                    None => tracing::info!(
                        alert_uuid = %indexed.root,
                        documents = indexed.documents,
                        chunks = indexed.chunks,
                        left_out = indexed.left_out,
                        skipped = indexed.skipped.as_deref(),
                        elapsed_ms = elapsed(started),
                        "indexed an alert for search"
                    ),
                },
                Ok(None) => break,
                Err(e) => {
                    tracing::error!("the search indexer failed: {e}");
                    break;
                }
            }
        }
        if completions.is_none() {
            match ace_core::queue::Completions::listen(service.gate.db()).await {
                Ok(listening) => completions = Some(listening),
                Err(e) => tracing::warn!("listening for completions failed; polling: {e}"),
            }
        }
        let wait = async {
            match completions.as_mut() {
                Some(listening) => listening.next(poll).await.map(|_| ()),
                None => {
                    tokio::time::sleep(poll).await;
                    Ok(())
                }
            }
        };
        tokio::select! {
            _ = stop.cancelled() => return,
            waited = wait => {
                if let Err(e) = waited {
                    tracing::warn!("the completions listener failed; listening again: {e}");
                    completions = None;
                }
            }
        }
    }
}
