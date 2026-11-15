//! Search (PLAN.md 7.11): ace3's manage-page search box and its "similar alerts" action,
//! `app/analysis/views/search.py` and the search rows of `analysis/manage.html`, over
//! `Service::search_alerts` and `Service::similar_alerts`.
//!
//! | ace3 | here |
//! |---|---|
//! | `POST /ace/search`, then the manage page | `GET /search?q=…` |
//! | `GET /ace/search/similar/<uuid>`, then the manage page | `GET /search?similar=<uuid>` |
//! | `POST /ace/search/include_tests` | the page's own link, `tests=1` |
//!
//! ace3 keeps the search in the session and draws it on the manage page. Here a search is a page of
//! its own whose URL says all of it, as the alert list's does: the query (`q`) or the alert to find
//! others like (`similar`), the alert screen's filters as a share link carries them (`f`, repeated),
//! whether test-run alerts are searched (`tests=1`), and the page (`page`, from 1). So a search can be
//! bookmarked and shared, the browser's Back leaves it, and nothing is written. The alert list's search
//! box is a form that asks this page with the list's filters, and an alert's page links to its similar
//! alerts.
//!
//! Each alert found is a row with its title, queue, disposition, owner and date, and under it its
//! tier as plain text and up to five of its hits, each a kind, a title and a snippet, as ace3's rows
//! are. A listing, which has no evidence, has no such line. The query's errors, the "did you mean" hint
//! for a bare indicator and a lane that didn't run are notices above the count, and the count says how
//! many test-run alerts were left out, with a link that includes them. The page doesn't refresh
//! itself, as ace3's list doesn't during a search.
//!
//! It needs `alert:read`, which the service checks: a viewer without it gets 403, a signed-out one the
//! login page, an id that isn't one or a page out of range 400, and `similar` naming no alert 404.
//! Everything shown is text other people wrote, an alert's title, an email's body, a command line: the
//! template escapes each, and a snippet is cut to a few hundred characters as text, never as markup.
//!
//! Left out of ace3's: the search's place on the manage page itself, with its bulk actions over the
//! results. A result's link opens the alert, and the alert list takes the same filters.

use ace_service::filters::{self, FilterScreen};
use ace_service::search::{MAX_QUERY_CHARS, SearchRequest, SearchResponse, SimilarRequest};
use ace_service::{FilterEntry, ServiceError};
use askama::Template;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono_tz::Tz;
use uuid::Uuid;

use crate::Gui;
use crate::list::{all, one, pairs, time_in, viewer_tz};
use crate::session::{Failure, SignedIn, render};
use crate::templates::Layout;

/// The alerts on one page of a search.
pub const PAGE_SIZE: u32 = 20;
/// The alerts on one page of similar alerts.
pub const SIMILAR_PAGE_SIZE: u32 = 10;
/// The hits shown under one alert: ace3's five.
pub const MAX_HITS_SHOWN: usize = 5;
/// The most characters of a hit's text shown.
pub const MAX_SNIPPET_CHARS: usize = 300;
/// The last page a URL may ask for.
const MAX_PAGE: u32 = 500;

/// What a search page's URL asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchQuery {
    pub q: String,
    /// The alert to find others like, in place of a query.
    pub similar: Option<Uuid>,
    pub filters: Vec<FilterEntry>,
    /// Whether test-run alerts are searched.
    pub tests: bool,
    /// From 1.
    pub page: u32,
}

impl SearchQuery {
    /// The search a URL's query asks for, with what its filters warn of. A `similar` that isn't an id
    /// or a `page` that isn't a number in range is an error, since only a hand-made URL has one; a
    /// filter that can't be used is one too, since the search would otherwise return more than asked.
    pub fn parse(pairs: &[(String, String)]) -> Result<(SearchQuery, Vec<String>), String> {
        let q = one(pairs, "q").unwrap_or("").trim().to_owned();
        if q.chars().count() > MAX_QUERY_CHARS {
            return Err(format!("A query has at most {MAX_QUERY_CHARS} characters."));
        }
        let similar = match one(pairs, "similar").filter(|id| !id.is_empty()) {
            None => None,
            Some(id) => Some(
                id.parse::<Uuid>()
                    .map_err(|_| format!("{id:?} isn't an alert's id."))?,
            ),
        };
        let page = match one(pairs, "page") {
            None => 1,
            Some(page) => page
                .parse::<u32>()
                .ok()
                .filter(|page| (1..=MAX_PAGE).contains(page))
                .ok_or_else(|| format!("{page:?} isn't a page from 1 to {MAX_PAGE}."))?,
        };
        // strict, where the alert list warns of a filter it doesn't have and lists without it: a
        // search without one of its filters finds what wasn't asked for
        let (filters, warnings) = filters::decode(FilterScreen::Alerts, &all(pairs, "f"), true)
            .map_err(|error| format!("That filter couldn't be used: {error}"))?;
        Ok((
            SearchQuery {
                q,
                similar,
                filters,
                tests: one(pairs, "tests") == Some("1"),
                page,
            },
            warnings,
        ))
    }

    fn page_size(&self) -> u32 {
        if self.similar.is_some() {
            SIMILAR_PAGE_SIZE
        } else {
            PAGE_SIZE
        }
    }

    /// This search's URL, at a page and with or without test-run alerts.
    pub fn url(&self, page: u32, tests: bool) -> String {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        match self.similar {
            Some(similar) => pairs.push(("similar", similar.to_string())),
            None => pairs.push(("q", self.q.clone())),
        }
        for f in filters::encode(FilterScreen::Alerts, &self.filters).unwrap_or_default() {
            pairs.push(("f", f));
        }
        if tests {
            pairs.push(("tests", "1".to_owned()));
        }
        if page > 1 {
            pairs.push(("page", page.to_string()));
        }
        format!(
            "/search?{}",
            serde_urlencoded::to_string(pairs).expect("pairs of text encode")
        )
    }
}

/// One hit under an alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HitView {
    /// `alert`, `comment`, `detection`, `analysis`, `context`, `observable`, `tag` or `uuid`: also the
    /// hit's class, so it's kept to those.
    pub kind: &'static str,
    pub title: Option<String>,
    pub text: String,
}

/// One alert a search found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRow {
    pub href: String,
    pub rank: usize,
    pub title: String,
    pub alerted: String,
    pub queue: String,
    pub disposition: String,
    pub owner: String,
    /// `exact`, `strong`, `good` or `weak`; None for a listing.
    pub tier: Option<&'static str>,
    pub hits: Vec<HitView>,
}

/// What the search page draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchView {
    /// The query as it was typed, for the box.
    pub q: String,
    /// The alert others are like, when the page is of similar alerts: its link and its id.
    pub similar: Option<(String, String)>,
    /// The filters, as a share link carries them, for the form to keep.
    pub f: Vec<String>,
    /// The alert list with the same filters.
    pub list: String,
    /// Whether anything was asked: a page with no query and no filters only has the box.
    pub asked: bool,
    pub errors: Vec<String>,
    pub hint: Option<String>,
    pub warnings: Vec<String>,
    pub total: u64,
    /// How many test-run alerts were left out, and the link that includes them.
    pub left_out: Option<(u64, String)>,
    /// The link that leaves test-run alerts out again, when they're included.
    pub leave_out: Option<String>,
    pub rows: Vec<SearchRow>,
    pub previous: Option<String>,
    pub next: Option<String>,
}

#[derive(Template)]
#[template(path = "search.html")]
pub struct SearchPage {
    pub layout: Layout,
    pub view: SearchView,
}

fn kind(kind: &str) -> &'static str {
    match kind {
        "alert" => "alert",
        "comment" => "comment",
        "detection" => "detection",
        "analysis" => "analysis",
        "context" => "context",
        "observable" => "observable",
        "tag" => "tag",
        "uuid" => "uuid",
        _ => "other",
    }
}

fn snippet(text: &str) -> String {
    let mut out: String = text.chars().take(MAX_SNIPPET_CHARS).collect();
    if text.chars().count() > MAX_SNIPPET_CHARS {
        out.push('…');
    }
    out
}

/// The view of a search's answer.
pub fn search_view(
    query: &SearchQuery,
    response: Option<&SearchResponse>,
    warnings: Vec<String>,
    tz: Tz,
) -> SearchView {
    let f = filters::encode(FilterScreen::Alerts, &query.filters).unwrap_or_default();
    let list = if f.is_empty() {
        "/".to_owned()
    } else {
        format!(
            "/?{}",
            serde_urlencoded::to_string(f.iter().map(|f| ("f", f)).collect::<Vec<_>>())
                .expect("pairs of text encode")
        )
    };
    let mut view = SearchView {
        q: query.q.clone(),
        similar: query
            .similar
            .map(|id| (format!("/alerts/{id}"), id.to_string())),
        f,
        list,
        asked: response.is_some(),
        errors: Vec::new(),
        hint: None,
        warnings,
        total: 0,
        left_out: None,
        leave_out: None,
        rows: Vec::new(),
        previous: None,
        next: None,
    };
    let Some(response) = response else {
        return view;
    };
    view.errors.clone_from(&response.errors);
    view.hint.clone_from(&response.hint);
    view.warnings.extend(response.warnings.iter().cloned());
    view.total = response.total;
    view.left_out = response
        .excluded_test_alerts
        .filter(|left_out| *left_out > 0)
        .map(|left_out| (left_out, query.url(1, true)));
    view.leave_out = query.tests.then(|| query.url(1, false));
    view.rows = response
        .results
        .iter()
        .map(|result| SearchRow {
            href: format!("/alerts/{}", result.alert.id),
            rank: result.rank,
            title: result.alert.title.clone(),
            alerted: time_in(result.alert.alerted_at, tz),
            queue: result.alert.queue.clone(),
            disposition: result
                .alert
                .disposition
                .clone()
                .unwrap_or_else(|| "OPEN".to_owned()),
            owner: result
                .alert
                .owner
                .as_ref()
                .map(|owner| owner.name.clone())
                .unwrap_or_default(),
            tier: result.tier.map(|tier| tier.as_str()),
            hits: result
                .hits
                .iter()
                .take(MAX_HITS_SHOWN)
                .map(|hit| HitView {
                    kind: kind(&hit.kind),
                    title: hit.title.clone(),
                    text: snippet(&hit.text),
                })
                .collect(),
        })
        .collect();
    let shown = u64::from(query.page) * u64::from(query.page_size());
    view.previous = (query.page > 1).then(|| query.url(query.page - 1, query.tests));
    view.next = (shown < response.total && query.page < MAX_PAGE)
        .then(|| query.url(query.page + 1, query.tests));
    view
}

/// `GET /search`.
pub(crate) async fn page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    RawQuery(raw): RawQuery,
) -> Response {
    let pairs = pairs(raw.as_deref().unwrap_or("").as_bytes());
    let (query, warnings) = match SearchQuery::parse(&pairs) {
        Ok(parsed) => parsed,
        Err(why) => return Failure::new(StatusCode::BAD_REQUEST, why, &parts).into_response(),
    };
    let tz = viewer_tz(&gui, &viewer).await;
    let actor = &viewer.actor;
    let offset = (query.page - 1) * query.page_size();
    let response: Result<Option<SearchResponse>, ServiceError> = match query.similar {
        Some(alert) => gui
            .service
            .similar_alerts(
                actor,
                &SimilarRequest {
                    filters: query.filters.clone(),
                    tz,
                    limit: SIMILAR_PAGE_SIZE,
                    offset,
                    include_test_alerts: query.tests,
                    ..SimilarRequest::of(alert)
                },
            )
            .await
            .map(Some),
        None if query.q.is_empty() && query.filters.is_empty() => {
            // nothing asked yet: the box alone, once the viewer may search
            match gui.service.allowed(actor, &ace_service::ALERT_READ).await {
                Ok(true) => Ok(None),
                Ok(false) => {
                    return Failure::new(
                        StatusCode::FORBIDDEN,
                        "Searching alerts needs alert:read. Ask an administrator.",
                        &parts,
                    )
                    .into_response();
                }
                Err(error) => Err(error),
            }
        }
        None => gui
            .service
            .search_alerts(
                actor,
                &SearchRequest {
                    query: query.q.clone(),
                    filters: query.filters.clone(),
                    tz,
                    limit: PAGE_SIZE,
                    offset,
                    include_test_alerts: query.tests,
                    ..SearchRequest::default()
                },
            )
            .await
            .map(Some),
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    render(&SearchPage {
        layout: viewer.layout,
        view: search_view(&query, response.as_ref(), warnings, tz),
    })
}
