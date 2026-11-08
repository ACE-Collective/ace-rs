//! The alert list (PLAN.md 5.10): ace3's `analysis/manage.html` and its partials `_manage_filter_bar.html`,
//! `_manage_alert_table.html`, `_manage_columns.html`, `_manage_column_chooser.html`, `_manage_refresh.html`
//! and `alert_filter_input.html`, at `/`, where ace3's home page goes.
//!
//! The list reads through `Service::alerts` with the alert screen's filters (`ace_service::filters`), the
//! same model and query as the JSON API's list, so a share link means the same in both. The page's state is
//! its URL: `f` repeated, in ace3's share-link encoding, `sort`, `dir`, `size` and `after`, the cursor. ace3
//! keeps a session's filter, sort and page in its session and in scratch rows, and its share link is a
//! second form of it; here the URL is both, so a reload, the back button and a copied link all show the same
//! list, and nothing is written to look at one. Every control is a link or a form, so the page works
//! without its script:
//! - The filter bar is ace3's: each filter as a chip whose values and name are links that remove them, the
//!   quick filters (the user's pinned saved filters) as links, Reset (`disposition:OPEN`, ace3's default
//!   but for its owner and queue filters) and Clear.
//! - ace3's filter modal is a form whose fields fold one filter into the URL's and come back to it
//!   (`ListQuery::parse`). An unknown filter in a link is left out with a warning, as ace3's link decoder
//!   does; a malformed one shows the list without filters, saying why, where ace3 redirects to a bare page.
//! - The columns are 5.7's `manage_columns` preference, and ace3's drag-and-drop chooser is a form per
//!   move, show or hide, which writes it through `Service::set_preference`.
//! - Saved filters are `Service::saved_filters`, and the forms here save one, delete one and pin or unpin
//!   one as a quick filter, each through the service with its audit row. They post to
//!   `crate::saved_filters`, whose manage page, linked as "Manage…", renames and reorders them (5.11).
//! - A column header sorts by it, ace3's orders that ace4's alerts have fields for, and the pager is a
//!   keyset: First and Next. ace3's offset pager also jumps back and to the end, which a keyset can't do
//!   without a second cursor; the back button goes back.
//! - Export goes to the JSON API's CSV and NDJSON exports with the same filters, in the viewer's timezone.
//!
//! Refresh: ace3's page polls `manage_refresh` every 30 seconds, while the tab is visible and no dialog is
//! open, and morphs in the new list. This does the same with Datastar: `data-on-interval` gets
//! `/alerts/list`, the same query, every `REFRESH_SECONDS` while `document.hidden` is false, and the answer
//! is the list's fragment, which Datastar morphs in by its id. It's a bounded poll, not 5.8's stream,
//! because what changes a list is any alert's arrival or disposition, which nothing notifies, and a list's
//! read is a page, not a tree. Its bounds, as 5.8's: the interval is the server's, in the page; a refresh
//! reads one page, of at most `MAX_PAGE_SIZE`, under the list's `LIST_TIMEOUT`; at most
//! `REFRESH_LIMITS` refreshes run at once in all and for one user, and past either the answer is 503 and
//! the page stays as it was; each one authenticates again, so a logout ends it, a Datastar request without
//! a session getting 401; and it holds nothing between polls.
//!
//! Selection: a row's checkbox belongs to the bulk form outside the refreshed fragment (`form="bulk"`), so
//! a plain submit sends the ticked rows. Datastar keeps the ticked ids in `$_sel`, as ace3 does, and each
//! checkbox's `data-effect` ticks it again after a refresh morphs the list. An id is a uuid, and the
//! expressions hold no outside text: the refresh URL is read from `data-refresh`, an attribute askama
//! escapes, through `el.dataset`.
//!
//! Bulk disposition is ace3's "Set Disposition" on the ticked rows. Each alert is its own
//! `Service::disposition`, which checks `alert:write` and writes its audit row, so the result is per alert:
//! the page lists the alerts it dispositioned and those it couldn't, with why. ace3's runs them in one
//! transaction and skips the ones another analyst owns; ace4's alerts have no owner. At most
//! `MAX_BULK` alerts go in one request. ace3's other bulk actions (review, comment, ownership, tags,
//! remediation, events, add observable) come with what they write.
//!
//! What ace3's page has that this leaves out: its search box (7.11), the remediation, queue and owner
//! columns and the queue-mix warning, the tag badges and comments under a title, the SVS status, and the
//! favicon dot.

use std::collections::HashMap;

use ace_service::filters::{self, DISPOSITIONS, FilterKind, FilterScreen};
use ace_service::{
    AlertPage, AlertQuery, AlertSort, AlertSummary, AnalysisState, FilterEntry, FilterValue,
    MANAGE_COLUMNS, ManageColumn, ManageColumnsPreference, PreferenceValue, SavedFilter,
    ServiceError,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use uuid::Uuid;

use crate::Gui;
use crate::session::{Failure, SignedIn, local_path, render, see_other};
use crate::templates::Layout;

/// A page's alerts when the URL doesn't say, ace3's `page_size`.
pub const DEFAULT_PAGE_SIZE: u32 = 50;
/// The most alerts one page of the list draws.
pub const MAX_PAGE_SIZE: u32 = 200;
/// How often an open list refreshes, ace3's `manage_auto_refresh_seconds`.
pub const REFRESH_SECONDS: u32 = 30;
/// How many refreshes run at once, in all and for one user.
pub const REFRESH_LIMITS: (usize, usize) = (64, 4);
/// The most alerts one bulk disposition takes.
pub const MAX_BULK: usize = 500;
/// The largest bulk form: `MAX_BULK` ids and the rest.
pub(crate) const MAX_BULK_FORM_BYTES: usize = 64 << 10;

/// The list as its URL asks for it.
#[derive(Debug, Clone, PartialEq)]
pub struct ListQuery {
    pub filters: Vec<FilterEntry>,
    pub sort: AlertSort,
    pub descending: bool,
    pub size: u32,
    pub after: Option<String>,
}

impl Default for ListQuery {
    fn default() -> Self {
        ListQuery {
            filters: Vec::new(),
            sort: AlertSort::AlertDate,
            descending: true,
            size: DEFAULT_PAGE_SIZE,
            after: None,
        }
    }
}

/// What a list URL read as: its query, the warnings of a link that names filters this list doesn't have,
/// why its filters couldn't be read, and whether the editor's form added one, which goes back to the
/// URL that holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub query: ListQuery,
    pub warnings: Vec<String>,
    pub error: Option<String>,
    pub added: bool,
}

/// The pairs of a query string or a form.
pub(crate) fn pairs(text: &[u8]) -> Vec<(String, String)> {
    serde_urlencoded::from_bytes(text).unwrap_or_default()
}

pub(crate) fn one<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

pub(crate) fn all(pairs: &[(String, String)], name: &str) -> Vec<String> {
    pairs
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .collect()
}

impl ListQuery {
    /// The list a URL's query asks for. A sort, direction, size or cursor that isn't one is an error, since
    /// only a hand-made URL has one.
    pub fn parse(pairs: &[(String, String)]) -> Result<Parsed, String> {
        let mut query = ListQuery::default();
        if let Some(sort) = one(pairs, "sort") {
            query.sort =
                AlertSort::named(sort).ok_or_else(|| format!("there's no order {sort:?}"))?;
        }
        query.descending = match one(pairs, "dir") {
            None | Some("desc") => true,
            Some("asc") => false,
            Some(other) => return Err(format!("dir is asc or desc, not {other:?}")),
        };
        if let Some(size) = one(pairs, "size") {
            query.size = size
                .parse()
                .ok()
                .filter(|size| (1..=MAX_PAGE_SIZE).contains(size))
                .ok_or_else(|| format!("a page holds 1 to {MAX_PAGE_SIZE} alerts"))?;
        }
        query.after = one(pairs, "after").map(str::to_owned);
        let (mut filters, warnings, mut error) =
            match filters::decode(FilterScreen::Alerts, &all(pairs, "f"), false) {
                Ok((filters, warnings)) => (filters, warnings, None),
                Err(error) => (
                    Vec::new(),
                    Vec::new(),
                    Some(format!(
                        "{error}; the list is shown without the link's filters"
                    )),
                ),
            };
        let mut added = false;
        if let Some(slug) = one(pairs, "add").filter(|slug| !slug.is_empty()) {
            let value = one(pairs, "value").unwrap_or("").trim().to_owned();
            match FilterScreen::Alerts
                .filters()
                .iter()
                .find(|spec| spec.slug == slug)
            {
                None => error = Some(format!("there's no filter {slug:?}")),
                Some(spec) => {
                    let value = match spec.kind {
                        FilterKind::Pair => FilterValue::Pair(
                            one(pairs, "type")
                                .map(str::trim)
                                .filter(|kind| !kind.is_empty())
                                .unwrap_or(filters::ANY_TYPE)
                                .to_owned(),
                            value,
                        ),
                        _ => FilterValue::Text(value),
                    };
                    let mut with = filters.clone();
                    with.push(FilterEntry::new(
                        spec.name,
                        one(pairs, "not").is_some(),
                        vec![value],
                    ));
                    match filters::check(FilterScreen::Alerts, &with) {
                        Ok(checked) => {
                            filters = checked;
                            added = true;
                        }
                        Err(why) => error = Some(why.to_string()),
                    }
                }
            }
            query.after = None;
        }
        query.filters = filters;
        Ok(Parsed {
            query,
            warnings,
            error,
            added,
        })
    }

    /// The filters' `f` values.
    pub fn f(&self) -> Vec<String> {
        filters::encode(FilterScreen::Alerts, &self.filters).unwrap_or_default()
    }

    fn pairs_with(
        &self,
        filters: &[FilterEntry],
        sort: AlertSort,
        descending: bool,
        after: Option<&str>,
    ) -> Vec<(&'static str, String)> {
        let mut pairs: Vec<(&'static str, String)> = filters::encode(FilterScreen::Alerts, filters)
            .unwrap_or_default()
            .into_iter()
            .map(|f| ("f", f))
            .collect();
        if sort != AlertSort::default() {
            pairs.push(("sort", sort.as_str().to_owned()));
        }
        if !descending {
            pairs.push(("dir", "asc".to_owned()));
        }
        if self.size != DEFAULT_PAGE_SIZE {
            pairs.push(("size", self.size.to_string()));
        }
        if let Some(after) = after {
            pairs.push(("after", after.to_owned()));
        }
        pairs
    }

    fn url(path: &str, pairs: &[(&'static str, String)]) -> String {
        if pairs.is_empty() {
            return path.to_owned();
        }
        format!(
            "{path}?{}",
            serde_urlencoded::to_string(pairs).expect("pairs of text encode")
        )
    }

    /// This list at another path, such as its refresh, with its cursor.
    pub fn at(&self, path: &str) -> String {
        ListQuery::url(
            path,
            &self.pairs_with(
                &self.filters,
                self.sort,
                self.descending,
                self.after.as_deref(),
            ),
        )
    }

    /// The first page of this list with other filters.
    pub(crate) fn with_filters(&self, filters: &[FilterEntry]) -> String {
        ListQuery::url(
            "/",
            &self.pairs_with(filters, self.sort, self.descending, None),
        )
    }

    /// The first page in another order.
    fn sorted(&self, sort: AlertSort, descending: bool) -> String {
        ListQuery::url("/", &self.pairs_with(&self.filters, sort, descending, None))
    }

    fn page(&self, after: Option<&str>) -> String {
        ListQuery::url(
            "/",
            &self.pairs_with(&self.filters, self.sort, self.descending, after),
        )
    }

    fn alert_query(&self, tz: Tz) -> AlertQuery {
        AlertQuery {
            filters: self.filters.clone(),
            sort: self.sort,
            descending: self.descending,
            tz,
        }
    }
}

/// A column's header: its label, and the link that sorts by it, if it sorts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub id: &'static str,
    pub label: String,
    pub href: Option<String>,
    /// `↓` or `↑` on the column the list is sorted by, as ace3's.
    pub arrow: &'static str,
}

/// One cell of a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub id: &'static str,
    pub text: String,
    pub title: Option<String>,
    pub href: Option<String>,
}

/// One alert's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: Uuid,
    pub cells: Vec<Cell>,
}

/// The list's table and pager: what the page includes and what a refresh sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertList {
    pub headers: Vec<Header>,
    pub rows: Vec<Row>,
    /// How many alerts the filters match.
    pub total: i64,
    /// The first page, when this isn't it.
    pub first: Option<String>,
    pub next: Option<String>,
    /// The page's ids as JSON, for the box that ticks every row.
    pub ids: String,
}

/// A filter in the bar, and links that take it or one of its values away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chip {
    pub name: String,
    pub inverted: bool,
    pub remove: String,
    pub values: Vec<(String, String)>,
}

/// A quick filter's badge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Badge {
    pub label: String,
    pub href: String,
    pub current: bool,
    /// How many alerts it matches, when its indicator is on.
    pub count: Option<i64>,
}

/// A saved filter in the manage list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub href: String,
    pub quick: bool,
}

/// A column in the chooser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnChoice {
    pub id: &'static str,
    pub label: &'static str,
    pub shown: bool,
    pub required: bool,
    pub first: bool,
    pub last: bool,
}

/// The column chooser's rows for a `manage_columns` preference, in its order.
pub fn column_choices(columns: &ManageColumnsPreference) -> Vec<ColumnChoice> {
    let order: Vec<&'static ManageColumn> = columns
        .order
        .iter()
        .filter_map(|id| MANAGE_COLUMNS.iter().find(|column| column.id == id))
        .collect();
    order
        .iter()
        .enumerate()
        .map(|(at, column)| ColumnChoice {
            id: column.id,
            label: column.label,
            shown: !columns.hidden.iter().any(|id| id == column.id),
            required: column.required,
            first: at == 0,
            last: at + 1 == order.len(),
        })
        .collect()
}

/// A filter the editor can add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorFilter {
    pub slug: &'static str,
    pub name: &'static str,
    pub hint: &'static str,
}

/// Everything the page shows besides its layout, from what the service read: the view function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListView {
    pub list: AlertList,
    pub chips: Vec<Chip>,
    pub f: Vec<String>,
    /// This page, for the forms to come back to.
    pub here: String,
    /// The saved filters' manage page, coming back here.
    pub manage: String,
    pub share: String,
    pub reset: String,
    pub clear: String,
    pub refresh: String,
    pub export_csv: String,
    pub export_ndjson: String,
    pub badges: Vec<Badge>,
    pub saved: Vec<Saved>,
    pub columns: Vec<ColumnChoice>,
    pub editor: Vec<EditorFilter>,
    /// ace3's filters this list doesn't have yet, with why.
    pub left_out: Vec<(&'static str, &'static str)>,
    pub dispositions: &'static [&'static str],
    pub warnings: Vec<String>,
    pub error: Option<String>,
    pub refresh_seconds: u32,
}

fn time_in(time: DateTime<Utc>, tz: Tz) -> String {
    time.with_timezone(&tz)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn status(state: AnalysisState) -> &'static str {
    match state {
        AnalysisState::Running => "Analyzing",
        AnalysisState::Complete => "Complete",
        AnalysisState::Cancelled => "Cancelled",
    }
}

/// The filters with this one in place of any of its name, ace3's overlay when a row's value is clicked.
fn overlaid(filters: &[FilterEntry], name: &str, value: &str) -> Vec<FilterEntry> {
    let mut out: Vec<FilterEntry> = filters
        .iter()
        .filter(|entry| entry.name != name)
        .cloned()
        .collect();
    out.push(FilterEntry::text(name, false, &[value]));
    out
}

fn row(alert: &AlertSummary, columns: &[&ManageColumn], query: &ListQuery, tz: Tz) -> Row {
    let disposition = alert
        .disposition
        .clone()
        .unwrap_or_else(|| "OPEN".to_owned());
    let cells = columns
        .iter()
        .map(|column| match column.id {
            "date" => Cell {
                id: "date",
                text: time_in(alert.alerted_at, tz),
                title: Some(alert.alerted_at.to_rfc3339()),
                href: None,
            },
            "description" => Cell {
                id: "description",
                text: alert.title.clone(),
                title: None,
                href: Some(format!("/alerts/{}", alert.id)),
            },
            "disposition" => Cell {
                id: "disposition",
                href: Some(query.with_filters(&overlaid(
                    &query.filters,
                    "Disposition",
                    &disposition,
                ))),
                text: disposition.clone(),
                title: None,
            },
            _ => Cell {
                id: "status",
                text: status(alert.analysis).to_owned(),
                title: None,
                href: None,
            },
        })
        .collect();
    Row {
        id: alert.id,
        cells,
    }
}

/// The list's table and pager for a page the service read.
pub fn alert_list(
    page: &AlertPage,
    query: &ListQuery,
    columns: &ManageColumnsPreference,
    tz: Tz,
) -> AlertList {
    let visible = columns.visible();
    let zone = Utc::now().with_timezone(&tz).format("%Z").to_string();
    let headers = visible
        .iter()
        .map(|column| {
            let current = column.sort == Some(query.sort);
            let label = match column.id {
                "date" => format!("Date ({zone})"),
                "description" => format!("Alert ({})", page.total),
                _ => column.label.to_owned(),
            };
            Header {
                id: column.id,
                label,
                href: column.sort.map(|sort| {
                    let descending = if current {
                        !query.descending
                    } else {
                        sort == AlertSort::AlertDate
                    };
                    query.sorted(sort, descending)
                }),
                arrow: match (current, query.descending) {
                    (false, _) => "",
                    (true, true) => "↓",
                    (true, false) => "↑",
                },
            }
        })
        .collect();
    let rows = page
        .alerts
        .iter()
        .map(|alert| row(alert, &visible, query, tz))
        .collect();
    let ids: Vec<String> = page
        .alerts
        .iter()
        .map(|alert| alert.id.to_string())
        .collect();
    AlertList {
        headers,
        rows,
        total: page.total,
        first: query.after.as_ref().map(|_| query.page(None)),
        next: page.next.as_deref().map(|next| query.page(Some(next))),
        ids: serde_json::to_string(&ids).expect("ids are JSON"),
    }
}

/// The whole page's view: the view function the page draws with and a test calls with fixtures.
#[allow(clippy::too_many_arguments)]
pub fn list_view(
    page: &AlertPage,
    query: &ListQuery,
    columns: &ManageColumnsPreference,
    saved: &[SavedFilter],
    counts: &HashMap<Uuid, i64>,
    tz: Tz,
    warnings: Vec<String>,
    error: Option<String>,
) -> ListView {
    let chips = query
        .filters
        .iter()
        .enumerate()
        .map(|(at, entry)| {
            let without: Vec<FilterEntry> = query
                .filters
                .iter()
                .enumerate()
                .filter(|(other, _)| *other != at)
                .map(|(_, entry)| entry.clone())
                .collect();
            let values = entry
                .values
                .iter()
                .enumerate()
                .map(|(which, value)| {
                    let text = match value {
                        FilterValue::Text(text) => text.clone(),
                        FilterValue::Pair(kind, value) => format!("{kind}:{value}"),
                    };
                    let mut fewer = query.filters.clone();
                    fewer[at].values.remove(which);
                    if fewer[at].values.is_empty() {
                        fewer.remove(at);
                    }
                    (text, query.with_filters(&fewer))
                })
                .collect();
            Chip {
                name: entry.name.clone(),
                inverted: entry.inverted,
                remove: query.with_filters(&without),
                values,
            }
        })
        .collect();
    let f = query.f();
    let current = |filter: &SavedFilter| {
        filters::encode(FilterScreen::Alerts, &filter.filters).ok() == Some(f.clone())
    };
    let href_of = |filter: &SavedFilter| crate::saved_filters::open_href(query, filter);
    let badges = saved
        .iter()
        .filter(|filter| filter.quick_filter_order.is_some())
        .map(|filter| Badge {
            label: filter.name.clone(),
            href: href_of(filter),
            current: current(filter),
            count: filter
                .quick_filter_indicator
                .then(|| counts.get(&filter.id).copied())
                .flatten(),
        })
        .collect();
    let saved_rows = saved
        .iter()
        .map(|filter| Saved {
            id: filter.id,
            name: filter.name.clone(),
            description: filter.description.clone().unwrap_or_default(),
            href: href_of(filter),
            quick: filter.quick_filter_order.is_some(),
        })
        .collect();
    let chooser = column_choices(columns);
    let export = |format: &str| {
        let mut pairs: Vec<(&'static str, String)> = f.iter().map(|f| ("f", f.clone())).collect();
        pairs.push(("sort", query.sort.as_str().to_owned()));
        pairs.push((
            "dir",
            if query.descending { "desc" } else { "asc" }.to_owned(),
        ));
        pairs.push(("tz", tz.name().to_owned()));
        ListQuery::url(&format!("/api/alerts/v1/alerts/export/{format}"), &pairs)
    };
    ListView {
        list: alert_list(page, query, columns, tz),
        chips,
        here: query.at("/"),
        manage: crate::saved_filters::manage_url(&query.at("/")),
        share: query.with_filters(&query.filters),
        reset: query.with_filters(&[FilterEntry::text("Disposition", false, &["OPEN"])]),
        clear: query.with_filters(&[]),
        refresh: query.at("/alerts/list"),
        export_csv: export("csv"),
        export_ndjson: export("ndjson"),
        f,
        badges,
        saved: saved_rows,
        columns: chooser,
        editor: FilterScreen::Alerts
            .filters()
            .iter()
            .map(|spec| EditorFilter {
                slug: spec.slug,
                name: spec.name,
                hint: spec.hint,
            })
            .collect(),
        left_out: FilterScreen::Alerts
            .left_out()
            .iter()
            .map(|gone| (gone.name, gone.why))
            .collect(),
        dispositions: DISPOSITIONS,
        warnings,
        error,
        refresh_seconds: REFRESH_SECONDS,
    }
}

/// `/`, the alert list.
#[derive(Debug, Template)]
#[template(path = "alerts.html")]
pub struct ListPage {
    pub layout: Layout,
    pub view: ListView,
    pub list: AlertList,
}

/// The list's table on its own: what the page includes and a refresh sends.
#[derive(Debug, Template)]
#[template(path = "alert_list.html")]
pub struct AlertListFragment {
    pub list: AlertList,
}

/// What a bulk disposition did.
#[derive(Debug, Template)]
#[template(path = "bulk.html")]
pub struct BulkPage {
    pub layout: Layout,
    pub disposition: String,
    pub done: Vec<Uuid>,
    pub failed: Vec<(Uuid, String)>,
    pub next: String,
}

/// The viewer's timezone, UTC when it can't be read.
async fn viewer_tz(gui: &Gui, viewer: &SignedIn) -> Tz {
    match gui.service.own_account(&viewer.actor).await {
        Ok(user) => user.timezone.parse().unwrap_or(Tz::UTC),
        Err(_) => Tz::UTC,
    }
}

/// `GET /`.
pub(crate) async fn page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    RawQuery(raw): RawQuery,
) -> Response {
    let pairs = pairs(raw.as_deref().unwrap_or("").as_bytes());
    let parsed = match ListQuery::parse(&pairs) {
        Ok(parsed) => parsed,
        Err(why) => return Failure::new(StatusCode::BAD_REQUEST, why, &parts).into_response(),
    };
    if parsed.added {
        return see_other(&parsed.query.at("/"), None);
    }
    let query = parsed.query;
    let tz = viewer_tz(&gui, &viewer).await;
    let actor = &viewer.actor;
    let page = match gui
        .service
        .alerts(
            actor,
            &query.alert_query(tz),
            Some(query.size),
            query.after.as_deref(),
        )
        .await
    {
        Ok(page) => page,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let columns = gui.service.manage_columns(actor).await.unwrap_or_else(|error| {
        tracing::warn!(%actor, "reading manage_columns failed, so the list has the default: {error}");
        ManageColumnsPreference::default()
    });
    let saved = match gui.service.saved_filters(actor, FilterScreen::Alerts).await {
        Ok(saved) => saved,
        Err(ServiceError::Forbidden(_)) => Vec::new(),
        Err(error) => {
            tracing::warn!(%actor, "reading saved filters failed, so the list has none: {error}");
            Vec::new()
        }
    };
    let mut counts = HashMap::new();
    for filter in saved
        .iter()
        .filter(|filter| filter.quick_filter_order.is_some() && filter.quick_filter_indicator)
    {
        let counted = AlertQuery {
            filters: filter.filters.clone(),
            tz,
            ..AlertQuery::default()
        };
        if let Ok(found) = gui.service.alerts(actor, &counted, Some(1), None).await {
            counts.insert(filter.id, found.total);
        }
    }
    let view = list_view(
        &page,
        &query,
        &columns,
        &saved,
        &counts,
        tz,
        parsed.warnings,
        parsed.error,
    );
    render(&ListPage {
        layout: viewer.layout,
        list: view.list.clone(),
        view,
    })
}

/// `GET /alerts/list`: the list's fragment, for the page's refresh.
pub(crate) async fn refresh(
    State(gui): State<Gui>,
    viewer: SignedIn,
    RawQuery(raw): RawQuery,
) -> Response {
    let Some(_place) = gui.refreshes.admit(&viewer.actor) else {
        tracing::warn!(actor = %viewer.actor, "a list refresh was refused: too many are running");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let pairs = pairs(raw.as_deref().unwrap_or("").as_bytes());
    let query = match ListQuery::parse(&pairs) {
        Ok(parsed) if parsed.error.is_none() && !parsed.added => parsed.query,
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    let tz = viewer_tz(&gui, &viewer).await;
    let actor = &viewer.actor;
    let page = match gui
        .service
        .alerts(
            actor,
            &query.alert_query(tz),
            Some(query.size),
            query.after.as_deref(),
        )
        .await
    {
        Ok(page) => page,
        Err(ServiceError::PermissionDenied { .. }) => return StatusCode::FORBIDDEN.into_response(),
        Err(ServiceError::InvalidRequest(_)) => return StatusCode::BAD_REQUEST.into_response(),
        Err(error) => {
            tracing::error!("a list refresh failed: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let columns = gui.service.manage_columns(actor).await.unwrap_or_default();
    render(&AlertListFragment {
        list: alert_list(&page, &query, &columns, tz),
    })
}

fn next_of(form: &[(String, String)]) -> String {
    one(form, "next")
        .and_then(local_path)
        .unwrap_or("/")
        .to_owned()
}

/// `POST /alerts/disposition`: ace3's bulk "Set Disposition", each alert through the service.
pub(crate) async fn bulk_disposition(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let next = next_of(&form);
    let Some(disposition) = one(&form, "disposition").map(str::to_owned) else {
        return Failure::new(StatusCode::BAD_REQUEST, "Choose a disposition.", &parts)
            .into_response();
    };
    let ids = all(&form, "alert");
    if ids.is_empty() {
        return Failure::new(StatusCode::BAD_REQUEST, "No alerts were ticked.", &parts)
            .into_response();
    }
    if ids.len() > MAX_BULK {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            format!("At most {MAX_BULK} alerts are dispositioned at once."),
            &parts,
        )
        .into_response();
    }
    let mut done = Vec::new();
    let mut failed = Vec::new();
    for raw in ids {
        let Ok(id) = raw.parse::<Uuid>() else {
            failed.push((Uuid::nil(), format!("{raw:?} isn't an alert's id")));
            continue;
        };
        if done.contains(&id) {
            continue;
        }
        match gui
            .service
            .disposition(&viewer.actor, id, &disposition)
            .await
        {
            Ok(_) => done.push(id),
            Err(ServiceError::InvalidRequest(why)) => {
                return Failure::new(StatusCode::BAD_REQUEST, why, &parts).into_response();
            }
            Err(error @ (ServiceError::PermissionDenied { .. } | ServiceError::NotFound(_))) => {
                failed.push((id, error.to_string()));
            }
            Err(error) => {
                tracing::warn!(actor = %viewer.actor, "a bulk disposition failed on {id}: {error}");
                failed.push((id, "it couldn't be dispositioned".to_owned()));
            }
        }
    }
    let status = if done.is_empty() && !failed.is_empty() {
        StatusCode::FORBIDDEN
    } else {
        StatusCode::OK
    };
    let mut response = render(&BulkPage {
        layout: viewer.layout,
        disposition,
        done,
        failed,
        next,
    });
    *response.status_mut() = status;
    response
}

/// `POST /preferences/manage-columns`: one move, show or hide of a column, or a reset, written to the
/// `manage_columns` preference as ace3's chooser writes it.
pub(crate) async fn set_columns(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let next = next_of(&form);
    let action = one(&form, "action").unwrap_or("");
    if action == "reset" {
        return match gui
            .service
            .reset_preference(&viewer.actor, ace_service::PreferenceKey::ManageColumns)
            .await
        {
            Ok(_) => see_other(&next, None),
            Err(error) => Failure::from_service(error, &parts).into_response(),
        };
    }
    let Some(column) =
        one(&form, "column").and_then(|id| MANAGE_COLUMNS.iter().find(|column| column.id == id))
    else {
        return Failure::new(StatusCode::BAD_REQUEST, "There's no such column.", &parts)
            .into_response();
    };
    let mut columns = match gui.service.manage_columns(&viewer.actor).await {
        Ok(columns) => columns,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let at = columns
        .order
        .iter()
        .position(|id| id == column.id)
        .expect("a normalized order has every column");
    match action {
        "up" if at > 0 => columns.order.swap(at, at - 1),
        "down" if at + 1 < columns.order.len() => columns.order.swap(at, at + 1),
        "up" | "down" => {}
        "hide" => columns.hidden.push(column.id.to_owned()),
        "show" => columns.hidden.retain(|id| id != column.id),
        _ => {
            return Failure::new(
                StatusCode::BAD_REQUEST,
                "action is up, down, hide, show or reset.",
                &parts,
            )
            .into_response();
        }
    }
    let value = PreferenceValue::ManageColumns(columns.normalized());
    match gui.service.set_preference(&viewer.actor, &value).await {
        Ok(_) => see_other(&next, None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
