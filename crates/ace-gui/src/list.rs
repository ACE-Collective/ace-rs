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
//!   quick filters (the user's pinned saved filters) as links, Reset (ace3's default, `_default_filters`:
//!   `disposition:OPEN`, `owner:None,$USER` and `queue:$USER_QUEUE`, the open alerts that are nobody's or
//!   the viewer's, in the viewer's default queue) and Clear. ace3 writes the viewer's name and queue into
//!   the filter; here they're `$USER` and `$USER_QUEUE`, read when the list is, so a copied Reset link
//!   means the same for whoever opens it.
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
//! A range of rows is ticked as in ace3 since `5fb36276` (`manage_alerts.js`): shift+click on a row's box
//! sets every row from the last one clicked to this one to this one's new state, ticked or not, and
//! pressing on a box and dragging over other rows sets the rows between to the first box's new state,
//! putting back the rows the pointer leaves again. It is `static/select.js`, the page's one script of its
//! own, loaded as the graph's is: from this origin, with the response's nonce, so the policy is as it
//! was. It is a file and not Datastar expressions because the behaviour is four document handlers that
//! share state (the anchor, the drag) and one function, which as attributes would be the same code
//! written out four times in the page. It changes no box: it sends `#alert-page` one `ace-select` event
//! with the ids to tick and to untick, and the page's `data-on:ace-select` folds them into `$_sel`, so
//! the boxes follow `$_sel` as they do for a single click, and the bulk forms read them as before. At the
//! edges it is ace3's:
//! - The anchor is the row last clicked or dragged to, by its id, and outlives a refresh. If the refresh
//!   dropped that row, a shift+click ticks its own box only and becomes the anchor. A range reaches the
//!   rows between the two as the list is now, so a row a refresh brought in between them is in it, and
//!   nothing is ticked that isn't between the two rows the analyst chose.
//! - A shift+click that unticks its box unticks the range. A shift+click on the anchor itself is a plain
//!   click. With no anchor yet, the first shift+click is a plain click.
//! - The box at the head of the column ticks or unticks every row and leaves the anchor where it was.
//! - A drag started with shift held does nothing; one released outside the window ends when the pointer
//!   comes back with no button down; one released back on its first box leaves that box as the drag set
//!   it.
//!
//! Where it differs from ace3's script, each for a reason:
//! - ace3 sets each box and fires its change event, one at a time, and a shift+click waits a turn of the
//!   event loop so the clicked box's own change lands first. Here the range is one event that holds the
//!   clicked box too, so there's one write to `$_sel` and nothing to wait for.
//! - ace3's `preventDefault` on the press, which stops the rows' text being selected, also stops the box
//!   taking the focus. Here the script gives the box the focus, so Tab and Space carry on from the box
//!   that was clicked.
//! - The keyboard: Shift+Space on a focused box is a shift+click in a browser, so it ticks the range from
//!   the anchor, and a box toggled with Space is the anchor. ace3's handler reads the same click, so it
//!   should do the same, but nothing in ace3 says so or tests it; here the e2e's browser checks it.
//! - A drag acts when the pointer enters another row, not on every move within one.
//! - Without the script (it failed to load, or scripts are off) each box still ticks by itself and the
//!   bulk forms still post the ticked rows.
//!
//! Bulk disposition is ace3's "Set Disposition" on the ticked rows. Each alert is its own
//! `Service::disposition`, which checks `alert:write` and writes its audit row, so the result is per alert:
//! the page lists the alerts it dispositioned and those it couldn't, with why. ace3's runs them in one
//! transaction. As in ace3, an alert another analyst owns is left alone (PLAN.md 7.17): the page says so
//! in ace3's words (`left 1 alert owned by Jane alone`) and has a form that dispositions those too, taking
//! them. That form is ace3's selection guard (`selection_guard.js`), which asks before the request is
//! sent; here the first request leaves them alone and the second carries the confirmation, ace3's
//! `take_owned` field: `alert:owner` pairs naming who owned each alert when the analyst looked, so one
//! that changed hands since is left alone again. The menu offers the
//! site's dispositions an analyst may choose, in their order, as ace3's modal does (`Dispositions`), and the
//! filter editor's suggestions are all of them. A disposition with `show_save_to_event`, chosen in ace3's
//! modal, shows its Save to Event button, which opens the event modal for the alerts; here the answer page
//! has that button, a form to the add-to-event page with the alerts dispositioned, for a viewer with
//! `event:write`. The list's Disposition cell is a badge in the disposition's `css`. At most
//! `MAX_BULK` alerts go in one request. "Add to Event" is the same form's other button, which opens
//! `crate::events`' page with the ticked alerts (5.11's events area). ace3's other bulk actions (review,
//! comment, tags, remediation, add observable) come with what they write.
//!
//! Ownership (PLAN.md 7.17) is ace3's Take Ownership and Assign Ownership, on the ticked rows here and on
//! one alert on its page (`crate::alert`): two more buttons of the bulk form, for a viewer with
//! `alert:write`, which post to `/alerts/owner`, through `Service::change_alert_owner`. Assign offers the
//! enabled users and nobody, which unassigns. When nothing was left alone the answer goes back where it
//! came from, as ace3 refreshes its list; otherwise a page says what was left with whom, with the same
//! confirming form as a disposition's. The Owner column is ace3's: who owns the alert, which a click
//! narrows the list to, and its header sorts by it.
//!
//! The Queue column is ace3's (PLAN.md 7.13): the alert's queue, which a click narrows the list to, as a
//! click on a disposition does, and its header sorts by it. A person new to the list gets ace3's `Last 24h`
//! and `Last 7d` quick filters (`Service::seed_saved_filters`), written when the page is drawn and never by
//! the refresh, as in ace3.
//!
//! ace3's search box is the form above the filters, which asks `crate::search`'s page with the list's
//! filters (PLAN.md 7.11). What ace3's page has that this leaves out: the remediation column and the
//! queue-mix warning, the tag badges and comments under a title, and the favicon dot.

use std::collections::HashMap;

use ace_service::Dispositions;
use ace_service::filters::{self, FilterKind, FilterScreen};
use ace_service::{
    AlertPage, AlertQuery, AlertSort, AlertSummary, AnalysisState, FilterEntry, FilterValue,
    MANAGE_COLUMNS, ManageColumn, ManageColumnsPreference, OwnerChoice, OwnershipCheck,
    PreferenceValue, SavedFilter, ServiceError, SkippedAlert, UserId, describe_skipped,
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
    /// A badge's class, the disposition's `css`: the Disposition cell's.
    pub badge: Option<String>,
    pub title: Option<String>,
    pub href: Option<String>,
    /// What stands beside the text: the Description cell's SVS status and the root's tags.
    pub marks: Vec<Mark>,
}

/// A word beside a cell's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub text: String,
    /// `svs-status` or `tag`: its look.
    pub class: &'static str,
    pub title: Option<&'static str>,
    /// Where it leads: the test run an SVS status names.
    pub href: Option<String>,
}

/// What stands beside an alert's description: what SVS makes of it (PLAN.md 7.10 batch 7b, ace3's SVS
/// status on the alert list), leading to the oldest run it's attributed to, and the root's tags.
fn marks(alert: &AlertSummary) -> Vec<Mark> {
    let mut marks = Vec::new();
    if let Some(svs) = &alert.svs {
        marks.push(Mark {
            text: svs.status.as_str().to_owned(),
            class: "svs-status",
            title: Some(crate::svs_alert::status_meaning(svs.status)),
            href: svs.runs.first().map(|run| crate::svs::run_href(*run)),
        });
    }
    marks.extend(alert.tags.iter().map(|tag| Mark {
        text: tag.clone(),
        class: "tag",
        title: None,
        href: None,
    }));
    marks
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
    /// Whether it's one of the commonly used filters, which the editor's menu lists first.
    pub common: bool,
}

/// The alert list's commonly used filters, by slug: the editor's menu lists them first and the rest
/// under them.
pub const COMMON_ALERT_FILTERS: &[&str] = &[
    "alert_date",
    "disposition",
    "owner",
    "queue",
    "observable",
    "tag",
    "description",
];

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
    /// The dispositions the bulk menu offers: the site's an analyst may choose, in order.
    pub dispositions: Vec<String>,
    /// The filter editor's suggested dispositions: every one the site has, in order.
    pub filter_dispositions: Vec<String>,
    /// Who Assign offers (PLAN.md 7.17): the enabled users, for a viewer with `alert:write`.
    pub owners: Vec<OwnerOption>,
    /// Whether the viewer may take and assign alerts: `alert:write`.
    pub can_own: bool,
    pub warnings: Vec<String>,
    pub error: Option<String>,
    pub refresh_seconds: u32,
}

/// A user Assign offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerOption {
    pub id: Uuid,
    pub name: String,
}

/// The users Assign offers, and whether the viewer may assign at all: None for one without
/// `alert:write`.
pub(crate) async fn owner_options(gui: &Gui, viewer: &SignedIn) -> Option<Vec<OwnerChoice>> {
    match gui.service.alert_owner_choices(&viewer.actor).await {
        Ok(choices) => Some(choices),
        Err(ServiceError::PermissionDenied { .. }) => None,
        Err(error) => {
            tracing::warn!(actor = %viewer.actor, "reading who an alert can be assigned to failed: {error}");
            None
        }
    }
}

pub(crate) fn owner_option(choice: &OwnerChoice) -> OwnerOption {
    OwnerOption {
        id: choice.id.0,
        name: if choice.name == choice.username {
            choice.name.clone()
        } else {
            format!("{} ({})", choice.name, choice.username)
        },
    }
}

pub(crate) fn time_in(time: DateTime<Utc>, tz: Tz) -> String {
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

fn row(
    alert: &AlertSummary,
    columns: &[&ManageColumn],
    query: &ListQuery,
    tz: Tz,
    dispositions: &Dispositions,
) -> Row {
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
                badge: None,
                title: Some(alert.alerted_at.to_rfc3339()),
                href: None,
                marks: Vec::new(),
            },
            "description" => Cell {
                id: "description",
                text: alert.title.clone(),
                badge: None,
                title: None,
                href: Some(format!("/alerts/{}", alert.id)),
                marks: marks(alert),
            },
            "queue" => Cell {
                id: "queue",
                href: Some(query.with_filters(&overlaid(&query.filters, "Queue", &alert.queue))),
                text: alert.queue.clone(),
                badge: None,
                title: None,
                marks: Vec::new(),
            },
            // ace3's owner cell: a click narrows the list to that owner's alerts
            "owner" => Cell {
                id: "owner",
                href: alert.owner.as_ref().map(|owner| {
                    query.with_filters(&overlaid(&query.filters, "Owner", &owner.name))
                }),
                text: alert
                    .owner
                    .as_ref()
                    .map(|owner| owner.name.clone())
                    .unwrap_or_default(),
                badge: None,
                title: alert
                    .owned_at
                    .map(|at| format!("since {}", at.to_rfc3339())),
                marks: Vec::new(),
            },
            "disposition" => Cell {
                id: "disposition",
                href: Some(query.with_filters(&overlaid(
                    &query.filters,
                    "Disposition",
                    &disposition,
                ))),
                text: disposition.clone(),
                badge: Some(dispositions.css(Some(&disposition)).to_owned()),
                title: None,
                marks: Vec::new(),
            },
            _ => Cell {
                id: "status",
                text: status(alert.analysis).to_owned(),
                badge: None,
                title: None,
                href: None,
                marks: Vec::new(),
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
    dispositions: &Dispositions,
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
        .map(|alert| row(alert, &visible, query, tz, dispositions))
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
    dispositions: &Dispositions,
    owners: Option<&[OwnerChoice]>,
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
        list: alert_list(page, query, columns, tz, dispositions),
        chips,
        here: query.at("/"),
        manage: crate::saved_filters::manage_url(&query.at("/")),
        share: query.with_filters(&query.filters),
        // ace3's `_default_filters`: open alerts nobody owns, or the viewer does, in the viewer's queue
        reset: query.with_filters(&[
            FilterEntry::text("Disposition", false, &["OPEN"]),
            FilterEntry::text("Owner", false, &["None", filters::USER]),
            FilterEntry::text("Queue", false, &[filters::USER_QUEUE]),
        ]),
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
                common: COMMON_ALERT_FILTERS.contains(&spec.slug),
            })
            .collect(),
        left_out: FilterScreen::Alerts
            .left_out()
            .iter()
            .map(|gone| (gone.name, gone.why))
            .collect(),
        dispositions: dispositions.selectable(),
        filter_dispositions: dispositions.names(),
        owners: owners
            .unwrap_or_default()
            .iter()
            .map(owner_option)
            .collect(),
        can_own: owners.is_some(),
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

impl ListPage {
    /// The page of `view`, which loads the list's script (`static/select.js`) after Datastar, with the
    /// response's nonce, as the graph's page loads its own.
    pub fn new(mut layout: Layout, view: ListView) -> Self {
        layout.scripts = vec![crate::assets::SELECT_SCRIPT.url()];
        ListPage {
            layout,
            list: view.list.clone(),
            view,
        }
    }
}

/// The list's table on its own: what the page includes and a refresh sends.
#[derive(Debug, Template)]
#[template(path = "alert_list.html")]
pub struct AlertListFragment {
    pub list: AlertList,
}

/// The alerts a bulk action left with their owners, and the form that takes them (PLAN.md 7.17): ace3's
/// selection guard.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeftAlone {
    /// Each alert and what its owner is called.
    pub alerts: Vec<(Uuid, String)>,
    /// ace3's sentence: `left 2 alerts owned by Jane alone`.
    pub summary: String,
    /// The form's `take_owned`: `alert:owner` pairs, who owned each when it was looked at.
    pub take_owned: String,
}

impl LeftAlone {
    pub fn of(skipped: &[SkippedAlert]) -> Option<Self> {
        let check = OwnershipCheck {
            skipped: skipped.to_vec(),
            ..OwnershipCheck::default()
        };
        let summary = describe_skipped(&check)?;
        Some(LeftAlone {
            alerts: skipped
                .iter()
                .map(|skipped| (skipped.alert, skipped.name.clone()))
                .collect(),
            summary,
            take_owned: skipped
                .iter()
                .map(|skipped| format!("{}:{}", skipped.alert, skipped.owner.0))
                .collect::<Vec<_>>()
                .join(","),
        })
    }
}

/// What a bulk disposition did.
#[derive(Debug, Template)]
#[template(path = "bulk.html")]
pub struct BulkPage {
    pub layout: Layout,
    pub disposition: String,
    pub done: Vec<Uuid>,
    pub failed: Vec<(Uuid, String)>,
    /// The alerts left with the analysts who own them, and the form that takes them.
    pub left_alone: Option<LeftAlone>,
    pub next: String,
    /// Whether to offer Save to Event for `done`: the disposition's `show_save_to_event`, to a viewer with
    /// `event:write`.
    pub save_to_event: bool,
}

/// What a change of owner left alone (PLAN.md 7.17): shown only when something was.
#[derive(Debug, Template)]
#[template(path = "owned.html")]
pub struct OwnedPage {
    pub layout: Layout,
    /// `Take Ownership` or `Assign Ownership`.
    pub heading: &'static str,
    /// ace3's message: `took ownership of 1 alerts; left 1 alert owned by Jane alone`.
    pub message: String,
    pub applied: Vec<Uuid>,
    pub left_alone: LeftAlone,
    /// The form's `owner` and `assignee`, to ask again with the confirmation.
    pub owner: &'static str,
    pub assignee: String,
    pub next: String,
}

/// The viewer's timezone, UTC when it can't be read.
pub(crate) async fn viewer_tz(gui: &Gui, viewer: &SignedIn) -> Tz {
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
    // a person new to the list gets ace3's Last 24h and Last 7d: here, where the page is drawn, and never
    // in the refresh, which writes nothing
    if let Err(error) = gui
        .service
        .seed_saved_filters(actor, FilterScreen::Alerts)
        .await
    {
        tracing::warn!(%actor, "seeding the default saved filters failed, so the list has none of them: {error}");
    }
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
    let owners = owner_options(&gui, &viewer).await;
    let view = list_view(
        &page,
        &query,
        &columns,
        &saved,
        &counts,
        tz,
        parsed.warnings,
        parsed.error,
        gui.service.dispositions(),
        owners.as_deref(),
    );
    render(&ListPage::new(viewer.layout, view))
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
        list: alert_list(&page, &query, &columns, tz, gui.service.dispositions()),
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
    // ace3's take_owned: the alerts the analyst agreed to take, each with who owned it then
    let takes = ace_service::confirmed_takes(one(&form, "take_owned").unwrap_or(""));
    let mut done = Vec::new();
    let mut failed = Vec::new();
    let mut skipped = Vec::new();
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
            .disposition(&viewer.actor, id, &disposition, takes.get(&id).copied())
            .await
        {
            Ok(_) => done.push(id),
            Err(ServiceError::AlertOwned { alert, owner, name }) => skipped.push(SkippedAlert {
                alert,
                owner: UserId(owner),
                name,
            }),
            Err(ServiceError::InvalidRequest(why)) => {
                return Failure::new(StatusCode::BAD_REQUEST, why, &parts).into_response();
            }
            Err(
                error @ (ServiceError::PermissionDenied { .. }
                | ServiceError::NotFound(_)
                | ServiceError::Conflict(_)),
            ) => {
                failed.push((id, error.to_string()));
            }
            Err(error) => {
                tracing::warn!(actor = %viewer.actor, "a bulk disposition failed on {id}: {error}");
                failed.push((id, "it couldn't be dispositioned".to_owned()));
            }
        }
    }
    let save_to_event = !done.is_empty()
        && gui.service.dispositions().show_save_to_event(&disposition)
        && gui
            .service
            .allowed(&viewer.actor, &ace_service::EVENT_WRITE)
            .await
            .unwrap_or(false);
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
        left_alone: LeftAlone::of(&skipped),
        next,
        save_to_event,
    });
    *response.status_mut() = status;
    response
}

/// `POST /alerts/owner`: ace3's Take Ownership and Assign Ownership, of the ticked alerts or of one from
/// its page, through `Service::change_alert_owner`. `owner` is `me`, which takes them, or `assign`, which
/// gives them to `assignee`, a user's id, or to nobody when it's empty. `take_owned` confirms taking the
/// alerts it names from their owners.
pub(crate) async fn bulk_owner(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let next = next_of(&form);
    let (owner_field, assignee) = (
        one(&form, "owner").unwrap_or(""),
        one(&form, "assignee").unwrap_or("").trim().to_owned(),
    );
    let (heading, owner_field, owner) = match owner_field {
        "me" => match &viewer.actor {
            ace_service::Actor::User { id, .. } => ("Take Ownership", "me", Some(*id)),
            // only a user's session opens a page
            _ => {
                return Failure::new(StatusCode::FORBIDDEN, "Only a user owns alerts.", &parts)
                    .into_response();
            }
        },
        "assign" if assignee.is_empty() => ("Assign Ownership", "assign", None),
        "assign" => match assignee.parse::<Uuid>() {
            Ok(id) => ("Assign Ownership", "assign", Some(UserId(id))),
            Err(_) => {
                return Failure::new(StatusCode::BAD_REQUEST, "There's no such user.", &parts)
                    .into_response();
            }
        },
        _ => {
            return Failure::new(StatusCode::BAD_REQUEST, "owner is me or assign.", &parts)
                .into_response();
        }
    };
    let ids = all(&form, "alert");
    if ids.is_empty() {
        return Failure::new(StatusCode::BAD_REQUEST, "No alerts were ticked.", &parts)
            .into_response();
    }
    if ids.len() > MAX_BULK {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            format!("At most {MAX_BULK} alerts change owner at once."),
            &parts,
        )
        .into_response();
    }
    let mut alerts = Vec::with_capacity(ids.len());
    for raw in &ids {
        match raw.parse::<Uuid>() {
            Ok(id) => alerts.push(id),
            Err(_) => {
                return Failure::new(
                    StatusCode::BAD_REQUEST,
                    format!("{raw:?} isn't an alert's id."),
                    &parts,
                )
                .into_response();
            }
        }
    }
    let takes = ace_service::confirmed_takes(one(&form, "take_owned").unwrap_or(""));
    let changed = match gui
        .service
        .change_alert_owner(&viewer.actor, &alerts, owner, &takes)
        .await
    {
        Ok(changed) => changed,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let Some(left_alone) = LeftAlone::of(&changed.skipped) else {
        // nothing was left alone: back where it came from, as ace3 refreshes its list
        return see_other(&next, None);
    };
    render(&OwnedPage {
        layout: viewer.layout,
        heading,
        message: changed
            .message
            .unwrap_or_else(|| left_alone.summary.clone()),
        applied: changed.applied,
        left_alone,
        owner: owner_field,
        assignee,
        next,
    })
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
