//! Saved filters (PLAN.md 5.11's `saved_filters` area): ace3's `saved_filters/_modals.html`, the Save
//! Filter and Manage Filters dialogs, and `static/js/saved_filters.js`, which drives them through
//! `/api/v2/saved-filters`. Here each is a page or a form, and every write goes through the service, which
//! checks the screen's permission (`FilterScreen::permission`: `alert:read` for the alert list) and the
//! row's owner and writes the audit row. Every post is a `SignedIn` request, so
//! `Service::authenticate_request` has checked it came from this site (5.7's CSRF check).
//!
//! ace3's dialogs and their places here:
//! - Save Filter, `saveAs`: the alert list's form, `POST /filters/saved`, over
//!   `Service::create_saved_filter` (5.10).
//! - Manage Filters, `openManage`: the page `GET /filters/saved`, over `Service::saved_filters`, linked as
//!   "Manage…" from the list, as ace3's filter bar links its dialog. `next` is the list to go back to.
//!   Each row, as ace3's:
//!   - its quick filter box: a Pin or Unpin form, `POST /filters/saved/{id}/quick` (5.10), which keeps
//!     the other quick filters in their order and puts a new one last, over `Service::set_quick_filters`;
//!   - its order: Up and Down forms, `POST /filters/saved/{id}/move`, over `Service::set_quick_filters`.
//!     ace3 moves rows in the dialog and saves the whole order with one button; here each move is saved,
//!     so there's no unsaved order to lose. A move past either end changes nothing;
//!   - Open: a link to the list with its filters, which is also ace3's "Copy a link": the link carries
//!     the filter itself, as ace3's share link does, so it keeps working after the filter changes;
//!   - Delete: `POST /filters/saved/{id}/delete` (5.10), over `Service::delete_saved_filter`.
//! - Rename: `GET` and `POST /filters/saved/{id}`, a page with the name, the description and whether the
//!   quick filter shows its count, over `Service::update_saved_filter`. ace3's `_modals.html` says its
//!   manage dialog renames, and its API's `PATCH` takes a name and a description, but the dialog
//!   `saved_filters.js` draws has no control for it; this is that control.
//!
//! The hint under the table has ace3's tip (`manageTipHtml`), where ace3 has it: `$USER_QUEUE` (7.13) and
//! `$USER`, which came with the alert list's Owner filter (7.17).
//!
//! What's left out: ace3's confirm before a delete, which needs a script. ace3's `saveCurrent`, which
//! overwrites a saved filter with the editor's rows from the alert list's Edit dialog, belongs to that list
//! (5.10) and isn't here.
//!
//! The other screens that draw ace3's quick filters (file collections, remediations, SVS's runs, tests,
//! coverage and worklist, the signatures' samples and validations) show theirs as links above their filter
//! form (`quick_filters`, the owner's decision of 2026-11-15): each page seeds ace3's defaults for its
//! screen the first time a person opens it (`Service::seed_saved_filters`), then lists the person's pinned
//! filters, each a link to the screen with its filters in `f`.
//!
//! Those eight screens manage their saved filters with the same pages (the owner's decision of
//! 2026-11-15), as ace3's filter bar and dialogs serve every screen that has them:
//! - Each screen's page has a Saved filters section under its quick filters (`QuickBar`,
//!   `quick_filters.html`): a form that saves the page's filter, `POST /filters/saved` with the screen's
//!   name in `screen`, pinned as a quick filter when asked, and a link to the screen's manage page.
//! - The manage page is `GET /filters/saved?screen=NAME`, the same page as the alert list's with the
//!   screen's own filters: Pin and Unpin, Up and Down, Open, Rename and Delete.
//! - A form that names a filter by its id (`/filters/saved/{id}` and below) works on the row's own
//!   screen: the pin and the moves read which screen the row is on, and set that screen's quick filters.
//! - Each call needs its screen's permission, which the service checks: `Service::saved_filters`,
//!   `create_saved_filter` and `set_quick_filters` the named screen's, and the by-id calls the row's
//!   screen's (7.17). So someone with `svs:run_read` and not `alert:read` manages the SVS screens' filters
//!   and is refused the alert list's, and the other way round. Each write has the audit row the alert
//!   list's has, since they are the same service calls.
//! - A screen's name that isn't one, or is a screen with no page of quick filters (the detection points
//!   and the coverage history, which ace3 doesn't seed either), is 404: their saved filters are the JSON
//!   API's (`/api/filters/v1/saved`), which takes every screen.
//! - The count on a quick filter is the alert list's alone, since only its badges show one, so the
//!   other screens' forms don't offer it.
//!
//! Each reorder reads the quick filters and writes the whole order, as ace3's dialog does, so a pin made
//! in another tab between the two is undone by the write; the audit row records both.

use ace_service::filters::{self, FilterScreen};
use ace_service::{
    MAX_SAVED_FILTER_DESCRIPTION_CHARS, MAX_SAVED_FILTER_NAME_CHARS, NewSavedFilter, SavedFilter,
    SavedFilterChange, ServiceError,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::Gui;
use crate::list::{ListQuery, all, one, pairs};
use crate::session::{Failure, SignedIn, local_path, render, see_other};
use crate::templates::Layout;

/// The manage page.
const MANAGE: &str = "/filters/saved";

/// Where a screen with saved filters pages is, and what its page is called: the alert list and the
/// eight screens ace3 seeds. None for a screen with no page that shows quick filters.
pub fn screen_place(screen: FilterScreen) -> Option<(&'static str, &'static str)> {
    match screen {
        FilterScreen::Alerts => Some(("/", "the alert list")),
        FilterScreen::Remediations => Some(("/remediations", "Remediations")),
        FilterScreen::FileCollections => Some(("/file-collections", "File Collections")),
        FilterScreen::SvsSamples => Some(("/signatures/samples", "Samples")),
        FilterScreen::SvsValidations => Some(("/signatures/validations", "Validations")),
        FilterScreen::SvsTests => Some(("/svs/tests", "SVS Tests")),
        FilterScreen::SvsRuns => Some(("/svs/runs", "SVS Runs")),
        FilterScreen::SvsCoverage => Some(("/svs/coverage", "SVS Coverage")),
        FilterScreen::SvsWorklist => Some(("/svs/worklist", "the SVS Worklist")),
        FilterScreen::DetectionPoints | FilterScreen::SvsCoverageHistory => None,
    }
}

/// A screen's path, `/` for one with no page.
fn screen_path(screen: FilterScreen) -> &'static str {
    screen_place(screen).map_or("/", |(path, _)| path)
}

/// A saved filter's row on the manage page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManageRow {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    /// The list with its filters: Open, and the link to share.
    pub href: String,
    /// Its rename page, coming back here.
    pub rename: String,
    /// Its place among the quick filters, from 1, or None when it isn't one.
    pub place: Option<usize>,
    pub indicator: bool,
    pub first: bool,
    pub last: bool,
}

/// The manage page's view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManageView {
    pub rows: Vec<ManageRow>,
    /// The list to go back to.
    pub back: String,
    /// This page, for its forms to come back to.
    pub here: String,
    /// What the screen's page is called: `the alert list`, `SVS Runs`.
    pub screen_label: &'static str,
    /// Whether these are the alert list's filters, whose page's words and count stay as they were.
    pub alerts: bool,
}

/// `/filters/saved`, ace3's Manage Filters dialog.
#[derive(Debug, Template)]
#[template(path = "saved_filters.html")]
pub struct ManagePage {
    pub layout: Layout,
    pub view: ManageView,
}

/// What the rename form holds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilterDraft {
    pub name: String,
    pub description: String,
    pub indicator: bool,
}

/// `/filters/saved/{id}`, renaming a saved filter.
#[derive(Debug, Template)]
#[template(path = "saved_filter.html")]
pub struct EditPage {
    pub layout: Layout,
    pub id: Uuid,
    pub draft: FilterDraft,
    pub quick: bool,
    /// The list the manage page goes back to, which the form passes on.
    pub next: String,
    /// The manage page, going back to that list.
    pub manage: String,
    pub problem: Option<String>,
    pub max_name: usize,
    pub max_description: usize,
    /// Whether the filter is the alert list's, whose quick filters can show a count.
    pub alerts: bool,
}

/// One of a screen's quick filters, as its page links it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickLink {
    pub label: String,
    /// What it shows, the link's title.
    pub description: String,
    pub href: String,
}

/// What a screen's page draws of its saved filters (`quick_filters.html`): the quick filters as links,
/// and the Saved filters section, the form that saves the page's filter and the link to the screen's
/// manage page. The default is neither, for a page drawn on its own.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QuickBar {
    pub links: Vec<QuickLink>,
    pub save: Option<SaveForm>,
}

/// The form that saves a screen's current filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveForm {
    /// The screen's name, `FilterScreen::name`: the form's `screen`.
    pub screen: &'static str,
    /// The page's filters, its `f` values.
    pub f: Vec<String>,
    /// The page with those filters, to come back to.
    pub next: String,
    /// The screen's manage page, coming back to `next`.
    pub manage: String,
    pub max_name: usize,
    pub max_description: usize,
}

impl SaveForm {
    /// The form of a screen's page at `path` showing the filters `f`.
    pub fn new(screen: FilterScreen, path: &str, f: &[String]) -> Self {
        let pairs: Vec<(&str, &String)> = f.iter().map(|f| ("f", f)).collect();
        let query = serde_urlencoded::to_string(&pairs).expect("pairs of text encode");
        let next = if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        };
        SaveForm {
            screen: screen.name(),
            f: f.to_vec(),
            manage: manage_url_of(screen, &next),
            next,
            max_name: MAX_SAVED_FILTER_NAME_CHARS,
            max_description: MAX_SAVED_FILTER_DESCRIPTION_CHARS,
        }
    }
}

/// The quick filters of `saved` as links to `path`, in their order. One whose filters no longer check for
/// the screen is left out.
pub fn quick_links(screen: FilterScreen, saved: &[SavedFilter], path: &str) -> Vec<QuickLink> {
    saved
        .iter()
        .filter(|filter| filter.quick_filter_order.is_some())
        .filter_map(|filter| {
            let pairs: Vec<(&str, String)> = filters::encode(screen, &filter.filters)
                .ok()?
                .into_iter()
                .map(|f| ("f", f))
                .collect();
            let query = serde_urlencoded::to_string(&pairs).ok()?;
            Some(QuickLink {
                label: filter.name.clone(),
                description: filter.description.clone().unwrap_or_default(),
                href: if query.is_empty() {
                    path.to_owned()
                } else {
                    format!("{path}?{query}")
                },
            })
        })
        .collect()
}

/// A screen's quick filters for its page at `path`, which shows the filters `f`: ace3's defaults seeded
/// the first time the viewer opens the screen, where the page is drawn as in ace3, then the viewer's
/// pinned filters, and the form that saves `f`. A failure leaves the page without them, and is logged.
pub(crate) async fn quick_filters(
    gui: &Gui,
    viewer: &SignedIn,
    screen: FilterScreen,
    path: &str,
    f: &[String],
) -> QuickBar {
    let actor = &viewer.actor;
    if let Err(error) = gui.service.seed_saved_filters(actor, screen).await {
        tracing::warn!(%actor, %screen, "seeding the default saved filters failed, so the page has none of them: {error}");
    }
    match gui.service.saved_filters(actor, screen).await {
        Ok(saved) => QuickBar {
            links: quick_links(screen, &saved, path),
            save: Some(SaveForm::new(screen, path, f)),
        },
        Err(error) => {
            tracing::warn!(%actor, %screen, "reading saved filters failed, so the page has none: {error}");
            QuickBar::default()
        }
    }
}

/// The alert list with a saved filter's filters, or the bare list when they no longer check, which the
/// list would refuse.
pub(crate) fn open_href(query: &ListQuery, filter: &SavedFilter) -> String {
    match filters::check(FilterScreen::Alerts, &filter.filters) {
        Ok(filters) => query.with_filters(&filters),
        Err(_) => "/".to_owned(),
    }
}

/// A saved filter's screen with its filters: the alert list's as `open_href`, another screen's as its
/// quick filter's link, and the bare screen when its filters no longer check.
fn open_on(screen: FilterScreen, filter: &SavedFilter) -> String {
    if screen == FilterScreen::Alerts {
        return open_href(&ListQuery::default(), filter);
    }
    let path = screen_path(screen);
    let pairs: Option<Vec<(&str, String)>> = filters::check(screen, &filter.filters)
        .ok()
        .and_then(|checked| filters::encode(screen, &checked).ok())
        .map(|f| f.into_iter().map(|f| ("f", f)).collect());
    match pairs.and_then(|pairs| serde_urlencoded::to_string(&pairs).ok()) {
        Some(query) if !query.is_empty() => format!("{path}?{query}"),
        _ => path.to_owned(),
    }
}

/// A path with the screen, when the path needs it named and it isn't the alert list, and `next` when
/// it isn't the screen's own page.
fn with_next(path: &str, screen: FilterScreen, named: bool, back: &str) -> String {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if named && screen != FilterScreen::Alerts {
        pairs.push(("screen", screen.name()));
    }
    if back != screen_path(screen) {
        pairs.push(("next", back));
    }
    if pairs.is_empty() {
        return path.to_owned();
    }
    format!(
        "{path}?{}",
        serde_urlencoded::to_string(&pairs).expect("pairs of text encode")
    )
}

/// The alert list's manage page's URL, going back to a list.
pub fn manage_url(back: &str) -> String {
    manage_url_of(FilterScreen::Alerts, back)
}

/// A screen's manage page's URL, going back to its page.
pub fn manage_url_of(screen: FilterScreen, back: &str) -> String {
    with_next(MANAGE, screen, true, back)
}

/// The alert list's manage page's view from the user's saved filters, in the service's order: the quick
/// filters in theirs, then the rest by name.
pub fn manage_view(saved: &[SavedFilter], back: &str) -> ManageView {
    manage_view_of(FilterScreen::Alerts, saved, back)
}

/// A screen's manage page's view from the user's saved filters on it.
pub fn manage_view_of(screen: FilterScreen, saved: &[SavedFilter], back: &str) -> ManageView {
    let quick = saved
        .iter()
        .filter(|filter| filter.quick_filter_order.is_some())
        .count();
    let mut place = 0;
    let rows = saved
        .iter()
        .map(|filter| {
            let at = filter.quick_filter_order.map(|_| {
                place += 1;
                place
            });
            ManageRow {
                id: filter.id,
                name: filter.name.clone(),
                description: filter.description.clone().unwrap_or_default(),
                href: open_on(screen, filter),
                // the rename page reads the screen from the row
                rename: with_next(&format!("{MANAGE}/{}", filter.id), screen, false, back),
                place: at,
                indicator: filter.quick_filter_indicator,
                first: at == Some(1),
                last: at == Some(quick),
            }
        })
        .collect();
    ManageView {
        rows,
        back: back.to_owned(),
        here: manage_url_of(screen, back),
        screen_label: screen_place(screen).map_or("the list", |(_, label)| label),
        alerts: screen == FilterScreen::Alerts,
    }
}

/// The page's `next`, the list to go back to: a path on this site, or the screen's own page.
fn back_of(pairs: &[(String, String)], screen: FilterScreen) -> String {
    one(pairs, "next")
        .and_then(local_path)
        .unwrap_or(screen_path(screen))
        .to_owned()
}

/// The screen a manage page or a save form names in `screen`: the alert list when it names none, as
/// before the other screens had these pages, and 404 for a name that isn't a screen with one.
fn screen_of(pairs: &[(String, String)], parts: &Parts) -> Result<FilterScreen, Failure> {
    match one(pairs, "screen") {
        None => Ok(FilterScreen::Alerts),
        Some(name) => FilterScreen::named(name)
            .filter(|screen| screen_place(*screen).is_some())
            .ok_or_else(|| {
                Failure::new(
                    StatusCode::NOT_FOUND,
                    "There's no such screen of saved filters.",
                    parts,
                )
            }),
    }
}

fn no_filter(parts: &Parts) -> Failure {
    Failure::new(
        StatusCode::NOT_FOUND,
        "There's no such saved filter.",
        parts,
    )
}

/// A saved filter's id from its path, or the 404 a malformed one gets.
fn id_of(raw: &str, parts: &Parts) -> Result<Uuid, Failure> {
    raw.parse().map_err(|_| no_filter(parts))
}

/// `GET /filters/saved`: ace3's Manage Filters dialog.
pub(crate) async fn manage_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = pairs(raw.as_deref().unwrap_or("").as_bytes());
    let screen = match screen_of(&query, &parts) {
        Ok(screen) => screen,
        Err(failure) => return failure.into_response(),
    };
    let back = back_of(&query, screen);
    match gui.service.saved_filters(&viewer.actor, screen).await {
        Ok(saved) => render(&ManagePage {
            layout: viewer.layout,
            view: manage_view_of(screen, &saved, &back),
        }),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// `POST /filters/saved`: saves the list's filters as a named filter.
pub(crate) async fn save_filter(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let screen = match screen_of(&form, &parts) {
        Ok(screen) => screen,
        Err(failure) => return failure.into_response(),
    };
    let next = back_of(&form, screen);
    let filters = match filters::decode(screen, &all(&form, "f"), true) {
        Ok((filters, _)) => filters,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let new = NewSavedFilter {
        name: one(&form, "name").unwrap_or("").trim().to_owned(),
        description: one(&form, "description")
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned),
        filters,
        quick_filter: one(&form, "quick").is_some(),
        // only the alert list's quick filters show a count
        quick_filter_indicator: screen == FilterScreen::Alerts && one(&form, "indicator").is_some(),
    };
    match gui
        .service
        .create_saved_filter(&viewer.actor, screen, &new)
        .await
    {
        Ok(_) => see_other(&next, None),
        Err(ServiceError::FilterNameTaken(name)) => {
            Failure::new(StatusCode::CONFLICT, taken(&name), &parts).into_response()
        }
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

fn taken(name: &str) -> String {
    format!("You have a saved filter named {name:?} already.")
}

/// `POST /filters/saved/{id}/delete`.
pub(crate) async fn delete_filter(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let id = match id_of(&raw, &parts) {
        Ok(id) => id,
        Err(failure) => return failure.into_response(),
    };
    // the forms say where to go back to; a post without it goes to the alert list, the row being gone
    match gui.service.delete_saved_filter(&viewer.actor, id).await {
        Ok(()) => see_other(&back_of(&form, FilterScreen::Alerts), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// The screen a saved filter of the viewer's is on, and the viewer's saved filters on it, in the
/// service's order. An id that isn't one of theirs reads as the alert list's, whose write then refuses
/// it as it did before the other screens had these forms. The read of the row checks its screen's
/// permission, and so does the read of the screen's filters.
async fn own_filters(
    gui: &Gui,
    viewer: &SignedIn,
    id: Uuid,
) -> Result<(FilterScreen, Vec<SavedFilter>), ServiceError> {
    let screen = match gui.service.saved_filter(&viewer.actor, id).await {
        Ok(filter) => filter.screen,
        Err(ServiceError::NotFound(_)) => FilterScreen::Alerts,
        Err(error) => return Err(error),
    };
    let saved = gui.service.saved_filters(&viewer.actor, screen).await?;
    Ok((screen, saved))
}

/// `POST /filters/saved/{id}/quick`: pins a saved filter as the last quick filter, or unpins it.
pub(crate) async fn pin_filter(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let id = match id_of(&raw, &parts) {
        Ok(id) => id,
        Err(failure) => return failure.into_response(),
    };
    let pin = match one(&form, "pin") {
        Some("true") => true,
        Some("false") => false,
        _ => {
            return Failure::new(StatusCode::BAD_REQUEST, "pin is true or false.", &parts)
                .into_response();
        }
    };
    let (screen, saved) = match own_filters(&gui, &viewer, id).await {
        Ok(found) => found,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let mut quick: Vec<Uuid> = saved
        .iter()
        .filter(|filter| filter.quick_filter_order.is_some() && filter.id != id)
        .map(|filter| filter.id)
        .collect();
    if pin {
        quick.push(id);
    }
    match gui
        .service
        .set_quick_filters(&viewer.actor, screen, &quick)
        .await
    {
        Ok(_) => see_other(&back_of(&form, screen), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// The quick filters' order with one moved a place up or down, or None when it's already at that end.
/// An id that isn't among them is an error.
pub fn moved(quick: &[Uuid], id: Uuid, up: bool) -> Result<Option<Vec<Uuid>>, &'static str> {
    let at = quick
        .iter()
        .position(|other| *other == id)
        .ok_or("Only a quick filter has a place to move. Pin it first.")?;
    let to = if up {
        at.checked_sub(1)
    } else {
        Some(at + 1).filter(|to| *to < quick.len())
    };
    Ok(to.map(|to| {
        let mut order = quick.to_vec();
        order.swap(at, to);
        order
    }))
}

/// `POST /filters/saved/{id}/move`: moves a quick filter a place up or down, ace3's arrows.
pub(crate) async fn move_filter(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let id = match id_of(&raw, &parts) {
        Ok(id) => id,
        Err(failure) => return failure.into_response(),
    };
    let up = match one(&form, "to") {
        Some("up") => true,
        Some("down") => false,
        _ => {
            return Failure::new(StatusCode::BAD_REQUEST, "to is up or down.", &parts)
                .into_response();
        }
    };
    let (screen, saved) = match own_filters(&gui, &viewer, id).await {
        Ok(found) => found,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    if !saved.iter().any(|filter| filter.id == id) {
        return no_filter(&parts).into_response();
    }
    let quick: Vec<Uuid> = saved
        .iter()
        .filter(|filter| filter.quick_filter_order.is_some())
        .map(|filter| filter.id)
        .collect();
    let order = match moved(&quick, id, up) {
        Ok(Some(order)) => order,
        Ok(None) => return see_other(&back_of(&form, screen), None),
        Err(why) => return Failure::new(StatusCode::BAD_REQUEST, why, &parts).into_response(),
    };
    match gui
        .service
        .set_quick_filters(&viewer.actor, screen, &order)
        .await
    {
        Ok(_) => see_other(&back_of(&form, screen), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// The rename page, with a draft and a problem, at a status.
fn edit_page(
    layout: Layout,
    filter: &SavedFilter,
    back: &str,
    draft: Option<FilterDraft>,
    problem: Option<String>,
    status: StatusCode,
) -> Response {
    let draft = draft.unwrap_or_else(|| FilterDraft {
        name: filter.name.clone(),
        description: filter.description.clone().unwrap_or_default(),
        indicator: filter.quick_filter_indicator,
    });
    let mut response = render(&EditPage {
        layout,
        id: filter.id,
        draft,
        quick: filter.quick_filter_order.is_some(),
        next: back.to_owned(),
        manage: manage_url_of(filter.screen, back),
        problem,
        max_name: MAX_SAVED_FILTER_NAME_CHARS,
        max_description: MAX_SAVED_FILTER_DESCRIPTION_CHARS,
        alerts: filter.screen == FilterScreen::Alerts,
    });
    *response.status_mut() = status;
    response
}

/// One of the user's saved filters, or the 404 for one that isn't theirs.
async fn own_filter(
    gui: &Gui,
    viewer: &SignedIn,
    raw: &str,
    parts: &Parts,
) -> Result<SavedFilter, Failure> {
    let id = id_of(raw, parts)?;
    match gui.service.saved_filter(&viewer.actor, id).await {
        Ok(filter) => Ok(filter),
        Err(ServiceError::NotFound(_)) => Err(no_filter(parts)),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

/// `GET /filters/saved/{id}`: the form that renames a saved filter.
pub(crate) async fn edit_filter_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Response {
    let query = pairs(query.as_deref().unwrap_or("").as_bytes());
    match own_filter(&gui, &viewer, &raw, &parts).await {
        Ok(filter) => {
            let back = back_of(&query, filter.screen);
            edit_page(viewer.layout, &filter, &back, None, None, StatusCode::OK)
        }
        Err(failure) => failure.into_response(),
    }
}

/// `POST /filters/saved/{id}`: renames a saved filter, and sets its description and whether its quick
/// filter shows a count.
pub(crate) async fn save_edit(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path(raw): Path<String>,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let filter = match own_filter(&gui, &viewer, &raw, &parts).await {
        Ok(filter) => filter,
        Err(failure) => return failure.into_response(),
    };
    let back = back_of(&form, filter.screen);
    let draft = FilterDraft {
        name: one(&form, "name").unwrap_or("").trim().to_owned(),
        description: one(&form, "description").unwrap_or("").trim().to_owned(),
        // only the alert list's form has the box; another screen's filter keeps what it has
        indicator: if filter.screen == FilterScreen::Alerts {
            one(&form, "indicator").is_some()
        } else {
            filter.quick_filter_indicator
        },
    };
    // an empty description stays as it was when there was none
    let description = (!draft.description.is_empty() || filter.description.is_some())
        .then(|| draft.description.clone());
    let change = SavedFilterChange {
        name: Some(draft.name.clone()),
        description,
        filters: None,
        quick_filter_indicator: Some(draft.indicator),
    };
    let problem = match gui
        .service
        .update_saved_filter(&viewer.actor, filter.id, &change)
        .await
    {
        Ok(_) => return see_other(&manage_url_of(filter.screen, &back), None),
        Err(ServiceError::InvalidRequest(why)) => {
            (StatusCode::BAD_REQUEST, format!("Not saved: {why}."))
        }
        Err(ServiceError::FilterNameTaken(name)) => (StatusCode::CONFLICT, taken(&name)),
        Err(ServiceError::NotFound(_)) => return no_filter(&parts).into_response(),
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    edit_page(
        viewer.layout,
        &filter,
        &back,
        Some(draft),
        Some(problem.1),
        problem.0,
    )
}
