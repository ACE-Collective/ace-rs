//! Saved filters (PLAN.md 5.11's `saved_filters` area): ace3's `saved_filters/_modals.html`, the Save
//! Filter and Manage Filters dialogs, and `static/js/saved_filters.js`, which drives them through
//! `/api/v2/saved-filters`. Here each is a page or a form, and every write goes through the service, which
//! checks `alert:read` and the row's owner and writes the audit row. Every post is a `SignedIn` request,
//! so `Service::authenticate_request` has checked it came from this site (5.7's CSRF check).
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
//! filters, each a link to the screen with its filters in `f`. Saving, renaming, pinning and deleting a
//! filter of those screens is the JSON API's (`/api/filters/v1/saved`), which takes every screen; this
//! module's pages are the alert list's.
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
}

/// One of a screen's quick filters, as its page links it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickLink {
    pub label: String,
    /// What it shows, the link's title.
    pub description: String,
    pub href: String,
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

/// A screen's quick filters for its page at `path`: ace3's defaults seeded the first time the viewer opens
/// the screen, where the page is drawn as in ace3, then the viewer's pinned filters. A failure leaves the
/// page without them, and is logged.
pub(crate) async fn quick_filters(
    gui: &Gui,
    viewer: &SignedIn,
    screen: FilterScreen,
    path: &str,
) -> Vec<QuickLink> {
    let actor = &viewer.actor;
    if let Err(error) = gui.service.seed_saved_filters(actor, screen).await {
        tracing::warn!(%actor, %screen, "seeding the default saved filters failed, so the page has none of them: {error}");
    }
    match gui.service.saved_filters(actor, screen).await {
        Ok(saved) => quick_links(screen, &saved, path),
        Err(error) => {
            tracing::warn!(%actor, %screen, "reading saved filters failed, so the page has none: {error}");
            Vec::new()
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

/// A path with `next` when it isn't the list's own default.
fn with_next(path: &str, back: &str) -> String {
    if back == "/" {
        return path.to_owned();
    }
    format!(
        "{path}?{}",
        serde_urlencoded::to_string([("next", back)]).expect("a string encodes")
    )
}

/// The manage page's URL, going back to a list.
pub fn manage_url(back: &str) -> String {
    with_next(MANAGE, back)
}

/// The manage page's view from the user's saved filters, in the service's order: the quick filters in
/// theirs, then the rest by name.
pub fn manage_view(saved: &[SavedFilter], back: &str) -> ManageView {
    let quick = saved
        .iter()
        .filter(|filter| filter.quick_filter_order.is_some())
        .count();
    let list = ListQuery::default();
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
                href: open_href(&list, filter),
                rename: with_next(&format!("{MANAGE}/{}", filter.id), back),
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
        here: manage_url(back),
    }
}

/// The page's `next`, the list to go back to: a path on this site, or `/`.
fn back_of(pairs: &[(String, String)]) -> String {
    one(pairs, "next")
        .and_then(local_path)
        .unwrap_or("/")
        .to_owned()
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
    let back = back_of(&pairs(raw.as_deref().unwrap_or("").as_bytes()));
    match gui
        .service
        .saved_filters(&viewer.actor, FilterScreen::Alerts)
        .await
    {
        Ok(saved) => render(&ManagePage {
            layout: viewer.layout,
            view: manage_view(&saved, &back),
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
    let next = back_of(&form);
    let filters = match filters::decode(FilterScreen::Alerts, &all(&form, "f"), true) {
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
        quick_filter_indicator: one(&form, "indicator").is_some(),
    };
    match gui
        .service
        .create_saved_filter(&viewer.actor, FilterScreen::Alerts, &new)
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
    match gui.service.delete_saved_filter(&viewer.actor, id).await {
        Ok(()) => see_other(&back_of(&form), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// The user's saved filters on the alert list, in the service's order.
async fn own_filters(gui: &Gui, viewer: &SignedIn) -> Result<Vec<SavedFilter>, ServiceError> {
    gui.service
        .saved_filters(&viewer.actor, FilterScreen::Alerts)
        .await
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
    let saved = match own_filters(&gui, &viewer).await {
        Ok(saved) => saved,
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
        .set_quick_filters(&viewer.actor, FilterScreen::Alerts, &quick)
        .await
    {
        Ok(_) => see_other(&back_of(&form), None),
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
    let saved = match own_filters(&gui, &viewer).await {
        Ok(saved) => saved,
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
        Ok(None) => return see_other(&back_of(&form), None),
        Err(why) => return Failure::new(StatusCode::BAD_REQUEST, why, &parts).into_response(),
    };
    match gui
        .service
        .set_quick_filters(&viewer.actor, FilterScreen::Alerts, &order)
        .await
    {
        Ok(_) => see_other(&back_of(&form), None),
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
        manage: manage_url(back),
        problem,
        max_name: MAX_SAVED_FILTER_NAME_CHARS,
        max_description: MAX_SAVED_FILTER_DESCRIPTION_CHARS,
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
    let back = back_of(&pairs(query.as_deref().unwrap_or("").as_bytes()));
    match own_filter(&gui, &viewer, &raw, &parts).await {
        Ok(filter) => edit_page(viewer.layout, &filter, &back, None, None, StatusCode::OK),
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
    let back = back_of(&form);
    let filter = match own_filter(&gui, &viewer, &raw, &parts).await {
        Ok(filter) => filter,
        Err(failure) => return failure.into_response(),
    };
    let draft = FilterDraft {
        name: one(&form, "name").unwrap_or("").trim().to_owned(),
        description: one(&form, "description").unwrap_or("").trim().to_owned(),
        indicator: one(&form, "indicator").is_some(),
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
        Ok(_) => return see_other(&manage_url(&back), None),
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
