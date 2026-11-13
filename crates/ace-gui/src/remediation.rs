//! The remediations and file collections areas (PLAN.md 7.9, 5.11's `remediation` and `file_collection`
//! areas): ace3's `remediation/manage.html` and `file_collection/manage.html`, each a shell over its
//! router there (`remediations_page.js`, `file_collections_page.js`), drawn on the server here over the
//! `remediation` and `file_collections` services, as the rest of the GUI is.
//!
//! | ace3 | here |
//! |---|---|
//! | `/remediation/manage`, the list with its filter bar, saved filters and exports | `GET /remediations`: a filter form whose fields are the remediations screen's filters, the list newest first with its total, First and Next, and links to the API's exports with the same filters |
//! | the history modal | `GET /remediations/{id}`: the remediation and each try |
//! | the bulk Restore, Retry, Cancel and Delete of the ticked rows | a form per row: `POST /remediations/{id}/restore`, `/retry`, `/cancel`, `/delete` |
//! | the Add Remediation modal: a type, values, Find Targets, Remediate | `GET /remediations/targets?type=&values=`, or `?alert=` repeated from an event's page, then `POST /remediations` with the ticked targets and Remove or Restore |
//! | `/file_collection/manage`, its list, history modal, Retry, Cancel and Delete | `GET /file-collections`, `GET /file-collections/{id}`, `POST /file-collections/{id}/retry`, `/cancel`, `/delete` |
//! | none: ace3's integrations ask for a collection, and a site's API takes a host | `GET /file-collections/new`, or `?alert=` repeated, then `POST /file-collections` with a collector, a value and the alerts, one per line, under `file_collection:create` (the owner's decision of 2026-11-13) |
//!
//! The pages need `remediation:read` or `file_collection:read`, and each form the matching `:write`, as
//! ace3's routes do, but for the request form, which needs `file_collection:create`; the service checks each and audits each write. Every form is a `SignedIn` post, which
//! passed 5.7's same-origin check. A list's filters are the shared filter model (`ace_service::filters`):
//! the page takes a share link's `f`, as the API does, and the form's fields, one per filter, each a value
//! or several separated by commas, which it folds into `f` and redirects to.
//!
//! What differs, and why: a row's own forms stand for ace3's bulk buttons over ticked rows, and a page for
//! its history modal, so the pages need no script. The filter bar's saved filters and inverted chips are
//! the API's (`/api/filters/v1`) and a share link's `!`, which the page takes; the form has a field per
//! filter. A remediation's restore asks for no confirm, as ace3's doesn't.

use ace_service::filters::{self, FilterScreen, FilterSpec};
use ace_service::{
    ActionAttempt, ActionQuery, CollectionAsk, FILE_COLLECTION_CREATE, FILE_COLLECTION_WRITE,
    FileCollection, FilterEntry, FilterValue, MAX_COLLECTION_ALERTS, REMEDIATION_WRITE,
    Remediation, RemediationAction, RemediationTarget, ServiceError, TargetKey,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::Gui;
use crate::list::{all, one, pairs};
use crate::session::{Failure, SignedIn, render, see_other};
use crate::templates::Layout;

/// A page of either list.
pub const PAGE_SIZE: u32 = 50;
/// The most tries a page shows.
pub const HISTORY: u32 = 100;
/// The most values the add form takes, as the service's bound on a lookup.
pub const MAX_VALUES: usize = ace_service::MAX_TARGETS;

fn time(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn optional(at: Option<DateTime<Utc>>) -> String {
    at.map(time).unwrap_or_default()
}

/// One field of a list's filter form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterField {
    pub name: &'static str,
    pub slug: &'static str,
    pub hint: &'static str,
    pub options: &'static [&'static str],
    /// What it holds now, its values joined by commas.
    pub value: String,
}

/// A list's filters as the form shows them, from the checked entries.
pub fn filter_fields(screen: FilterScreen, entries: &[FilterEntry]) -> Vec<FilterField> {
    screen
        .filters()
        .iter()
        .map(|spec: &FilterSpec| FilterField {
            name: spec.name,
            slug: spec.slug,
            hint: spec.hint,
            options: spec.options,
            value: entries
                .iter()
                .filter(|e| e.name == spec.name && !e.inverted)
                .flat_map(|e| e.values.iter())
                .filter_map(|v| match v {
                    FilterValue::Text(text) => Some(text.clone()),
                    FilterValue::Pair(..) => None,
                })
                .collect::<Vec<_>>()
                .join(","),
        })
        .collect()
}

/// A list's query string: its filters as a share link, and `after`.
fn list_href(
    path: &str,
    screen: FilterScreen,
    entries: &[FilterEntry],
    after: Option<i64>,
) -> String {
    let mut query: Vec<(&str, String)> = filters::encode(screen, entries)
        .unwrap_or_default()
        .into_iter()
        .map(|f| ("f", f))
        .collect();
    if let Some(after) = after {
        query.push(("after", after.to_string()));
    }
    let encoded = serde_urlencoded::to_string(&query).unwrap_or_default();
    if encoded.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{encoded}")
    }
}

/// What a list's URL asks for.
#[derive(Debug, Clone, PartialEq)]
pub struct ListRequest {
    pub filters: Vec<FilterEntry>,
    pub after: Option<i64>,
    pub done: Option<String>,
    /// The filter form was sent: fold its fields into `f` and redirect.
    pub folded: bool,
}

/// A list's URL: `f` as a share link, the form's fields by slug, `after` and `done`. A filter that
/// doesn't read is `InvalidRequest`.
pub fn list_request(screen: FilterScreen, raw: Option<&str>) -> Result<ListRequest, ServiceError> {
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(raw.unwrap_or("")).unwrap_or_default();
    let (mut entries, _) = filters::decode(screen, &all(&pairs, "f"), true)?;
    let mut folded = false;
    for spec in screen.filters() {
        if let Some(value) = one(&pairs, spec.slug) {
            folded = true;
            let values: Vec<&str> = value
                .split(',')
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .collect();
            entries.retain(|e| !(e.name == spec.name && !e.inverted));
            if !values.is_empty() {
                entries.push(FilterEntry::text(spec.name, false, &values));
            }
        }
    }
    let entries = filters::check(screen, &entries)?;
    let after =
        match one(&pairs, "after") {
            Some(after) => Some(after.parse().map_err(|_| {
                ServiceError::InvalidRequest(format!("after is an id, not {after:?}"))
            })?),
            None => None,
        };
    Ok(ListRequest {
        filters: entries,
        after,
        done: one(&pairs, "done").map(str::to_owned),
        folded,
    })
}

/// A remediation as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationRow {
    pub id: i64,
    pub href: String,
    pub remediator: String,
    pub observable_type: String,
    pub value: String,
    pub action: String,
    pub status: String,
    pub result: String,
    pub message: String,
    pub analyst: String,
    pub attempts: i32,
    pub created: String,
    pub updated: String,
    /// The forms this row offers a viewer with `remediation:write`, as (path, label).
    pub forms: Vec<(String, &'static str)>,
}

fn remediation_row(r: Remediation, can_write: bool) -> RemediationRow {
    let href = format!("/remediations/{}", r.id);
    let mut forms = Vec::new();
    if can_write {
        if r.status == "COMPLETED" {
            if r.action == "remove" && r.result.as_deref() == Some("SUCCESS") {
                forms.push((format!("{href}/restore"), "Restore"));
            }
            forms.push((format!("{href}/retry"), "Retry"));
        } else {
            forms.push((format!("{href}/cancel"), "Cancel"));
        }
        forms.push((format!("{href}/delete"), "Delete"));
    }
    RemediationRow {
        id: r.id,
        remediator: r.display_name.unwrap_or(r.remediator),
        observable_type: r.observable_type,
        value: r.observable_value,
        action: r.action,
        status: r.status,
        result: r.result.unwrap_or_default(),
        message: r.result_message.unwrap_or_default(),
        analyst: r.analyst.unwrap_or_default(),
        attempts: r.attempts,
        created: time(r.created_at),
        updated: optional(r.updated_at),
        forms,
        href,
    }
}

/// A try as a page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRow {
    pub at: String,
    pub status: String,
    pub result: String,
    pub message: String,
}

fn attempt_row(a: ActionAttempt) -> AttemptRow {
    AttemptRow {
        at: time(a.created_at),
        status: a.status,
        result: a.result,
        message: a.message,
    }
}

/// What a list page shows, of either screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListView<R> {
    pub fields: Vec<FilterField>,
    pub rows: Vec<R>,
    pub total: i64,
    /// First, when this isn't the first page, and Next, when there's one.
    pub first: Option<String>,
    pub next: Option<String>,
    /// The API's exports with the same filters.
    pub csv: String,
    pub ndjson: String,
    /// Where the forms come back to: the page with its filters.
    pub back: String,
    pub can_write: bool,
    pub notice: Option<&'static str>,
}

fn notice(done: Option<&str>) -> Option<&'static str> {
    Some(match done? {
        "queued" => {
            "The remediations are queued. A pool that runs their remediator tries each until it completes."
        }
        "requested" => {
            "The file collection is queued. A pool that runs its collector tries it until it completes."
        }
        "joined" => {
            "A collection of that file by that collector was already pending: the alerts now belong to it as well."
        }
        "cancelled" => "It's cancelled.",
        "retried" => "It's queued again.",
        "restored" => "A restore is queued.",
        "deleted" => "It's deleted.",
        _ => return None,
    })
}

/// `/remediations`.
#[derive(Debug, Template)]
#[template(path = "remediation/list.html")]
pub struct RemediationsPage {
    pub layout: Layout,
    pub view: ListView<RemediationRow>,
}

/// The remediations page's view of a page of them.
pub fn remediations_view(
    request: &ListRequest,
    page: ace_service::RemediationPage,
    can_write: bool,
) -> ListView<RemediationRow> {
    let screen = FilterScreen::Remediations;
    list_view(
        screen,
        "/remediations",
        "/api/remediation/v1/remediations",
        request,
        page.total,
        page.next,
        can_write,
        page.remediations
            .into_iter()
            .map(|r| remediation_row(r, can_write))
            .collect(),
    )
}

#[allow(clippy::too_many_arguments)]
fn list_view<R>(
    screen: FilterScreen,
    path: &str,
    api: &str,
    request: &ListRequest,
    total: i64,
    next: Option<i64>,
    can_write: bool,
    rows: Vec<R>,
) -> ListView<R> {
    let first = list_href(path, screen, &request.filters, None);
    let exports = list_href(&format!("{api}/export/csv"), screen, &request.filters, None);
    ListView {
        fields: filter_fields(screen, &request.filters),
        rows,
        total,
        first: request.after.is_some().then(|| first.clone()),
        next: next.map(|next| list_href(path, screen, &request.filters, Some(next))),
        ndjson: exports.replacen("/export/csv", "/export/ndjson", 1),
        csv: exports,
        back: list_href(path, screen, &request.filters, request.after),
        can_write,
        notice: notice(request.done.as_deref()),
    }
}

/// The list's request, or a refusal drawn as the error page.
fn request_or_fail(
    screen: FilterScreen,
    raw: &RawQuery,
    parts: &Parts,
) -> Result<ListRequest, Failure> {
    list_request(screen, raw.0.as_deref()).map_err(|error| Failure::from_service(error, parts))
}

/// `GET /remediations`.
pub(crate) async fn remediations(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    let request = match request_or_fail(FilterScreen::Remediations, &raw, &parts) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    if request.folded {
        return see_other(
            &list_href(
                "/remediations",
                FilterScreen::Remediations,
                &request.filters,
                None,
            ),
            None,
        );
    }
    let query = ActionQuery {
        filters: request.filters.clone(),
        ..ActionQuery::default()
    };
    let page = match gui
        .service
        .remediations(&viewer.actor, &query, Some(PAGE_SIZE), request.after)
        .await
    {
        Ok(page) => page,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let can_write = gui
        .service
        .allowed(&viewer.actor, &REMEDIATION_WRITE)
        .await
        .unwrap_or(false);
    render(&RemediationsPage {
        layout: viewer.layout,
        view: remediations_view(&request, page, can_write),
    })
}

/// What a remediation's own page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationView {
    pub row: RemediationRow,
    pub attempts: Vec<AttemptRow>,
}

/// `/remediations/{id}`.
#[derive(Debug, Template)]
#[template(path = "remediation/one.html")]
pub struct RemediationPage {
    pub layout: Layout,
    pub view: RemediationView,
}

pub fn remediation_view(
    remediation: Remediation,
    attempts: Vec<ActionAttempt>,
    can_write: bool,
) -> RemediationView {
    RemediationView {
        row: remediation_row(remediation, can_write),
        attempts: attempts.into_iter().map(attempt_row).collect(),
    }
}

fn id_or_fail(id: Result<Path<i64>, PathRejection>, parts: &Parts) -> Result<i64, Failure> {
    id.map(|Path(id)| id)
        .map_err(|_| Failure::new(StatusCode::BAD_REQUEST, "An id is a number.", parts))
}

/// `GET /remediations/{id}`.
pub(crate) async fn remediation(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<i64>, PathRejection>,
) -> Response {
    let id = match id_or_fail(id, &parts) {
        Ok(id) => id,
        Err(failure) => return failure.into_response(),
    };
    let read = async {
        let remediation = gui.service.remediation(&viewer.actor, id).await?;
        let attempts = gui
            .service
            .remediation_history(&viewer.actor, id, HISTORY)
            .await?;
        let can_write = gui
            .service
            .allowed(&viewer.actor, &REMEDIATION_WRITE)
            .await?;
        Ok::<_, ServiceError>(remediation_view(remediation, attempts, can_write))
    };
    match read.await {
        Ok(view) => render(&RemediationPage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// Where a row's form goes back to: the form's `back`, if it's one of the list's own pages.
fn back_of(form: &[(String, String)], list: &str, done: &str) -> String {
    let back = one(form, "back")
        .filter(|b| *b == list || b.starts_with(&format!("{list}?")))
        .unwrap_or(list);
    let joiner = if back.contains('?') { '&' } else { '?' };
    format!("{back}{joiner}done={done}")
}

/// `POST /remediations/{id}/{cancel,retry,restore,delete}`.
pub(crate) async fn remediation_write(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path((id, what)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return Failure::new(StatusCode::BAD_REQUEST, "An id is a number.", &parts).into_response();
    };
    let actor = &viewer.actor;
    let service = &gui.service;
    let (done, result) = match what.as_str() {
        "cancel" => ("cancelled", service.cancel_remediation(actor, id).await),
        "retry" => ("retried", service.retry_remediation(actor, id).await),
        "restore" => ("restored", service.restore_remediation(actor, id).await),
        "delete" => ("deleted", service.delete_remediation(actor, id).await),
        _ => {
            return Failure::new(StatusCode::NOT_FOUND, "There's no such page.", &parts)
                .into_response();
        }
    };
    match result {
        Ok(_) => see_other(&back_of(&pairs(&body), "/remediations", done), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// A target the add form offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRow {
    /// The checkbox's value: `<remediator>:<type>:<value>`.
    pub key: String,
    pub remediator: String,
    pub observable_type: String,
    pub value: String,
    /// The latest remediation, as `#id action status result`, or empty.
    pub current: String,
}

/// What the add form shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetsView {
    pub types: Vec<&'static str>,
    pub selected_type: String,
    pub values: String,
    pub alerts: Vec<Uuid>,
    /// None until something was looked up.
    pub targets: Option<Vec<TargetRow>>,
    pub can_write: bool,
    pub problem: Option<String>,
}

/// `/remediations/targets`.
#[derive(Debug, Template)]
#[template(path = "remediation/targets.html")]
pub struct TargetsPage {
    pub layout: Layout,
    pub view: TargetsView,
}

pub fn target_row(target: RemediationTarget) -> TargetRow {
    let key = &target.key;
    TargetRow {
        key: format!(
            "{}:{}:{}",
            key.remediator, key.observable_type, key.observable_value
        ),
        current: target
            .current
            .map(|c| {
                format!(
                    "#{} {} {} {}",
                    c.id,
                    c.action.unwrap_or_default(),
                    c.status,
                    c.result.unwrap_or_default()
                )
            })
            .unwrap_or_default(),
        remediator: target
            .display_name
            .unwrap_or_else(|| key.remediator.clone()),
        observable_type: key.observable_type.clone(),
        value: key.observable_value.clone(),
    }
}

/// A checkbox's value as a target: the remediator and the type hold no colon, so the value is the rest.
pub fn target_key(text: &str) -> Option<TargetKey> {
    let (remediator, rest) = text.split_once(':')?;
    let (observable_type, value) = rest.split_once(':')?;
    Some(TargetKey {
        remediator: remediator.to_owned(),
        observable_type: observable_type.to_owned(),
        observable_value: value.to_owned(),
    })
}

/// `GET /remediations/targets?type=&values=` or `?alert=`: the targets of what was given.
pub(crate) async fn targets(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    let query: Vec<(String, String)> =
        serde_urlencoded::from_str(raw.0.as_deref().unwrap_or("")).unwrap_or_default();
    let mut types: Vec<&'static str> = gui
        .service
        .actions()
        .of_kind(ace_service::ActionKind::Remediation)
        .map(|spec| spec.observable_type)
        .collect();
    types.sort_unstable();
    types.dedup();
    let alerts: Vec<Uuid> = all(&query, "alert")
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect();
    let selected_type = one(&query, "type").unwrap_or_default().to_owned();
    let values = one(&query, "values").unwrap_or_default().to_owned();
    let lines: Vec<(String, String)> = values
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| (selected_type.clone(), l.to_owned()))
        .collect();
    let looked_up = if !alerts.is_empty() {
        Some(
            gui.service
                .remediation_targets_of_alerts(&viewer.actor, &alerts)
                .await,
        )
    } else if !lines.is_empty() {
        Some(
            gui.service
                .remediation_targets_of_observables(&viewer.actor, &lines)
                .await,
        )
    } else {
        // the empty form, which needs what reading the targets would
        match gui
            .service
            .allowed(&viewer.actor, &ace_service::REMEDIATION_READ)
            .await
        {
            Ok(true) => None,
            Ok(false) => {
                return Failure::new(
                    StatusCode::FORBIDDEN,
                    "Remediation needs remediation:read. Ask an administrator.",
                    &parts,
                )
                .into_response();
            }
            Err(error) => return Failure::from_service(error, &parts).into_response(),
        }
    };
    let (targets, problem, status) = match looked_up {
        None => (None, None, StatusCode::OK),
        Some(Ok(found)) => (
            Some(found.into_iter().map(target_row).collect()),
            None,
            StatusCode::OK,
        ),
        Some(Err(error @ (ServiceError::InvalidRequest(_) | ServiceError::TooLarge(_)))) => {
            (None, Some(error.to_string()), StatusCode::BAD_REQUEST)
        }
        Some(Err(error)) => return Failure::from_service(error, &parts).into_response(),
    };
    let can_write = gui
        .service
        .allowed(&viewer.actor, &REMEDIATION_WRITE)
        .await
        .unwrap_or(false);
    let mut response = render(&TargetsPage {
        layout: viewer.layout,
        view: TargetsView {
            types,
            selected_type,
            values,
            alerts,
            targets,
            can_write,
            problem,
        },
    });
    *response.status_mut() = status;
    response
}

/// `POST /remediations`: queues a removal or a restore of each ticked target.
pub(crate) async fn queue(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let action = match one(&form, "action") {
        Some("restore") => RemediationAction::Restore,
        _ => RemediationAction::Remove,
    };
    let targets: Option<Vec<TargetKey>> =
        all(&form, "target").iter().map(|t| target_key(t)).collect();
    let Some(targets) = targets.filter(|t| !t.is_empty()) else {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            "Tick at least one target to remediate.",
            &parts,
        )
        .into_response();
    };
    match gui
        .service
        .queue_remediations(&viewer.actor, action, &targets)
        .await
    {
        Ok(_) => see_other("/remediations?done=queued", None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// A file collection as the list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRow {
    pub id: i64,
    pub href: String,
    pub collector: String,
    pub observable_type: String,
    pub value: String,
    pub status: String,
    pub result: String,
    pub message: String,
    /// Tries, of the most.
    pub attempts: String,
    pub alerts: Vec<(String, String)>,
    pub requested_by: String,
    /// The file's name and sha256, once collected.
    pub file: Option<(String, String)>,
    pub created: String,
    pub updated: String,
    pub forms: Vec<(String, &'static str)>,
}

fn collection_row(c: FileCollection, can_write: bool) -> CollectionRow {
    let href = format!("/file-collections/{}", c.id);
    let mut forms = Vec::new();
    if can_write {
        if c.status != "COMPLETED" {
            forms.push((format!("{href}/cancel"), "Cancel"));
        }
        forms.push((format!("{href}/retry"), "Retry"));
        forms.push((format!("{href}/delete"), "Delete"));
    }
    CollectionRow {
        id: c.id,
        collector: c.display_name.unwrap_or(c.collector),
        observable_type: c.observable_type,
        value: c.observable_value,
        status: c.status,
        result: c.result.unwrap_or_default(),
        message: c.result_message.unwrap_or_default(),
        attempts: match c.max_attempts {
            Some(max) => format!("{}/{max}", c.attempts),
            None => c.attempts.to_string(),
        },
        alerts: c
            .alerts
            .into_iter()
            .map(|a| (format!("/alerts/{a}"), a.to_string()))
            .collect(),
        requested_by: c.requested_by.unwrap_or_default(),
        file: c.file.map(|(sha256, _, name)| (name, sha256)),
        created: time(c.created_at),
        updated: optional(c.updated_at),
        forms,
        href,
    }
}

/// `/file-collections`.
#[derive(Debug, Template)]
#[template(path = "remediation/collections.html")]
pub struct CollectionsPage {
    pub layout: Layout,
    pub view: ListView<CollectionRow>,
    /// Whether the viewer holds `file_collection:create`, for the link to the request form.
    pub can_create: bool,
}

pub fn collections_view(
    request: &ListRequest,
    page: ace_service::FileCollectionPage,
    can_write: bool,
) -> ListView<CollectionRow> {
    list_view(
        FilterScreen::FileCollections,
        "/file-collections",
        "/api/file-collections/v1/collections",
        request,
        page.total,
        page.next,
        can_write,
        page.collections
            .into_iter()
            .map(|c| collection_row(c, can_write))
            .collect(),
    )
}

/// `GET /file-collections`.
pub(crate) async fn collections(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    let screen = FilterScreen::FileCollections;
    let request = match request_or_fail(screen, &raw, &parts) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    if request.folded {
        return see_other(
            &list_href("/file-collections", screen, &request.filters, None),
            None,
        );
    }
    let query = ActionQuery {
        filters: request.filters.clone(),
        ..ActionQuery::default()
    };
    let page = match gui
        .service
        .file_collections(&viewer.actor, &query, Some(PAGE_SIZE), request.after)
        .await
    {
        Ok(page) => page,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let can_write = gui
        .service
        .allowed(&viewer.actor, &FILE_COLLECTION_WRITE)
        .await
        .unwrap_or(false);
    let can_create = gui
        .service
        .allowed(&viewer.actor, &FILE_COLLECTION_CREATE)
        .await
        .unwrap_or(false);
    render(&CollectionsPage {
        layout: viewer.layout,
        view: collections_view(&request, page, can_write),
        can_create,
    })
}

/// A collector the request form offers: its name, its display name and the type it collects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorChoice {
    pub name: &'static str,
    pub display_name: &'static str,
    pub observable_type: &'static str,
}

/// What the request form shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestView {
    pub collectors: Vec<CollectorChoice>,
    /// The alerts, one per line, as the form had them or the event page's `?alert=` gave them.
    pub alerts: String,
}

/// `/file-collections/new`.
#[derive(Debug, Template)]
#[template(path = "remediation/request.html")]
pub struct RequestPage {
    pub layout: Layout,
    pub view: RequestView,
}

/// The request form's view: the collectors offered, by name, and the alerts.
pub fn request_view(collectors: Vec<CollectorChoice>, alerts: &[String]) -> RequestView {
    RequestView {
        collectors,
        alerts: alerts.join("\n"),
    }
}

/// `GET /file-collections/new`, or `?alert=` repeated: the request form.
pub(crate) async fn request_form(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    raw: RawQuery,
) -> Response {
    match gui
        .service
        .allowed(&viewer.actor, &FILE_COLLECTION_CREATE)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Failure::new(
                StatusCode::FORBIDDEN,
                "Requesting a file collection needs file_collection:create. Ask an administrator.",
                &parts,
            )
            .into_response();
        }
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    }
    let query: Vec<(String, String)> =
        serde_urlencoded::from_str(raw.0.as_deref().unwrap_or("")).unwrap_or_default();
    let alerts: Vec<String> = all(&query, "alert")
        .into_iter()
        .take(MAX_COLLECTION_ALERTS)
        .collect();
    render(&RequestPage {
        layout: viewer.layout,
        view: request_view(
            gui.service
                .actions()
                .of_kind(ace_service::ActionKind::FileCollection)
                .map(|spec| CollectorChoice {
                    name: spec.name,
                    display_name: spec.display_name,
                    observable_type: spec.observable_type,
                })
                .collect(),
            &alerts,
        ),
    })
}

/// `POST /file-collections`: asks the collector for the file, for the alerts listed.
pub(crate) async fn request(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let Some(collector) = one(&form, "collector").and_then(|name| {
        gui.service
            .actions()
            .get(ace_service::ActionKind::FileCollection, name)
    }) else {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            "Pick a collector this server runs.",
            &parts,
        )
        .into_response();
    };
    let mut alerts = Vec::new();
    for line in one(&form, "alerts").unwrap_or_default().lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(alert) = line.parse::<Uuid>() else {
            return Failure::new(
                StatusCode::BAD_REQUEST,
                "An alert is its id, one per line.",
                &parts,
            )
            .into_response();
        };
        alerts.push(alert);
    }
    let ask = CollectionAsk {
        collector: collector.name.to_owned(),
        observable_type: collector.observable_type.to_owned(),
        observable_value: one(&form, "value").unwrap_or_default().trim().to_owned(),
        alerts,
    };
    match gui
        .service
        .request_file_collection(&viewer.actor, &ask)
        .await
    {
        Ok(requested) if requested.queued => see_other("/file-collections?done=requested", None),
        Ok(_) => see_other("/file-collections?done=joined", None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// What a collection's own page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionView {
    pub row: CollectionRow,
    pub attempts: Vec<AttemptRow>,
}

/// `/file-collections/{id}`.
#[derive(Debug, Template)]
#[template(path = "remediation/collection.html")]
pub struct CollectionPage {
    pub layout: Layout,
    pub view: CollectionView,
}

pub fn collection_view(
    collection: FileCollection,
    attempts: Vec<ActionAttempt>,
    can_write: bool,
) -> CollectionView {
    CollectionView {
        row: collection_row(collection, can_write),
        attempts: attempts.into_iter().map(attempt_row).collect(),
    }
}

/// `GET /file-collections/{id}`.
pub(crate) async fn collection(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<i64>, PathRejection>,
) -> Response {
    let id = match id_or_fail(id, &parts) {
        Ok(id) => id,
        Err(failure) => return failure.into_response(),
    };
    let read = async {
        let collection = gui.service.file_collection(&viewer.actor, id).await?;
        let attempts = gui
            .service
            .file_collection_history(&viewer.actor, id, HISTORY)
            .await?;
        let can_write = gui
            .service
            .allowed(&viewer.actor, &FILE_COLLECTION_WRITE)
            .await?;
        Ok::<_, ServiceError>(collection_view(collection, attempts, can_write))
    };
    match read.await {
        Ok(view) => render(&CollectionPage {
            layout: viewer.layout,
            view,
        }),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// `POST /file-collections/{id}/{cancel,retry,delete}`.
pub(crate) async fn collection_write(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    Path((id, what)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let Ok(id) = id.parse::<i64>() else {
        return Failure::new(StatusCode::BAD_REQUEST, "An id is a number.", &parts).into_response();
    };
    let actor = &viewer.actor;
    let service = &gui.service;
    let (done, result) = match what.as_str() {
        "cancel" => ("cancelled", service.cancel_file_collection(actor, id).await),
        "retry" => ("retried", service.retry_file_collection(actor, id).await),
        "delete" => ("deleted", service.delete_file_collection(actor, id).await),
        _ => {
            return Failure::new(StatusCode::NOT_FOUND, "There's no such page.", &parts)
                .into_response();
        }
    };
    match result {
        Ok(_) => see_other(&back_of(&pairs(&body), "/file-collections", done), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}

/// An alert's remediation coverage as the event page's badge shows it, ace3's
/// `analysis/_remediation_badge.html`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageBadge {
    pub label: String,
    pub tooltip: String,
    /// The badge's class, by its state: `coverage-remediated`, `-partial`, `-failed`, `-pending` or
    /// `-unremediated`.
    pub class: &'static str,
}

/// The badge of an alert's coverage, or None when ace3 shows none.
pub fn coverage_badge(coverage: &ace_service::Coverage) -> Option<CoverageBadge> {
    use ace_service::CoverageState as S;
    let class = match coverage.state() {
        S::None => return None,
        S::Remediated => "coverage-remediated",
        S::Partial => "coverage-partial",
        S::Failed => "coverage-failed",
        S::Pending => "coverage-pending",
        S::NotFound | S::Unremediated => "coverage-unremediated",
    };
    Some(CoverageBadge {
        label: coverage.label(),
        tooltip: coverage.tooltip(),
        class,
    })
}
