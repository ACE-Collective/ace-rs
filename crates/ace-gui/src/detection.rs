//! Administration's Observables page (PLAN.md 7.6, 5.11's admin area): ace3's `admin/detection.html`,
//! `app/admin/views/detection.py` and `admin_detection.js`, over the `detection` service: the observables
//! ACE detects wherever they appear, entries of the `observable_detection` list.
//!
//! The area's `admin:read` gates every route, as the rest of `crate::admin` does, and the service checks
//! `detection:read` on the page and `detection:write` on each write, as ace3's view and its
//! `/api/v2/detection` routes do. The hub shows the page's tile, ace3's Observables, to whoever holds
//! `detection:read`.
//!
//! ace3's page renders in Flask and writes from its script through the `detection` router. Here:
//! - `GET /admin/detection` is the page: ace3's filters (`q`, `type`, `status`, `page_size`) as a GET
//!   form with a Reset link, the count shown and ace3's pager (First, Previous, Next, Last) as links, the
//!   form for a new detection, and the table: type, value, who added it and when, context, the
//!   observable's comments, its expiry with its two controls, and Delete.
//! - `POST /admin/detection` adds one (`Service::create_detection`); `POST /admin/detection/{id}/expiration`
//!   sets an expiry or, with its Never button, takes it away (`set_detection_expiration`); and
//!   `POST /admin/detection/{id}/delete` removes one (`delete_detection`). Each is a `SignedIn` post that
//!   passed 5.7's same-origin check, and goes back to the page with the filters it came from and a notice.
//!   A refusal about the form, such as a type ace-rs doesn't have, a value that isn't one for it, an expiry
//!   that passed or a duplicate, draws the page again at 400 or 409 with the service's reason and what was
//!   typed; anything else is the error page.
//!
//! Times are UTC, as the CLI's are: an expiry is typed `YYYY-MM-DD HH:MM:SS`, `YYYY-MM-DDTHH:MM` or
//! `YYYY-MM-DD` and read as UTC, where ace3's page shows and takes the server's naive time. An empty
//! expiry on a new detection takes its type's default lifetime, as in ace3.
//!
//! Under the table the page says what the current ruleset holds of the detections as YARA rules (PLAN.md
//! 7.16, `Service::detection_export`): the ruleset, each exported type's counts, and each detection the
//! export left out with why. ace3 has no such section: its export logs a value its YARA refuses.
//!
//! What differs, and why: ace3's "not yet observed" and FA hits come from its index of every observable,
//! which ace-rs doesn't have; its confirm before a delete needs a script; and its `style=` and `<style>`
//! are classes in the stylesheet.

use ace_service::{
    ADMIN_READ, DETECTION_PAGE_SIZES, DETECTION_WRITE, Detection, DetectionExpiry, DetectionExport,
    DetectionFilter, DetectionPage, DetectionStatus, DetectionTypes, NewDetection, ServiceError,
    clamp_detection_page_size,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::{PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::Deserialize;

use crate::Gui;
use crate::list::{one, pairs};
use crate::session::{Failure, SignedIn, render, see_other};
use crate::templates::Layout;

/// The page's path.
pub const PAGE: &str = "/admin/detection";

/// A detection as the table shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionRow {
    pub id: i64,
    pub observable_type: String,
    pub value: String,
    pub added_by: String,
    pub added_at: String,
    pub context: String,
    pub comments: Vec<CommentRow>,
    /// When it expires, or `never`.
    pub expires: String,
    pub expired: bool,
}

/// One of an observable's comments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentRow {
    pub comment: String,
    pub by: String,
    pub at: String,
    pub edited: Option<String>,
}

/// A pager's link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageLink {
    pub label: &'static str,
    /// None where ace3's is disabled.
    pub href: Option<String>,
}

/// What a new detection's form had, drawn again when it's refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetectionDraft {
    pub observable_type: String,
    pub value: String,
    pub expires: String,
    pub context: String,
}

/// A detection the YARA export left out, as the page shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRow {
    pub id: i64,
    pub observable_type: String,
    /// The value now, or empty when the detection is gone.
    pub value: String,
    pub error: String,
}

/// The page's section on the YARA export of the detections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportView {
    /// The ruleset's commit and key, shortened, and when it was built; None when none has been.
    pub ruleset: Option<(String, String, String)>,
    pub exported: i64,
    /// Each exported type with its detections and strings.
    pub types: Vec<(String, i64, i64)>,
    pub skipped: Vec<SkippedRow>,
    pub error: Option<String>,
}

/// The page's view of the export.
pub fn export_view(export: DetectionExport) -> ExportView {
    let short = |text: &str| text.chars().take(12).collect::<String>();
    ExportView {
        ruleset: export
            .ruleset
            .map(|r| (short(&r.commit), short(&r.key), time(r.built_at))),
        exported: export.exported,
        types: export
            .types
            .into_iter()
            .map(|t| (t.observable_type, t.detections, t.strings))
            .collect(),
        skipped: export
            .skipped
            .into_iter()
            .map(|s| SkippedRow {
                id: s.id,
                observable_type: s.observable_type,
                value: s.value.unwrap_or_default(),
                error: s.error,
            })
            .collect(),
        error: export.error,
    }
}

/// What the page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionView {
    pub search: String,
    pub selected_type: String,
    pub selected_status: &'static str,
    pub page_size: i64,
    /// The types with a detection, for the filter.
    pub present_types: Vec<String>,
    /// Every type a detection can be of, for the new one.
    pub all_types: Vec<String>,
    pub statuses: Vec<&'static str>,
    pub page_sizes: Vec<i64>,
    pub total: i64,
    pub first_index: i64,
    pub last_index: i64,
    pub page: i64,
    pub total_pages: i64,
    pub pager: Vec<PageLink>,
    pub rows: Vec<DetectionRow>,
    /// The filters as hidden fields, so a write comes back to them.
    pub back: Vec<(&'static str, String)>,
    /// Whether the viewer may change anything.
    pub can_write: bool,
    pub notice: Option<&'static str>,
    pub problem: Option<String>,
    pub draft: DetectionDraft,
    /// The YARA export of the detections; `detection_view` leaves it empty.
    pub export: ExportView,
}

/// `/admin/detection`.
#[derive(Debug, Template)]
#[template(path = "admin/detection.html")]
pub struct DetectionSettingsPage {
    pub layout: Layout,
    pub view: DetectionView,
}

/// The page's query, as ace3's view reads it: anything that doesn't read takes its default.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageQuery {
    q: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    status: Option<String>,
    page: Option<String>,
    page_size: Option<String>,
    done: Option<String>,
}

fn filter_of(
    q: Option<&str>,
    kind: Option<&str>,
    status: Option<&str>,
    page: Option<&str>,
    page_size: Option<&str>,
) -> DetectionFilter {
    let number = |text: Option<&str>, default: i64| {
        text.and_then(|t| t.trim().parse::<i64>().ok())
            .unwrap_or(default)
    };
    DetectionFilter {
        search: q.filter(|q| !q.is_empty()).map(str::to_owned),
        observable_type: kind.filter(|k| !k.is_empty()).map(str::to_owned),
        status: status
            .and_then(DetectionStatus::parse)
            .unwrap_or(DetectionStatus::Active),
        page: number(page, 1),
        page_size: clamp_detection_page_size(number(
            page_size,
            ace_service::DEFAULT_DETECTION_PAGE_SIZE,
        )),
    }
}

/// The filters as a query, at `page`.
fn query_of(filter: &DetectionFilter, page: i64) -> Vec<(&'static str, String)> {
    let mut query = Vec::new();
    if let Some(q) = &filter.search {
        query.push(("q", q.clone()));
    }
    if let Some(kind) = &filter.observable_type {
        query.push(("type", kind.clone()));
    }
    query.push(("status", filter.status.as_str().to_owned()));
    query.push(("page_size", filter.page_size.to_string()));
    query.push(("page", page.to_string()));
    query
}

fn href(query: &[(&str, String)]) -> String {
    let encoded = serde_urlencoded::to_string(query).unwrap_or_default();
    if encoded.is_empty() {
        PAGE.to_owned()
    } else {
        format!("{PAGE}?{encoded}")
    }
}

fn time(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn row(detection: Detection) -> DetectionRow {
    DetectionRow {
        id: detection.id,
        observable_type: detection.observable_type,
        value: detection.value,
        added_by: detection.created_by.name.unwrap_or(detection.created_by.id),
        added_at: detection.created_at.format("%Y-%m-%d %H:%M").to_string(),
        context: detection.context,
        comments: detection
            .comments
            .into_iter()
            .map(|c| CommentRow {
                by: c.author.display_name.unwrap_or(c.author.username),
                at: c.created_at.format("%Y-%m-%d %H:%M").to_string(),
                edited: c
                    .edited_at
                    .map(|at| at.format("%Y-%m-%d %H:%M").to_string()),
                comment: c.comment,
            })
            .collect(),
        expires: detection
            .expires_at
            .map_or_else(|| "never".to_owned(), time),
        expired: detection.expired,
    }
}

fn pager(filter: &DetectionFilter, page: &DetectionPage) -> Vec<PageLink> {
    if page.total_pages <= 1 {
        return Vec::new();
    }
    let at = |n: i64, enabled: bool| enabled.then(|| href(&query_of(filter, n)));
    vec![
        PageLink {
            label: "First",
            href: at(1, page.has_prev()),
        },
        PageLink {
            label: "Previous",
            href: at(page.page - 1, page.has_prev()),
        },
        PageLink {
            label: "Next",
            href: at(page.page + 1, page.has_next()),
        },
        PageLink {
            label: "Last",
            href: at(page.total_pages, page.has_next()),
        },
    ]
}

/// What a page's `done` says the last form did.
fn notice(done: Option<&str>) -> Option<&'static str> {
    Some(match done? {
        "added" => {
            "The detection is added. Every alert holding the observable gets a detection point from the next task that checks it."
        }
        "expiration" => "The expiry is set.",
        "deleted" => "The detection is removed.",
        "unchanged" => "Nothing changed: it was already so.",
        _ => return None,
    })
}

async fn enter(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    match gui.service.allowed(&viewer.actor, &ADMIN_READ).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::new(
            StatusCode::FORBIDDEN,
            "The administration area needs admin:read. Ask an administrator.",
            parts,
        )),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

/// The page's view of a listing, its types and whether the viewer may write.
pub fn detection_view(
    filter: &DetectionFilter,
    page: DetectionPage,
    types: DetectionTypes,
    can_write: bool,
) -> DetectionView {
    let filter = DetectionFilter {
        page_size: page.page_size,
        ..filter.clone()
    };
    DetectionView {
        search: filter.search.clone().unwrap_or_default(),
        selected_type: filter.observable_type.clone().unwrap_or_default(),
        selected_status: filter.status.as_str(),
        page_size: page.page_size,
        present_types: types.present,
        all_types: types.all,
        statuses: DetectionStatus::ALL.iter().map(|s| s.as_str()).collect(),
        page_sizes: DETECTION_PAGE_SIZES.to_vec(),
        total: page.total,
        first_index: page.first_index(),
        last_index: page.last_index(),
        page: page.page,
        total_pages: page.total_pages,
        pager: pager(&filter, &page),
        back: query_of(&filter, page.page),
        can_write,
        notice: None,
        problem: None,
        draft: DetectionDraft::default(),
        export: ExportView::default(),
        rows: page.items.into_iter().map(row).collect(),
    }
}

async fn read_view(
    gui: &Gui,
    viewer: &SignedIn,
    filter: &DetectionFilter,
) -> Result<DetectionView, ServiceError> {
    let actor = &viewer.actor;
    let page = gui.service.detections(actor, filter).await?;
    let types = gui.service.detection_types(actor).await?;
    let can_write = gui.service.allowed(actor, &DETECTION_WRITE).await?;
    let export = gui.service.detection_export(actor).await?;
    let mut view = detection_view(filter, page, types, can_write);
    view.export = export_view(export);
    Ok(view)
}

async fn page_with(
    gui: &Gui,
    viewer: SignedIn,
    parts: &Parts,
    filter: &DetectionFilter,
    status: StatusCode,
    change: impl FnOnce(&mut DetectionView),
) -> Response {
    let mut view = match read_view(gui, &viewer, filter).await {
        Ok(view) => view,
        Err(error) => return Failure::from_service(error, parts).into_response(),
    };
    change(&mut view);
    let mut response = render(&DetectionSettingsPage {
        layout: viewer.layout,
        view,
    });
    *response.status_mut() = status;
    response
}

/// `GET /admin/detection`.
pub(crate) async fn page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let query = query.map(|Query(q)| q).unwrap_or_default();
    let filter = filter_of(
        query.q.as_deref(),
        query.kind.as_deref(),
        query.status.as_deref(),
        query.page.as_deref(),
        query.page_size.as_deref(),
    );
    let notice = notice(query.done.as_deref());
    page_with(&gui, viewer, &parts, &filter, StatusCode::OK, |view| {
        view.notice = notice;
    })
    .await
}

/// The filters a form came from, in its hidden fields.
fn back_filter(form: &[(String, String)]) -> DetectionFilter {
    filter_of(
        one(form, "q"),
        one(form, "type"),
        one(form, "status"),
        one(form, "page"),
        one(form, "page_size"),
    )
}

/// Back to the page with the filters and `done`.
fn back_to(filter: &DetectionFilter, done: &str) -> Response {
    let mut query = query_of(filter, filter.page);
    query.push(("done", done.to_owned()));
    see_other(&href(&query), None)
}

/// The status a refusal of a form draws the page again at, or None for an error that isn't the form's.
fn refused(error: &ServiceError) -> Option<StatusCode> {
    match error {
        ServiceError::InvalidRequest(_) => Some(StatusCode::BAD_REQUEST),
        ServiceError::Conflict(_) => Some(StatusCode::CONFLICT),
        _ => None,
    }
}

/// An expiry as the form types it, read as UTC.
pub fn parse_expiry(text: &str) -> Option<DateTime<Utc>> {
    let text = text.trim().trim_end_matches("UTC").trim();
    for format in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(at) = NaiveDateTime::parse_from_str(text, format) {
            return Some(at.and_utc());
        }
    }
    NaiveDate::parse_from_str(text, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|at| at.and_utc())
}

const BAD_EXPIRY: &str =
    "An expiry is a UTC time: YYYY-MM-DD HH:MM:SS, YYYY-MM-DDTHH:MM or YYYY-MM-DD.";

/// `POST /admin/detection`: adds a detection.
pub(crate) async fn add(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let form = pairs(&body);
    let field = |name: &str| one(&form, name).unwrap_or("").to_owned();
    let filter = back_filter(&form);
    let draft = DetectionDraft {
        observable_type: field("observable_type"),
        value: field("value"),
        expires: field("expires"),
        context: field("context"),
    };
    let redraw = |viewer, problem: String, status, draft: DetectionDraft| {
        let gui = gui.clone();
        let parts = parts.clone();
        let filter = filter.clone();
        async move {
            page_with(&gui, viewer, &parts, &filter, status, |view| {
                view.problem = Some(problem);
                view.draft = draft;
            })
            .await
        }
    };
    let expires = if draft.expires.trim().is_empty() {
        DetectionExpiry::Default
    } else {
        match parse_expiry(&draft.expires) {
            Some(at) => DetectionExpiry::At(at),
            None => {
                return redraw(
                    viewer,
                    BAD_EXPIRY.to_owned(),
                    StatusCode::BAD_REQUEST,
                    draft,
                )
                .await;
            }
        }
    };
    let detection = NewDetection {
        observable_type: draft.observable_type.clone(),
        value: draft.value.clone(),
        expires,
        context: Some(draft.context.clone()).filter(|c| !c.trim().is_empty()),
    };
    match gui
        .service
        .create_detection(&viewer.actor, &detection)
        .await
    {
        Ok(_) => back_to(&filter, "added"),
        Err(error) => match refused(&error) {
            Some(status) => redraw(viewer, error.to_string(), status, draft).await,
            None => Failure::from_service(error, &parts).into_response(),
        },
    }
}

fn id_of(id: Result<Path<i64>, PathRejection>) -> Option<i64> {
    id.ok().map(|Path(id)| id)
}

/// `POST /admin/detection/{id}/expiration`: sets the expiry typed, or, with `never`, takes it away.
pub(crate) async fn set_expiration(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<i64>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = id_of(id) else {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            "A detection's id is a number.",
            &parts,
        )
        .into_response();
    };
    let form = pairs(&body);
    let filter = back_filter(&form);
    let expires = if one(&form, "action") == Some("never") {
        None
    } else {
        match parse_expiry(one(&form, "expires").unwrap_or("")) {
            Some(at) => Some(at),
            None => {
                return page_with(
                    &gui,
                    viewer,
                    &parts,
                    &filter,
                    StatusCode::BAD_REQUEST,
                    |view| {
                        view.problem = Some(BAD_EXPIRY.to_owned());
                    },
                )
                .await;
            }
        }
    };
    let before = gui.service.detection(&viewer.actor, id).await;
    match gui
        .service
        .set_detection_expiration(&viewer.actor, id, expires)
        .await
    {
        Ok(after) => {
            let same = before.is_ok_and(|before| before.expires_at == after.expires_at);
            back_to(&filter, if same { "unchanged" } else { "expiration" })
        }
        Err(error) => match refused(&error) {
            Some(status) => {
                let problem = error.to_string();
                page_with(&gui, viewer, &parts, &filter, status, |view| {
                    view.problem = Some(problem);
                })
                .await
            }
            None => Failure::from_service(error, &parts).into_response(),
        },
    }
}

/// `POST /admin/detection/{id}/delete`: removes a detection.
pub(crate) async fn delete(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    id: Result<Path<i64>, PathRejection>,
    body: Bytes,
) -> Response {
    if let Err(failure) = enter(&gui, &viewer, &parts).await {
        return failure.into_response();
    }
    let Some(id) = id_of(id) else {
        return Failure::new(
            StatusCode::BAD_REQUEST,
            "A detection's id is a number.",
            &parts,
        )
        .into_response();
    };
    let filter = back_filter(&pairs(&body));
    match gui.service.delete_detection(&viewer.actor, id).await {
        Ok(_) => back_to(&filter, "deleted"),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
