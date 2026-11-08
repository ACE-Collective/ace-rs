//! The events area (PLAN.md 5.11's `events` area), so far 6b: adding alerts to an event, ace3's
//! `app/analysis/views/edit/event.py` and the event modal in `app/templates/base.html`, over
//! `Service::add_to_event`. The event list, an event's page and its edit come with 6c and 6d.
//!
//! ace3's views and where they are here:
//! - The modal `base.html` draws on the alert list, opened by its "Add to Event" button, is the page
//!   `GET /events/add`, which the alert list's bulk form opens with the ticked alerts
//!   (`formaction`, so the same boxes go). It lists the open events and the closed ones, each a radio
//!   button labelled as ace3 labels it (creation date, type, vector, name), and New Event with its name
//!   and comment, and the six times, which ace3's modal has as hidden fields; here they're in a closed
//!   `<details>`, in UTC, as ace3's are. The open events are the service's first page,
//!   `MAX_EVENTS_PAGE`, where ace3 lists them all, newest first.
//! - `analysis.load_more_events`, the script that appends the next `CLOSED_EVENT_LIMIT` closed events, is
//!   the page's Show more button, which opens the page again at the next page of closed events
//!   (`Service::closed_events`), with First to go back. It's a small form of its own, so what was typed
//!   for a new event isn't put in the URL.
//! - `analysis.add_to_event` is `POST /events/add`, a `SignedIn` post past 5.7's same-origin check,
//!   through `Service::add_to_event`, which checks `event:write` and writes the audit row. ace3 flashes
//!   how many ticked alerts were gone and redirects; here the answer is a page saying what happened: the
//!   event made or added to, the alerts added, those in it already, and those gone since they were ticked,
//!   with a link back to the list. A refusal is the service's answer as an error page, such as times out
//!   of order (400), which ace3 flashes.
//! - The event list's "Create Event", the same modal with New Event chosen and no alerts, is the same
//!   page with no alerts: only a new event's fields. `events/manage.html` is 6c's, which links it; until
//!   then it's reached by its path.
//!
//! The page needs `event:write`, as its post does, and `event:read` to list the events to choose from;
//! a visitor who isn't signed in goes to the login. Everything an event brings, its name, type and vector,
//! is text that askama escapes; an alert's id is a uuid, and an event's an integer.
//!
//! Left out: the disposition and its comment that ace3's script copies into the modal's form, which its
//! `add_to_event` never reads; clearing the session's ticked alerts, since the ticked boxes here are the
//! list page's own state; ace3's `redirect_to`, since the answer links back to where the form came
//! from; and its company mapping, since roots have none.

use ace_service::{
    AddedToEvent, CLOSED_EVENTS_PAGE, EVENT_WRITE, Event, EventChoice, EventRef, EventTimes,
    MAX_EVENT_COMMENT_CHARS, MAX_EVENT_NAME_CHARS, MAX_EVENTS_PAGE, NewEvent, ServiceError,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, NaiveDateTime, Utc};
use uuid::Uuid;

use crate::Gui;
use crate::list::{MAX_BULK, MAX_BULK_FORM_BYTES, all, one, pairs};
use crate::session::{Failure, SignedIn, local_path, render};
use crate::templates::Layout;

/// The largest add form: `MAX_BULK` ids, and a comment of `MAX_EVENT_COMMENT_CHARS` characters of up to
/// 4 bytes, each percent-encoded to 3.
pub(crate) const MAX_ADD_FORM_BYTES: usize =
    MAX_BULK_FORM_BYTES + MAX_EVENT_COMMENT_CHARS * 4 * 3 + 4096;

/// The six times' form fields, in ace3's order, with their labels.
pub const TIMES: [(&str, &str); 6] = [
    ("event_time", "Event time"),
    ("alert_time", "Alert time"),
    ("ownership_time", "Ownership time"),
    ("disposition_time", "Disposition time"),
    ("contain_time", "Contain time"),
    ("remediation_time", "Remediation time"),
];

/// An event to choose, labelled as ace3's modal labels it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventOption {
    pub id: i64,
    pub label: String,
}

impl EventOption {
    pub fn of(event: &Event) -> Self {
        EventOption {
            id: event.id,
            label: format!(
                "{} - {} - {} - {}",
                event.creation_date, event.kind, event.vector, event.name
            ),
        }
    }
}

/// What the add page shows: the view function's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddView {
    /// The ticked alerts. None ticked is the event list's Create Event.
    pub alerts: Vec<Uuid>,
    pub open: Vec<EventOption>,
    /// Whether there are more open events than the page lists.
    pub more_open: bool,
    pub closed: Vec<EventOption>,
    /// The cursor of the next page of closed events, if there's one.
    pub closed_next: Option<i64>,
    /// Whether this isn't the first page of closed events.
    pub closed_later: bool,
    /// Where the answer links back to.
    pub next: String,
    pub times: &'static [(&'static str, &'static str)],
    pub max_name: usize,
    pub max_comment: usize,
}

impl AddView {
    pub fn creating(&self) -> bool {
        self.alerts.is_empty()
    }
}

/// The view function: the page for these alerts and these events as the service read them. Open
/// events are listed newest first, as ace3 lists them.
pub fn add_view(
    alerts: Vec<Uuid>,
    open: &[Event],
    more_open: bool,
    closed: &[Event],
    closed_next: Option<i64>,
    closed_later: bool,
    next: String,
) -> AddView {
    let mut open: Vec<&Event> = open.iter().collect();
    open.sort_by_key(|event| std::cmp::Reverse((event.creation_date, event.id)));
    AddView {
        alerts,
        open: open.into_iter().map(EventOption::of).collect(),
        more_open,
        closed: closed.iter().map(EventOption::of).collect(),
        closed_next,
        closed_later,
        next,
        times: &TIMES,
        max_name: MAX_EVENT_NAME_CHARS,
        max_comment: MAX_EVENT_COMMENT_CHARS,
    }
}

/// `GET /events/add`.
#[derive(Debug, Template)]
#[template(path = "events/add.html")]
pub struct AddPage {
    pub layout: Layout,
    pub view: AddView,
}

/// What an add did, for the answer page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedView {
    pub event: EventOption,
    pub made: bool,
    pub added: Vec<Uuid>,
    pub already: Vec<Uuid>,
    pub missing: Vec<Uuid>,
    pub next: String,
}

pub fn added_view(added: &AddedToEvent, next: String) -> AddedView {
    AddedView {
        event: EventOption::of(&added.event),
        made: added.made,
        added: added.added.clone(),
        already: added.already.clone(),
        missing: added.missing.clone(),
        next,
    }
}

/// The answer to `POST /events/add`.
#[derive(Debug, Template)]
#[template(path = "events/added.html")]
pub struct AddedPage {
    pub layout: Layout,
    pub view: AddedView,
}

fn bad_request(why: impl Into<String>, parts: &Parts) -> Response {
    Failure::new(StatusCode::BAD_REQUEST, why, parts).into_response()
}

/// Where the answer goes back to: the form's `next` if it's a path on this site, else the list.
fn next_of(form: &[(String, String)]) -> String {
    one(form, "next")
        .and_then(local_path)
        .unwrap_or("/")
        .to_owned()
}

/// The ticked alerts, each once, or why they can't be.
fn alerts_of(form: &[(String, String)]) -> Result<Vec<Uuid>, String> {
    let raw = all(form, "alert");
    if raw.len() > MAX_BULK {
        return Err(format!("At most {MAX_BULK} alerts are added at once."));
    }
    let mut alerts = Vec::with_capacity(raw.len());
    for text in raw {
        let id: Uuid = text
            .parse()
            .map_err(|_| format!("{text:?} isn't an alert's id."))?;
        if !alerts.contains(&id) {
            alerts.push(id);
        }
    }
    Ok(alerts)
}

/// A time as the form sends it, in UTC: a `datetime-local` value, with or without its seconds, or ace3's
/// `YYYY-MM-DD HH:MM:SS`. Empty is none.
pub fn form_time(text: &str) -> Result<Option<DateTime<Utc>>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"]
        .iter()
        .find_map(|format| NaiveDateTime::parse_from_str(text, format).ok())
        .map(|time| Some(time.and_utc()))
        .ok_or_else(|| format!("{text:?} isn't a time: use YYYY-MM-DD HH:MM:SS, in UTC."))
}

fn times_of(form: &[(String, String)]) -> Result<EventTimes, String> {
    let time = |name: &str| form_time(one(form, name).unwrap_or(""));
    Ok(EventTimes {
        event_time: time("event_time")?,
        alert_time: time("alert_time")?,
        ownership_time: time("ownership_time")?,
        disposition_time: time("disposition_time")?,
        contain_time: time("contain_time")?,
        remediation_time: time("remediation_time")?,
    })
}

/// The event the form chose, or why it didn't choose one.
fn choice_of(form: &[(String, String)]) -> Result<EventChoice, String> {
    match one(form, "event").map(str::trim) {
        Some("NEW") => Ok(EventChoice::New(NewEvent {
            name: one(form, "name").unwrap_or("").to_owned(),
            comment: one(form, "comment").map(str::to_owned),
            times: times_of(form)?,
        })),
        Some(id) if !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) => id
            .parse()
            .map(|id| EventChoice::Existing(EventRef::Id(id)))
            .map_err(|_| format!("There's no event {id}.")),
        Some(_) => Err("An event is chosen by its id, or New Event.".to_owned()),
        None => Err("Choose an event, or New Event.".to_owned()),
    }
}

/// Refuses a viewer without `event:write` before anything is read, as the post would.
async fn may_add(gui: &Gui, viewer: &SignedIn, parts: &Parts) -> Result<(), Failure> {
    match gui.service.allowed(&viewer.actor, &EVENT_WRITE).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::from_service(
            ServiceError::PermissionDenied {
                actor: viewer.actor.to_string(),
                permission: EVENT_WRITE,
            },
            parts,
        )),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

/// `GET /events/add`: the form, for the ticked alerts or, with none, a new event.
pub(crate) async fn add_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = pairs(raw.as_deref().unwrap_or("").as_bytes());
    let alerts = match alerts_of(&query) {
        Ok(alerts) => alerts,
        Err(why) => return bad_request(why, &parts),
    };
    let closed_after = match one(&query, "closed_after").map(str::trim) {
        None | Some("") => None,
        Some(text) => match text.parse::<i64>() {
            Ok(id) => Some(id),
            Err(_) => return bad_request("closed_after is an event's id.", &parts),
        },
    };
    if let Err(refused) = may_add(&gui, &viewer, &parts).await {
        return refused.into_response();
    }
    let next = next_of(&query);
    let view = if alerts.is_empty() {
        add_view(alerts, &[], false, &[], None, false, next)
    } else {
        let open = match gui
            .service
            .open_events(&viewer.actor, None, MAX_EVENTS_PAGE)
            .await
        {
            Ok(page) => page,
            Err(error) => return Failure::from_service(error, &parts).into_response(),
        };
        let closed = match gui
            .service
            .closed_events(&viewer.actor, closed_after, CLOSED_EVENTS_PAGE)
            .await
        {
            Ok(page) => page,
            Err(error) => return Failure::from_service(error, &parts).into_response(),
        };
        add_view(
            alerts,
            &open.events,
            open.next.is_some(),
            &closed.events,
            closed.next,
            closed_after.is_some(),
            next,
        )
    };
    render(&AddPage {
        layout: viewer.layout,
        view,
    })
}

/// `POST /events/add`: ace3's `add_to_event`, through `Service::add_to_event`.
pub(crate) async fn add(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    body: Bytes,
) -> Response {
    let form = pairs(&body);
    let next = next_of(&form);
    let alerts = match alerts_of(&form) {
        Ok(alerts) => alerts,
        Err(why) => return bad_request(why, &parts),
    };
    let choice = match choice_of(&form) {
        Ok(choice) => choice,
        Err(why) => return bad_request(why, &parts),
    };
    match gui
        .service
        .add_to_event(&viewer.actor, &choice, &alerts)
        .await
    {
        Ok(added) => render(&AddedPage {
            layout: viewer.layout,
            view: added_view(&added, next),
        }),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
