//! The events area (PLAN.md 5.11's `events` area): 6b, adding alerts to an event, ace3's
//! `app/analysis/views/edit/event.py` and the event modal in `app/templates/base.html`, over
//! `Service::add_to_event`; and 6c, the event list and an event's page, ace3's `app/events/views/manage.py`
//! and `index.py`. An event's edit comes with 6d.
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
//!   event made or added to, linked to its page, the alerts added, those in it already, and those gone
//!   since they were ticked, with a link back to the list. A refusal is the service's answer as an error
//!   page, such as times out of order (400), which ace3 flashes.
//! - The event list's "Create Event", the same modal with New Event chosen and no alerts, is the same
//!   page with no alerts: only a new event's fields. The event list links it for a viewer with
//!   `event:write`.
//! - `events.manage` (`events/manage.html`) is `GET /events`, through `Service::event_list` with the
//!   event list's filters (`ace_service::filters::events`) and `Service::event_choices` for the form's
//!   options. ace3 keeps its filters and sort in the session, from a POSTed modal; here they're the URL,
//!   from a `GET` form in a closed `<details>`, so a reload, the back button and a copied link show the
//!   same list and looking writes nothing. A URL without the form's `filtered` field is ace3's list as it
//!   opens, the open events; Reset Filters links there. A filter that can't be read is said above the
//!   form, with no rows, where ace3 flashes it and falls back to the last 7 days. The column headers sort
//!   as ace3's do: the column sorted by turns around, another starts descending; the id breaks ties, and
//!   the pages are a keyset of `EVENTS_PAGE_SIZE`, First and Next, where ace3 shows every event.
//! - ace3's expand caret, `events.manage_event_details` (`manage_event_summary.html`), which draws the
//!   event's comment, times and alerts under its row, is the row's link to its page's alerts, which has
//!   all three. ace3's alert filters have no event filter, so it's the event's page, not the alert list.
//! - Export to CSV, ace3's `export_events_to_csv` script, is a `GET` form of the ticked rows to
//!   `GET /events/export`, which sends the browser on to 6a's `GET /api/events/v1/events/export/csv`
//!   with their ids, which takes the session, checks `event:read` and guards formula cells. At most
//!   `MAX_EXPORT_EVENTS` go.
//! - `events.index` (`events/index.html`, `event_details.html`, `alert_summary.html`,
//!   `event_alerts.html`, `alerts_still_analyzing.html`) is `GET /events/{event}`, by its id or its uuid
//!   as ace3's `direct` takes either: its name, own tags, comment, six times (UTC), disposition, status,
//!   owner, remediation, type, vector, severity, prevention tool, threat actor, threat types and malware,
//!   and its alerts, oldest first, each with its date, title (linked), tags, disposition and analysis
//!   state, ace3's `status`. ace3's "ALERTS ARE STILL ANALYZING!" shows while one runs
//!   (`Event::still_analyzing`).
//! - Close Event, ace3's `close_event` script, which confirms with `window.confirm` and sends
//!   `PATCH /events/{id}` with `events.closed_status`, is a link, for a viewer with `event:write` and an
//!   event that isn't closed, to the confirm page `GET /events/{event}/close`, whose form posts
//!   `POST /events/{event}/close`, a `SignedIn` post past the same-origin check, through
//!   `Service::set_event_status` to `CLOSED`, audited. That's all ace3's close does: its route sets the
//!   status and nothing else, no disposition and no time. The answer goes back to the event's page.
//!
//! Every page here needs `event:read`, which the service checks, and the add page and Close Event
//! `event:write` too; a visitor who isn't signed in goes to the login. Everything an event brings, its
//! name, comment, tags, type and vector, its malware and campaign, its owner's name and its alerts'
//! titles, is text that askama escapes; an alert's id is a uuid, and an event's an integer.
//!
//! Left out: from the add page, the disposition and its comment that ace3's script copies into the
//! modal's form, which its `add_to_event` never reads; clearing the session's ticked alerts, since the
//! ticked boxes here are the list page's own state; ace3's `redirect_to`, since the answer links back to
//! where the form came from; and its company mapping and Companies filter, since roots have none. From
//! the list and the event page, what 6d brings: the edit pencil and Edit Event, Remove Alert(s) and Add
//! Tag(s), and the event page's bulk Set Disposition; and what waits for what writes it (PLAN.md 5.11's
//! events item): the alerts' Add Tag, Remove Tag, Add Comment and Review Disposition, their comments,
//! owners, priorities and remediation badges (7.9), and tag colours. ace3's `wiki` is always empty, its
//! copy-link button needs a script, and the owner filter offers the users who own an event, where ace3
//! offers every user (`Service::event_choices`).

use ace_service::filters::DISPOSITIONS;
use ace_service::{
    AddedToEvent, AnalysisState, CLOSED_EVENTS_PAGE, CLOSED_STATUS, EVENT_READ, EVENT_WRITE, Event,
    EventChoice, EventChoices, EventFilters, EventListPage, EventOwner, EventOwnerFilter,
    EventQuery, EventRef, EventSort, EventTimes, EventValue, MAX_EVENT_COMMENT_CHARS,
    MAX_EVENT_NAME_CHARS, MAX_EVENTS_PAGE, MAX_EXPORT_EVENTS, NewEvent, OPEN, PermissionName,
    ServiceError,
};
use askama::Template;
use axum::body::Bytes;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, NaiveDateTime, Utc};
use uuid::Uuid;

use crate::Gui;
use crate::list::{MAX_BULK, MAX_BULK_FORM_BYTES, all, one, pairs};
use crate::session::{Failure, SignedIn, local_path, render, see_other};
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
    if let Err(refused) = may(&gui, &viewer, &EVENT_WRITE, &parts).await {
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

// ---- 6c: the event list and an event's page ----

/// How many events a page of the list shows. ace3's list shows them all.
pub const EVENTS_PAGE_SIZE: u32 = 100;

/// The event list as its URL asks for it: the filters, the order and the cursor. The filters' form has a
/// `filtered` field, so a URL without it is the list as ace3 opens it (`EventFilters::ace3_default`), and
/// one with it is exactly what the form chose, all statuses included.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventListQuery {
    pub query: EventQuery,
    pub after: Option<String>,
}

/// A select's `ANY`, or nothing, is no filter.
fn any(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "ANY")
        .map(str::to_owned)
}

fn int_ids(form: &[(String, String)], name: &str, label: &str) -> Result<Vec<i32>, String> {
    all(form, name)
        .iter()
        .map(|text| {
            text.trim()
                .parse()
                .map_err(|_| format!("{text:?} isn't a {label}'s id."))
        })
        .collect()
}

impl EventListQuery {
    /// The list a URL's query asks for. A sort, direction or id that isn't one is an error, since only a
    /// hand-made URL has one; a filter's value is checked by the service (`EventFilters::check`).
    pub fn parse(form: &[(String, String)]) -> Result<Self, String> {
        let filters = if one(form, "filtered").is_some() {
            let owners = all(form, "owner")
                .iter()
                .map(|text| match text.trim() {
                    "None" => Ok(EventOwnerFilter::Nobody),
                    id => id
                        .parse()
                        .map(EventOwnerFilter::User)
                        .map_err(|_| format!("{text:?} isn't a user's id or None.")),
                })
                .collect::<Result<Vec<_>, _>>()?;
            EventFilters {
                created: one(form, "created").map(str::to_owned),
                dispositions: all(form, "disposition"),
                statuses: all(form, "status"),
                owners,
                kind: any(one(form, "type")),
                vector: any(one(form, "vector")),
                prevention_tool: any(one(form, "prevention_tool")),
                risk_level: any(one(form, "risk_level")),
                observable_type: any(one(form, "observable_type")),
                observable_value: one(form, "observable_value").map(str::to_owned),
                tags: all(form, "tag"),
                malware: int_ids(form, "malware", "malware")?,
                campaigns: int_ids(form, "campaign", "threat actor")?,
            }
        } else {
            EventFilters::ace3_default()
        };
        let sort = match one(form, "sort") {
            None | Some("") => EventSort::default(),
            Some(name) => {
                EventSort::named(name).ok_or_else(|| format!("{name:?} isn't a sort."))?
            }
        };
        let descending = match one(form, "dir") {
            None | Some("") | Some("desc") => true,
            Some("asc") => false,
            Some(dir) => return Err(format!("{dir:?} isn't asc or desc.")),
        };
        let after = one(form, "after")
            .filter(|after| !after.is_empty())
            .map(str::to_owned);
        Ok(EventListQuery {
            query: EventQuery {
                filters,
                sort,
                descending,
            },
            after,
        })
    }

    fn pairs(
        &self,
        sort: EventSort,
        descending: bool,
        after: Option<&str>,
    ) -> Vec<(&'static str, String)> {
        let f = &self.query.filters;
        let mut pairs: Vec<(&'static str, String)> = vec![("filtered", "1".to_owned())];
        let mut text = |name: &'static str, value: &Option<String>| {
            if let Some(value) = value {
                pairs.push((name, value.clone()));
            }
        };
        text("created", &f.created);
        text("type", &f.kind);
        text("vector", &f.vector);
        text("prevention_tool", &f.prevention_tool);
        text("risk_level", &f.risk_level);
        text("observable_type", &f.observable_type);
        text("observable_value", &f.observable_value);
        pairs.extend(f.dispositions.iter().map(|v| ("disposition", v.clone())));
        pairs.extend(f.statuses.iter().map(|v| ("status", v.clone())));
        pairs.extend(f.owners.iter().map(|owner| {
            (
                "owner",
                match owner {
                    EventOwnerFilter::Nobody => "None".to_owned(),
                    EventOwnerFilter::User(id) => id.to_string(),
                },
            )
        }));
        pairs.extend(f.tags.iter().map(|v| ("tag", v.clone())));
        pairs.extend(f.malware.iter().map(|v| ("malware", v.to_string())));
        pairs.extend(f.campaigns.iter().map(|v| ("campaign", v.to_string())));
        if sort != EventSort::default() {
            pairs.push(("sort", sort.as_str().to_owned()));
        }
        if !descending {
            pairs.push(("dir", "asc".to_owned()));
        }
        if let Some(after) = after {
            pairs.push(("after", after.to_owned()));
        }
        pairs
    }

    fn url(&self, sort: EventSort, descending: bool, after: Option<&str>) -> String {
        format!(
            "/events?{}",
            serde_urlencoded::to_string(self.pairs(sort, descending, after))
                .expect("pairs of text encode")
        )
    }
}

/// A time as the event pages show it, in UTC as ace3's are, or nothing.
fn utc(time: Option<DateTime<Utc>>) -> String {
    time.map(|time| time.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// An owner as ace3's `gui_display` names them: their display name, else their username.
fn owner_name(owner: Option<&EventOwner>) -> String {
    owner
        .map(|owner| {
            owner
                .display_name
                .clone()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| owner.username.clone())
        })
        .unwrap_or_default()
}

/// An event's path, by its id.
pub fn event_href(id: i64) -> String {
    format!("/events/{id}")
}

/// One row of the event list, ace3's columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRow {
    pub id: i64,
    pub href: String,
    /// Where its alerts are: its page's alerts, ace3's expanded row.
    pub alerts_href: String,
    pub alerts: usize,
    pub date: String,
    pub kind: String,
    pub vector: String,
    pub name: String,
    pub tags: Vec<String>,
    pub campaign: String,
    pub threat_types: Vec<String>,
    pub malware: Vec<String>,
    pub risk_level: String,
    pub disposition: String,
    pub prevention_tool: String,
    pub remediation: String,
    pub status: String,
    pub owner: String,
}

impl EventRow {
    fn of(event: &Event) -> Self {
        EventRow {
            id: event.id,
            href: event_href(event.id),
            alerts_href: format!("{}#alerts", event_href(event.id)),
            alerts: event.alerts.len(),
            date: event.creation_date.to_string(),
            kind: event.kind.clone(),
            vector: event.vector.clone(),
            name: event.name.clone(),
            tags: event.tags.clone(),
            campaign: event.campaign.clone().unwrap_or_default(),
            threat_types: event
                .threat_types()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            malware: event.malware.iter().map(|m| m.name.clone()).collect(),
            risk_level: event.risk_level.clone(),
            disposition: event.disposition.clone(),
            prevention_tool: event.prevention_tool.clone(),
            remediation: event.remediation.clone(),
            status: event.status.clone(),
            owner: owner_name(event.owner.as_ref()),
        }
    }
}

/// A column's header: its label, and for a column that sorts, the link that sorts by it and the arrow
/// that says it's the order now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventColumn {
    pub label: &'static str,
    pub href: Option<String>,
    pub mark: &'static str,
}

/// The list's columns in ace3's order, with the sort each has.
const COLUMNS: [(&str, Option<EventSort>); 11] = [
    ("Date", Some(EventSort::Date)),
    ("Event", Some(EventSort::Event)),
    ("Threat Actor", Some(EventSort::Campaign)),
    ("Threat Type", None),
    ("Threat Name", None),
    ("Severity", Some(EventSort::RiskLevel)),
    ("Disposition", Some(EventSort::Disposition)),
    ("Prevention", Some(EventSort::Prevention)),
    ("Remediation", Some(EventSort::Remediation)),
    ("Status", Some(EventSort::Status)),
    ("Owner", Some(EventSort::Owner)),
];

/// One option of the filters' form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterChoice {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

impl FilterChoice {
    fn new(value: impl Into<String>, label: impl Into<String>, selected: bool) -> Self {
        FilterChoice {
            value: value.into(),
            label: label.into(),
            selected,
        }
    }
}

/// What the event list shows: the view function's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventListView {
    pub rows: Vec<EventRow>,
    pub total: i64,
    pub columns: Vec<EventColumn>,
    pub first: Option<String>,
    pub next: Option<String>,
    /// Why the filters couldn't be read, in which case there are no rows.
    pub error: Option<String>,
    /// Whether the viewer holds `event:write`, for Create Event.
    pub can_write: bool,
    pub created: String,
    pub dispositions: Vec<FilterChoice>,
    pub statuses: Vec<FilterChoice>,
    pub owners: Vec<FilterChoice>,
    pub types: Vec<FilterChoice>,
    pub vectors: Vec<FilterChoice>,
    pub prevention_tools: Vec<FilterChoice>,
    pub risk_levels: Vec<FilterChoice>,
    pub observable_types: Vec<FilterChoice>,
    pub observable_value: String,
    pub tags: Vec<FilterChoice>,
    pub malware: Vec<FilterChoice>,
    pub campaigns: Vec<FilterChoice>,
    pub max_export: usize,
}

/// A single select's options: `ANY`, then each value, the chosen one selected.
fn single(values: &[EventValue], chosen: Option<&str>) -> Vec<FilterChoice> {
    std::iter::once(FilterChoice::new("ANY", "ANY", chosen.is_none()))
        .chain(
            values
                .iter()
                .map(|v| FilterChoice::new(&v.value, &v.value, chosen == Some(v.value.as_str()))),
        )
        .collect()
}

fn multi(values: &[EventValue], chosen: &[String]) -> Vec<FilterChoice> {
    values
        .iter()
        .map(|v| FilterChoice::new(&v.value, &v.value, chosen.contains(&v.value)))
        .collect()
}

fn by_id(values: &[EventValue], chosen: &[i32]) -> Vec<FilterChoice> {
    values
        .iter()
        .map(|v| FilterChoice::new(v.id.to_string(), &v.value, chosen.contains(&v.id)))
        .collect()
}

/// The view function: a page of the list as the service read it, for this query, with the filters'
/// choices. `error` is why the filters couldn't be read, and then `page` is None.
pub fn event_list_view(
    page: Option<&EventListPage>,
    query: &EventListQuery,
    choices: &EventChoices,
    error: Option<String>,
    can_write: bool,
) -> EventListView {
    let q = &query.query;
    let f = &q.filters;
    let columns = COLUMNS
        .iter()
        .map(|(label, sort)| match sort {
            Some(sort) => {
                let current = *sort == q.sort;
                // ace3: the column sorted by now turns around, and another starts descending
                let descending = if current { !q.descending } else { true };
                EventColumn {
                    label,
                    href: Some(query.url(*sort, descending, None)),
                    mark: match (current, q.descending) {
                        (false, _) => "",
                        (true, true) => "↓",
                        (true, false) => "↑",
                    },
                }
            }
            None => EventColumn {
                label,
                href: None,
                mark: "",
            },
        })
        .collect();
    let mut owners = vec![FilterChoice::new(
        "None",
        "None",
        f.owners.contains(&EventOwnerFilter::Nobody),
    )];
    owners.extend(choices.owners.iter().map(|owner| {
        let name = owner
            .display_name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| owner.username.clone());
        FilterChoice::new(
            owner.id.0.to_string(),
            name,
            f.owners.contains(&EventOwnerFilter::User(owner.id.0)),
        )
    }));
    let mut tags: Vec<FilterChoice> = choices
        .tags
        .iter()
        .map(|tag| FilterChoice::new(tag, tag, f.tags.contains(tag)))
        .collect();
    // a tag in the URL that no event has any more stays chosen, so the form doesn't drop it
    for tag in &f.tags {
        if !choices.tags.contains(tag) {
            tags.push(FilterChoice::new(tag, tag, true));
        }
    }
    let observable_types =
        std::iter::once(FilterChoice::new("ANY", "ANY", f.observable_type.is_none()))
            .chain(ace_results::ObservableKind::all().iter().map(|kind| {
                FilterChoice::new(
                    kind.as_str(),
                    kind.as_str(),
                    f.observable_type.as_deref() == Some(kind.as_str()),
                )
            }))
            .collect();
    let dispositions = DISPOSITIONS
        .iter()
        .map(|d| FilterChoice::new(*d, *d, f.dispositions.iter().any(|c| c == d)))
        .collect();
    EventListView {
        rows: page
            .map(|page| page.events.iter().map(EventRow::of).collect())
            .unwrap_or_default(),
        total: page.map_or(0, |page| page.total),
        columns,
        first: query
            .after
            .is_some()
            .then(|| query.url(q.sort, q.descending, None)),
        next: page
            .and_then(|page| page.next.as_deref())
            .map(|next| query.url(q.sort, q.descending, Some(next))),
        error,
        can_write,
        created: f.created.clone().unwrap_or_default(),
        dispositions,
        statuses: multi(&choices.statuses, &f.statuses),
        owners,
        types: single(&choices.types, f.kind.as_deref()),
        vectors: single(&choices.vectors, f.vector.as_deref()),
        prevention_tools: single(&choices.prevention_tools, f.prevention_tool.as_deref()),
        risk_levels: single(&choices.risk_levels, f.risk_level.as_deref()),
        observable_types,
        observable_value: f.observable_value.clone().unwrap_or_default(),
        tags,
        malware: by_id(&choices.malware, &f.malware),
        campaigns: by_id(&choices.campaigns, &f.campaigns),
        max_export: MAX_EXPORT_EVENTS,
    }
}

/// `GET /events`, ace3's `events/manage.html`.
#[derive(Debug, Template)]
#[template(path = "events/list.html")]
pub struct EventListPageHtml {
    pub layout: Layout,
    pub view: EventListView,
}

/// One of an event's alerts, ace3's `event_alerts.html` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventAlertRow {
    pub href: String,
    pub date: String,
    pub title: String,
    pub tags: Vec<String>,
    pub disposition: String,
    pub status: &'static str,
}

/// An alert's analysis as ace3's alert `status` names it, as the alert list does.
fn analysis_status(state: AnalysisState) -> &'static str {
    match state {
        AnalysisState::Running => "Analyzing",
        AnalysisState::Complete => "Completed",
        AnalysisState::Cancelled => "Cancelled",
    }
}

/// What an event's page shows: the view function's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventView {
    pub id: i64,
    pub uuid: String,
    pub name: String,
    pub comment: String,
    /// The six times, labelled, in ace3's order.
    pub times: Vec<(&'static str, String)>,
    pub disposition: String,
    pub status: String,
    pub owner: String,
    pub remediation: String,
    pub kind: String,
    pub vector: String,
    pub risk_level: String,
    pub prevention_tool: String,
    pub campaign: String,
    pub threat_types: Vec<String>,
    pub malware: Vec<String>,
    pub tags: Vec<String>,
    pub still_analyzing: bool,
    pub alerts: Vec<EventAlertRow>,
    /// The Close Event confirm's path, for a viewer with `event:write` and an event that isn't closed.
    pub close: Option<String>,
}

pub fn event_view(event: &Event, can_write: bool) -> EventView {
    let times = [
        event.event_time,
        event.alert_time,
        event.ownership_time,
        event.disposition_time,
        event.contain_time,
        event.remediation_time,
    ];
    EventView {
        id: event.id,
        uuid: event.uuid.to_string(),
        name: event.name.clone(),
        comment: event.comment.clone().unwrap_or_default(),
        times: [
            "Event Time",
            "Alert Time",
            "Ownership Time",
            "Disposition Time",
            "Contain Time",
            "Remediation Time",
        ]
        .into_iter()
        .zip(times)
        .map(|(label, time)| (label, utc(time)))
        .collect(),
        disposition: event.disposition.clone(),
        status: event.status.clone(),
        owner: owner_name(event.owner.as_ref()),
        remediation: event.remediation.clone(),
        kind: event.kind.clone(),
        vector: event.vector.clone(),
        risk_level: event.risk_level.clone(),
        prevention_tool: event.prevention_tool.clone(),
        campaign: event.campaign.clone().unwrap_or_default(),
        threat_types: event
            .threat_types()
            .into_iter()
            .map(str::to_owned)
            .collect(),
        malware: event.malware.iter().map(|m| m.name.clone()).collect(),
        tags: event.tags.clone(),
        still_analyzing: event.still_analyzing(),
        alerts: event
            .alerts
            .iter()
            .map(|alert| EventAlertRow {
                href: format!("/alerts/{}", alert.id),
                date: utc(alert.alerted_at),
                title: alert.title.clone(),
                tags: alert.tags.clone(),
                disposition: alert.disposition.clone().unwrap_or_else(|| OPEN.to_owned()),
                status: analysis_status(alert.analysis),
            })
            .collect(),
        close: (can_write && event.status != CLOSED_STATUS)
            .then(|| format!("{}/close", event_href(event.id))),
    }
}

/// `GET /events/{event}`, ace3's `events/index.html`.
#[derive(Debug, Template)]
#[template(path = "events/event.html")]
pub struct EventPageHtml {
    pub layout: Layout,
    pub view: EventView,
}

/// The Close Event confirm, where ace3's script asks with `window.confirm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseView {
    pub name: String,
    pub label: String,
    pub href: String,
    pub action: String,
    /// Whether it's closed already, so there's nothing to confirm.
    pub closed: bool,
}

pub fn close_view(event: &Event) -> CloseView {
    CloseView {
        name: event.name.clone(),
        label: EventOption::of(event).label,
        href: event_href(event.id),
        action: format!("{}/close", event_href(event.id)),
        closed: event.status == CLOSED_STATUS,
    }
}

/// `GET /events/{event}/close`.
#[derive(Debug, Template)]
#[template(path = "events/close.html")]
pub struct ClosePage {
    pub layout: Layout,
    pub view: CloseView,
}

/// Refuses a viewer without `permission` before anything is read.
async fn may(
    gui: &Gui,
    viewer: &SignedIn,
    permission: &PermissionName,
    parts: &Parts,
) -> Result<(), Failure> {
    match gui.service.allowed(&viewer.actor, permission).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Failure::from_service(
            ServiceError::PermissionDenied {
                actor: viewer.actor.to_string(),
                permission: permission.clone(),
            },
            parts,
        )),
        Err(error) => Err(Failure::from_service(error, parts)),
    }
}

/// Whether the viewer may write events; false when that can't be read, so a page still draws.
async fn can_write(gui: &Gui, viewer: &SignedIn) -> bool {
    gui.service
        .allowed(&viewer.actor, &EVENT_WRITE)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(actor = %viewer.actor, "checking event:write failed: {error}");
            false
        })
}

/// `GET /events`: the event list.
pub(crate) async fn list_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    RawQuery(raw): RawQuery,
) -> Response {
    let form = pairs(raw.as_deref().unwrap_or("").as_bytes());
    let query = match EventListQuery::parse(&form) {
        Ok(query) => query,
        Err(why) => return bad_request(why, &parts),
    };
    let actor = &viewer.actor;
    let choices = match gui.service.event_choices(actor).await {
        Ok(choices) => choices,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let (page, error) = match gui
        .service
        .event_list(
            actor,
            &query.query,
            query.after.as_deref(),
            EVENTS_PAGE_SIZE,
        )
        .await
    {
        Ok(page) => (Some(page), None),
        // a filter that can't be read is said on the list, with its form, as ace3 flashes it
        Err(ServiceError::InvalidRequest(why)) => (None, Some(why)),
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    let view = event_list_view(
        page.as_ref(),
        &query,
        &choices,
        error,
        can_write(&gui, &viewer).await,
    );
    let mut response = render(&EventListPageHtml {
        layout: viewer.layout,
        view,
    });
    if page.is_none() {
        *response.status_mut() = StatusCode::BAD_REQUEST;
    }
    response
}

/// `GET /events/export`: ace3's Export to CSV of the ticked events, sent on to the API's export (6a),
/// which takes the session and checks `event:read` again.
pub(crate) async fn export(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Err(refused) = may(&gui, &viewer, &EVENT_READ, &parts).await {
        return refused.into_response();
    }
    let form = pairs(raw.as_deref().unwrap_or("").as_bytes());
    let raw_ids = all(&form, "id");
    if raw_ids.len() > MAX_EXPORT_EVENTS {
        return Failure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("An export holds at most {MAX_EXPORT_EVENTS} events."),
            &parts,
        )
        .into_response();
    }
    let mut ids: Vec<i64> = Vec::with_capacity(raw_ids.len());
    for text in &raw_ids {
        match text.trim().parse::<i64>() {
            Ok(id) if !ids.contains(&id) => ids.push(id),
            Ok(_) => {}
            Err(_) => return bad_request(format!("{text:?} isn't an event's id."), &parts),
        }
    }
    if ids.is_empty() {
        return bad_request("Tick the events to export.", &parts);
    }
    let ids: Vec<String> = ids.iter().map(i64::to_string).collect();
    see_other(
        &format!(
            "/api/events/v1/events/export/csv?{}",
            serde_urlencoded::to_string([("ids", ids.join(","))]).expect("text encodes")
        ),
        None,
    )
}

/// The event a path names, read under `event:read`.
async fn event_of(
    gui: &Gui,
    viewer: &SignedIn,
    event: &Result<Path<String>, PathRejection>,
    parts: &Parts,
) -> Result<Event, Failure> {
    let Ok(Path(event)) = event else {
        return Err(Failure::new(
            StatusCode::BAD_REQUEST,
            "An event is named by its numeric id or its uuid.",
            parts,
        ));
    };
    let event = EventRef::parse(event).map_err(|error| Failure::from_service(error, parts))?;
    gui.service
        .event(&viewer.actor, event)
        .await
        .map_err(|error| Failure::from_service(error, parts))
}

/// `GET /events/{event}`: an event's page, by its id or uuid, as ace3's `direct` takes either.
pub(crate) async fn event_page(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    event: Result<Path<String>, PathRejection>,
) -> Response {
    let event = match event_of(&gui, &viewer, &event, &parts).await {
        Ok(event) => event,
        Err(failure) => return failure.into_response(),
    };
    let view = event_view(&event, can_write(&gui, &viewer).await);
    render(&EventPageHtml {
        layout: viewer.layout,
        view,
    })
}

/// `GET /events/{event}/close`: the confirm, for a viewer with `event:write`.
pub(crate) async fn confirm_close(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    event: Result<Path<String>, PathRejection>,
) -> Response {
    if let Err(refused) = may(&gui, &viewer, &EVENT_WRITE, &parts).await {
        return refused.into_response();
    }
    match event_of(&gui, &viewer, &event, &parts).await {
        Ok(event) => render(&ClosePage {
            layout: viewer.layout,
            view: close_view(&event),
        }),
        Err(failure) => failure.into_response(),
    }
}

/// `POST /events/{event}/close`: ace3's Close Event, `PATCH /events/{id}` with its `closed_status`, which
/// is all ace3's does: `Service::set_event_status` to `CLOSED`, under `event:write`, with its audit row.
/// Closing a closed event changes nothing. The answer goes back to the event's page, as ace3's reloads it.
pub(crate) async fn close(
    State(gui): State<Gui>,
    viewer: SignedIn,
    parts: Parts,
    event: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(Path(event)) = event else {
        return bad_request("An event is named by its numeric id or its uuid.", &parts);
    };
    let event = match EventRef::parse(&event) {
        Ok(event) => event,
        Err(error) => return Failure::from_service(error, &parts).into_response(),
    };
    match gui
        .service
        .set_event_status(&viewer.actor, event, CLOSED_STATUS)
        .await
    {
        Ok(event) => see_other(&event_href(event.id), None),
        Err(error) => Failure::from_service(error, &parts).into_response(),
    }
}
