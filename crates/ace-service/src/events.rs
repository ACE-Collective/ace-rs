//! Events (PLAN.md 5.11's events area, 6a to 6d): ace3's `Event` and the three routers over it,
//! `aceapi_v2/events`, `threat_types` and `threats`. Migration 0031 holds the tables.
//!
//! An event groups alerts an analyst decided are one incident, with what they recorded about it: a status,
//! a remediation, a type, a vector, a risk level, a prevention tool, a campaign (ace3's GUI calls it the
//! threat actor), malware with its threat types, an owner, a comment, six times and tags. Reading needs
//! ace3's `event:read`, and writing `event:write`, as ace3's routers check, and each write has its audit
//! row, which ace3's don't write.
//!
//! As in ace3:
//! - An event is named by its numeric id or its uuid (`EventRef`). ace3's GUI page takes either, and its
//!   router does too.
//! - An event's disposition is its alerts' highest by the site's ranks (`Dispositions::rolled_up`), `OPEN`
//!   while none is dispositioned, and `DELIVERY` for an event with no alerts, as ace3's `Event.disposition`
//!   has it. A disposition the site's set doesn't have never wins.
//! - A status is one of `events.statuses`' values. Setting the one an event has changes nothing.
//! - A threat type's name is unique, and one that malware still uses can't be deleted (409).
//!
//! What differs:
//! - An event's alerts are listed with their own state here (title, when each became an alert, its
//!   disposition and who made it), ace3's `alerts` and `alert_details`. ace3's `owner` and `owner_time` of
//!   an alert, and its `alert_versions`, aren't there: roots have no owner or version token.
//! - `tags` are the event's own, ace3's `event_tag_mapping`, and `alert_tags` its alerts', from each
//!   root's own tags, its observables and its results (PLAN.md decision 57), as ace3's `tag_mapping` is
//!   built from `all_tags`, which counts the root as one of its analyses, each sorted by name. ace3's JSON calls its alerts' tags `tags` and sorts them
//!   by its tag scores, which ace-rs doesn't have; its export has both, as here.
//! - ace3's `companies`: roots have no company.
//! - A threat that names malware or a threat type that isn't there is a 404, and one that's mapped
//!   already is a 409, where ace3's database refuses them with a 500.
//! - A name is checked: 1 to 256 characters for a threat type, as ace3's column, with something besides
//!   whitespace and no control characters.
//!
//! Adding alerts to an event (6b), ace3's `add_to_event` (`app/analysis/views/edit/event.py`), is
//! `Service::add_to_event`, under `event:write` as ace3's route is, one transaction and one audit row
//! whose `after` lists the alerts it added. As in ace3:
//! - The event is one that exists, open or closed, or a new one by name. A new one is dated by the
//!   oldest of its ticked alerts that's still there, or today (UTC) when none is, takes the first row by
//!   id of each reference table but the risk level, which it takes first by value, as ace3's defaults
//!   are, and its owner is the actor's user: an API key's owner, or none for a key without one or a
//!   component. It keeps the comment and the six times given.
//! - ace3's unique key is (creation date, name), and a new event whose name its day has already adds the
//!   alerts to that one, with that one's comment and times. ace3 looks before it inserts, so two analysts
//!   making the same event at once can both miss it and one gets a 500 from the key; here the insert
//!   is `ON CONFLICT DO NOTHING` and the second finds the first's event once it commits.
//! - The times given are in order, each no earlier than the one before it: event, alert, ownership,
//!   disposition, contain, remediation. ace3's message says some steps are strictly later, but its check
//!   is a sort, which lets two be equal; this is the check. ace3 checks them when adding to an event that
//!   exists too, and then ignores them; here only a new event takes times, so there's nothing to check.
//! - A ticked alert that's gone, or never was one, isn't added, and the answer names it, where ace3
//!   flashes how many there were. An alert in the event already is left as it is, as ace3's `INSERT
//!   IGNORE` leaves it; two adds of one alert at once both succeed and it's in the event once. The alerts
//!   found are held (`FOR KEY SHARE`) until the commit, so one deleted meanwhile is either added before
//!   the delete runs or reported gone, never an error.
//!
//! What differs: a name is checked (1 to `MAX_EVENT_NAME_CHARS` after trimming, no control characters),
//! where ace3 makes an event with an empty name; ace3's company mapping is left out, as roots have none;
//! and ace3's `touch_alerts`, which changes each alert's version token, has nothing to change, since roots
//! have none (migration 0031). Adding only alerts already in the event, or none, to an event that exists
//! changes nothing and has no row. The form's closed events, ace3's `load_more_events`, are
//! `Service::closed_events`, a page at a time, newest first.
//!
//! The event list (6c), ace3's `events.manage`, is `Service::event_list`, under `event:read`: the events
//! its filters match (`crate::filters::events`, with ace3's filters and sorts), in one static query in which
//! each filter is a fixed condition a NULL parameter turns off and every value a bound parameter, under
//! `LIST_TIMEOUT`. The rolled-up disposition is computed in the query from the site's ranks (`Dispositions::ranks`), bound as
//! arrays, so it filters and sorts there, where ace3 filters and sorts it in Python after reading every
//! event. Each order breaks a tie with the id, and the list is a keyset: a cursor names its last event and
//! that event's sort key then, so an event changed meanwhile is where its new key puts it, as in any
//! keyset. ace3 lists every event; this reads a page of at most `MAX_EVENTS_PAGE`, with the total.
//! `Service::event_choices` is what the filters offer. An event's alerts carry their analysis state and
//! tags, for its page and ace3's "still analyzing" note (`Event::still_analyzing`). Close Event is
//! `set_event_status` to `CLOSED_STATUS`, which is all ace3's does.
//!
//! An event's edit (6d), ace3's `edit_event` (`app/events/views/edit/modal.py`), is `Service::edit_event`,
//! under `event:write` as ace3's route is, one transaction and one audit row whose `before` and `after`
//! are everything an edit sets, and whose details name the campaign and malware it made and the threats it
//! gave. As in ace3:
//! - `CLOSED` is for Close Event: an event that isn't closed can't be given it by an edit, which ace3's
//!   form enforces by not offering it, so an event is closed one way. A closed event keeps it, or is
//!   reopened, by an edit.
//! - The times change only while the event isn't closed, judged by its status before the edit. A time
//!   given replaces the stored one and one left empty keeps it, as ace3's `none_values` do, so a time once
//!   set isn't cleared here either; the six after the edit are in order, ace3's sorted check.
//! - A campaign (threat actor) is none, one that exists, or a name, which is the campaign of that name if
//!   there's one and a new one if not. Malware is the event's whole list: each one that exists, or a name
//!   with its threat types, which is the malware of that name, made if it isn't there, given those of the
//!   types it lacks, as ace3's loop does. Two edits making one name at once both get the one made.
//! - The name, status, remediation, type, vector, risk level, prevention tool, comment and owner are set
//!   as given; a reference value is one of its table's.
//!
//! What differs, each where ace3 fails or loses what was typed:
//! - Concurrency: ace3's form has no version, so of two analysts editing one event the last save wins and
//!   undoes the first's changes to fields the second didn't touch. Here the form carries
//!   `Event::edit_version`, the event's edited state when the form was drawn, and the write locks the
//!   event and refuses a version it has left with a 409, so the second analyst reopens the edit and sees
//!   the first's changes. Adding alerts or tags doesn't change the version, so it doesn't refuse an edit.
//! - ace3 accepts `CLOSED` from a hand-made POST; this refuses it (400).
//! - A value that isn't in its table, a campaign, malware, threat type or owner that isn't there, and a
//!   name another event has on its day are 400, 404 and 409, where ace3's `.one()` and its unique key
//!   answer 500, or a campaign id that isn't there silently clears the event's.
//! - New malware without a name or a threat type is refused, where ace3 skips it and drops what was
//!   typed; a new campaign with no name is refused, where ace3 clears the event's campaign.
//! - The owner is a user, or none, since an event made by a key without an owner has none; a disabled
//!   user can be kept but not given an event, as ace3's form offers only enabled users.
//! - Names are trimmed and checked as an event's are, an empty comment is none, and an edit that changes
//!   nothing has no row. ace3's form also sends `event_disposition`, which its route never reads.
//!
//! `Service::remove_alerts`, ace3's `remove_alerts`, takes alerts out of one event, under `event:write`,
//! one row listing those taken; one not in it is said, as ace3 skips it. ace3's form names
//! `<event>_<alert>` pairs across the event list's open rows; here it's one event's page, since the list's
//! open row is that page. `Service::add_event_tags`, ace3's `add_tag`, puts tags on an event itself, one
//! row per event listing the tags it didn't have; ace3 splits its form's text on whitespace, so a tag has
//! none. The event page's bulk Set Disposition of its alerts is 5.10's `Service::disposition` per alert.
//!
//! What adding an alert to an event does to its analysis: nothing, here or in ace3. ace3's GUI only
//! writes the mapping (`app/analysis/views/edit/event.py`). Its `alert_added_to_event` module, which
//! dispositioned mode runs, switches an alert in an event to `event` mode, which runs no modules in
//! ace3's configuration; ace3 ships it disabled and marks it "TODO trash this". ace-rs has no such module,
//! so 2.12's dispositioned mode finds none to run, and no step ports it.

use std::collections::HashMap;

use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::actor::{Actor, UserId};
use crate::alerts::{AnalysisState, RecordedActor, SET_LIST_TIMEOUT, timed_out};
use crate::filters::events::{EventOwnerFilter, EventQuery, EventSort};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{EVENT_READ, EVENT_WRITE};
use crate::{Service, ServiceError};

/// The most events one page of a list holds.
pub const MAX_EVENTS_PAGE: u32 = 1000;
/// The most events one export holds.
pub const MAX_EXPORT_EVENTS: usize = 1000;
/// The longest threat type name, in characters: ace3's column.
pub const MAX_THREAT_TYPE_CHARS: usize = 256;

/// The most alerts one `add_to_event` takes.
pub const MAX_EVENT_ALERTS: usize = 1000;
/// The longest event name, in characters: ace3's column.
pub const MAX_EVENT_NAME_CHARS: usize = 128;
/// The longest event comment, in characters: the table's check, after ace3's `TEXT`.
pub const MAX_EVENT_COMMENT_CHARS: usize = 65535;
/// How many closed events a page of the add-to-event form shows: ace3's `CLOSED_EVENT_LIMIT`.
pub const CLOSED_EVENTS_PAGE: u32 = 15;

/// How a request names an event: its numeric id or its uuid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventRef {
    Id(i64),
    Uuid(Uuid),
}

impl EventRef {
    /// An id is all digits and a uuid has hyphens, so the two never look alike, as ace3's
    /// `resolve_event` says. Anything else is refused.
    pub fn parse(text: &str) -> Result<EventRef, ServiceError> {
        let text = text.trim();
        if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
            return text
                .parse()
                .map(EventRef::Id)
                .map_err(|_| ServiceError::NotFound(format!("no event {text}")));
        }
        Uuid::try_parse(text).map(EventRef::Uuid).map_err(|_| {
            ServiceError::InvalidRequest(
                "an event is named by its numeric id or its uuid".to_owned(),
            )
        })
    }
}

/// The user who owns an event, as they're called now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventOwner {
    pub id: UserId,
    pub username: String,
    pub display_name: Option<String>,
}

/// Malware recorded on an event, with its threat types by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventMalware {
    pub id: i32,
    pub name: String,
    pub threat_types: Vec<String>,
}

/// One of an event's alerts, with its own state.
#[derive(Debug, Clone, PartialEq)]
pub struct EventAlert {
    pub id: Uuid,
    pub title: String,
    pub alerted_at: Option<DateTime<Utc>>,
    pub disposition: Option<String>,
    pub dispositioned_at: Option<DateTime<Utc>>,
    pub dispositioned_by: Option<RecordedActor>,
    /// When it was added to the event.
    pub added_at: DateTime<Utc>,
    /// Where its analysis is, ace3's alert `status`.
    pub analysis: AnalysisState,
    /// Its tags: the root's own and its observables' and results', by name.
    pub tags: Vec<String>,
}

/// An event, with everything ace3's `Event.json` gives that ace-rs has.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub id: i64,
    pub uuid: Uuid,
    pub creation_date: NaiveDate,
    pub name: String,
    pub status: String,
    pub remediation: String,
    pub kind: String,
    pub vector: String,
    pub risk_level: String,
    pub prevention_tool: String,
    pub campaign: Option<String>,
    pub comment: Option<String>,
    pub event_time: Option<DateTime<Utc>>,
    pub alert_time: Option<DateTime<Utc>>,
    pub ownership_time: Option<DateTime<Utc>>,
    pub disposition_time: Option<DateTime<Utc>>,
    pub contain_time: Option<DateTime<Utc>>,
    pub remediation_time: Option<DateTime<Utc>>,
    pub owner: Option<EventOwner>,
    pub malware: Vec<EventMalware>,
    /// The highest of its alerts' dispositions (`Dispositions::rolled_up`).
    pub disposition: String,
    /// Oldest alert first.
    pub alerts: Vec<EventAlert>,
    /// The event's own tags, by name.
    pub tags: Vec<String>,
    /// Its alerts' tags: each root's own and its observables' and results', by name.
    pub alert_tags: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl Event {
    /// Whether any of its alerts is still being analyzed, ace3's `alerts_still_analyzing`: ace3's alert
    /// is until its status is `Completed`; here, while its pass runs. One whose analysis was cancelled
    /// isn't running.
    pub fn still_analyzing(&self) -> bool {
        self.alerts
            .iter()
            .any(|alert| alert.analysis == AnalysisState::Running)
    }

    /// The threat types of its malware, each once, by name: ace3's `Event.threats`.
    pub fn threat_types(&self) -> Vec<&str> {
        let mut types: Vec<&str> = self
            .malware
            .iter()
            .flat_map(|m| m.threat_types.iter().map(String::as_str))
            .collect();
        types.sort_unstable();
        types.dedup();
        types
    }
}

/// A page of events and the id the next starts after, None after the last.
#[derive(Debug, Clone, PartialEq)]
pub struct EventPage {
    pub events: Vec<Event>,
    pub next: Option<i64>,
}

/// A page of the event list (`Service::event_list`), the cursor of the next, None on the last, and how
/// many events the filters match in all.
#[derive(Debug, Clone, PartialEq)]
pub struct EventListPage {
    pub events: Vec<Event>,
    pub next: Option<String>,
    pub total: i64,
}

/// A reference row, such as a status or a type: its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventValue {
    pub id: i32,
    pub value: String,
}

/// A user who owns an event, for the owner filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventOwnerChoice {
    pub id: UserId,
    pub username: String,
    pub display_name: Option<String>,
}

/// What the event list's filters offer, ace3's lists for its filter dialog: each reference table by
/// value, as ace3 orders them, the owners, malware, campaigns and the events' own tags. Each list holds at
/// most `MAX_EVENT_CHOICES`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventChoices {
    pub statuses: Vec<EventValue>,
    pub types: Vec<EventValue>,
    pub vectors: Vec<EventValue>,
    pub prevention_tools: Vec<EventValue>,
    pub risk_levels: Vec<EventValue>,
    pub owners: Vec<EventOwnerChoice>,
    pub malware: Vec<EventValue>,
    pub campaigns: Vec<EventValue>,
    pub tags: Vec<String>,
}

/// The most of each kind `EventChoices` lists.
pub const MAX_EVENT_CHOICES: i64 = 1000;

/// The status ace3's Close Event sets, its `events.closed_status`.
pub const CLOSED_STATUS: &str = "CLOSED";

/// Where a page of the event list ends: its order, its last event, and that event's sort key then, so the
/// next page starts after it even if the event has changed since. As text it's
/// `<sort>.<asc|desc>.<id>.<key>`, the key a JSON array of text in hex.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventCursor {
    sort: EventSort,
    descending: bool,
    id: i64,
    key: Vec<String>,
}

/// The longest cursor that's read.
const MAX_EVENT_CURSOR: usize = 4096;

impl EventCursor {
    fn encode(&self) -> String {
        let dir = if self.descending { "desc" } else { "asc" };
        let key = serde_json::to_vec(&self.key).expect("text encodes");
        format!(
            "{}.{dir}.{}.{}",
            self.sort.as_str(),
            self.id,
            hex::encode(key)
        )
    }

    fn decode(text: &str, query: &EventQuery) -> Result<Self, ServiceError> {
        let bad = || ServiceError::InvalidRequest(format!("{text:?} isn't a cursor of this list"));
        if text.len() > MAX_EVENT_CURSOR {
            return Err(bad());
        }
        let mut parts = text.splitn(4, '.');
        let sort = parts.next().and_then(EventSort::named).ok_or_else(bad)?;
        let descending = match parts.next() {
            Some("desc") => true,
            Some("asc") => false,
            _ => return Err(bad()),
        };
        let id = parts
            .next()
            .and_then(|id| id.parse().ok())
            .ok_or_else(bad)?;
        let key: Vec<String> = parts
            .next()
            .and_then(|key| hex::decode(key).ok())
            .and_then(|key| serde_json::from_slice(&key).ok())
            .ok_or_else(bad)?;
        if !(1..=3).contains(&key.len()) {
            return Err(bad());
        }
        if sort != query.sort || descending != query.descending {
            return Err(ServiceError::InvalidRequest(format!(
                "the cursor {text:?} pages another order: ask for the order of the request that gave it"
            )));
        }
        Ok(EventCursor {
            sort,
            descending,
            id,
            key,
        })
    }
}

/// A threat type, such as `ransomware`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThreatType {
    pub id: i32,
    pub name: String,
}

impl Recorded for ThreatType {}

/// A threat: one of a malware's threat types, ace3's `malware_threat_mapping`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Threat {
    pub malware_id: i32,
    pub malware_name: String,
    pub threat_type_id: i32,
    pub threat_type_name: String,
}

impl Recorded for Threat {}

/// A status change's before and after.
#[derive(Serialize)]
struct EventStatus<'a> {
    status: &'a str,
}

impl Recorded for EventStatus<'_> {}

/// What a status change's row says the event is, so it reads after the event is gone.
#[derive(Serialize)]
struct EventNamed<'a> {
    uuid: Uuid,
    name: &'a str,
}

impl Recorded for EventNamed<'_> {}

/// A threat type's name before and after a rename.
#[derive(Serialize)]
struct ThreatTypeName<'a> {
    name: &'a str,
}

impl Recorded for ThreatTypeName<'_> {}

/// An event's six times, ace3's, each optional.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EventTimes {
    pub event_time: Option<DateTime<Utc>>,
    pub alert_time: Option<DateTime<Utc>>,
    pub ownership_time: Option<DateTime<Utc>>,
    pub disposition_time: Option<DateTime<Utc>>,
    pub contain_time: Option<DateTime<Utc>>,
    pub remediation_time: Option<DateTime<Utc>>,
}

impl EventTimes {
    /// Whether the times given are in ace3's order, each no earlier than the one before, as ace3's
    /// `dates == sorted(dates)` checks.
    pub fn in_order(&self) -> bool {
        let given: Vec<DateTime<Utc>> = [
            self.event_time,
            self.alert_time,
            self.ownership_time,
            self.disposition_time,
            self.contain_time,
            self.remediation_time,
        ]
        .into_iter()
        .flatten()
        .collect();
        given.windows(2).all(|pair| pair[0] <= pair[1])
    }
}

/// A new event for `add_to_event`, as ace3's form names it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewEvent {
    pub name: String,
    pub comment: Option<String>,
    pub times: EventTimes,
}

/// The event `add_to_event` adds to: one that exists, or a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventChoice {
    Existing(EventRef),
    New(NewEvent),
}

/// What `add_to_event` did.
#[derive(Debug, Clone, PartialEq)]
pub struct AddedToEvent {
    /// The event, as it is after.
    pub event: Event,
    /// Whether this made it. False for one that existed, a new one's name found on its day among them.
    pub made: bool,
    /// The ticked alerts it added, in the order they were ticked.
    pub added: Vec<Uuid>,
    /// Those in the event already.
    pub already: Vec<Uuid>,
    /// Those that are gone since they were ticked, or never were alerts.
    pub missing: Vec<Uuid>,
}

/// A new event's name, trimmed as ace3 trims it, or why it can't be one.
fn event_name(name: &str) -> Result<&str, ServiceError> {
    let name = name.trim();
    let fits = !name.is_empty()
        && name.chars().count() <= MAX_EVENT_NAME_CHARS
        && !name.chars().any(char::is_control);
    if fits {
        Ok(name)
    } else {
        Err(ServiceError::InvalidRequest(format!(
            "an event's name is 1 to {MAX_EVENT_NAME_CHARS} characters, not all whitespace, with no control characters"
        )))
    }
}

/// A new event as `add_to_event` stores it, or why it can't be stored: its name trimmed, an empty comment
/// none, and its times in order.
fn checked_new_event(new: &NewEvent) -> Result<NewEvent, ServiceError> {
    let name = event_name(&new.name)?.to_owned();
    let comment = new.comment.as_deref().filter(|c| !c.trim().is_empty());
    if comment.is_some_and(|c| c.chars().count() > MAX_EVENT_COMMENT_CHARS) {
        return Err(ServiceError::InvalidRequest(format!(
            "an event's comment is at most {MAX_EVENT_COMMENT_CHARS} characters"
        )));
    }
    if !new.times.in_order() {
        return Err(ServiceError::InvalidRequest(
            "one or more of the times is out of order: each of event time, alert time, ownership time, \
             disposition time, contain time and remediation time is no earlier than the one before it"
                .to_owned(),
        ));
    }
    Ok(NewEvent {
        name,
        comment: comment.map(str::to_owned),
        times: new.times,
    })
}

/// A made event as its audit row keeps it, with the alerts added to it.
#[derive(Serialize)]
struct EventMade<'a> {
    uuid: Uuid,
    creation_date: NaiveDate,
    name: &'a str,
    status: &'a str,
    remediation: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    vector: &'a str,
    risk_level: &'a str,
    prevention_tool: &'a str,
    comment: Option<&'a str>,
    #[serde(flatten)]
    times: EventTimes,
    owner: Option<Uuid>,
    alerts: &'a [Uuid],
}

impl Recorded for EventMade<'_> {}

/// The alerts added to an event that existed.
#[derive(Serialize)]
struct AlertsAdded<'a> {
    alerts: &'a [Uuid],
}

impl Recorded for AlertsAdded<'_> {}

/// What an add's row says the event is, and the ticked alerts that were gone.
#[derive(Serialize)]
struct AddedDetails<'a> {
    uuid: Uuid,
    name: &'a str,
    missing: &'a [Uuid],
}

impl Recorded for AddedDetails<'_> {}

/// The id of a new event `add_to_event` makes on `day`, with ace3's defaults, and true; or the id of the
/// one of its name on that day, and false. `ON CONFLICT` waits for an insert of the same key that hasn't
/// committed, so the event it finds then is visible to the select after it.
async fn make_or_find(
    conn: &mut PgConnection,
    day: NaiveDate,
    new: &NewEvent,
    owner: Option<Uuid>,
) -> Result<(i64, bool), ServiceError> {
    for _ in 0..3 {
        let made = sqlx::query_scalar!(
            "INSERT INTO events.events
                 (creation_date, name, status_id, remediation_id, type_id, vector_id, risk_level_id,
                  prevention_tool_id, comment, event_time, alert_time, ownership_time,
                  disposition_time, contain_time, remediation_time, owner_id)
             VALUES ($1, $2,
                     (SELECT id FROM events.statuses ORDER BY id LIMIT 1),
                     (SELECT id FROM events.remediations ORDER BY id LIMIT 1),
                     (SELECT id FROM events.types ORDER BY id LIMIT 1),
                     (SELECT id FROM events.vectors ORDER BY id LIMIT 1),
                     (SELECT id FROM events.risk_levels ORDER BY value, id LIMIT 1),
                     (SELECT id FROM events.prevention_tools ORDER BY id LIMIT 1),
                     $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT ON CONSTRAINT event_names_are_unique_per_day DO NOTHING
             RETURNING id",
            day,
            new.name,
            new.comment,
            new.times.event_time,
            new.times.alert_time,
            new.times.ownership_time,
            new.times.disposition_time,
            new.times.contain_time,
            new.times.remediation_time,
            owner,
        )
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = made {
            return Ok((id, true));
        }
        let found = sqlx::query_scalar!(
            "SELECT id FROM events.events WHERE creation_date = $1 AND name = $2 FOR KEY SHARE",
            day,
            new.name,
        )
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = found {
            return Ok((id, false));
        }
    }
    Err(ServiceError::Conflict(format!(
        "the event {:?} of {day} kept changing; try again",
        new.name
    )))
}

fn no_event(event: EventRef) -> ServiceError {
    ServiceError::NotFound(match event {
        EventRef::Id(id) => format!("no event {id}"),
        EventRef::Uuid(uuid) => format!("no event {uuid}"),
    })
}

fn no_threat_type(id: i32) -> ServiceError {
    ServiceError::NotFound(format!("no threat type {id}"))
}

/// A threat type's name as it's stored, or why it can't be one.
fn threat_type_name(name: &str) -> Result<&str, ServiceError> {
    let fits = !name.trim().is_empty()
        && name.chars().count() <= MAX_THREAT_TYPE_CHARS
        && !name.chars().any(char::is_control);
    if fits {
        Ok(name)
    } else {
        Err(ServiceError::InvalidRequest(format!(
            "a threat type's name is 1 to {MAX_THREAT_TYPE_CHARS} characters, not all whitespace, with no control characters"
        )))
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
}

struct EventRow {
    id: i64,
    uuid: Uuid,
    creation_date: NaiveDate,
    name: String,
    status: String,
    remediation: String,
    kind: String,
    vector: String,
    risk_level: String,
    prevention_tool: String,
    campaign: Option<String>,
    comment: Option<String>,
    event_time: Option<DateTime<Utc>>,
    alert_time: Option<DateTime<Utc>>,
    ownership_time: Option<DateTime<Utc>>,
    disposition_time: Option<DateTime<Utc>>,
    contain_time: Option<DateTime<Utc>>,
    remediation_time: Option<DateTime<Utc>>,
    owner_id: Option<Uuid>,
    owner_username: Option<String>,
    owner_display_name: Option<String>,
    created_at: DateTime<Utc>,
}

/// The events with these ids, whole, in id order. An id with no event is left out.
async fn load_events(
    conn: &mut PgConnection,
    dispositions: &crate::Dispositions,
    ids: &[i64],
) -> Result<Vec<Event>, ServiceError> {
    let rows = sqlx::query_as!(
        EventRow,
        r#"SELECT e.id, e.uuid, e.creation_date, e.name, s.value AS status, rm.value AS remediation,
                  t.value AS kind, v.value AS vector, rl.value AS risk_level,
                  p.value AS prevention_tool, c.name AS "campaign?", e.comment, e.event_time,
                  e.alert_time, e.ownership_time, e.disposition_time, e.contain_time,
                  e.remediation_time, u.id AS "owner_id?", u.username::text AS "owner_username?",
                  u.display_name AS "owner_display_name?", e.created_at
           FROM events.events e
           JOIN events.statuses s ON s.id = e.status_id
           JOIN events.remediations rm ON rm.id = e.remediation_id
           JOIN events.types t ON t.id = e.type_id
           JOIN events.vectors v ON v.id = e.vector_id
           JOIN events.risk_levels rl ON rl.id = e.risk_level_id
           JOIN events.prevention_tools p ON p.id = e.prevention_tool_id
           LEFT JOIN events.campaigns c ON c.id = e.campaign_id
           LEFT JOIN service.users u ON u.id = e.owner_id
           WHERE e.id = ANY($1)
           ORDER BY e.id"#,
        ids,
    )
    .fetch_all(&mut *conn)
    .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let mut malware: HashMap<i64, Vec<EventMalware>> = HashMap::new();
    for row in sqlx::query!(
        r#"SELECT em.event_id, m.id, m.name,
                  COALESCE(array_agg(tt.name ORDER BY tt.name) FILTER (WHERE tt.name IS NOT NULL),
                           '{}') AS "threat_types!"
           FROM events.event_malware em
           JOIN events.malware m ON m.id = em.malware_id
           LEFT JOIN events.malware_threats mt ON mt.malware_id = m.id
           LEFT JOIN events.threat_types tt ON tt.id = mt.threat_type_id
           WHERE em.event_id = ANY($1)
           GROUP BY em.event_id, m.id, m.name
           ORDER BY em.event_id, m.name"#,
        ids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        malware.entry(row.event_id).or_default().push(EventMalware {
            id: row.id,
            name: row.name,
            threat_types: row.threat_types,
        });
    }

    // each alert's tags, from the root itself, its observables and its results, as ace3's `all_tags`
    let mut tags_of: HashMap<(i64, Uuid), Vec<String>> = HashMap::new();
    let mut alert_tags: HashMap<i64, Vec<String>> = HashMap::new();
    for row in sqlx::query!(
        r#"SELECT ea.event_id, ea.root_id, t.tag AS "tag!"
           FROM events.event_alerts ea
           CROSS JOIN LATERAL (
               SELECT unnest(r.tags) FROM analysis.roots r WHERE r.id = ea.root_id
               UNION
               SELECT unnest(o.tags) FROM analysis.observables o WHERE o.root_id = ea.root_id
               UNION
               SELECT unnest(x.tags) FROM analysis.results x WHERE x.root_id = ea.root_id
           ) t(tag)
           WHERE ea.event_id = ANY($1)
           GROUP BY ea.event_id, ea.root_id, t.tag
           ORDER BY ea.event_id, lower(t.tag), t.tag, ea.root_id"#,
        ids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        let event = alert_tags.entry(row.event_id).or_default();
        if event.last() != Some(&row.tag) {
            event.push(row.tag.clone());
        }
        tags_of
            .entry((row.event_id, row.root_id))
            .or_default()
            .push(row.tag);
    }

    let mut alerts: HashMap<i64, Vec<EventAlert>> = HashMap::new();
    for row in sqlx::query!(
        r#"SELECT ea.event_id, r.id, r.description, r.alerted_at, r.disposition, r.dispositioned_at,
                  r.dispositioned_by AS "dispositioned_by: Value", ea.added_at,
                  r.pass, r.completed_pass, r.cancelled_at IS NOT NULL AS "cancelled!"
           FROM events.event_alerts ea
           JOIN analysis.roots r ON r.id = ea.root_id
           WHERE ea.event_id = ANY($1)
           ORDER BY ea.event_id, r.alerted_at NULLS LAST, r.id"#,
        ids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        alerts.entry(row.event_id).or_default().push(EventAlert {
            id: row.id,
            title: row.description,
            alerted_at: row.alerted_at,
            disposition: row.disposition,
            dispositioned_at: row.dispositioned_at,
            dispositioned_by: RecordedActor::from_row(row.dispositioned_by)?,
            added_at: row.added_at,
            analysis: AnalysisState::of(row.pass, row.completed_pass, row.cancelled),
            tags: tags_of.remove(&(row.event_id, row.id)).unwrap_or_default(),
        });
    }

    let mut tags: HashMap<i64, Vec<String>> = HashMap::new();
    for row in sqlx::query!(
        "SELECT event_id, tag FROM events.event_tags WHERE event_id = ANY($1)
         ORDER BY event_id, lower(tag), tag",
        ids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        tags.entry(row.event_id).or_default().push(row.tag);
    }

    Ok(rows
        .into_iter()
        .map(|row| {
            let alerts = alerts.remove(&row.id).unwrap_or_default();
            let disposition =
                dispositions.rolled_up(alerts.iter().map(|a| a.disposition.as_deref()));
            let owner = match (row.owner_id, row.owner_username) {
                (Some(id), Some(username)) => Some(EventOwner {
                    id: UserId(id),
                    username,
                    display_name: row.owner_display_name,
                }),
                _ => None,
            };
            Event {
                id: row.id,
                uuid: row.uuid,
                creation_date: row.creation_date,
                name: row.name,
                status: row.status,
                remediation: row.remediation,
                kind: row.kind,
                vector: row.vector,
                risk_level: row.risk_level,
                prevention_tool: row.prevention_tool,
                campaign: row.campaign,
                comment: row.comment,
                event_time: row.event_time,
                alert_time: row.alert_time,
                ownership_time: row.ownership_time,
                disposition_time: row.disposition_time,
                contain_time: row.contain_time,
                remediation_time: row.remediation_time,
                owner,
                malware: malware.remove(&row.id).unwrap_or_default(),
                disposition,
                alerts,
                tags: tags.remove(&row.id).unwrap_or_default(),
                alert_tags: alert_tags.remove(&row.id).unwrap_or_default(),
                created_at: row.created_at,
            }
        })
        .collect())
}

/// The id of the event a reference names.
async fn event_id(conn: &mut PgConnection, event: EventRef) -> Result<i64, ServiceError> {
    let found = match event {
        EventRef::Id(id) => {
            sqlx::query_scalar!("SELECT id FROM events.events WHERE id = $1", id)
                .fetch_optional(conn)
                .await?
        }
        EventRef::Uuid(uuid) => {
            sqlx::query_scalar!("SELECT id FROM events.events WHERE uuid = $1", uuid)
                .fetch_optional(conn)
                .await?
        }
    };
    found.ok_or_else(|| no_event(event))
}

async fn one_event(
    conn: &mut PgConnection,
    dispositions: &crate::Dispositions,
    id: i64,
) -> Result<Event, ServiceError> {
    load_events(conn, dispositions, &[id])
        .await?
        .pop()
        .ok_or_else(|| no_event(EventRef::Id(id)))
}

// ---- 6d: an event's edit, its alerts removed and its own tags ----

/// The most malware one edit names.
pub const MAX_EDIT_MALWARE: usize = 100;
/// The most threat types new malware takes in one edit.
pub const MAX_NEW_MALWARE_THREATS: usize = 256;
/// The longest campaign or malware name, in characters: ace3's columns.
pub const MAX_CATALOG_NAME_CHARS: usize = 128;
/// The longest event tag, in characters: the table's check, after ace3's `tags.name`.
pub const MAX_EVENT_TAG_CHARS: usize = 256;
/// The most tags one `add_event_tags` takes.
pub const MAX_EVENT_TAGS: usize = 64;

/// An edit's campaign, ace3's threat actor: none, one that exists, or one by name, made if it isn't there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CampaignChoice {
    None,
    Existing(i32),
    New(String),
}

/// One of an edit's malware: one that exists, or one by name with its threat types, made if it isn't
/// there and given the types it lacks, as ace3's `edit_event` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalwareChoice {
    Existing(i32),
    New {
        name: String,
        threat_types: Vec<i32>,
    },
}

/// What `Service::edit_event` sets, ace3's edit form: everything but the event's alerts and tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEdit {
    /// The event's `Event::edit_version` when the form was drawn. Another edit since is a conflict.
    pub version: String,
    pub name: String,
    pub status: String,
    pub owner: Option<UserId>,
    pub remediation: String,
    pub kind: String,
    pub vector: String,
    pub risk_level: String,
    pub prevention_tool: String,
    pub comment: Option<String>,
    pub campaign: CampaignChoice,
    /// A time given replaces the stored one, and one not given leaves it, as in ace3, while the event
    /// isn't closed. A closed event's times don't change.
    pub times: EventTimes,
    /// The event's malware after the edit, all of it, as ace3's form sends it.
    pub malware: Vec<MalwareChoice>,
}

/// What an edit's form offers, ace3's `edit_event_modal`: each reference table by value, the campaigns
/// and malware by name, the threat types, and the enabled users. Each list holds at most
/// `MAX_EVENT_CHOICES`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventEditChoices {
    pub statuses: Vec<EventValue>,
    pub remediations: Vec<EventValue>,
    pub types: Vec<EventValue>,
    pub vectors: Vec<EventValue>,
    pub risk_levels: Vec<EventValue>,
    pub prevention_tools: Vec<EventValue>,
    pub campaigns: Vec<EventValue>,
    /// With their threat types, as ace3's options label them.
    pub malware: Vec<EventMalware>,
    pub threat_types: Vec<ThreatType>,
    pub users: Vec<EventOwnerChoice>,
}

/// What `remove_alerts` did.
#[derive(Debug, Clone, PartialEq)]
pub struct RemovedAlerts {
    /// The event, as it is after.
    pub event: Event,
    /// The alerts taken out of it, in the order given.
    pub removed: Vec<Uuid>,
    /// Those given that weren't in it.
    pub not_in: Vec<Uuid>,
}

impl Event {
    /// A token of what an edit sets, for `EventEdit::version`: it changes when any of those does, by an
    /// edit or Close Event, and not when alerts or tags are added. ace3 has none, so its last save wins.
    pub fn edit_version(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut malware: Vec<i32> = self.malware.iter().map(|m| m.id).collect();
        malware.sort_unstable();
        let state = serde_json::json!([
            self.name,
            self.status,
            self.remediation,
            self.kind,
            self.vector,
            self.risk_level,
            self.prevention_tool,
            self.campaign,
            self.comment,
            self.event_time,
            self.alert_time,
            self.ownership_time,
            self.disposition_time,
            self.contain_time,
            self.remediation_time,
            self.owner.as_ref().map(|owner| owner.id.0),
            malware,
        ]);
        hex::encode(Sha256::digest(state.to_string().as_bytes()))
    }

    fn times(&self) -> EventTimes {
        EventTimes {
            event_time: self.event_time,
            alert_time: self.alert_time,
            ownership_time: self.ownership_time,
            disposition_time: self.disposition_time,
            contain_time: self.contain_time,
            remediation_time: self.remediation_time,
        }
    }
}

/// Malware as an edit's row keeps it.
#[derive(Debug, PartialEq, Serialize)]
struct MalwareState {
    name: String,
    threat_types: Vec<String>,
}

/// An event's state as an edit's row keeps it, before and after: all an edit sets.
#[derive(Debug, PartialEq, Serialize)]
struct EditState {
    name: String,
    status: String,
    remediation: String,
    #[serde(rename = "type")]
    kind: String,
    vector: String,
    risk_level: String,
    prevention_tool: String,
    campaign: Option<String>,
    comment: Option<String>,
    #[serde(flatten)]
    times: EventTimes,
    owner: Option<Uuid>,
    malware: Vec<MalwareState>,
}

impl Recorded for EditState {}

impl EditState {
    fn of(event: &Event) -> Self {
        EditState {
            name: event.name.clone(),
            status: event.status.clone(),
            remediation: event.remediation.clone(),
            kind: event.kind.clone(),
            vector: event.vector.clone(),
            risk_level: event.risk_level.clone(),
            prevention_tool: event.prevention_tool.clone(),
            campaign: event.campaign.clone(),
            comment: event.comment.clone(),
            times: event.times(),
            owner: event.owner.as_ref().map(|owner| owner.id.0),
            malware: event
                .malware
                .iter()
                .map(|m| MalwareState {
                    name: m.name.clone(),
                    threat_types: m.threat_types.clone(),
                })
                .collect(),
        }
    }
}

/// A threat an edit gave malware, by the malware's name and the type's id.
#[derive(Debug, Serialize)]
struct ThreatGiven {
    malware: String,
    threat_type: i32,
}

/// What an edit's row says the event is, and what it made on the way.
#[derive(Serialize)]
struct EditDetails<'a> {
    uuid: Uuid,
    made_campaign: Option<&'a str>,
    made_malware: &'a [String],
    added_threats: &'a [ThreatGiven],
}

impl Recorded for EditDetails<'_> {}

/// The alerts taken from an event.
#[derive(Serialize)]
struct AlertsInEvent<'a> {
    alerts: &'a [Uuid],
}

impl Recorded for AlertsInEvent<'_> {}

/// Tags put on an event.
#[derive(Serialize)]
struct TagsAdded<'a> {
    tags: &'a [String],
}

impl Recorded for TagsAdded<'_> {}

/// A campaign's or malware's name, trimmed, or why it can't be one.
fn catalog_name<'a>(name: &'a str, what: &str) -> Result<&'a str, ServiceError> {
    let name = name.trim();
    let fits = !name.is_empty()
        && name.chars().count() <= MAX_CATALOG_NAME_CHARS
        && !name.chars().any(char::is_control);
    if fits {
        Ok(name)
    } else {
        Err(ServiceError::InvalidRequest(format!(
            "{what}'s name is 1 to {MAX_CATALOG_NAME_CHARS} characters, not all whitespace, with no control characters"
        )))
    }
}

/// An event tag, or why it can't be one: as ace3's form splits them on whitespace, a tag has none.
fn event_tag(tag: &str) -> Result<&str, ServiceError> {
    let fits = !tag.is_empty()
        && tag.chars().count() <= MAX_EVENT_TAG_CHARS
        && !tag.chars().any(|c| c.is_control() || c.is_whitespace());
    if fits {
        Ok(tag)
    } else {
        Err(ServiceError::InvalidRequest(format!(
            "a tag is 1 to {MAX_EVENT_TAG_CHARS} characters with no whitespace or control characters"
        )))
    }
}

/// An edit as it's stored, or why it can't be: names trimmed, an empty comment none, and the lists
/// bounded. What needs the database is checked in the write.
fn checked_edit(edit: &EventEdit) -> Result<EventEdit, ServiceError> {
    let name = event_name(&edit.name)?.to_owned();
    let comment = edit.comment.as_deref().filter(|c| !c.trim().is_empty());
    if comment.is_some_and(|c| c.chars().count() > MAX_EVENT_COMMENT_CHARS) {
        return Err(ServiceError::InvalidRequest(format!(
            "an event's comment is at most {MAX_EVENT_COMMENT_CHARS} characters"
        )));
    }
    let campaign = match &edit.campaign {
        CampaignChoice::New(name) => {
            CampaignChoice::New(catalog_name(name, "a threat actor")?.to_owned())
        }
        other => other.clone(),
    };
    if edit.malware.len() > MAX_EDIT_MALWARE {
        return Err(ServiceError::TooLarge(format!(
            "an event has at most {MAX_EDIT_MALWARE} malware in one edit"
        )));
    }
    let mut malware = Vec::with_capacity(edit.malware.len());
    for choice in &edit.malware {
        malware.push(match choice {
            MalwareChoice::Existing(id) => MalwareChoice::Existing(*id),
            MalwareChoice::New { name, threat_types } => {
                let name = catalog_name(name, "malware")?.to_owned();
                // ace3 skips new malware without a type, and drops what was typed; this says so
                if threat_types.is_empty() {
                    return Err(ServiceError::InvalidRequest(format!(
                        "new malware {name:?} needs at least one threat type"
                    )));
                }
                if threat_types.len() > MAX_NEW_MALWARE_THREATS {
                    return Err(ServiceError::TooLarge(format!(
                        "new malware takes at most {MAX_NEW_MALWARE_THREATS} threat types"
                    )));
                }
                let mut types = threat_types.clone();
                types.sort_unstable();
                types.dedup();
                MalwareChoice::New {
                    name,
                    threat_types: types,
                }
            }
        });
    }
    Ok(EventEdit {
        version: edit.version.clone(),
        name,
        status: edit.status.clone(),
        owner: edit.owner,
        remediation: edit.remediation.clone(),
        kind: edit.kind.clone(),
        vector: edit.vector.clone(),
        risk_level: edit.risk_level.clone(),
        prevention_tool: edit.prevention_tool.clone(),
        comment: comment.map(str::to_owned),
        campaign,
        times: edit.times,
        malware,
    })
}

/// The id of the campaign of this name and whether this made it, as `make_or_find` does for an event:
/// two edits making one at once both get it.
async fn campaign_named(conn: &mut PgConnection, name: &str) -> Result<(i32, bool), ServiceError> {
    for _ in 0..3 {
        let made = sqlx::query_scalar!(
            "INSERT INTO events.campaigns (name) VALUES ($1) ON CONFLICT (name) DO NOTHING RETURNING id",
            name,
        )
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = made {
            return Ok((id, true));
        }
        let found = sqlx::query_scalar!(
            "SELECT id FROM events.campaigns WHERE name = $1 FOR KEY SHARE",
            name,
        )
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = found {
            return Ok((id, false));
        }
    }
    Err(ServiceError::Conflict(format!(
        "the threat actor {name:?} kept changing; try again"
    )))
}

/// The id of the malware of this name and whether this made it.
async fn malware_named(conn: &mut PgConnection, name: &str) -> Result<(i32, bool), ServiceError> {
    for _ in 0..3 {
        let made = sqlx::query_scalar!(
            "INSERT INTO events.malware (name) VALUES ($1) ON CONFLICT (name) DO NOTHING RETURNING id",
            name,
        )
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = made {
            return Ok((id, true));
        }
        let found = sqlx::query_scalar!(
            "SELECT id FROM events.malware WHERE name = $1 FOR KEY SHARE",
            name,
        )
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(id) = found {
            return Ok((id, false));
        }
    }
    Err(ServiceError::Conflict(format!(
        "the malware {name:?} kept changing; try again"
    )))
}

async fn threat_row(
    conn: &mut PgConnection,
    malware: i32,
    threat_type: i32,
) -> Result<Option<Threat>, ServiceError> {
    Ok(sqlx::query_as!(
        Threat,
        r#"SELECT mt.malware_id, m.name AS malware_name, mt.threat_type_id,
                  tt.name AS threat_type_name
           FROM events.malware_threats mt
           JOIN events.malware m ON m.id = mt.malware_id
           JOIN events.threat_types tt ON tt.id = mt.threat_type_id
           WHERE mt.malware_id = $1 AND mt.threat_type_id = $2"#,
        malware,
        threat_type,
    )
    .fetch_optional(conn)
    .await?)
}

impl Service {
    /// The events whose status is `OPEN`, ace3's `GET /events/open`, in id order, a page at a time after
    /// `after`. ace3's list isn't paged; this one stops at `MAX_EVENTS_PAGE`.
    pub async fn open_events(
        &self,
        actor: &Actor,
        after: Option<i64>,
        limit: u32,
    ) -> Result<EventPage, ServiceError> {
        if !(1..=MAX_EVENTS_PAGE).contains(&limit) {
            return Err(ServiceError::InvalidRequest(format!(
                "a page holds 1 to {MAX_EVENTS_PAGE} events"
            )));
        }
        let take = i64::from(limit);
        self.gate
            .read(actor, "open_events", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    let mut ids = sqlx::query_scalar!(
                        "SELECT e.id FROM events.events e
                         JOIN events.statuses s ON s.id = e.status_id
                         WHERE s.value = 'OPEN' AND ($1::bigint IS NULL OR e.id > $1)
                         ORDER BY e.id
                         LIMIT $2",
                        after,
                        take + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let more = ids.len() > limit as usize;
                    ids.truncate(limit as usize);
                    let next = more.then(|| ids.last().copied()).flatten();
                    let events = load_events(tx.conn(), &self.dispositions, &ids).await?;
                    Ok(EventPage { events, next })
                })
            })
            .await
    }

    /// The events whose status is `CLOSED`, newest first by creation date, as ace3's add-to-event form
    /// lists them, `limit` at a time after the event `after`, ace3's `load_more_events`. ace3 reads them
    /// all and slices; this reads one page.
    pub async fn closed_events(
        &self,
        actor: &Actor,
        after: Option<i64>,
        limit: u32,
    ) -> Result<EventPage, ServiceError> {
        if !(1..=MAX_EVENTS_PAGE).contains(&limit) {
            return Err(ServiceError::InvalidRequest(format!(
                "a page holds 1 to {MAX_EVENTS_PAGE} events"
            )));
        }
        let take = i64::from(limit);
        self.gate
            .read(actor, "closed_events", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    let mut ids = sqlx::query_scalar!(
                        "SELECT e.id FROM events.events e
                         JOIN events.statuses s ON s.id = e.status_id
                         WHERE s.value = 'CLOSED'
                           AND ($1::bigint IS NULL
                                OR (e.creation_date, e.id) <
                                   (SELECT c.creation_date, c.id FROM events.events c WHERE c.id = $1))
                         ORDER BY e.creation_date DESC, e.id DESC
                         LIMIT $2",
                        after,
                        take + 1,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let more = ids.len() > limit as usize;
                    ids.truncate(limit as usize);
                    let next = more.then(|| ids.last().copied()).flatten();
                    let mut events = load_events(tx.conn(), &self.dispositions, &ids).await?;
                    events.sort_by_key(|event| ids.iter().position(|id| *id == event.id));
                    Ok(EventPage { events, next })
                })
            })
            .await
    }

    /// A page of the event list, ace3's `events.manage`: the events `query`'s filters match
    /// (`EventFilters::check`), in its order with the id to break a tie, `limit` at a time after the
    /// cursor `after`, a page's `next`. ace3's list isn't paged; this one is a keyset of at most
    /// `MAX_EVENTS_PAGE`. A cursor of another order is `InvalidRequest`, and so is a filter that runs past
    /// `LIST_TIMEOUT`.
    pub async fn event_list(
        &self,
        actor: &Actor,
        query: &EventQuery,
        after: Option<&str>,
        limit: u32,
    ) -> Result<EventListPage, ServiceError> {
        if !(1..=MAX_EVENTS_PAGE).contains(&limit) {
            return Err(ServiceError::InvalidRequest(format!(
                "a page holds 1 to {MAX_EVENTS_PAGE} events"
            )));
        }
        let after = after
            .map(|after| EventCursor::decode(after, query))
            .transpose()?;
        let page = self
            .event_page(actor, query, after.as_ref(), i64::from(limit))
            .await?;
        if page.events.is_empty() && after.is_some() {
            // past the end, the page has no row to carry the total, so the first page counts
            let first = self.event_page(actor, query, None, 1).await?;
            return Ok(EventListPage {
                total: first.total,
                ..page
            });
        }
        Ok(page)
    }

    async fn event_page(
        &self,
        actor: &Actor,
        query: &EventQuery,
        after: Option<&EventCursor>,
        limit: i64,
    ) -> Result<EventListPage, ServiceError> {
        let f = query.filters.check()?;
        let (created_start, created_end) = match &f.created {
            Some(range) => {
                let (start, end) =
                    crate::filters::date_window(range, Utc::now(), chrono_tz::Tz::UTC)?;
                (Some(start), Some(end))
            }
            None => (None, None),
        };
        let some = |values: &Vec<String>| (!values.is_empty()).then(|| values.clone());
        let dispositions = some(&f.dispositions);
        let statuses = some(&f.statuses);
        let tags = some(&f.tags);
        let owners: Option<Vec<Uuid>> = (!f.owners.is_empty()).then(|| {
            f.owners
                .iter()
                .filter_map(|owner| match owner {
                    EventOwnerFilter::User(id) => Some(*id),
                    EventOwnerFilter::Nobody => None,
                })
                .collect()
        });
        let nobody = f.owners.contains(&EventOwnerFilter::Nobody);
        let malware = (!f.malware.is_empty()).then(|| f.malware.clone());
        let campaigns = (!f.campaigns.is_empty()).then(|| f.campaigns.clone());
        let (rank_names, rank_values) = self.dispositions.ranks();
        let sort = query.sort;
        let descending = query.descending;
        let after_id = after.map(|cursor| cursor.id);
        let after_key = after.map(|cursor| cursor.key.clone());
        let lists = (
            &dispositions,
            &statuses,
            &owners,
            &tags,
            &malware,
            &campaigns,
            &rank_names,
            &rank_values,
            &after_key,
        );
        let f = &f;
        self.gate
            .read(actor, "event_list", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    let (dispositions, statuses, owners, tags, malware, campaigns, rank_names, rank_values, after_key) =
                        lists;
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    let rows = sqlx::query!(
                        r#"WITH ranks(d, rank) AS (SELECT * FROM unnest($6::text[], $7::int[])),
                           matched AS (
                             SELECT e.id,
                                    (CASE $1::text
                                       WHEN 'date' THEN ARRAY[e.creation_date::text]
                                       WHEN 'event' THEN ARRAY[t.value, v.value, e.name]
                                       WHEN 'campaign' THEN
                                         ARRAY[(c.name IS NOT NULL)::int::text, COALESCE(c.name, '')]
                                       WHEN 'risk_level' THEN ARRAY[rl.value]
                                       WHEN 'disposition' THEN
                                         ARRAY[lpad(COALESCE(dr.rank, 0)::text, 10, '0')]
                                       WHEN 'prevention' THEN ARRAY[p.value]
                                       WHEN 'remediation' THEN ARRAY[rm.value]
                                       WHEN 'status' THEN ARRAY[s.value]
                                       ELSE ARRAY[(u.id IS NOT NULL)::int::text,
                                                  COALESCE(u.display_name, u.username::text, '')]
                                     END) COLLATE "C" AS k,
                                    count(*) OVER () AS total
                             FROM events.events e
                             JOIN events.statuses s ON s.id = e.status_id
                             JOIN events.remediations rm ON rm.id = e.remediation_id
                             JOIN events.types t ON t.id = e.type_id
                             JOIN events.vectors v ON v.id = e.vector_id
                             JOIN events.risk_levels rl ON rl.id = e.risk_level_id
                             JOIN events.prevention_tools p ON p.id = e.prevention_tool_id
                             LEFT JOIN events.campaigns c ON c.id = e.campaign_id
                             LEFT JOIN service.users u ON u.id = e.owner_id
                             -- the rolled-up disposition: DELIVERY with no alerts, else the highest
                             -- ranked of theirs, else OPEN (Dispositions::rolled_up)
                             CROSS JOIN LATERAL (
                               SELECT CASE
                                 WHEN NOT EXISTS (SELECT FROM events.event_alerts ea
                                                  WHERE ea.event_id = e.id) THEN 'DELIVERY'
                                 ELSE COALESCE((SELECT k.d FROM events.event_alerts ea
                                                JOIN analysis.roots r ON r.id = ea.root_id
                                                JOIN ranks k ON k.d = r.disposition AND k.rank > 0
                                                WHERE ea.event_id = e.id
                                                ORDER BY k.rank DESC, k.d COLLATE "C" LIMIT 1), 'OPEN')
                               END AS disposition
                             ) dd
                             LEFT JOIN ranks dr ON dr.d = dd.disposition
                             WHERE ($8::timestamptz IS NULL
                                    OR (e.creation_date::timestamp AT TIME ZONE 'UTC') >= $8)
                               AND ($9::timestamptz IS NULL
                                    OR (e.creation_date::timestamp AT TIME ZONE 'UTC') <= $9)
                               AND ($10::text[] IS NULL OR dd.disposition = ANY($10))
                               AND ($11::text[] IS NULL OR s.value = ANY($11))
                               AND ($12::uuid[] IS NULL OR e.owner_id = ANY($12)
                                    OR ($13::boolean AND e.owner_id IS NULL))
                               AND ($14::text IS NULL OR t.value = $14)
                               AND ($15::text IS NULL OR v.value = $15)
                               AND ($16::text IS NULL OR p.value = $16)
                               AND ($17::text IS NULL OR rl.value = $17)
                               -- an alert in it holding the observable, matched on its hash as the
                               -- alert list's observable filter is
                               AND (($18::text IS NULL AND $19::text IS NULL) OR EXISTS (
                                     SELECT FROM events.event_alerts ea
                                     JOIN analysis.observables o ON o.root_id = ea.root_id
                                     WHERE ea.event_id = e.id
                                       AND ($18::text IS NULL OR o.type = $18)
                                       AND ($19::text IS NULL
                                            OR (o.value_hash = analysis.value_hash($19) AND o.value = $19))))
                               AND ($20::text[] IS NULL OR EXISTS (
                                     SELECT FROM events.event_tags g
                                     WHERE g.event_id = e.id AND g.tag = ANY($20)))
                               AND ($21::int[] IS NULL OR EXISTS (
                                     SELECT FROM events.event_malware em
                                     WHERE em.event_id = e.id AND em.malware_id = ANY($21)))
                               AND ($22::int[] IS NULL OR e.campaign_id = ANY($22))
                           )
                           SELECT m.id, m.k AS "k!", m.total AS "total!"
                           FROM matched m
                           WHERE $3::bigint IS NULL OR CASE
                             WHEN $2::boolean THEN (m.k, m.id) < ($4::text[] COLLATE "C", $3)
                             ELSE (m.k, m.id) > ($4::text[] COLLATE "C", $3)
                           END
                           ORDER BY
                             CASE WHEN $2 THEN m.k END DESC,
                             CASE WHEN NOT $2 THEN m.k END ASC,
                             CASE WHEN $2 THEN m.id END DESC,
                             CASE WHEN NOT $2 THEN m.id END ASC
                           LIMIT $5"#,
                        sort.as_str(),
                        descending,
                        after_id,
                        after_key.as_deref(),
                        limit + 1,
                        rank_names.as_slice(),
                        rank_values.as_slice(),
                        created_start,
                        created_end,
                        dispositions.as_deref(),
                        statuses.as_deref(),
                        owners.as_deref(),
                        nobody,
                        f.kind.as_deref(),
                        f.vector.as_deref(),
                        f.prevention_tool.as_deref(),
                        f.risk_level.as_deref(),
                        f.observable_type.as_deref(),
                        f.observable_value.as_deref(),
                        tags.as_deref(),
                        malware.as_deref(),
                        campaigns.as_deref(),
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(timed_out)?;
                    let total = rows.first().map_or(0, |row| row.total);
                    let take = usize::try_from(limit).unwrap_or(usize::MAX);
                    let more = rows.len() > take;
                    let rows: Vec<_> = rows.into_iter().take(take).collect();
                    let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
                    let mut events = load_events(tx.conn(), &self.dispositions, &ids).await?;
                    events.sort_by_key(|event| ids.iter().position(|id| *id == event.id));
                    let next = match rows.last() {
                        Some(last) if more => Some(
                            EventCursor {
                                sort,
                                descending,
                                id: last.id,
                                key: last.k.clone(),
                            }
                            .encode(),
                        ),
                        _ => None,
                    };
                    Ok(EventListPage {
                        events,
                        next,
                        total,
                    })
                })
            })
            .await
    }

    /// What the event list's filters offer (`EventChoices`), under `event:read`. The owners are the users
    /// who own an event, where ace3 lists every user: filtering on anyone else finds nothing, and the list
    /// tells an event reader no more than the events do.
    pub async fn event_choices(&self, actor: &Actor) -> Result<EventChoices, ServiceError> {
        self.gate
            .read(actor, "event_choices", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    let mut choices = EventChoices::default();
                    for row in sqlx::query!(
                        r#"SELECT 'status' AS "table!", id::int AS "id!", value AS "value!" FROM events.statuses
                           UNION ALL SELECT 'type', id::int, value FROM events.types
                           UNION ALL SELECT 'vector', id::int, value FROM events.vectors
                           UNION ALL SELECT 'prevention', id::int, value FROM events.prevention_tools
                           UNION ALL SELECT 'risk', id::int, value FROM events.risk_levels
                           ORDER BY 1, 3, 2"#
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        let value = EventValue {
                            id: row.id,
                            value: row.value,
                        };
                        match row.table.as_str() {
                            "status" => choices.statuses.push(value),
                            "type" => choices.types.push(value),
                            "vector" => choices.vectors.push(value),
                            "prevention" => choices.prevention_tools.push(value),
                            _ => choices.risk_levels.push(value),
                        }
                    }
                    choices.owners = sqlx::query!(
                        r#"SELECT u.id, u.username::text AS "username!", u.display_name
                           FROM service.users u
                           WHERE EXISTS (SELECT FROM events.events e WHERE e.owner_id = u.id)
                           ORDER BY COALESCE(u.display_name, u.username::text), u.id
                           LIMIT $1"#,
                        MAX_EVENT_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| EventOwnerChoice {
                        id: UserId(row.id),
                        username: row.username,
                        display_name: row.display_name,
                    })
                    .collect();
                    choices.malware = sqlx::query_as!(
                        EventValue,
                        "SELECT id, name AS value FROM events.malware ORDER BY name, id LIMIT $1",
                        MAX_EVENT_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    choices.campaigns = sqlx::query_as!(
                        EventValue,
                        "SELECT id, name AS value FROM events.campaigns ORDER BY name, id LIMIT $1",
                        MAX_EVENT_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    choices.tags = sqlx::query_scalar!(
                        "SELECT DISTINCT tag FROM events.event_tags ORDER BY tag LIMIT $1",
                        MAX_EVENT_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    Ok(choices)
                })
            })
            .await
    }

    /// Adds alerts to an event, ace3's `add_to_event`: to one that exists, or to a new one, made unless
    /// its name is taken on its day (the module's docs). One transaction, and one audit row whose `after`
    /// lists the alerts added. At most `MAX_EVENT_ALERTS` ticked alerts; one ticked twice counts once.
    pub async fn add_to_event(
        &self,
        actor: &Actor,
        event: &EventChoice,
        alerts: &[Uuid],
    ) -> Result<AddedToEvent, ServiceError> {
        if alerts.len() > MAX_EVENT_ALERTS {
            return Err(ServiceError::TooLarge(format!(
                "at most {MAX_EVENT_ALERTS} alerts are added to an event at once"
            )));
        }
        let mut ticked: Vec<Uuid> = Vec::with_capacity(alerts.len());
        for alert in alerts {
            if !ticked.contains(alert) {
                ticked.push(*alert);
            }
        }
        let choice = match event {
            EventChoice::Existing(event) => EventChoice::Existing(*event),
            EventChoice::New(new) => EventChoice::New(checked_new_event(new)?),
        };
        let owner = match actor {
            Actor::User { id, .. } => Some(id.0),
            Actor::ApiKey { owner, .. } => owner.map(|owner| owner.0),
            Actor::Internal { .. } => None,
        };
        let (ticked, choice) = (ticked.as_slice(), &choice);
        self.gate
            .write(actor, "add_to_event", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    // held until the commit, so an alert found here isn't deleted before it's added
                    let found = sqlx::query!(
                        r#"SELECT id, alerted_at AS "alerted_at!" FROM analysis.roots
                           WHERE id = ANY($1) AND alerted_at IS NOT NULL
                           FOR KEY SHARE"#,
                        ticked,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let present: Vec<Uuid> = ticked
                        .iter()
                        .copied()
                        .filter(|id| found.iter().any(|row| row.id == *id))
                        .collect();
                    let missing: Vec<Uuid> = ticked
                        .iter()
                        .copied()
                        .filter(|id| !present.contains(id))
                        .collect();
                    let (id, made) = match choice {
                        EventChoice::Existing(event) => (event_id(tx.conn(), *event).await?, false),
                        EventChoice::New(new) => {
                            // ace3 dates it by the oldest alert's insert date, or today
                            let day = found
                                .iter()
                                .map(|row| row.alerted_at)
                                .min()
                                .unwrap_or_else(Utc::now)
                                .date_naive();
                            make_or_find(tx.conn(), day, new, owner).await?
                        }
                    };
                    let inserted = sqlx::query_scalar!(
                        "INSERT INTO events.event_alerts (event_id, root_id)
                         SELECT $1, unnest($2::uuid[])
                         ON CONFLICT DO NOTHING
                         RETURNING root_id",
                        id,
                        &present,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let (added, already): (Vec<Uuid>, Vec<Uuid>) = present
                        .iter()
                        .copied()
                        .partition(|id| inserted.contains(id));
                    let event = one_event(tx.conn(), &self.dispositions, id).await?;
                    let details = AddedDetails {
                        uuid: event.uuid,
                        name: &event.name,
                        missing: &missing,
                    };
                    let change = if made {
                        Some(Change::added(
                            Target::event(id),
                            &EventMade {
                                uuid: event.uuid,
                                creation_date: event.creation_date,
                                name: &event.name,
                                status: &event.status,
                                remediation: &event.remediation,
                                kind: &event.kind,
                                vector: &event.vector,
                                risk_level: &event.risk_level,
                                prevention_tool: &event.prevention_tool,
                                comment: event.comment.as_deref(),
                                times: EventTimes {
                                    event_time: event.event_time,
                                    alert_time: event.alert_time,
                                    ownership_time: event.ownership_time,
                                    disposition_time: event.disposition_time,
                                    contain_time: event.contain_time,
                                    remediation_time: event.remediation_time,
                                },
                                owner: event.owner.as_ref().map(|owner| owner.id.0),
                                alerts: &added,
                            },
                        )?)
                    } else if added.is_empty() {
                        None
                    } else {
                        Some(Change::added(
                            Target::event(id),
                            &AlertsAdded { alerts: &added },
                        )?)
                    };
                    let change = change.map(|change| change.details(&details)).transpose()?;
                    let value = AddedToEvent {
                        event,
                        made,
                        added,
                        already,
                        missing,
                    };
                    Ok(match change {
                        Some(change) => Audited::changed(value, change),
                        None => Audited::unchanged(value),
                    })
                })
            })
            .await
    }

    /// One event, by its id or uuid.
    pub async fn event(&self, actor: &Actor, event: EventRef) -> Result<Event, ServiceError> {
        self.gate
            .read(actor, "event", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    let id = event_id(tx.conn(), event).await?;
                    one_event(tx.conn(), &self.dispositions, id).await
                })
            })
            .await
    }

    /// The events with these ids, for ace3's CSV export, in id order. An id with no event is left out, as
    /// in ace3. At most `MAX_EXPORT_EVENTS` ids, where ace3 takes any number.
    pub async fn events_for_export(
        &self,
        actor: &Actor,
        ids: &[i64],
    ) -> Result<Vec<Event>, ServiceError> {
        if ids.len() > MAX_EXPORT_EVENTS {
            return Err(ServiceError::TooLarge(format!(
                "an export holds at most {MAX_EXPORT_EVENTS} events"
            )));
        }
        self.gate
            .read(actor, "events_for_export", &EVENT_READ, &|tx| {
                Box::pin(async move { load_events(tx.conn(), &self.dispositions, ids).await })
            })
            .await
    }

    /// Sets an event's status, ace3's `PATCH /events/{id}`. A status that isn't one is refused, and the one
    /// it has changes nothing.
    pub async fn set_event_status(
        &self,
        actor: &Actor,
        event: EventRef,
        status: &str,
    ) -> Result<Event, ServiceError> {
        self.gate
            .write(actor, "set_event_status", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let id = event_id(tx.conn(), event).await?;
                    let found = sqlx::query!(
                        "SELECT e.uuid, e.name, s.value AS status
                         FROM events.events e JOIN events.statuses s ON s.id = e.status_id
                         WHERE e.id = $1
                         FOR UPDATE OF e",
                        id,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let new = sqlx::query_scalar!(
                        "SELECT id FROM events.statuses WHERE value = $1",
                        status,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| {
                        ServiceError::InvalidRequest(format!("{status:?} isn't an event status"))
                    })?;
                    if found.status == status {
                        return Ok(Audited::unchanged(
                            one_event(tx.conn(), &self.dispositions, id).await?,
                        ));
                    }
                    sqlx::query!(
                        "UPDATE events.events SET status_id = $2 WHERE id = $1",
                        id,
                        new,
                    )
                    .execute(tx.conn())
                    .await?;
                    let change = Change::updated(
                        Target::event(id),
                        &EventStatus {
                            status: &found.status,
                        },
                        &EventStatus { status },
                    )?
                    .details(&EventNamed {
                        uuid: found.uuid,
                        name: &found.name,
                    })?;
                    Ok(Audited::changed(
                        one_event(tx.conn(), &self.dispositions, id).await?,
                        change,
                    ))
                })
            })
            .await
    }

    /// What an edit's form offers (`EventEditChoices`), ace3's `edit_event_modal`'s lists, under
    /// `event:read` as ace3's modal is. The users are the enabled ones, as ace3's owner select lists them.
    pub async fn event_edit_choices(
        &self,
        actor: &Actor,
    ) -> Result<EventEditChoices, ServiceError> {
        self.gate
            .read(actor, "event_edit_choices", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    let mut choices = EventEditChoices::default();
                    for row in sqlx::query!(
                        r#"SELECT 'status' AS "table!", id::int AS "id!", value AS "value!" FROM events.statuses
                           UNION ALL SELECT 'remediation', id::int, value FROM events.remediations
                           UNION ALL SELECT 'type', id::int, value FROM events.types
                           UNION ALL SELECT 'vector', id::int, value FROM events.vectors
                           UNION ALL SELECT 'risk', id::int, value FROM events.risk_levels
                           UNION ALL SELECT 'prevention', id::int, value FROM events.prevention_tools
                           UNION ALL (SELECT 'campaign', id, name FROM events.campaigns
                                      ORDER BY name, id LIMIT $1)
                           ORDER BY 1, 3, 2"#,
                        MAX_EVENT_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    {
                        let value = EventValue {
                            id: row.id,
                            value: row.value,
                        };
                        match row.table.as_str() {
                            "status" => choices.statuses.push(value),
                            "remediation" => choices.remediations.push(value),
                            "type" => choices.types.push(value),
                            "vector" => choices.vectors.push(value),
                            "risk" => choices.risk_levels.push(value),
                            "prevention" => choices.prevention_tools.push(value),
                            _ => choices.campaigns.push(value),
                        }
                    }
                    choices.malware = sqlx::query!(
                        r#"SELECT m.id, m.name,
                                  COALESCE(array_agg(tt.name ORDER BY tt.name)
                                           FILTER (WHERE tt.name IS NOT NULL), '{}') AS "threat_types!"
                           FROM (SELECT id, name FROM events.malware ORDER BY name, id LIMIT $1) m
                           LEFT JOIN events.malware_threats mt ON mt.malware_id = m.id
                           LEFT JOIN events.threat_types tt ON tt.id = mt.threat_type_id
                           GROUP BY m.id, m.name
                           ORDER BY m.name, m.id"#,
                        MAX_EVENT_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| EventMalware {
                        id: row.id,
                        name: row.name,
                        threat_types: row.threat_types,
                    })
                    .collect();
                    choices.threat_types = sqlx::query_as!(
                        ThreatType,
                        "SELECT id, name FROM events.threat_types ORDER BY name, id LIMIT $1",
                        MAX_EVENT_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    choices.users = sqlx::query!(
                        r#"SELECT id, username::text AS "username!", display_name
                           FROM service.users WHERE enabled
                           ORDER BY COALESCE(display_name, username::text), id
                           LIMIT $1"#,
                        MAX_EVENT_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| EventOwnerChoice {
                        id: UserId(row.id),
                        username: row.username,
                        display_name: row.display_name,
                    })
                    .collect();
                    Ok(choices)
                })
            })
            .await
    }

    /// Edits an event, ace3's `edit_event`, under `event:write`: one transaction, and one audit row with
    /// the event's state before and after and what it made (the module's docs). An edit that changes
    /// nothing has no row. An edit drawn from a version the event has left is a conflict.
    pub async fn edit_event(
        &self,
        actor: &Actor,
        event: EventRef,
        edit: &EventEdit,
    ) -> Result<Event, ServiceError> {
        let edit = checked_edit(edit)?;
        let edit = &edit;
        self.gate
            .write(actor, "edit_event", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let id = event_id(tx.conn(), event).await?;
                    // held until the commit, so two edits of one version can't both pass the check;
                    // NO KEY, so adding an alert or a tag meanwhile isn't held up by it
                    sqlx::query!(
                        "SELECT id FROM events.events WHERE id = $1 FOR NO KEY UPDATE",
                        id
                    )
                        .fetch_one(tx.conn())
                        .await?;
                    let before = one_event(tx.conn(), &self.dispositions, id).await?;
                    if before.edit_version() != edit.version {
                        return Err(ServiceError::Conflict(format!(
                            "event {id} has changed since this edit began: open its edit again"
                        )));
                    }
                    let closed = before.status == CLOSED_STATUS;
                    if !closed && edit.status == CLOSED_STATUS {
                        return Err(ServiceError::InvalidRequest(
                            "an open event is closed with Close Event, not an edit".to_owned(),
                        ));
                    }
                    let refs = sqlx::query!(
                        r#"SELECT (SELECT id FROM events.statuses WHERE value = $1) AS "status?",
                                  (SELECT id FROM events.remediations WHERE value = $2) AS "remediation?",
                                  (SELECT id FROM events.types WHERE value = $3) AS "kind?",
                                  (SELECT id FROM events.vectors WHERE value = $4) AS "vector?",
                                  (SELECT id FROM events.risk_levels WHERE value = $5) AS "risk_level?",
                                  (SELECT id FROM events.prevention_tools WHERE value = $6)
                                      AS "prevention_tool?""#,
                        edit.status,
                        edit.remediation,
                        edit.kind,
                        edit.vector,
                        edit.risk_level,
                        edit.prevention_tool,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    let need = |found: Option<i16>, what: &str, value: &str| {
                        found.ok_or_else(|| {
                            ServiceError::InvalidRequest(format!("{value:?} isn't an event {what}"))
                        })
                    };
                    let status = need(refs.status, "status", &edit.status)?;
                    let remediation = need(refs.remediation, "remediation", &edit.remediation)?;
                    let kind = need(refs.kind, "type", &edit.kind)?;
                    let vector = need(refs.vector, "vector", &edit.vector)?;
                    let risk_level = need(refs.risk_level, "risk level", &edit.risk_level)?;
                    let prevention_tool =
                        need(refs.prevention_tool, "prevention tool", &edit.prevention_tool)?;

                    if let Some(owner) = edit.owner {
                        let enabled = sqlx::query_scalar!(
                            "SELECT enabled FROM service.users WHERE id = $1 FOR KEY SHARE",
                            owner.0,
                        )
                        .fetch_optional(tx.conn())
                        .await?
                        .ok_or_else(|| ServiceError::NotFound(format!("no user {}", owner.0)))?;
                        let kept = before.owner.as_ref().is_some_and(|o| o.id == owner);
                        if !enabled && !kept {
                            return Err(ServiceError::InvalidRequest(format!(
                                "user {} is disabled, so can't be given an event",
                                owner.0
                            )));
                        }
                    }

                    // ace3 sets the times given only while the event isn't closed, then checks the order
                    let times = if closed {
                        before.times()
                    } else {
                        let stored = before.times();
                        let merged = EventTimes {
                            event_time: edit.times.event_time.or(stored.event_time),
                            alert_time: edit.times.alert_time.or(stored.alert_time),
                            ownership_time: edit.times.ownership_time.or(stored.ownership_time),
                            disposition_time: edit
                                .times
                                .disposition_time
                                .or(stored.disposition_time),
                            contain_time: edit.times.contain_time.or(stored.contain_time),
                            remediation_time: edit
                                .times
                                .remediation_time
                                .or(stored.remediation_time),
                        };
                        if !merged.in_order() {
                            return Err(ServiceError::InvalidRequest(
                                "one or more of the times is out of order: each of event time, alert \
                                 time, ownership time, disposition time, contain time and remediation \
                                 time is no earlier than the one before it"
                                    .to_owned(),
                            ));
                        }
                        merged
                    };

                    let (campaign, made_campaign) = match &edit.campaign {
                        CampaignChoice::None => (None, None),
                        CampaignChoice::Existing(campaign) => {
                            let found = sqlx::query_scalar!(
                                "SELECT id FROM events.campaigns WHERE id = $1 FOR KEY SHARE",
                                campaign,
                            )
                            .fetch_optional(tx.conn())
                            .await?
                            .ok_or_else(|| {
                                ServiceError::NotFound(format!("no threat actor {campaign}"))
                            })?;
                            (Some(found), None)
                        }
                        CampaignChoice::New(name) => {
                            let (found, made) = campaign_named(tx.conn(), name).await?;
                            (Some(found), made.then_some(name.as_str()))
                        }
                    };

                    let mut malware: Vec<i32> = Vec::new();
                    let mut made_malware: Vec<String> = Vec::new();
                    let mut added_threats: Vec<ThreatGiven> = Vec::new();
                    for choice in &edit.malware {
                        let found = match choice {
                            MalwareChoice::Existing(id) => sqlx::query_scalar!(
                                "SELECT id FROM events.malware WHERE id = $1 FOR KEY SHARE",
                                id,
                            )
                            .fetch_optional(tx.conn())
                            .await?
                            .ok_or_else(|| ServiceError::NotFound(format!("no malware {id}")))?,
                            MalwareChoice::New { name, threat_types } => {
                                let there = sqlx::query_scalar!(
                                    r#"SELECT count(*) AS "count!" FROM events.threat_types
                                       WHERE id = ANY($1)"#,
                                    threat_types,
                                )
                                .fetch_one(tx.conn())
                                .await?;
                                if usize::try_from(there).ok() != Some(threat_types.len()) {
                                    return Err(ServiceError::NotFound(format!(
                                        "a threat type of new malware {name:?} isn't there"
                                    )));
                                }
                                let (found, made) = malware_named(tx.conn(), name).await?;
                                if made {
                                    made_malware.push(name.clone());
                                }
                                for threat_type in sqlx::query_scalar!(
                                    "INSERT INTO events.malware_threats (malware_id, threat_type_id)
                                     SELECT $1, unnest($2::int[])
                                     ON CONFLICT DO NOTHING
                                     RETURNING threat_type_id",
                                    found,
                                    threat_types,
                                )
                                .fetch_all(tx.conn())
                                .await?
                                {
                                    added_threats.push(ThreatGiven {
                                        malware: name.clone(),
                                        threat_type,
                                    });
                                }
                                found
                            }
                        };
                        if !malware.contains(&found) {
                            malware.push(found);
                        }
                    }
                    sqlx::query!(
                        "DELETE FROM events.event_malware WHERE event_id = $1 AND malware_id <> ALL($2)",
                        id,
                        &malware,
                    )
                    .execute(tx.conn())
                    .await?;
                    sqlx::query!(
                        "INSERT INTO events.event_malware (event_id, malware_id)
                         SELECT $1, unnest($2::int[])
                         ON CONFLICT DO NOTHING",
                        id,
                        &malware,
                    )
                    .execute(tx.conn())
                    .await?;

                    sqlx::query!(
                        "UPDATE events.events
                         SET name = $2, status_id = $3, remediation_id = $4, type_id = $5,
                             vector_id = $6, risk_level_id = $7, prevention_tool_id = $8,
                             campaign_id = $9, comment = $10, event_time = $11, alert_time = $12,
                             ownership_time = $13, disposition_time = $14, contain_time = $15,
                             remediation_time = $16, owner_id = $17
                         WHERE id = $1",
                        id,
                        edit.name,
                        status,
                        remediation,
                        kind,
                        vector,
                        risk_level,
                        prevention_tool,
                        campaign,
                        edit.comment,
                        times.event_time,
                        times.alert_time,
                        times.ownership_time,
                        times.disposition_time,
                        times.contain_time,
                        times.remediation_time,
                        edit.owner.map(|owner| owner.0),
                    )
                    .execute(tx.conn())
                    .await
                    .map_err(|error| {
                        if is_unique_violation(&error) {
                            ServiceError::Conflict(format!(
                                "an event named {:?} exists on {} already",
                                edit.name, before.creation_date
                            ))
                        } else {
                            error.into()
                        }
                    })?;

                    let after = one_event(tx.conn(), &self.dispositions, id).await?;
                    let (was, is) = (EditState::of(&before), EditState::of(&after));
                    if was == is {
                        return Ok(Audited::unchanged(after));
                    }
                    let change = Change::updated(Target::event(id), &was, &is)?.details(
                        &EditDetails {
                            uuid: after.uuid,
                            made_campaign,
                            made_malware: &made_malware,
                            added_threats: &added_threats,
                        },
                    )?;
                    Ok(Audited::changed(after, change))
                })
            })
            .await
    }

    /// Takes alerts out of an event, ace3's `remove_alerts`, under `event:write`, with one audit row
    /// listing those taken. An alert that isn't in it is said, not an error, as ace3 skips one; taking out
    /// none has no row. At most `MAX_EVENT_ALERTS`.
    pub async fn remove_alerts(
        &self,
        actor: &Actor,
        event: EventRef,
        alerts: &[Uuid],
    ) -> Result<RemovedAlerts, ServiceError> {
        if alerts.len() > MAX_EVENT_ALERTS {
            return Err(ServiceError::TooLarge(format!(
                "at most {MAX_EVENT_ALERTS} alerts are removed from an event at once"
            )));
        }
        let mut given: Vec<Uuid> = Vec::with_capacity(alerts.len());
        for alert in alerts {
            if !given.contains(alert) {
                given.push(*alert);
            }
        }
        let given = given.as_slice();
        self.gate
            .write(actor, "remove_alerts", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let id = event_id(tx.conn(), event).await?;
                    let deleted = sqlx::query_scalar!(
                        "DELETE FROM events.event_alerts WHERE event_id = $1 AND root_id = ANY($2)
                         RETURNING root_id",
                        id,
                        given,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let (removed, not_in): (Vec<Uuid>, Vec<Uuid>) =
                        given.iter().copied().partition(|id| deleted.contains(id));
                    let event = one_event(tx.conn(), &self.dispositions, id).await?;
                    let change = if removed.is_empty() {
                        None
                    } else {
                        Some(
                            Change::removed(
                                Target::event(id),
                                &AlertsInEvent { alerts: &removed },
                            )?
                            .details(&EventNamed {
                                uuid: event.uuid,
                                name: &event.name,
                            })?,
                        )
                    };
                    let value = RemovedAlerts {
                        event,
                        removed,
                        not_in,
                    };
                    Ok(match change {
                        Some(change) => Audited::changed(value, change),
                        None => Audited::unchanged(value),
                    })
                })
            })
            .await
    }

    /// Puts tags on an event itself, ace3's `add_tag` (`add_event_tag_mapping`), under `event:write`, with
    /// one audit row listing those it didn't have. A tag it has is left; adding only those has no row. At
    /// most `MAX_EVENT_TAGS`, each an `event_tag`.
    pub async fn add_event_tags(
        &self,
        actor: &Actor,
        event: EventRef,
        tags: &[String],
    ) -> Result<Event, ServiceError> {
        if tags.len() > MAX_EVENT_TAGS {
            return Err(ServiceError::TooLarge(format!(
                "at most {MAX_EVENT_TAGS} tags are added at once"
            )));
        }
        let mut given: Vec<String> = Vec::with_capacity(tags.len());
        for tag in tags {
            let tag = event_tag(tag)?;
            if !given.iter().any(|g| g == tag) {
                given.push(tag.to_owned());
            }
        }
        if given.is_empty() {
            return Err(ServiceError::InvalidRequest(
                "give one or more tags to add".to_owned(),
            ));
        }
        let given = given.as_slice();
        self.gate
            .write(actor, "add_event_tags", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let id = event_id(tx.conn(), event).await?;
                    let inserted = sqlx::query_scalar!(
                        "INSERT INTO events.event_tags (event_id, tag)
                         SELECT $1, unnest($2::text[])
                         ON CONFLICT DO NOTHING
                         RETURNING tag",
                        id,
                        given,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let added: Vec<String> = given
                        .iter()
                        .filter(|tag| inserted.contains(tag))
                        .cloned()
                        .collect();
                    let event = one_event(tx.conn(), &self.dispositions, id).await?;
                    if added.is_empty() {
                        return Ok(Audited::unchanged(event));
                    }
                    let change = Change::added(Target::event(id), &TagsAdded { tags: &added })?
                        .details(&EventNamed {
                            uuid: event.uuid,
                            name: &event.name,
                        })?;
                    Ok(Audited::changed(event, change))
                })
            })
            .await
    }

    /// Every threat type, by name, ace3's `GET /threat-types/`.
    pub async fn threat_types(&self, actor: &Actor) -> Result<Vec<ThreatType>, ServiceError> {
        self.gate
            .read(actor, "threat_types", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    Ok(sqlx::query_as!(
                        ThreatType,
                        "SELECT id, name FROM events.threat_types ORDER BY name, id"
                    )
                    .fetch_all(tx.conn())
                    .await?)
                })
            })
            .await
    }

    pub async fn threat_type(&self, actor: &Actor, id: i32) -> Result<ThreatType, ServiceError> {
        self.gate
            .read(actor, "threat_type", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    sqlx::query_as!(
                        ThreatType,
                        "SELECT id, name FROM events.threat_types WHERE id = $1",
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| no_threat_type(id))
                })
            })
            .await
    }

    /// Adds a threat type. A name that's taken is a conflict.
    pub async fn create_threat_type(
        &self,
        actor: &Actor,
        name: &str,
    ) -> Result<ThreatType, ServiceError> {
        let name = threat_type_name(name)?;
        self.gate
            .write(actor, "create_threat_type", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let made = sqlx::query_as!(
                        ThreatType,
                        "INSERT INTO events.threat_types (name) VALUES ($1) RETURNING id, name",
                        name,
                    )
                    .fetch_one(tx.conn())
                    .await
                    .map_err(|error| taken(error, name))?;
                    let change = Change::added(Target::threat_type(made.id), &made)?;
                    Ok(Audited::changed(made, change))
                })
            })
            .await
    }

    /// Renames a threat type, ace3's `PATCH /threat-types/{id}`. The name it has changes nothing, and one
    /// another type has is a conflict.
    pub async fn rename_threat_type(
        &self,
        actor: &Actor,
        id: i32,
        name: &str,
    ) -> Result<ThreatType, ServiceError> {
        let name = threat_type_name(name)?;
        self.gate
            .write(actor, "rename_threat_type", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let found = sqlx::query_as!(
                        ThreatType,
                        "SELECT id, name FROM events.threat_types WHERE id = $1 FOR UPDATE",
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| no_threat_type(id))?;
                    if found.name == name {
                        return Ok(Audited::unchanged(found));
                    }
                    let renamed = sqlx::query_as!(
                        ThreatType,
                        "UPDATE events.threat_types SET name = $2 WHERE id = $1 RETURNING id, name",
                        id,
                        name,
                    )
                    .fetch_one(tx.conn())
                    .await
                    .map_err(|error| taken(error, name))?;
                    let change = Change::updated(
                        Target::threat_type(id),
                        &ThreatTypeName { name: &found.name },
                        &ThreatTypeName { name },
                    )?;
                    Ok(Audited::changed(renamed, change))
                })
            })
            .await
    }

    /// Deletes a threat type no malware uses. One in use is a conflict, as in ace3.
    pub async fn delete_threat_type(&self, actor: &Actor, id: i32) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "delete_threat_type", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let found = sqlx::query_as!(
                        ThreatType,
                        "SELECT id, name FROM events.threat_types WHERE id = $1 FOR UPDATE",
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| no_threat_type(id))?;
                    // the row lock keeps a new threat from naming it until this commits
                    let used_by = sqlx::query_scalar!(
                        r#"SELECT count(*) AS "count!" FROM events.malware_threats
                           WHERE threat_type_id = $1"#,
                        id,
                    )
                    .fetch_one(tx.conn())
                    .await?;
                    if used_by > 0 {
                        return Err(ServiceError::Conflict(format!(
                            "threat type {:?} is used by {used_by} malware",
                            found.name
                        )));
                    }
                    sqlx::query!("DELETE FROM events.threat_types WHERE id = $1", id)
                        .execute(tx.conn())
                        .await?;
                    let change = Change::removed(Target::threat_type(id), &found)?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }

    /// The threats, by malware name, ace3's `GET /threats/`, or one malware's.
    pub async fn threats(
        &self,
        actor: &Actor,
        malware: Option<i32>,
    ) -> Result<Vec<Threat>, ServiceError> {
        self.gate
            .read(actor, "threats", &EVENT_READ, &|tx| {
                Box::pin(async move {
                    Ok(sqlx::query_as!(
                        Threat,
                        r#"SELECT mt.malware_id, m.name AS malware_name, mt.threat_type_id,
                                  tt.name AS threat_type_name
                           FROM events.malware_threats mt
                           JOIN events.malware m ON m.id = mt.malware_id
                           JOIN events.threat_types tt ON tt.id = mt.threat_type_id
                           WHERE $1::integer IS NULL OR mt.malware_id = $1
                           ORDER BY m.name, m.id, tt.name, tt.id"#,
                        malware,
                    )
                    .fetch_all(tx.conn())
                    .await?)
                })
            })
            .await
    }

    /// Gives malware a threat type, ace3's `POST /threats/`. Malware or a type that isn't there is a 404,
    /// and a threat it has already is a conflict.
    pub async fn add_threat(
        &self,
        actor: &Actor,
        malware: i32,
        threat_type: i32,
    ) -> Result<Threat, ServiceError> {
        self.gate
            .write(actor, "add_threat", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let malware_there = sqlx::query_scalar!(
                        "SELECT id FROM events.malware WHERE id = $1 FOR SHARE",
                        malware,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .is_some();
                    if !malware_there {
                        return Err(ServiceError::NotFound(format!("no malware {malware}")));
                    }
                    let type_there = sqlx::query_scalar!(
                        "SELECT id FROM events.threat_types WHERE id = $1 FOR SHARE",
                        threat_type,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .is_some();
                    if !type_there {
                        return Err(no_threat_type(threat_type));
                    }
                    let added = sqlx::query!(
                        "INSERT INTO events.malware_threats (malware_id, threat_type_id)
                         VALUES ($1, $2) ON CONFLICT DO NOTHING",
                        malware,
                        threat_type,
                    )
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if added == 0 {
                        return Err(ServiceError::Conflict(format!(
                            "malware {malware} has threat type {threat_type} already"
                        )));
                    }
                    let threat = threat_row(tx.conn(), malware, threat_type)
                        .await?
                        .ok_or_else(|| no_threat_type(threat_type))?;
                    let change = Change::added(Target::threat(malware, threat_type), &threat)?;
                    Ok(Audited::changed(threat, change))
                })
            })
            .await
    }

    /// Takes a threat type from malware, ace3's `DELETE /threats/`. One it doesn't have is a 404.
    pub async fn remove_threat(
        &self,
        actor: &Actor,
        malware: i32,
        threat_type: i32,
    ) -> Result<(), ServiceError> {
        self.gate
            .write(actor, "remove_threat", &EVENT_WRITE, &|tx| {
                Box::pin(async move {
                    let threat = threat_row(tx.conn(), malware, threat_type)
                        .await?
                        .ok_or_else(|| {
                            ServiceError::NotFound(format!(
                                "malware {malware} doesn't have threat type {threat_type}"
                            ))
                        })?;
                    let removed = sqlx::query!(
                        "DELETE FROM events.malware_threats
                         WHERE malware_id = $1 AND threat_type_id = $2",
                        malware,
                        threat_type,
                    )
                    .execute(tx.conn())
                    .await?
                    .rows_affected();
                    if removed == 0 {
                        return Err(ServiceError::NotFound(format!(
                            "malware {malware} doesn't have threat type {threat_type}"
                        )));
                    }
                    let change = Change::removed(Target::threat(malware, threat_type), &threat)?;
                    Ok(Audited::changed((), change))
                })
            })
            .await
    }
}

/// A unique violation on a threat type's name as the conflict it is.
fn taken(error: sqlx::Error, name: &str) -> ServiceError {
    if is_unique_violation(&error) {
        ServiceError::Conflict(format!("a threat type named {name:?} exists already"))
    } else {
        error.into()
    }
}
