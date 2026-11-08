//! Events (PLAN.md 5.11's events area, 6a): ace3's `Event` and the three routers over it,
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
//! - An event's disposition is its alerts' highest by ace3's ranks (`disposition_rank`), `OPEN` while
//!   none is dispositioned, and `DELIVERY` for an event with no alerts, as ace3's `Event.disposition` has
//!   it. A disposition with no rank, such as a site's own, never wins.
//! - A status is one of `events.statuses`' values. Setting the one an event has changes nothing.
//! - A threat type's name is unique, and one that malware still uses can't be deleted (409).
//!
//! What differs:
//! - An event's alerts are listed with their own state here (title, when each became an alert, its
//!   disposition and who made it), ace3's `alerts` and `alert_details`. ace3's `owner` and `owner_time` of
//!   an alert, and its `alert_versions`, aren't there: roots have no owner or version token.
//! - `tags` are the event's own, ace3's `event_tag_mapping`, and `alert_tags` its alerts', from their
//!   observables and results, each sorted by name. ace3's JSON calls its alerts' tags `tags` and sorts them
//!   by its tag scores, which ace4 doesn't have; its export has both, as here.
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
//! What adding an alert to an event does to its analysis: nothing, here or in ace3. ace3's GUI only
//! writes the mapping (`app/analysis/views/edit/event.py`). Its `alert_added_to_event` module, which
//! dispositioned mode runs, switches an alert in an event to `event` mode, which runs no modules in
//! ace3's configuration; ace3 ships it disabled and marks it "TODO trash this". ace4 has no such module,
//! so 2.12's dispositioned mode finds none to run, and no step ports it.

use std::collections::HashMap;

use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::actor::{Actor, UserId};
use crate::alerts::RecordedActor;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::observables::OPEN;
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

/// ace3's disposition of an event with no alerts.
const NO_ALERTS: &str = "DELIVERY";

/// A disposition's rank from ace3's `saq.default.yaml`, which an event's roll-up takes the highest of.
/// None for a name ace3 doesn't configure.
pub fn disposition_rank(disposition: &str) -> Option<u16> {
    Some(match disposition {
        "OPEN" => 0,
        "IGNORE" => 10,
        "FALSE_POSITIVE" => 20,
        "UNKNOWN" => 40,
        "REVIEWED" => 50,
        "SIMULATED" => 55,
        "GRAYWARE" => 60,
        "POLICY_VIOLATION" => 70,
        "RECONNAISSANCE" => 80,
        "WEAPONIZATION" => 90,
        "DELIVERY" => 100,
        "EXPLOITATION" => 110,
        "INSTALLATION" => 120,
        "COMMAND_AND_CONTROL" => 130,
        "EXFIL" => 150,
        "DAMAGE" => 160,
        _ => return None,
    })
}

/// An event's disposition from its alerts', as ace3's `Event.disposition` rolls it up. An alert with none
/// is open.
pub fn rolled_up<'a>(dispositions: impl IntoIterator<Item = Option<&'a str>>) -> String {
    let mut dispositions = dispositions.into_iter().peekable();
    if dispositions.peek().is_none() {
        return NO_ALERTS.to_owned();
    }
    let mut best = OPEN;
    for disposition in dispositions.flatten() {
        if disposition == OPEN {
            continue;
        }
        let beats = disposition_rank(disposition)
            .is_some_and(|rank| rank > disposition_rank(best).unwrap_or(0));
        if beats {
            best = disposition;
        }
    }
    best.to_owned()
}

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
}

/// An event, with everything ace3's `Event.json` gives that ace4 has.
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
    /// The highest of its alerts' dispositions (`rolled_up`).
    pub disposition: String,
    /// Oldest alert first.
    pub alerts: Vec<EventAlert>,
    /// The event's own tags, by name.
    pub tags: Vec<String>,
    /// Its alerts' tags, from their observables and results, by name.
    pub alert_tags: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl Event {
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
async fn load_events(conn: &mut PgConnection, ids: &[i64]) -> Result<Vec<Event>, ServiceError> {
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

    let mut alerts: HashMap<i64, Vec<EventAlert>> = HashMap::new();
    for row in sqlx::query!(
        r#"SELECT ea.event_id, r.id, r.description, r.alerted_at, r.disposition, r.dispositioned_at,
                  r.dispositioned_by AS "dispositioned_by: Value", ea.added_at
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

    let mut alert_tags: HashMap<i64, Vec<String>> = HashMap::new();
    for row in sqlx::query!(
        r#"SELECT ea.event_id, t.tag AS "tag!"
           FROM events.event_alerts ea
           CROSS JOIN LATERAL (
               SELECT unnest(o.tags) FROM analysis.observables o WHERE o.root_id = ea.root_id
               UNION
               SELECT unnest(x.tags) FROM analysis.results x WHERE x.root_id = ea.root_id
           ) t(tag)
           WHERE ea.event_id = ANY($1)
           GROUP BY ea.event_id, t.tag
           ORDER BY ea.event_id, lower(t.tag), t.tag"#,
        ids,
    )
    .fetch_all(&mut *conn)
    .await?
    {
        alert_tags.entry(row.event_id).or_default().push(row.tag);
    }

    Ok(rows
        .into_iter()
        .map(|row| {
            let alerts = alerts.remove(&row.id).unwrap_or_default();
            let disposition = rolled_up(alerts.iter().map(|a| a.disposition.as_deref()));
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

async fn one_event(conn: &mut PgConnection, id: i64) -> Result<Event, ServiceError> {
    load_events(conn, &[id])
        .await?
        .pop()
        .ok_or_else(|| no_event(EventRef::Id(id)))
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
                    let events = load_events(tx.conn(), &ids).await?;
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
                    let mut events = load_events(tx.conn(), &ids).await?;
                    events.sort_by_key(|event| ids.iter().position(|id| *id == event.id));
                    Ok(EventPage { events, next })
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
                    let event = one_event(tx.conn(), id).await?;
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
                    one_event(tx.conn(), id).await
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
                Box::pin(async move { load_events(tx.conn(), ids).await })
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
                        return Ok(Audited::unchanged(one_event(tx.conn(), id).await?));
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
                    Ok(Audited::changed(one_event(tx.conn(), id).await?, change))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_rolls_its_alerts_dispositions_up_as_ace3_does() {
        assert_eq!(rolled_up([]), "DELIVERY", "no alerts");
        assert_eq!(rolled_up([None, Some("OPEN")]), "OPEN");
        assert_eq!(rolled_up([Some("IGNORE")]), "IGNORE");
        assert_eq!(
            rolled_up([Some("DAMAGE"), Some("FALSE_POSITIVE"), None]),
            "DAMAGE"
        );
        assert_eq!(
            rolled_up([Some("GRAYWARE"), Some("SIMULATED"), Some("REVIEWED")]),
            "GRAYWARE"
        );
        assert_eq!(rolled_up([Some("SITE_OWN")]), "OPEN", "no rank never wins");
        assert_eq!(rolled_up([Some("SITE_OWN"), Some("IGNORE")]), "IGNORE");
    }

    #[test]
    fn an_event_is_named_by_its_id_or_its_uuid() {
        assert_eq!(EventRef::parse("42").expect("an id"), EventRef::Id(42));
        let uuid = Uuid::from_u128(7);
        assert_eq!(
            EventRef::parse(&uuid.to_string()).expect("a uuid"),
            EventRef::Uuid(uuid)
        );
        // ace3's warning: a uuid starting with digits isn't an id
        assert!(matches!(
            EventRef::parse("443c2e1a-719b-4f5d"),
            Err(ServiceError::InvalidRequest(_))
        ));
        assert!(matches!(
            EventRef::parse("99999999999999999999"),
            Err(ServiceError::NotFound(_))
        ));
        assert!(matches!(
            EventRef::parse(""),
            Err(ServiceError::InvalidRequest(_))
        ));
    }

    #[test]
    fn a_threat_type_name_is_checked() {
        assert!(threat_type_name("ransomware").is_ok());
        assert!(threat_type_name(&"x".repeat(MAX_THREAT_TYPE_CHARS)).is_ok());
        for bad in [
            "",
            "  ",
            "a\nb",
            "a\0b",
            &"x".repeat(MAX_THREAT_TYPE_CHARS + 1),
        ] {
            assert!(threat_type_name(bad).is_err(), "{bad:?}");
        }
    }
}
