//! `/api/events/v1`: events, their status and export, the threat types and malware's threats
//! (`ace_service`'s `events` docs). Reading needs `event:read` and writing `event:write`, as in ace3. An
//! event's names, comment and tags are an analyst's text and its alerts' titles a sender's: show them as
//! text.
//!
//! ace3's `events`, `threat_types` and `threats` routers (PLAN.md 5.6, 5.11):
//!
//! | ace3 `/api/v2` | here, under `/api/events/v1` |
//! |---|---|
//! | `GET /events/open` | `GET /events/open?after=&limit=`, in id order, a page at a time |
//! | `GET /events/{event_ref}`, an id or a uuid | `GET /events/{event}`, the same |
//! | `PATCH /events/{event_id}`, `{status}` | `PUT /events/{event}/status`, `{status}`, audited |
//! | `GET /events/export?checked_events[]=&type=csv` | `GET /events/export/csv?ids=`, ids separated by commas |
//! | `GET`, `POST /threat-types/` | `GET`, `POST /threat-types`, the write audited |
//! | `GET`, `PATCH`, `DELETE /threat-types/{id}` | `GET`, `PATCH`, `DELETE /threat-types/{id}`, the writes audited |
//! | `GET /threats/?malware_id=` | `GET /threats?malware=` |
//! | `POST /threats/`, `{malware_id, threat_type_id}` | `POST /threats`, the same body, audited |
//! | `DELETE /threats/?malware_id=&threat_type_id=` | `DELETE /threats/{malware}/{threat_type}`, audited |
//!
//! What differs, or is left out, and why:
//! - An event's body is ace-rs's own (decision 7): `type` for ace3's event type, `owner` with the user's
//!   id, username and display name, `malware` as `[{id, name, threat_types}]` where ace3 gives
//!   `[{name: [types]}]`, and `alerts` with each alert's own state in place of ace3's `alerts`,
//!   `alert_versions` and `alert_details`. ace3's `companies`, `wiki` and an alert's owner aren't there,
//!   since ace-rs has no companies, wiki or alert owners, and no version token.
//! - The open list is paged, up to 1000 events at a time, where ace3's isn't.
//! - The export takes up to 1000 ids, as `ids=1,2,3`, which axum's query reader takes, where ace3 repeats
//!   `checked_events[]` and takes any number. It has ace3's columns in ace3's order, with times in RFC 3339
//!   and a cell that a spreadsheet would run as a formula guarded (`export`'s docs). `owner` is the
//!   owner's username, `MONTH(events.alert_time)` the month's short name, as ace3's `%b`.
//! - A status change is `PUT .../status`, as an alert's disposition is `PUT .../disposition`, and the
//!   status it has changes nothing. ace3's 404 for an unknown event and 400 for an unknown status stay.
//! - ace3's 60-second cache of the threat types and its `Cache-Control`: the list is one small query.
//! - A rename's `name` is required, where ace3's `PATCH` takes a body with none and changes nothing.
//! - A threat naming malware or a threat type that isn't there is a 404 and one that exists a 409, where
//!   ace3's database answers 500. Each threat also has its malware's and its type's names.
//! - Nothing here makes an event or adds alerts to one, as ace3's router doesn't: that's the GUI's (5.11's
//!   6b), as in ace3.

use ace_service::{Event, EventAlert, EventRef, Threat, ThreatType};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{ExportRow, Format, respond, time_cell};

/// The user who owns an event, as they're called now.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EventOwnerBody {
    id: Uuid,
    username: String,
    display_name: Option<String>,
}

/// Malware recorded on an event.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EventMalwareBody {
    id: i32,
    name: String,
    /// Its threat types, by name.
    threat_types: Vec<String>,
}

/// One of an event's alerts.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EventAlertBody {
    id: Uuid,
    /// As its sender wrote it. Show it as text.
    title: String,
    alerted_at: Option<DateTime<Utc>>,
    /// Null while it's open.
    disposition: Option<String>,
    dispositioned_at: Option<DateTime<Utc>>,
    dispositioned_by: Option<ActorBody>,
    /// When it was added to the event.
    added_at: DateTime<Utc>,
}

impl From<EventAlert> for EventAlertBody {
    fn from(alert: EventAlert) -> Self {
        EventAlertBody {
            id: alert.id,
            title: alert.title,
            alerted_at: alert.alerted_at,
            disposition: alert.disposition,
            dispositioned_at: alert.dispositioned_at,
            dispositioned_by: alert.dispositioned_by.map(ActorBody::from),
            added_at: alert.added_at,
        }
    }
}

/// An event: alerts an analyst grouped as one incident, and what they recorded about it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EventBody {
    id: i64,
    uuid: Uuid,
    /// The day of its first alert, or the day it was made.
    creation_date: NaiveDate,
    name: String,
    status: String,
    remediation: String,
    /// ace3's event type, such as `phish`.
    #[serde(rename = "type")]
    kind: String,
    vector: String,
    /// ace3's GUI calls it the severity.
    risk_level: String,
    prevention_tool: String,
    /// ace3's GUI calls it the threat actor.
    campaign: Option<String>,
    comment: Option<String>,
    event_time: Option<DateTime<Utc>>,
    alert_time: Option<DateTime<Utc>>,
    ownership_time: Option<DateTime<Utc>>,
    disposition_time: Option<DateTime<Utc>>,
    contain_time: Option<DateTime<Utc>>,
    remediation_time: Option<DateTime<Utc>>,
    owner: Option<EventOwnerBody>,
    malware: Vec<EventMalwareBody>,
    /// The highest of its alerts' dispositions, OPEN while none has one, DELIVERY with no alerts.
    disposition: String,
    /// Oldest first.
    alerts: Vec<EventAlertBody>,
    /// The event's own tags.
    tags: Vec<String>,
    /// Its alerts' tags: each alert's own and those of its observables and results.
    alert_tags: Vec<String>,
    created_at: DateTime<Utc>,
}

impl From<Event> for EventBody {
    fn from(event: Event) -> Self {
        EventBody {
            id: event.id,
            uuid: event.uuid,
            creation_date: event.creation_date,
            name: event.name,
            status: event.status,
            remediation: event.remediation,
            kind: event.kind,
            vector: event.vector,
            risk_level: event.risk_level,
            prevention_tool: event.prevention_tool,
            campaign: event.campaign,
            comment: event.comment,
            event_time: event.event_time,
            alert_time: event.alert_time,
            ownership_time: event.ownership_time,
            disposition_time: event.disposition_time,
            contain_time: event.contain_time,
            remediation_time: event.remediation_time,
            owner: event.owner.map(|owner| EventOwnerBody {
                id: owner.id.0,
                username: owner.username,
                display_name: owner.display_name,
            }),
            malware: event
                .malware
                .into_iter()
                .map(|m| EventMalwareBody {
                    id: m.id,
                    name: m.name,
                    threat_types: m.threat_types,
                })
                .collect(),
            disposition: event.disposition,
            alerts: event.alerts.into_iter().map(EventAlertBody::from).collect(),
            tags: event.tags,
            alert_tags: event.alert_tags,
            created_at: event.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct EventPageBody {
    events: Vec<EventBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct OpenEventsQuery {
    /// How many, 1 to 1000; 1000 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ExportQuery {
    /// The events' ids, separated by commas, up to 1000.
    ids: String,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusRequest {
    /// One of the site's event statuses, such as `OPEN` or `CLOSED`.
    status: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ThreatTypeBody {
    id: i32,
    name: String,
}

impl From<ThreatType> for ThreatTypeBody {
    fn from(threat_type: ThreatType) -> Self {
        ThreatTypeBody {
            id: threat_type.id,
            name: threat_type.name,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ThreatTypesBody {
    threat_types: Vec<ThreatTypeBody>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThreatTypeRequest {
    /// 1 to 256 characters, not all whitespace, with no control characters.
    name: String,
}

/// One of a malware's threat types.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ThreatBody {
    malware_id: i32,
    malware_name: String,
    threat_type_id: i32,
    threat_type_name: String,
}

impl From<Threat> for ThreatBody {
    fn from(threat: Threat) -> Self {
        ThreatBody {
            malware_id: threat.malware_id,
            malware_name: threat.malware_name,
            threat_type_id: threat.threat_type_id,
            threat_type_name: threat.threat_type_name,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ThreatsBody {
    threats: Vec<ThreatBody>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ThreatsQuery {
    /// Only this malware's threats, by its id.
    malware: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThreatRequest {
    malware_id: i32,
    threat_type_id: i32,
}

/// An event as a CSV row, with ace3's columns.
#[derive(Debug, Serialize)]
struct EventRow {
    cells: Vec<String>,
}

impl ExportRow for EventRow {
    const HEADER: &'static [&'static str] = &[
        "id",
        "uuid",
        "creation_date",
        "name",
        "type",
        "vector",
        "threat_type",
        "threat_name",
        "severity",
        "prevention_tool",
        "remediation",
        "status",
        "owner",
        "comment",
        "campaign",
        "event_time",
        "alert_time",
        "ownership_time",
        "disposition_time",
        "contain_time",
        "remediation_time",
        "YEAR(events.alert_time)",
        "MONTH(events.alert_time)",
        "MAX(disposition)",
        "tags",
        "alert_tags",
    ];

    fn cells(&self) -> Vec<String> {
        self.cells.clone()
    }
}

impl From<Event> for EventRow {
    fn from(event: Event) -> Self {
        let threat_types = event.threat_types().join(", ");
        let malware = event
            .malware
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let year = event
            .alert_time
            .map(|t| t.year().to_string())
            .unwrap_or_default();
        let month = event
            .alert_time
            .map(|t| t.format("%b").to_string())
            .unwrap_or_default();
        EventRow {
            cells: vec![
                event.id.to_string(),
                event.uuid.to_string(),
                event.creation_date.to_string(),
                event.name,
                event.kind,
                event.vector,
                threat_types,
                malware,
                event.risk_level,
                event.prevention_tool,
                event.remediation,
                event.status,
                event.owner.map(|o| o.username).unwrap_or_default(),
                event.comment.unwrap_or_default(),
                event.campaign.unwrap_or_default(),
                time_cell(event.event_time),
                time_cell(event.alert_time),
                time_cell(event.ownership_time),
                time_cell(event.disposition_time),
                time_cell(event.contain_time),
                time_cell(event.remediation_time),
                year,
                month,
                event.disposition,
                event.tags.join(", "),
                event.alert_tags.join(", "),
            ],
        }
    }
}

fn event_ref(path: Result<Path<String>, PathRejection>) -> Result<EventRef, ApiError> {
    let Path(text) = path?;
    Ok(EventRef::parse(&text)?)
}

/// The events whose status is OPEN, in id order, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/events/v1/events/open",
    tag = "events",
    params(OpenEventsQuery),
    responses(
        (status = 200, description = "A page of open events", body = EventPageBody),
        (status = 400, description = "A limit out of range, or a parameter that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:read", body = ErrorBody),
    )
)]
pub(crate) async fn open(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<OpenEventsQuery>, QueryRejection>,
) -> Result<Json<EventPageBody>, ApiError> {
    let Query(query) = query?;
    let page = web
        .service
        .open_events(
            &actor,
            query.after,
            query.limit.unwrap_or(ace_service::MAX_EVENTS_PAGE),
        )
        .await?;
    Ok(Json(EventPageBody {
        events: page.events.into_iter().map(EventBody::from).collect(),
        next: page.next,
    }))
}

/// One event, by its numeric id or its uuid, with its alerts.
#[utoipa::path(
    get,
    path = "/api/events/v1/events/{event}",
    tag = "events",
    params(("event" = String, Path, description = "The event's numeric id or its uuid")),
    responses(
        (status = 200, description = "The event", body = EventBody),
        (status = 400, description = "Neither an id nor a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:read", body = ErrorBody),
        (status = 404, description = "No such event", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<EventBody>, ApiError> {
    let event = web.service.event(&actor, event_ref(path)?).await?;
    Ok(Json(EventBody::from(event)))
}

/// Sets an event's status. The status it has changes nothing.
#[utoipa::path(
    put,
    path = "/api/events/v1/events/{event}/status",
    tag = "events",
    params(("event" = String, Path, description = "The event's numeric id or its uuid")),
    request_body = StatusRequest,
    responses(
        (status = 200, description = "The event as it is now", body = EventBody),
        (status = 400, description = "Neither an id nor a uuid, a status that isn't one, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such event", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_status(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<StatusRequest>, JsonRejection>,
) -> Result<Json<EventBody>, ApiError> {
    let event = event_ref(path)?;
    let Json(body) = body?;
    let event = web
        .service
        .set_event_status(&actor, event, &body.status)
        .await?;
    Ok(Json(EventBody::from(event)))
}

/// The events with these ids as CSV, in id order, with ace3's columns. An id with no event is left out.
#[utoipa::path(
    get,
    path = "/api/events/v1/events/export/csv",
    tag = "events",
    params(ExportQuery),
    responses(
        (status = 200, description = "The events", content_type = "text/csv", body = String),
        (status = 400, description = "Ids that aren't a list of numbers", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:read", body = ErrorBody),
        (status = 413, description = "More ids than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<ExportQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query?;
    let ids = query
        .ids
        .split(',')
        .map(|id| id.trim().parse::<i64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::bad_request("ids are event ids separated by commas"))?;
    let events = web.service.events_for_export(&actor, &ids).await?;
    let rows: Vec<EventRow> = events.into_iter().map(EventRow::from).collect();
    let total = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    respond(
        Format::Csv,
        "events",
        total,
        total,
        (rows, None),
        |_: ()| async { Ok((Vec::new(), None)) },
    )
}

/// Every threat type, by name.
#[utoipa::path(
    get,
    path = "/api/events/v1/threat-types",
    tag = "events",
    responses(
        (status = 200, description = "The threat types", body = ThreatTypesBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:read", body = ErrorBody),
    )
)]
pub(crate) async fn threat_types(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<ThreatTypesBody>, ApiError> {
    let types = web.service.threat_types(&actor).await?;
    Ok(Json(ThreatTypesBody {
        threat_types: types.into_iter().map(ThreatTypeBody::from).collect(),
    }))
}

/// Adds a threat type.
#[utoipa::path(
    post,
    path = "/api/events/v1/threat-types",
    tag = "events",
    request_body = ThreatTypeRequest,
    responses(
        (status = 201, description = "The threat type", body = ThreatTypeBody),
        (status = 400, description = "A name that isn't one, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:write, or a session's request came from another site", body = ErrorBody),
        (status = 409, description = "A threat type has that name", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn create_threat_type(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<ThreatTypeRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ThreatTypeBody>), ApiError> {
    let Json(body) = body?;
    let made = web.service.create_threat_type(&actor, &body.name).await?;
    Ok((StatusCode::CREATED, Json(ThreatTypeBody::from(made))))
}

/// One threat type.
#[utoipa::path(
    get,
    path = "/api/events/v1/threat-types/{id}",
    tag = "events",
    params(("id" = i32, Path, description = "The threat type's id")),
    responses(
        (status = 200, description = "The threat type", body = ThreatTypeBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:read", body = ErrorBody),
        (status = 404, description = "No such threat type", body = ErrorBody),
    )
)]
pub(crate) async fn threat_type(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i32>, PathRejection>,
) -> Result<Json<ThreatTypeBody>, ApiError> {
    let Path(id) = id?;
    let found = web.service.threat_type(&actor, id).await?;
    Ok(Json(ThreatTypeBody::from(found)))
}

/// Renames a threat type. The name it has changes nothing.
#[utoipa::path(
    patch,
    path = "/api/events/v1/threat-types/{id}",
    tag = "events",
    params(("id" = i32, Path, description = "The threat type's id")),
    request_body = ThreatTypeRequest,
    responses(
        (status = 200, description = "The threat type as it is now", body = ThreatTypeBody),
        (status = 400, description = "An id or a name that isn't one, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such threat type", body = ErrorBody),
        (status = 409, description = "Another threat type has that name", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn rename_threat_type(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i32>, PathRejection>,
    body: Result<Json<ThreatTypeRequest>, JsonRejection>,
) -> Result<Json<ThreatTypeBody>, ApiError> {
    let Path(id) = id?;
    let Json(body) = body?;
    let renamed = web
        .service
        .rename_threat_type(&actor, id, &body.name)
        .await?;
    Ok(Json(ThreatTypeBody::from(renamed)))
}

/// Deletes a threat type that no malware has.
#[utoipa::path(
    delete,
    path = "/api/events/v1/threat-types/{id}",
    tag = "events",
    params(("id" = i32, Path, description = "The threat type's id")),
    responses(
        (status = 204, description = "The threat type is gone"),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such threat type", body = ErrorBody),
        (status = 409, description = "Malware has the threat type", body = ErrorBody),
    )
)]
pub(crate) async fn delete_threat_type(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i32>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    web.service.delete_threat_type(&actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The threats, by malware name, or one malware's.
#[utoipa::path(
    get,
    path = "/api/events/v1/threats",
    tag = "events",
    params(ThreatsQuery),
    responses(
        (status = 200, description = "The threats", body = ThreatsBody),
        (status = 400, description = "A malware id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:read", body = ErrorBody),
    )
)]
pub(crate) async fn threats(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    query: Result<Query<ThreatsQuery>, QueryRejection>,
) -> Result<Json<ThreatsBody>, ApiError> {
    let Query(query) = query?;
    let threats = web.service.threats(&actor, query.malware).await?;
    Ok(Json(ThreatsBody {
        threats: threats.into_iter().map(ThreatBody::from).collect(),
    }))
}

/// Gives malware a threat type.
#[utoipa::path(
    post,
    path = "/api/events/v1/threats",
    tag = "events",
    request_body = ThreatRequest,
    responses(
        (status = 201, description = "The threat", body = ThreatBody),
        (status = 400, description = "A body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such malware or threat type", body = ErrorBody),
        (status = 409, description = "The malware has that threat type already", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn add_threat(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<ThreatRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ThreatBody>), ApiError> {
    let Json(body) = body?;
    let threat = web
        .service
        .add_threat(&actor, body.malware_id, body.threat_type_id)
        .await?;
    Ok((StatusCode::CREATED, Json(ThreatBody::from(threat))))
}

/// Takes a threat type from malware.
#[utoipa::path(
    delete,
    path = "/api/events/v1/threats/{malware}/{threat_type}",
    tag = "events",
    params(
        ("malware" = i32, Path, description = "The malware's id"),
        ("threat_type" = i32, Path, description = "The threat type's id"),
    ),
    responses(
        (status = 204, description = "The malware no longer has the threat type"),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold event:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "The malware doesn't have that threat type", body = ErrorBody),
    )
)]
pub(crate) async fn remove_threat(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    ids: Result<Path<(i32, i32)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path((malware, threat_type)) = ids?;
    web.service
        .remove_threat(&actor, malware, threat_type)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
