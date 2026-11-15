//! `/api/alerts/v1`: the alert list with its filters, sorts and exports, one alert, its observables, its
//! relationship graph, a file's download, the disposition and the owner, and the site's dispositions.
//!
//! `PUT /api/alerts/v1/owner` is ace3's `PUT /api/v2/alerts/owner` (PLAN.md 7.17): take, assign or
//! unassign alerts, leaving alone those another analyst owns unless `take_owned` confirms taking them.
//! ace3's `owner_id` and `alert_uuids` are `owner` and `alerts` here, ids are uuids, and `skipped` says
//! each owner's id beside their name, since a confirmation names the id. An alert's owner is on the alert
//! itself (`owner`, `owner_name`, `owned_at`), where ace3's page polls `GET /alerts/{uuid}/meta` for it.
//! `PUT .../disposition` takes `take_from`, the same confirmation for one alert, which ace3's API has no
//! route for: its GUI's forms carry it.
//!
//! `GET /api/alerts/v1/dispositions` has no ace3 route: ace3's clients read `dispositions:` from its
//! config. It's the site's set in order with each disposition's metadata (the owner's decision of
//! 2026-11-14), under `alert:read`.

use std::io::{Seek, SeekFrom};

use ace_core::bucket::ALERT_FILES;
use ace_results::Sha256;
use ace_service::filters::{FilterScreen, decode};
use ace_service::{
    Actor, AlertDetection, AlertFile, AlertGraph, AlertObservable, AlertQuery, AlertSort,
    AlertSummary, AnalysisState, GraphEdge, GraphNode, ModuleResult, RecordedActor, Relationship,
};
use axum::Json;
use axum::body::Body;
use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::params::Params;

/// The password of a download's zip, as ace3's. It's there so that a scanner on the analyst's machine
/// leaves the file alone, not to keep it secret.
pub(crate) const ZIP_PASSWORD: &str = "infected";

/// A download's bytes, as the document shows them.
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
#[allow(dead_code)]
pub(crate) struct ZipBody(Vec<u8>);

/// Who did something, as the row recorded them then.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ActorBody {
    /// `user`, `api_key` or `internal`.
    kind: String,
    id: String,
    /// The user's or key's name at the time. An internal component's id is its name.
    name: Option<String>,
}

impl ActorBody {
    /// Its name, or its id when it has none, as a cell of an export.
    pub(crate) fn shown(&self) -> String {
        self.name.clone().unwrap_or_else(|| self.id.clone())
    }
}

impl From<RecordedActor> for ActorBody {
    fn from(actor: RecordedActor) -> Self {
        ActorBody {
            kind: actor.kind,
            id: actor.id,
            name: actor.name,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AnalysisBody {
    /// Tasks are queued or running.
    Running,
    /// The current pass completed.
    Complete,
    /// Analysis was cancelled and hasn't started again.
    Cancelled,
}

/// An alert: a root that a detection made worth an analyst's time.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertBody {
    id: Uuid,
    /// The submission's description, as its sender wrote it. Show it as text.
    pub(crate) title: String,
    analysis_mode: String,
    event_time: Option<DateTime<Utc>>,
    /// `event`, `query_time`, `now` or `unset`: where `event_time` came from.
    event_time_source: String,
    created_at: DateTime<Utc>,
    /// When a detection made the root an alert.
    alerted_at: DateTime<Utc>,
    pub(crate) disposition: Option<String>,
    dispositioned_at: Option<DateTime<Utc>>,
    dispositioned_by: Option<ActorBody>,
    submitted_by: Option<ActorBody>,
    analysis: AnalysisBody,
    /// The queue it's in. Show it as text.
    pub(crate) queue: String,
    /// The tags the core gave it: SVS's `svs_test`, `svs:marker_mismatch` and `svs:maintenance`.
    tags: Vec<String>,
    /// What SVS makes of it: `test` (every detection attributed to a test run, one by a marker), `test?`
    /// (every detection, by context alone), `partial` (some) or `mismatch` (a marker that doesn't agree
    /// with its run); null when SVS never touched it.
    pub(crate) svs_status: Option<String>,
    /// The test runs it's attributed to, oldest first: `GET /api/svs/v1/runs/{run_id}`.
    svs_runs: Vec<Uuid>,
    /// The analyst who took it; null when nobody owns it. What a confirmation to take it names.
    owner: Option<Uuid>,
    /// What the owner is called: their display name, or their username. Show it as text.
    pub(crate) owner_name: Option<String>,
    /// When they took it.
    owned_at: Option<DateTime<Utc>>,
}

impl From<AlertSummary> for AlertBody {
    fn from(alert: AlertSummary) -> Self {
        let (svs_status, svs_runs) = match alert.svs {
            Some(svs) => (Some(svs.status.as_str().to_owned()), svs.runs),
            None => (None, Vec::new()),
        };
        let (owner, owner_name) = match alert.owner {
            Some(owner) => (Some(owner.id.0), Some(owner.name)),
            None => (None, None),
        };
        AlertBody {
            owner,
            owner_name,
            owned_at: alert.owned_at,
            tags: alert.tags,
            svs_status,
            svs_runs,
            id: alert.id,
            title: alert.title,
            analysis_mode: alert.analysis_mode,
            event_time: alert.event_time,
            event_time_source: alert.event_time_source,
            created_at: alert.created_at,
            alerted_at: alert.alerted_at,
            disposition: alert.disposition,
            dispositioned_at: alert.dispositioned_at,
            dispositioned_by: alert.dispositioned_by.map(ActorBody::from),
            submitted_by: alert.submitted_by.map(ActorBody::from),
            analysis: match alert.analysis {
                AnalysisState::Running => AnalysisBody::Running,
                AnalysisState::Complete => AnalysisBody::Complete,
                AnalysisState::Cancelled => AnalysisBody::Cancelled,
            },
            queue: alert.queue,
        }
    }
}

impl ExportRow for AlertBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "title",
        "analysis_mode",
        "event_time",
        "event_time_source",
        "created_at",
        "alerted_at",
        "disposition",
        "dispositioned_at",
        "dispositioned_by",
        "submitted_by",
        "analysis",
        "queue",
        "tags",
        "svs_status",
        "svs_runs",
        "owner",
        "owned_at",
    ];

    fn cells(&self) -> Vec<String> {
        let actor = |actor: &Option<ActorBody>| {
            actor
                .as_ref()
                .map(|actor| actor.name.clone().unwrap_or_else(|| actor.id.clone()))
                .unwrap_or_default()
        };
        vec![
            self.id.to_string(),
            self.title.clone(),
            self.analysis_mode.clone(),
            time_cell(self.event_time),
            self.event_time_source.clone(),
            time_cell(Some(self.created_at)),
            time_cell(Some(self.alerted_at)),
            self.disposition.clone().unwrap_or_default(),
            time_cell(self.dispositioned_at),
            actor(&self.dispositioned_by),
            actor(&self.submitted_by),
            match self.analysis {
                AnalysisBody::Running => "running",
                AnalysisBody::Complete => "complete",
                AnalysisBody::Cancelled => "cancelled",
            }
            .to_owned(),
            self.queue.clone(),
            self.tags.join(" "),
            self.svs_status.clone().unwrap_or_default(),
            self.svs_runs
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            self.owner_name.clone().unwrap_or_default(),
            time_cell(self.owned_at),
        ]
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertPageBody {
    alerts: Vec<AlertBody>,
    /// Pass as `after` for the next page, with the same filters and order; null on the last.
    next: Option<String>,
    /// How many alerts the filters match in all.
    total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AlertDetailBody {
    alert: AlertBody,
    observables: i64,
    files: i64,
    detections: i64,
}

/// The alert list's parameters, which its exports share but for `limit` and `after`. The handler reads
/// them from the query itself, since `f` repeats.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct AlertsQuery {
    /// A filter in the share-link encoding, `[!]<slug>:<value>,<value>`, with the alert screen's slugs
    /// (`GET /api/filters/v1/screens/alerts`); repeat it for more. Filters are ANDed, the values of one
    /// ORed, and `!` inverts one.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// `alert_date`, the default, `description`, `disposition`, `queue` or `owner`.
    sort: Option<String>,
    /// `desc`, the default, or `asc`.
    dir: Option<String>,
    /// The IANA timezone relative date filters (`-7d`, `@d`) resolve in; UTC when left out.
    tz: Option<String>,
    /// How many alerts, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<String>,
}

/// The export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct AlertExportQuery {
    /// A filter, as the list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// `alert_date`, the default, `description`, `disposition`, `queue` or `owner`.
    sort: Option<String>,
    /// `desc`, the default, or `asc`.
    dir: Option<String>,
    /// The IANA timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
}

/// The list's query from its parameters.
fn alert_query(params: &Params) -> Result<AlertQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::Alerts, &params.all("f"), true)?;
    let sort = match params.one("sort")? {
        None => AlertSort::default(),
        Some(name) => AlertSort::named(name).ok_or_else(|| {
            ApiError::bad_request(format!(
                "sort is alert_date, description, disposition, queue or owner, not {name:?}"
            ))
        })?,
    };
    let descending = match params.one("dir")? {
        None | Some("desc") => true,
        Some("asc") => false,
        Some(other) => {
            return Err(ApiError::bad_request(format!(
                "dir is asc or desc, not {other:?}"
            )));
        }
    };
    Ok(AlertQuery {
        filters,
        sort,
        descending,
        tz: params.tz()?,
    })
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ObservablesQuery {
    /// How many observables, 1 to 500; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct FileBody {
    /// The file's path in the alert, such as `email.rfc822.parts/invoice.zip`.
    path: String,
    yara_meta: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RelationshipBody {
    kind: String,
    target_type: String,
    target_value: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ResultBody {
    module: String,
    analysis_type: String,
    schema_version: i32,
    summary: Option<String>,
    tags: Vec<String>,
    /// The result's details, as the analysis type's JSON Schema (`ace schema export`) says.
    details: Value,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DetectionBody {
    description: String,
    details: Option<Value>,
    /// The module whose result raised it.
    module: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RedirectionBody {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

/// An observable of an alert and everything recorded about it.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ObservableBody {
    /// The observable's id in this alert, for `after` and for its file.
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    /// A file's value is its sha256.
    value: String,
    time: Option<DateTime<Utc>>,
    tags: Vec<String>,
    directives: Vec<String>,
    exclude_modules: Vec<String>,
    /// The observable an analyst should look at instead.
    redirection: Option<RedirectionBody>,
    /// The label a module gave it in place of its type's name, such as `Source IP`, or null.
    display_type: Option<String>,
    files: Vec<FileBody>,
    relationships: Vec<RelationshipBody>,
    results: Vec<ResultBody>,
    detections: Vec<DetectionBody>,
}

impl From<AlertObservable> for ObservableBody {
    fn from(observable: AlertObservable) -> Self {
        ObservableBody {
            id: observable.id,
            kind: observable.kind,
            value: observable.value,
            time: observable.time,
            tags: observable.tags,
            directives: observable.directives,
            exclude_modules: observable.exclude_modules,
            redirection: observable
                .redirection
                .map(|(kind, value)| RedirectionBody { kind, value }),
            display_type: observable.display_type,
            files: observable
                .files
                .into_iter()
                .map(|AlertFile { path, yara_meta }| FileBody { path, yara_meta })
                .collect(),
            relationships: observable
                .relationships
                .into_iter()
                .map(
                    |Relationship {
                         kind,
                         target_type,
                         target_value,
                     }| RelationshipBody {
                        kind,
                        target_type,
                        target_value,
                    },
                )
                .collect(),
            results: observable
                .results
                .into_iter()
                .map(|result: ModuleResult| ResultBody {
                    module: result.module,
                    analysis_type: result.analysis_type,
                    schema_version: result.schema_version,
                    summary: result.summary,
                    tags: result.tags,
                    details: result.details,
                    created_at: result.created_at,
                })
                .collect(),
            detections: observable
                .detections
                .into_iter()
                .map(
                    |AlertDetection {
                         description,
                         details,
                         module,
                     }| DetectionBody {
                        description,
                        details,
                        module,
                    },
                )
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ObservablePageBody {
    observables: Vec<ObservableBody>,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DispositionRequest {
    /// One of the site's dispositions, such as `FALSE_POSITIVE`. The set is the site overlay's
    /// `dispositions` over ace3's, so it's a string here, not an enum; `GET /api/filters/v1/screens/alerts`
    /// lists it as the `Disposition` filter's options. An analyst's must be one an analyst may choose.
    disposition: String,
    /// The analyst the caller agrees to take the alert from: its `owner`, as the caller last read it. An
    /// alert another analyst owns is changed only with it, and the caller then owns the alert.
    #[serde(default)]
    take_from: Option<Uuid>,
}

/// An owner that's required and may be null, so leaving it out never quietly unassigns.
fn required_owner<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Uuid>, D::Error> {
    Option::<Uuid>::deserialize(deserializer)
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerRequest {
    /// The alerts, 1 to 500. One that names no alert is left out of the answer.
    alerts: Vec<Uuid>,
    /// The user who gets the alerts: the caller's own id takes them, another user's assigns them, and
    /// null unassigns them. It has to be there.
    #[serde(deserialize_with = "required_owner")]
    #[schema(required = true)]
    owner: Option<Uuid>,
    /// Per alert, the analyst the caller agrees to take it from: its `owner`, as the caller last read it.
    /// An alert another analyst owns is changed only when it's named here with that analyst; otherwise it's
    /// left alone and listed in `skipped`.
    #[serde(default)]
    take_owned: std::collections::BTreeMap<Uuid, Uuid>,
}

/// The analyst an alert was left with.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SkippedOwnerBody {
    /// Their id, which `take_owned` names to take the alert from them.
    owner: Uuid,
    /// What they're called. Show it as text.
    name: String,
}

/// What a change of owner did.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct OwnerChangeBody {
    /// The alerts that now have the owner asked for, in the order asked for.
    applied: Vec<Uuid>,
    /// The alerts left alone, each with the analyst who owns it.
    skipped: std::collections::BTreeMap<Uuid, SkippedOwnerBody>,
    /// What to tell a person when alerts were skipped, such as `took ownership of 1 alerts; left 1 alert
    /// owned by Jane alone`; null otherwise.
    message: Option<String>,
}

/// Sets the owner of the alerts: the caller takes them when `owner` is their own id, assigns them to
/// someone else otherwise, and unassigns them when it's null. An alert another analyst owns is left alone
/// unless `take_owned` confirms taking it from them; one whose owner's account is disabled changes hands
/// with no confirmation. The caller is a user, or an API key that belongs to one. Each alert that changes
/// has an audit row.
#[utoipa::path(
    put,
    path = "/api/alerts/v1/owner",
    tag = "alerts",
    request_body = OwnerRequest,
    responses(
        (status = 200, description = "The alerts that changed and those left alone", body = OwnerChangeBody),
        (status = 400, description = "No alerts or more than 500, a new owner who doesn't exist or is disabled, a caller that isn't a user, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn owner(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<OwnerRequest>, JsonRejection>,
) -> Result<Json<OwnerChangeBody>, ApiError> {
    let Json(body) = body?;
    let confirmed = body
        .take_owned
        .into_iter()
        .map(|(alert, owner)| (alert, ace_service::UserId(owner)))
        .collect();
    let changed = web
        .service
        .change_alert_owner(
            &actor,
            &body.alerts,
            body.owner.map(ace_service::UserId),
            &confirmed,
        )
        .await?;
    Ok(Json(OwnerChangeBody {
        applied: changed.applied,
        skipped: changed
            .skipped
            .into_iter()
            .map(|skipped| {
                (
                    skipped.alert,
                    SkippedOwnerBody {
                        owner: skipped.owner.0,
                        name: skipped.name,
                    },
                )
            })
            .collect(),
        message: changed.message,
    }))
}

/// What the disposition did to the alert's analysis.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DispositionedBody {
    /// Queued and delayed tasks it cancelled.
    cancelled: usize,
    /// Running tasks it asked to stop.
    stopped: usize,
    /// The dispositioned mode's tasks it queued.
    queued: usize,
}

/// The alerts the filters match, newest first or in the order asked, a page at a time, with how many
/// match in all. Follow `next` until it's null, with the same filters and order: each order breaks ties by
/// the alert's id, so an alert that arrives meanwhile never shifts a later page.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts",
    tag = "alerts",
    params(AlertsQuery),
    responses(
        (status = 200, description = "A page of alerts", body = AlertPageBody),
        (status = 400, description = "A filter, order, timezone or limit that isn't one, a cursor of another order or that names no alert, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<AlertPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = alert_query(&params)?;
    let limit = params.parsed("limit", "a number from 1 to 1000")?;
    let page = web
        .service
        .alerts(&actor, &query, limit, params.one("after")?)
        .await?;
    Ok(Json(AlertPageBody {
        alerts: page.alerts.into_iter().map(AlertBody::from).collect(),
        next: page.next,
        total: page.total,
    }))
}

async fn export_alerts(
    format: Format,
    actor: Actor,
    web: Web,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let query = alert_query(&params)?;
    let first = service
        .alerts(&actor, &query, Some(EXPORT_PAGE), None)
        .await?;
    let total = first.total;
    let first = (
        first.alerts.into_iter().map(AlertBody::from).collect(),
        first.next,
    );
    export::respond(
        format,
        "alerts",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .alerts(&actor, &query, Some(EXPORT_PAGE), Some(&cursor))
                    .await?;
                Ok((
                    page.alerts.into_iter().map(AlertBody::from).collect(),
                    page.next,
                ))
            }
        },
    )
}

/// Every alert the list's filters match, in its order, as CSV: a header line, then a row per alert, with a
/// cell that a spreadsheet would read as a formula behind a `'`. A failure part-way ends the file there.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/export/csv",
    tag = "alerts",
    params(AlertExportQuery),
    responses(
        (status = 200, description = "The alerts", content_type = "text/csv", body = String),
        (status = 400, description = "A filter, order or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 413, description = "More alerts than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_alerts(Format::Csv, actor, web, raw).await
}

/// Every alert the list's filters match, in its order, as NDJSON: an alert as the list gives it on each
/// line. A failure part-way ends it with an `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/export/ndjson",
    tag = "alerts",
    params(AlertExportQuery),
    responses(
        (status = 200, description = "The alerts", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A filter, order or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 413, description = "More alerts than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_alerts(Format::Ndjson, actor, web, raw).await
}

/// One alert, with how many observables, files and detections it holds.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    responses(
        (status = 200, description = "The alert", body = AlertDetailBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<AlertDetailBody>, ApiError> {
    let Path(id) = id?;
    let alert = web.service.alert(&actor, id).await?;
    Ok(Json(AlertDetailBody {
        alert: alert.summary.into(),
        observables: alert.observables,
        files: alert.files,
        detections: alert.detections,
    }))
}

/// An alert's observables in the order they were added, each with its files, relationships, results
/// and detections, a page at a time.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/observables",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id"), ObservablesQuery),
    responses(
        (status = 200, description = "A page of observables", body = ObservablePageBody),
        (status = 400, description = "A limit out of range, or an id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn observables(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    query: Result<Query<ObservablesQuery>, QueryRejection>,
) -> Result<Json<ObservablePageBody>, ApiError> {
    let (Path(id), Query(query)) = (id?, query?);
    let page = web
        .service
        .alert_observables(&actor, id, query.limit, query.after)
        .await?;
    Ok(Json(ObservablePageBody {
        observables: page
            .observables
            .into_iter()
            .map(ObservableBody::from)
            .collect(),
        next: page.next,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphNodeKindBody {
    Alert,
    Observable,
    Result,
    Tag,
}

/// A node of the graph.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GraphNodeBody {
    /// `alert`, `o<id>`, `r<id>` or `t<n>`, unique in the graph, which its edges name.
    id: String,
    kind: GraphNodeKindBody,
    /// The alert's title, an observable's type and value, a result's module or a tag, at most 80
    /// characters. It's the alert's text: show it as text.
    label: String,
    /// An observable's id in the alert, as `/observables` gives it.
    observable: Option<i64>,
    /// A result's id in the alert.
    result: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GraphEdgeKindBody {
    /// The alert to an observable its submission added.
    Observed,
    /// An observable to a result of it.
    Analyzed,
    /// A result to an observable it added.
    Added,
    /// An observable or result to its tag.
    Tagged,
    /// An observable to the observable a relationship of it names.
    Related,
}

/// An edge of the graph, between two of its nodes.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GraphEdgeBody {
    from: String,
    to: String,
    kind: GraphEdgeKindBody,
    /// A `related` edge's relationship, such as `extracted_from`.
    relationship: Option<String>,
}

/// An alert's relationship graph.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct GraphBody {
    alert: Uuid,
    nodes: Vec<GraphNodeBody>,
    edges: Vec<GraphEdgeBody>,
    /// Whether the graph was cut short: it holds at most 1000 nodes and 2000 edges, nearest the alert
    /// first, from a tree of at most 5000 observables.
    truncated: bool,
    /// What was left out, when anything was.
    note: Option<String>,
}

impl From<AlertGraph> for GraphBody {
    fn from(graph: AlertGraph) -> Self {
        use ace_service::{GraphEdgeKind, GraphNodeKind};
        GraphBody {
            alert: graph.alert,
            nodes: graph
                .nodes
                .into_iter()
                .map(|node: GraphNode| GraphNodeBody {
                    id: node.id,
                    kind: match node.kind {
                        GraphNodeKind::Alert => GraphNodeKindBody::Alert,
                        GraphNodeKind::Observable => GraphNodeKindBody::Observable,
                        GraphNodeKind::Result => GraphNodeKindBody::Result,
                        GraphNodeKind::Tag => GraphNodeKindBody::Tag,
                    },
                    label: node.label,
                    observable: node.observable,
                    result: node.result,
                })
                .collect(),
            edges: graph
                .edges
                .into_iter()
                .map(|edge: GraphEdge| GraphEdgeBody {
                    from: edge.from,
                    to: edge.to,
                    kind: match edge.kind {
                        GraphEdgeKind::Observed => GraphEdgeKindBody::Observed,
                        GraphEdgeKind::Analyzed => GraphEdgeKindBody::Analyzed,
                        GraphEdgeKind::Added => GraphEdgeKindBody::Added,
                        GraphEdgeKind::Tagged => GraphEdgeKindBody::Tagged,
                        GraphEdgeKind::Related => GraphEdgeKindBody::Related,
                    },
                    relationship: edge.relationship,
                })
                .collect(),
            truncated: graph.truncated,
            note: graph.note,
        }
    }
}

/// An alert's relationship graph, which the GUI's graph page draws: a node for the alert, each
/// observable, each result and each tag, and an edge for each observable the submission or a result
/// added, each result of an observable, each tag and each relationship between two of the alert's
/// observables. It's read from one snapshot of the alert's tree, and bounded, saying so when it was cut.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/graph",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    responses(
        (status = 200, description = "The graph", body = GraphBody),
        (status = 400, description = "An id that isn't a uuid", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert", body = ErrorBody),
    )
)]
pub(crate) async fn graph(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
) -> Result<Json<GraphBody>, ApiError> {
    let Path(id) = id?;
    Ok(Json(web.service.alert_graph(&actor, id).await?.into()))
}

/// A file observable's bytes, as a zip encrypted with AES-256 and the password `infected`, as ace3's
/// downloads are, holding the file under its name in the alert. The download is in the audit record.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/alerts/{id}/observables/{observable}/file",
    tag = "alerts",
    params(
        ("id" = Uuid, Path, description = "The alert's id"),
        ("observable" = i64, Path, description = "The file observable's id in the alert"),
    ),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "An observable that isn't a file, or an id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
        (status = 404, description = "No such alert or observable", body = ErrorBody),
    )
)]
pub(crate) async fn file(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    ids: Result<Path<(Uuid, i64)>, PathRejection>,
) -> Result<Response, ApiError> {
    let Path((id, observable)) = ids?;
    let download = web.service.download_file(&actor, id, observable).await?;
    let sha256: Sha256 = download.sha256.parse().map_err(ApiError::internal)?;
    let cached = web
        .bucket
        .get(ALERT_FILES, &sha256)
        .await
        .map_err(ApiError::internal)?;
    let name = download
        .path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("file")
        .to_owned();
    let mut source = cached.file;
    let zipped = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        let out = tempfile::tempfile()?;
        let mut zip = zip::ZipWriter::new(out);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .large_file(cached.size >= u64::from(u32::MAX))
            .with_aes_encryption(zip::AesMode::Aes256, ZIP_PASSWORD);
        zip.start_file(name, options)
            .map_err(std::io::Error::other)?;
        std::io::copy(&mut source, &mut zip)?;
        let mut out = zip.finish().map_err(std::io::Error::other)?;
        out.seek(SeekFrom::Start(0))?;
        Ok(out)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(ApiError::internal)?;
    let length = zipped.metadata().map_err(ApiError::internal)?.len();
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(
        tokio::fs::File::from_std(zipped),
    ));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/zip".to_owned()),
            (header::CONTENT_LENGTH, length.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{sha256}.zip\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        body,
    )
        .into_response())
}

/// One of the site's dispositions.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DispositionBody {
    name: String,
    /// An event's disposition is its alerts' highest ranked. OPEN is 0.
    rank: i32,
    /// The badge's class: a class token of letters, digits, `-` and `_`, such as Bootstrap's `danger`.
    css: String,
    /// Whether choosing it offers Save to Event.
    show_save_to_event: bool,
    /// False when only ACE sets it: `PUT .../disposition` refuses it from an analyst or an API key, and
    /// refuses a change to an alert that has it.
    analyst_selectable: bool,
    /// What it says about an alert's detections: `tp`, `fp`, or null for an unclassified one.
    #[schema(value_type = Option<String>)]
    class: Option<&'static str>,
}

/// The site's dispositions.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct DispositionsBody {
    /// In the site's order: ace3's, then the site's own.
    dispositions: Vec<DispositionBody>,
}

/// The site's dispositions in order, each with its rank, badge class, whether it offers Save to Event,
/// whether an analyst may choose it, and its class in the detection verdicts. An alert may still carry a
/// disposition that isn't listed, one the site has since dropped from its configuration.
#[utoipa::path(
    get,
    path = "/api/alerts/v1/dispositions",
    tag = "alerts",
    responses(
        (status = 200, description = "The site's dispositions", body = DispositionsBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:read", body = ErrorBody),
    )
)]
pub(crate) async fn dispositions(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<DispositionsBody>, ApiError> {
    let set = web.service.disposition_list(&actor).await?;
    Ok(Json(DispositionsBody {
        dispositions: set
            .all()
            .iter()
            .map(|disposition| DispositionBody {
                name: disposition.name.clone(),
                rank: disposition.rank,
                css: disposition.css.clone(),
                show_save_to_event: disposition.show_save_to_event,
                analyst_selectable: disposition.analyst_selectable,
                class: set.class(&disposition.name).map(|class| match class {
                    ace_service::DispositionClass::Tp => "tp",
                    ace_service::DispositionClass::Fp => "fp",
                }),
            })
            .collect(),
    }))
}

/// Records an analyst's verdict on the alert. Its analysis is cancelled and it moves to the
/// dispositioned mode. A later disposition replaces the earlier one and who made it. A root that no
/// detection made an alert can be dispositioned too, as the service allows. The disposition is one of
/// the site's, and one only ACE sets is refused, as is a change to an alert that has one. The caller, a
/// user or a key of one, becomes the owner of an alert nobody owns. An alert another analyst owns is left
/// alone, unless `take_from` names that analyst or their account is disabled, and is then the caller's.
#[utoipa::path(
    put,
    path = "/api/alerts/v1/alerts/{id}/disposition",
    tag = "alerts",
    params(("id" = Uuid, Path, description = "The alert's id")),
    request_body = DispositionRequest,
    responses(
        (status = 200, description = "The disposition is recorded", body = DispositionedBody),
        (status = 400, description = "Not one of the site's dispositions, one only ACE sets, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold alert:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such root", body = ErrorBody),
        (status = 409, description = "The alert's disposition is one only ACE sets, which an analyst can't change, or another analyst owns the alert and `take_from` doesn't name them", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn disposition(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<Uuid>, PathRejection>,
    body: Result<Json<DispositionRequest>, JsonRejection>,
) -> Result<Json<DispositionedBody>, ApiError> {
    let (Path(id), Json(body)) = (id?, body?);
    let done = web
        .service
        .disposition(
            &actor,
            id,
            &body.disposition,
            body.take_from.map(ace_service::UserId),
        )
        .await?;
    Ok(Json(DispositionedBody {
        cancelled: done.cancelled.cancelled.len(),
        stopped: done.cancelled.signalled.len(),
        queued: done.queued.len(),
    }))
}
