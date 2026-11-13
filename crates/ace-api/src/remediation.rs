//! `/api/remediation/v1`: remediations (PLAN.md 7.9, `ace_service`'s `remediation` docs). Reading needs
//! `remediation:read`, and queueing, stopping, retrying, restoring and deleting need `remediation:write`,
//! each write audited. A remediation is an analyst's, so a key with no owner can't queue one (403).
//! A value is returned as it was stored: show it as text.

use ace_service::filters::{FilterScreen, decode};
use ace_service::{
    ActionAttempt, ActionQuery, ActionSummary, Actor, Remediation, RemediationAction,
    RemediationTarget, TargetKey,
};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::params::Params;

/// A remediation's state, in short.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ActionSummaryBody {
    id: i64,
    /// `remove` or `restore`; null for a file collection.
    action: Option<String>,
    /// `NEW`, `IN_PROGRESS` or `COMPLETED`.
    status: String,
    /// How a completed one ended, or how its last try went, such as `SUCCESS` or `DELAYED`.
    result: Option<String>,
}

impl From<ActionSummary> for ActionSummaryBody {
    fn from(summary: ActionSummary) -> Self {
        ActionSummaryBody {
            id: summary.id,
            action: summary.action,
            status: summary.status,
            result: summary.result,
        }
    }
}

/// What a remediator acts on.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetBody {
    /// The remediator's name, such as `test`.
    remediator: String,
    observable_type: String,
    observable_value: String,
}

/// A target, with its remediator's display name and its latest remediation.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TargetReadBody {
    remediator: String,
    observable_type: String,
    observable_value: String,
    /// Null when this server has no remediator by that name.
    remediator_display_name: Option<String>,
    /// The target's latest remediation, which cancel and delete act on.
    current: Option<ActionSummaryBody>,
}

impl From<RemediationTarget> for TargetReadBody {
    fn from(target: RemediationTarget) -> Self {
        TargetReadBody {
            remediator: target.key.remediator,
            observable_type: target.key.observable_type,
            observable_value: target.key.observable_value,
            remediator_display_name: target.display_name,
            current: target.current.map(ActionSummaryBody::from),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TargetsBody {
    targets: Vec<TargetReadBody>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ObservableKeyBody {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

/// The alerts, or the observables, to find the targets of: exactly one of the two.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LookupBody {
    /// Every observable of a remediator's type in these alerts, at most 200.
    #[serde(default)]
    alerts: Vec<Uuid>,
    /// These observables, at most 1000.
    #[serde(default)]
    observables: Vec<ObservableKeyBody>,
}

/// One remediation of each target.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueueBody {
    /// `remove` or `restore`. A restore takes the restore key of the target's latest successful removal.
    #[schema(value_type = String)]
    action: RemediationAction,
    /// 1 to 1000 targets, each checked before any is queued.
    targets: Vec<TargetBody>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct QueuedBody {
    remediations: Vec<ActionSummaryBody>,
}

/// One remediation, as the list gives it. Times are UTC.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RemediationBody {
    id: i64,
    remediator: String,
    /// Null when this server has no remediator by that name.
    remediator_display_name: Option<String>,
    observable_type: String,
    observable_value: String,
    /// `remove` or `restore`.
    action: String,
    /// `NEW`, `IN_PROGRESS` or `COMPLETED`.
    status: String,
    /// How the latest try ended, such as `SUCCESS` or `DELAYED`.
    result: Option<String>,
    result_message: Option<String>,
    /// The person it's attributed to.
    analyst: Option<String>,
    /// The tries so far.
    attempts: i32,
    created_at: DateTime<Utc>,
    /// The end of the latest try, a cancel or a retry; null before the first try.
    updated_at: Option<DateTime<Utc>>,
}

impl From<Remediation> for RemediationBody {
    fn from(r: Remediation) -> Self {
        RemediationBody {
            id: r.id,
            remediator: r.remediator,
            remediator_display_name: r.display_name,
            observable_type: r.observable_type,
            observable_value: r.observable_value,
            action: r.action,
            status: r.status,
            result: r.result,
            result_message: r.result_message,
            analyst: r.analyst,
            attempts: r.attempts,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

impl ExportRow for RemediationBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "remediator",
        "observable_type",
        "observable_value",
        "action",
        "status",
        "result",
        "result_message",
        "analyst",
        "attempts",
        "created_at",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.remediator.clone(),
            self.observable_type.clone(),
            self.observable_value.clone(),
            self.action.clone(),
            self.status.clone(),
            self.result.clone().unwrap_or_default(),
            self.result_message.clone().unwrap_or_default(),
            self.analyst.clone().unwrap_or_default(),
            self.attempts.to_string(),
            time_cell(Some(self.created_at)),
            time_cell(self.updated_at),
        ]
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RemediationPageBody {
    remediations: Vec<RemediationBody>,
    /// How many the filters match, on every page.
    total: i64,
    /// Pass as `after` for the next page; null on the last.
    next: Option<i64>,
}

/// One try. Times are UTC.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct AttemptBody {
    created_at: DateTime<Utc>,
    status: String,
    result: String,
    message: String,
}

impl From<ActionAttempt> for AttemptBody {
    fn from(a: ActionAttempt) -> Self {
        AttemptBody {
            created_at: a.created_at,
            status: a.status,
            result: a.result,
            message: a.message,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct HistoryBody {
    /// Newest first.
    attempts: Vec<AttemptBody>,
}

impl HistoryBody {
    pub(crate) fn of(attempts: Vec<AttemptBody>) -> Self {
        HistoryBody { attempts }
    }
}

/// A list's parameters. The handler reads them from the query itself, since `f` repeats.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ListQuery {
    /// A filter in the share-link encoding, `[!]<slug>:<value>,<value>`, with the screen's slugs
    /// (`GET /api/filters/v1/screens/{screen}`); repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// The IANA timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    after: Option<i64>,
}

/// An export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ExportQuery {
    /// A filter, as the list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// The IANA timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
}

#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct HistoryQuery {
    /// At most this many of the latest tries, 1 to 1000; 100 when left out.
    limit: Option<u32>,
}

/// The list's query, for `screen`.
pub(crate) fn query(params: &Params, screen: FilterScreen) -> Result<ActionQuery, ApiError> {
    let (filters, _) = decode(screen, &params.all("f"), true)?;
    Ok(ActionQuery {
        filters,
        tz: params.tz()?,
    })
}

/// A history's limit.
pub(crate) fn history_limit(raw: RawQuery) -> Result<u32, ApiError> {
    Ok(Params::of(raw)?
        .parsed("limit", "a number from 1 to 1000")?
        .unwrap_or(100))
}

/// The remediation targets of the observables in these alerts, or of these observables, each with its
/// latest remediation. A POST so that a long selection fits in the body.
#[utoipa::path(
    post,
    path = "/api/remediation/v1/targets",
    tag = "remediation",
    request_body = LookupBody,
    responses(
        (status = 200, description = "The targets, by remediator, type and value", body = TargetsBody),
        (status = 400, description = "Both alerts and observables or neither, too many, a type this server hasn't, a value its type refuses, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:read", body = ErrorBody),
        (status = 404, description = "An alert that isn't one", body = ErrorBody),
        (status = 413, description = "The body is too large, or the targets too many", body = ErrorBody),
    )
)]
pub(crate) async fn targets(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<LookupBody>, JsonRejection>,
) -> Result<Json<TargetsBody>, ApiError> {
    let Json(body) = body?;
    let targets = match (body.alerts.is_empty(), body.observables.is_empty()) {
        (false, true) => {
            web.service
                .remediation_targets_of_alerts(&actor, &body.alerts)
                .await?
        }
        (true, false) => {
            let pairs: Vec<(String, String)> = body
                .observables
                .into_iter()
                .map(|o| (o.kind, o.value))
                .collect();
            web.service
                .remediation_targets_of_observables(&actor, &pairs)
                .await?
        }
        _ => {
            return Err(ApiError::bad_request("give either alerts or observables"));
        }
    };
    Ok(Json(TargetsBody {
        targets: targets.into_iter().map(TargetReadBody::from).collect(),
    }))
}

/// Remediations the filters match, newest first, a page at a time. Follow `next` until it's null.
#[utoipa::path(
    get,
    path = "/api/remediation/v1/remediations",
    tag = "remediation",
    params(ListQuery),
    responses(
        (status = 200, description = "A page of remediations", body = RemediationPageBody),
        (status = 400, description = "A filter, timezone, limit or cursor that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<RemediationPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = query(&params, FilterScreen::Remediations)?;
    let page = web
        .service
        .remediations(
            &actor,
            &query,
            params.parsed("limit", "a number from 1 to 1000")?,
            params.parsed("after", "a remediation's id")?,
        )
        .await?;
    Ok(Json(RemediationPageBody {
        remediations: page
            .remediations
            .into_iter()
            .map(RemediationBody::from)
            .collect(),
        total: page.total,
        next: page.next,
    }))
}

async fn export_remediations(
    format: Format,
    actor: Actor,
    web: Web,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let query = query(&params, FilterScreen::Remediations)?;
    let first = service
        .remediations(&actor, &query, Some(EXPORT_PAGE), None)
        .await?;
    let total = first.total;
    let first = (
        first
            .remediations
            .into_iter()
            .map(RemediationBody::from)
            .collect(),
        first.next,
    );
    export::respond(
        format,
        "remediations",
        max,
        total,
        first,
        move |after: i64| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .remediations(&actor, &query, Some(EXPORT_PAGE), Some(after))
                    .await?;
                Ok((
                    page.remediations
                        .into_iter()
                        .map(RemediationBody::from)
                        .collect(),
                    page.next,
                ))
            }
        },
    )
}

/// Every remediation the list's filters match, newest first, as CSV, a cell a spreadsheet would read as a
/// formula behind a `'`. A failure part-way ends the file there.
#[utoipa::path(
    get,
    path = "/api/remediation/v1/remediations/export/csv",
    tag = "remediation",
    params(ExportQuery),
    responses(
        (status = 200, description = "The remediations", content_type = "text/csv", body = String),
        (status = 400, description = "A filter or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:read", body = ErrorBody),
        (status = 413, description = "More remediations than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_remediations(Format::Csv, actor, web, raw).await
}

/// Every remediation the list's filters match, newest first, as NDJSON. A failure part-way ends it with an
/// `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/remediation/v1/remediations/export/ndjson",
    tag = "remediation",
    params(ExportQuery),
    responses(
        (status = 200, description = "The remediations", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A filter or timezone that isn't one, or filters that took too long", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:read", body = ErrorBody),
        (status = 413, description = "More remediations than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_remediations(Format::Ndjson, actor, web, raw).await
}

/// Queues a removal or a restore of each target, every one checked before any is queued, attributed to the
/// person asking. Audited as one write.
#[utoipa::path(
    post,
    path = "/api/remediation/v1/remediations",
    tag = "remediation",
    request_body = QueueBody,
    responses(
        (status = 201, description = "The remediations, in the targets' order", body = QueuedBody),
        (status = 400, description = "No targets or too many, a remediator this server hasn't, a type it doesn't remediate, a value its type refuses, or a body that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:write, is a key with no owner, or a session's request came from another site", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn queue(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<QueueBody>, JsonRejection>,
) -> Result<(StatusCode, Json<QueuedBody>), ApiError> {
    let Json(body) = body?;
    let targets: Vec<TargetKey> = body
        .targets
        .into_iter()
        .map(|t| TargetKey {
            remediator: t.remediator,
            observable_type: t.observable_type,
            observable_value: t.observable_value,
        })
        .collect();
    let queued = web
        .service
        .queue_remediations(&actor, body.action, &targets)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(QueuedBody {
            remediations: queued.into_iter().map(ActionSummaryBody::from).collect(),
        }),
    ))
}

/// One remediation.
#[utoipa::path(
    get,
    path = "/api/remediation/v1/remediations/{id}",
    tag = "remediation",
    params(("id" = i64, Path, description = "The remediation's id")),
    responses(
        (status = 200, description = "The remediation", body = RemediationBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:read", body = ErrorBody),
        (status = 404, description = "No such remediation", body = ErrorBody),
    )
)]
pub(crate) async fn one(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<RemediationBody>, ApiError> {
    let Path(id) = id?;
    let remediation = web.service.remediation(&actor, id).await?;
    Ok(Json(RemediationBody::from(remediation)))
}

/// Each try at a remediation, newest first.
#[utoipa::path(
    get,
    path = "/api/remediation/v1/remediations/{id}/history",
    tag = "remediation",
    params(("id" = i64, Path, description = "The remediation's id"), HistoryQuery),
    responses(
        (status = 200, description = "Its tries", body = HistoryBody),
        (status = 400, description = "An id or a limit that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:read", body = ErrorBody),
        (status = 404, description = "No such remediation", body = ErrorBody),
    )
)]
pub(crate) async fn history(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<HistoryBody>, ApiError> {
    let Path(id) = id?;
    let limit = history_limit(raw)?;
    let attempts = web.service.remediation_history(&actor, id, limit).await?;
    Ok(Json(HistoryBody::of(
        attempts.into_iter().map(AttemptBody::from).collect(),
    )))
}

/// Stops a remediation that hasn't completed; it completes `CANCELLED`. Audited.
#[utoipa::path(
    post,
    path = "/api/remediation/v1/remediations/{id}/cancel",
    tag = "remediation",
    params(("id" = i64, Path, description = "The remediation's id")),
    responses(
        (status = 200, description = "The remediation as it is now", body = ActionSummaryBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such remediation", body = ErrorBody),
        (status = 409, description = "It has completed: its result stands", body = ErrorBody),
    )
)]
pub(crate) async fn cancel(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<ActionSummaryBody>, ApiError> {
    let Path(id) = id?;
    let summary = web.service.cancel_remediation(&actor, id).await?;
    Ok(Json(ActionSummaryBody::from(summary)))
}

/// Queues a completed remediation again, as it was. Audited.
#[utoipa::path(
    post,
    path = "/api/remediation/v1/remediations/{id}/retry",
    tag = "remediation",
    params(("id" = i64, Path, description = "The remediation's id")),
    responses(
        (status = 200, description = "The remediation as it is now", body = ActionSummaryBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such remediation", body = ErrorBody),
        (status = 409, description = "It hasn't completed", body = ErrorBody),
    )
)]
pub(crate) async fn retry(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<Json<ActionSummaryBody>, ApiError> {
    let Path(id) = id?;
    let summary = web.service.retry_remediation(&actor, id).await?;
    Ok(Json(ActionSummaryBody::from(summary)))
}

/// Queues a restore of what a successful removal removed, with the restore key it gave back, attributed to
/// the person asking. Audited.
#[utoipa::path(
    post,
    path = "/api/remediation/v1/remediations/{id}/restore",
    tag = "remediation",
    params(("id" = i64, Path, description = "The removal's id")),
    responses(
        (status = 201, description = "The restore", body = ActionSummaryBody),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:write, is a key with no owner, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such remediation", body = ErrorBody),
        (status = 409, description = "It isn't a removal that succeeded", body = ErrorBody),
    )
)]
pub(crate) async fn restore(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<(StatusCode, Json<ActionSummaryBody>), ApiError> {
    let Path(id) = id?;
    let summary = web.service.restore_remediation(&actor, id).await?;
    Ok((StatusCode::CREATED, Json(ActionSummaryBody::from(summary))))
}

/// Deletes a remediation's record and its history. Its audit row keeps what it was.
#[utoipa::path(
    delete,
    path = "/api/remediation/v1/remediations/{id}",
    tag = "remediation",
    params(("id" = i64, Path, description = "The remediation's id")),
    responses(
        (status = 204, description = "It's gone"),
        (status = 400, description = "An id that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold remediation:write, or a session's request came from another site", body = ErrorBody),
        (status = 404, description = "No such remediation", body = ErrorBody),
    )
)]
pub(crate) async fn delete(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    id: Result<Path<i64>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(id) = id?;
    web.service.delete_remediation(&actor, id).await?;
    Ok(StatusCode::NO_CONTENT)
}
