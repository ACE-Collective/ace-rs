//! `/api/svs/v1/worklist`: SVS's declared-vs-measured worklist (PLAN.md 7.10 batch 8), ace3's
//! `aceapi_v2/svs/worklist` router, over `ace_service`'s `svs_worklist`. One row per (signature, ATT&CK
//! technique) for each measured signature: its `mitre:` tags, confirmed or not by the tests it is expected
//! of, and the techniques it is measured on that no tag names. Read with `svs:run_read`; a tag measurement
//! doesn't confirm is resolved keep or remove with `svs:run_manage`.
//!
//! | ace3 `/api/v2/svs/worklist` | here |
//! |---|---|
//! | `GET /?f=&changed_since=&tz=&cursor=&limit=` | `GET /api/svs/v1/worklist`, the same filters, orders and keyset paging |
//! | `GET /export/ndjson`, `GET /export/csv` | `GET /api/svs/v1/worklist/export/{format}` |
//! | `POST /bulk/resolve` | `POST /api/svs/v1/worklist/bulk/resolve`, audited |
//! | `GET /{signature_uuid}` | `GET /api/svs/v1/worklist/{signature_uuid}` |
//! | `PUT`, `DELETE /{signature_uuid}/{technique}/resolution` | the same under `/api/svs/v1/worklist`, audited |
//!
//! From ace3: a page is `{rows, next}`; a refused parameter or resolution is 400 where ace3 answers 422;
//! a 412's body is `{"error": ...}` and the client reads the row again; who resolved a row is an actor
//! (`kind`, `id`, `name`), so a key that belongs to nobody resolves too, where ace3 refuses a config key;
//! and clearing a resolution answers with the row, 200, where ace3 answers 204.

use ace_service::filters::{FilterScreen, decode};
use ace_service::{BulkResolution, SignatureWorklist, WorklistQuery, WorklistRow};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::HeaderMap;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::ActorBody;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, time_cell};
use crate::params::Params;
use crate::svs_decisions::precondition;
use crate::svs_run_reads::format_of;

fn cell(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

/// One signature's tag on, or measurement of, one ATT&CK technique, as of the last coverage refresh (the
/// resolution as of now).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct WorklistRowBody {
    signature_uuid: String,
    /// The technique in the pinned ATT&CK release (a revoked tag id counts as its successor).
    technique: String,
    /// Its name in the pinned release.
    technique_name: Option<String>,
    /// `declared` (a tag of the signature), `undeclared` (measured, but no tag names it) or `unknown` (a
    /// tag naming an id the release doesn't have).
    kind: String,
    /// `confirmed`, `open`, `kept`, `remove_pending`, `removed`, `undeclared`, `unknown` or `retired`.
    status: String,
    /// The tag ids, as the signature writes them, that count as the technique.
    declared_as: Vec<String>,
    /// The signature has the tag now.
    tag_present: bool,
    /// The signature is enabled, and isn't a YARA rule in QA mode.
    signature_counts: bool,
    /// The tag counts toward coverage as a manual mapping (from the next refresh, after a resolution).
    counts: bool,
    /// The signature is expected of a catalog test.
    measured: bool,
    /// The techniques the signature is measured on.
    measured_techniques: Vec<String>,
    signature_family: Option<String>,
    signature_name: Option<String>,
    /// `keep` or `remove`; null when nobody resolved the row.
    resolution: Option<String>,
    reason: Option<String>,
    /// A link, such as the pull request removing the tag.
    reference: Option<String>,
    /// Who resolved it.
    resolved_by: Option<ActorBody>,
    resolved_at: Option<DateTime<Utc>>,
    first_seen_at: DateTime<Utc>,
    status_changed_at: DateTime<Utc>,
    /// When the row last changed: the `changed_since` key, and what an `If-Match` names.
    updated_at: DateTime<Utc>,
}

impl From<WorklistRow> for WorklistRowBody {
    fn from(r: WorklistRow) -> Self {
        WorklistRowBody {
            signature_uuid: r.signature_uuid,
            technique: r.technique,
            technique_name: r.technique_name,
            kind: r.kind.as_str().to_owned(),
            status: r.status.as_str().to_owned(),
            declared_as: r.declared_as,
            tag_present: r.tag_present,
            signature_counts: r.signature_counts,
            counts: r.counts,
            measured: r.measured,
            measured_techniques: r.measured_techniques,
            signature_family: r.signature_family,
            signature_name: r.signature_name,
            resolution: r
                .resolution
                .map(|resolution| resolution.as_str().to_owned()),
            reason: r.reason,
            reference: r.reference,
            resolved_by: r.resolved_by.map(ActorBody::from),
            resolved_at: r.resolved_at,
            first_seen_at: r.first_seen_at,
            status_changed_at: r.status_changed_at,
            updated_at: r.updated_at,
        }
    }
}

impl ExportRow for WorklistRowBody {
    const HEADER: &'static [&'static str] = &[
        "signature_uuid",
        "technique",
        "technique_name",
        "kind",
        "status",
        "declared_as",
        "tag_present",
        "signature_counts",
        "counts",
        "measured",
        "measured_techniques",
        "signature_family",
        "signature_name",
        "resolution",
        "reason",
        "reference",
        "resolved_by",
        "resolved_at",
        "first_seen_at",
        "status_changed_at",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.signature_uuid.clone(),
            self.technique.clone(),
            cell(&self.technique_name),
            self.kind.clone(),
            self.status.clone(),
            // joined with ",", as ace3's CSV writes them
            self.declared_as.join(","),
            self.tag_present.to_string(),
            self.signature_counts.to_string(),
            self.counts.to_string(),
            self.measured.to_string(),
            self.measured_techniques.join(","),
            cell(&self.signature_family),
            cell(&self.signature_name),
            cell(&self.resolution),
            cell(&self.reason),
            cell(&self.reference),
            self.resolved_by
                .as_ref()
                .map(ActorBody::shown)
                .unwrap_or_default(),
            time_cell(self.resolved_at),
            time_cell(Some(self.first_seen_at)),
            time_cell(Some(self.status_changed_at)),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of worklist rows.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct WorklistPageBody {
    rows: Vec<WorklistRowBody>,
    /// Pass it as `cursor`, with the same filters, for the next page; null on the last.
    next: Option<String>,
}

/// A catalog test, on a platform, that the signature is expected of.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MeasuredTestBody {
    guid: Uuid,
    name: Option<String>,
    platform: String,
}

/// A technique the signature is measured on now.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct MeasuredTechniqueBody {
    technique: String,
    technique_name: Option<String>,
    /// The catalog tests, on each platform, the signature is expected of.
    tests: Vec<MeasuredTestBody>,
}

/// A signature's worklist rows, and what it is measured on now.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct SignatureWorklistBody {
    signature_uuid: String,
    signature_family: Option<String>,
    signature_name: Option<String>,
    /// Every row of the signature, retired ones included.
    rows: Vec<WorklistRowBody>,
    /// The techniques the signature is measured on now, with the tests that measure it, computed at the
    /// request.
    measured: Vec<MeasuredTechniqueBody>,
}

impl From<SignatureWorklist> for SignatureWorklistBody {
    fn from(s: SignatureWorklist) -> Self {
        SignatureWorklistBody {
            signature_uuid: s.signature_uuid,
            signature_family: s.signature_family,
            signature_name: s.signature_name,
            rows: s.rows.into_iter().map(WorklistRowBody::from).collect(),
            measured: s
                .measured
                .into_iter()
                .map(|m| MeasuredTechniqueBody {
                    technique: m.technique,
                    technique_name: m.technique_name,
                    tests: m
                        .tests
                        .into_iter()
                        .map(|test| MeasuredTestBody {
                            guid: test.guid,
                            name: test.name,
                            platform: test.platform,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// A resolution to make.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolutionRequest {
    /// `keep`: the tag covers something no test reaches; `remove`: the signature repository will drop the
    /// tag.
    resolution: String,
    /// Why; required, at most 4096 characters.
    reason: String,
    /// An http(s) link, such as the pull request removing the tag; at most 1024 characters.
    #[serde(default)]
    reference: Option<String>,
}

/// A worklist row's key.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorklistKeyBody {
    signature_uuid: String,
    technique: String,
}

/// A resolution to make of many rows alike.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct BulkResolutionRequest {
    /// `keep` or `remove`.
    resolution: String,
    /// Why; required.
    reason: String,
    #[serde(default)]
    reference: Option<String>,
    /// The rows, 1 to 500.
    rows: Vec<WorklistKeyBody>,
}

/// A row that can't be resolved, and the status that says why.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct WorklistConflictBody {
    signature_uuid: String,
    technique: String,
    /// The row's status, which can't be resolved.
    status: String,
}

/// What a bulk resolution did to each row it was given.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct BulkResolutionBody {
    /// The rows resolved.
    done: Vec<WorklistKeyBody>,
    /// Rows that are confirmed, informational, retired or removed; left alone.
    conflicts: Vec<WorklistConflictBody>,
    /// Rows that don't exist.
    unknown: Vec<WorklistKeyBody>,
}

impl From<BulkResolution> for BulkResolutionBody {
    fn from(b: BulkResolution) -> Self {
        let key = |(signature_uuid, technique): (String, String)| WorklistKeyBody {
            signature_uuid,
            technique,
        };
        BulkResolutionBody {
            done: b.done.into_iter().map(key).collect(),
            conflicts: b
                .conflicts
                .into_iter()
                .map(|(signature_uuid, technique, status)| WorklistConflictBody {
                    signature_uuid,
                    technique,
                    status: status.as_str().to_owned(),
                })
                .collect(),
            unknown: b.unknown.into_iter().map(key).collect(),
        }
    }
}

/// The worklist's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct WorklistListQuery {
    /// A filter in the share-link encoding (`[!]slug:v1,v2`) with the worklist screen's slugs: signature
    /// (a uuid, or text in the name), family, technique (T1059 also finds its sub-techniques), status,
    /// kind, resolution (keep, remove, none), resolved_by, resolved. Repeat it for more; filters are
    /// ANDed, the values of one ORed.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only rows written or changed at or after this time; the pages are then in (updated_at, id) order.
    changed_since: Option<String>,
    /// The timezone relative date filters resolve in; UTC when left out.
    tz: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// The filters of an export: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct WorklistFilterQuery {
    /// A filter, as the worklist takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    changed_since: Option<String>,
    tz: Option<String>,
}

fn worklist_query(params: &Params) -> Result<WorklistQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::SvsWorklist, &params.all("f"), true)?;
    Ok(WorklistQuery {
        filters,
        changed_since: params.time("changed_since")?,
        tz: params.tz()?,
    })
}

/// The worklist rows by signature, then technique, a page at a time. Follow `next` with the same filters
/// until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/worklist",
    tag = "svs",
    params(WorklistListQuery),
    responses(
        (status = 200, description = "A page of worklist rows", body = WorklistPageBody),
        (status = 400, description = "A filter, time, timezone, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<WorklistPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = worklist_query(&params)?;
    let page = web
        .service
        .svs_worklist(
            &actor,
            &query,
            params.one("cursor")?,
            params.parsed("limit", "a number from 1 to 1000")?,
        )
        .await?;
    Ok(Json(WorklistPageBody {
        rows: page.rows.into_iter().map(WorklistRowBody::from).collect(),
        next: page.next_cursor,
    }))
}

/// Every row the list's filters match, as CSV (`declared_as` and `measured_techniques` joined with `,`,
/// who resolved it by name) or NDJSON, one row as the list gives it on each line.
#[utoipa::path(
    get,
    path = "/api/svs/v1/worklist/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), WorklistFilterQuery),
    responses(
        (status = 200, description = "The rows, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, filter, time or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More rows than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = worklist_query(&Params::of(raw)?)?;
    let total = service.svs_worklist_count(&actor, &query, max).await?;
    let first = service
        .svs_worklist(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.rows.into_iter().map(WorklistRowBody::from).collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-worklist",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_worklist(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.rows.into_iter().map(WorklistRowBody::from).collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// Resolve many rows alike; a row that doesn't exist or can't be resolved is reported and left alone.
#[utoipa::path(
    post,
    path = "/api/svs/v1/worklist/bulk/resolve",
    tag = "svs",
    request_body = BulkResolutionRequest,
    responses(
        (status = 200, description = "What happened to each row", body = BulkResolutionBody),
        (status = 400, description = "A body, resolution, reason or reference that isn't one, or no rows, or more than 500", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn bulk_resolve(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<BulkResolutionRequest>, JsonRejection>,
) -> Result<Json<BulkResolutionBody>, ApiError> {
    let Json(body) = body?;
    let keys: Vec<(String, String)> = body
        .rows
        .into_iter()
        .map(|key| (key.signature_uuid, key.technique))
        .collect();
    let result = web
        .service
        .resolve_svs_worklist_rows(
            &actor,
            &keys,
            &body.resolution,
            Some(&body.reason),
            body.reference.as_deref(),
            Utc::now(),
        )
        .await?;
    Ok(Json(result.into()))
}

/// A signature's rows, retired ones included, and what it is measured on now.
#[utoipa::path(
    get,
    path = "/api/svs/v1/worklist/{signature_uuid}",
    tag = "svs",
    params(("signature_uuid" = String, Path, description = "The signature")),
    responses(
        (status = 200, description = "The signature's rows", body = SignatureWorklistBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "The signature has no worklist rows", body = ErrorBody),
    )
)]
pub(crate) async fn signature(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<SignatureWorklistBody>, ApiError> {
    let Path(signature_uuid) = path?;
    let detail = web
        .service
        .svs_worklist_signature(&actor, &signature_uuid)
        .await?;
    Ok(Json(detail.into()))
}

/// Resolve a tag measurement doesn't confirm: keep it, or remove it (it stops counting toward coverage
/// from the next refresh). With `If-Match`, the row's `updated_at` as last read, it applies only while the
/// row is unchanged since.
#[utoipa::path(
    put,
    path = "/api/svs/v1/worklist/{signature_uuid}/{technique}/resolution",
    tag = "svs",
    params(
        ("signature_uuid" = String, Path, description = "The signature"),
        ("technique" = String, Path, description = "The row's technique"),
        ("If-Match" = Option<String>, Header, description = "The row's updated_at as last read"),
        ("If-None-Match" = Option<String>, Header, description = "`*`: no row was seen, which a row that exists never satisfies"),
    ),
    request_body = ResolutionRequest,
    responses(
        (status = 200, description = "The row, resolved", body = WorklistRowBody),
        (status = 400, description = "A body, resolution, reason, reference or precondition that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such row", body = ErrorBody),
        (status = 409, description = "The row is confirmed, informational, retired or removed", body = ErrorBody),
        (status = 412, description = "The row changed since it was read; read it again", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_resolution(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
    body: Result<Json<ResolutionRequest>, JsonRejection>,
) -> Result<Json<WorklistRowBody>, ApiError> {
    let Path((signature_uuid, technique)) = path?;
    let precondition = precondition(&headers)?;
    let Json(body) = body?;
    let row = web
        .service
        .resolve_svs_worklist_row(
            &actor,
            &signature_uuid,
            &technique,
            &body.resolution,
            Some(&body.reason),
            body.reference.as_deref(),
            precondition,
            Utc::now(),
        )
        .await?;
    Ok(Json(row.into()))
}

/// Clear a row's resolution: an unconfirmed tag is open again, and counts from the next refresh.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/worklist/{signature_uuid}/{technique}/resolution",
    tag = "svs",
    params(
        ("signature_uuid" = String, Path, description = "The signature"),
        ("technique" = String, Path, description = "The row's technique"),
        ("If-Match" = Option<String>, Header, description = "The row's updated_at as last read"),
    ),
    responses(
        (status = 200, description = "The row, with no resolution", body = WorklistRowBody),
        (status = 400, description = "A precondition that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such row, or it has no resolution", body = ErrorBody),
        (status = 412, description = "The row changed since it was read; read it again", body = ErrorBody),
    )
)]
pub(crate) async fn clear_resolution(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
) -> Result<Json<WorklistRowBody>, ApiError> {
    let Path((signature_uuid, technique)) = path?;
    let precondition = precondition(&headers)?;
    let row = web
        .service
        .reopen_svs_worklist_row(
            &actor,
            &signature_uuid,
            &technique,
            precondition,
            Utc::now(),
        )
        .await?;
    Ok(Json(row.into()))
}
