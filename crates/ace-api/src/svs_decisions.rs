//! What has been decided about a test's signatures (PLAN.md 7.10 batch 5, part 5b): ace3's
//! `aceapi_v2/svs/expectations` and `ignores` routers and the catalog router's decision routes, over
//! `ace_service`'s `svs_decisions`. Reading needs `svs:run_read`; a test's decisions, ignores, settings
//! and exclusion (batch 10) need `svs:run_manage`; a global ignore needs `svs:admin`.
//!
//! A write may say what it was made from (`If-Match`, the row's `updated_at` as last read, or
//! `If-None-Match: *`, no row seen), and one made from a row that has changed since is 412 and changes
//! nothing: ace3's *Conflicting writes*.
//!
//! From ace3: a page is its rows under their own name and `next`; a refused parameter or decision is 400
//! where ace3 answers 422; a 412's body is `{"error": ...}` and the client reads the row again, where
//! ace3's carries the row as it is now; who decided is an actor, so a key that belongs to nobody decides
//! and excludes too, where ace3 answers 422 for a config key; and an export is one operation,
//! `.../export/{format}`.

use ace_service::{
    Expectation, ExpectationQuery, Ignore, IgnoreQuery, Precondition, SvsFeed, TestExclusion,
    TestSettings,
};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
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
use crate::svs_run_reads::format_of;

/// A write's precondition, from its `If-Match` and `If-None-Match` headers.
pub(crate) fn precondition(headers: &HeaderMap) -> Result<Precondition, ApiError> {
    let header = |name: &str| -> Result<Option<&str>, ApiError> {
        headers
            .get(name)
            .map(|value| {
                value
                    .to_str()
                    .map_err(|_| ApiError::bad_request(format!("{name} isn't text")))
            })
            .transpose()
    };
    Precondition::parse(header("if-match")?, header("if-none-match")?)
        .map_err(ApiError::bad_request)
}

fn cell(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

/// A decision to make.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectationRequest {
    /// `expected`: a run of the test should fire it; `rejected`: it fires, but it isn't what the test is
    /// about, and it isn't proposed again.
    state: String,
    /// At most 4096 characters.
    #[serde(default)]
    reason: Option<String>,
    /// The run (of this test, on this platform) whose result the decision was made from; its event log
    /// records it.
    #[serde(default)]
    run_id: Option<String>,
}

/// A decision about a signature for a test on one platform.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ExpectationBody {
    test_guid: Uuid,
    /// The platform the decision is about: only the test's runs on it are judged by it.
    platform: String,
    signature_uuid: String,
    /// `expected` or `rejected`.
    state: String,
    /// The signature's family and name as last known.
    signature_family: Option<String>,
    signature_name: Option<String>,
    reason: Option<String>,
    /// The uuid of the run the decision was made from.
    decided_from_run_id: Option<Uuid>,
    decided_by: Option<ActorBody>,
    decided_at: DateTime<Utc>,
    /// The `changed_since` key, and what an `If-Match` names.
    updated_at: DateTime<Utc>,
}

impl From<Expectation> for ExpectationBody {
    fn from(e: Expectation) -> Self {
        ExpectationBody {
            test_guid: e.test_guid,
            platform: e.platform,
            signature_uuid: e.signature_uuid,
            state: e.state.as_str().to_owned(),
            signature_family: e.signature_family,
            signature_name: e.signature_name,
            reason: e.reason,
            decided_from_run_id: e.decided_from_run,
            decided_by: e.decided_by.map(ActorBody::from),
            decided_at: e.decided_at,
            updated_at: e.updated_at,
        }
    }
}

impl ExportRow for ExpectationBody {
    const HEADER: &'static [&'static str] = &[
        "test_guid",
        "platform",
        "signature_uuid",
        "state",
        "signature_family",
        "signature_name",
        "reason",
        "decided_from_run_id",
        "decided_by",
        "decided_at",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.test_guid.to_string(),
            self.platform.clone(),
            self.signature_uuid.clone(),
            self.state.clone(),
            cell(&self.signature_family),
            cell(&self.signature_name),
            cell(&self.reason),
            self.decided_from_run_id
                .map(|run| run.to_string())
                .unwrap_or_default(),
            self.decided_by
                .as_ref()
                .map(ActorBody::shown)
                .unwrap_or_default(),
            time_cell(Some(self.decided_at)),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of decisions.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ExpectationPageBody {
    expectations: Vec<ExpectationBody>,
    /// Pass it as `cursor`, with the same filters, for the next page; null on the last.
    next: Option<String>,
}

/// An ignore to set.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct IgnoreRequest {
    /// Why its detections during runs are noise; at most 4096 characters.
    #[serde(default)]
    reason: Option<String>,
}

/// A signature ignored during a test's runs, or every test's.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct IgnoreBody {
    /// `global` (every test's runs) or `test`.
    scope: String,
    /// The test, for a test's ignore.
    test_guid: Option<Uuid>,
    signature_uuid: String,
    /// The signature's family and name as last known.
    signature_family: Option<String>,
    signature_name: Option<String>,
    reason: Option<String>,
    created_by: Option<ActorBody>,
    created_at: DateTime<Utc>,
    /// The `changed_since` key, and what an `If-Match` names.
    updated_at: DateTime<Utc>,
}

impl From<Ignore> for IgnoreBody {
    fn from(i: Ignore) -> Self {
        IgnoreBody {
            scope: i.scope().to_owned(),
            test_guid: i.test_guid,
            signature_uuid: i.signature_uuid,
            signature_family: i.signature_family,
            signature_name: i.signature_name,
            reason: i.reason,
            created_by: i.created_by.map(ActorBody::from),
            created_at: i.created_at,
            updated_at: i.updated_at,
        }
    }
}

impl ExportRow for IgnoreBody {
    const HEADER: &'static [&'static str] = &[
        "scope",
        "test_guid",
        "signature_uuid",
        "signature_family",
        "signature_name",
        "reason",
        "created_by",
        "created_at",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.scope.clone(),
            self.test_guid
                .map(|test| test.to_string())
                .unwrap_or_default(),
            self.signature_uuid.clone(),
            cell(&self.signature_family),
            cell(&self.signature_name),
            cell(&self.reason),
            self.created_by
                .as_ref()
                .map(ActorBody::shown)
                .unwrap_or_default(),
            time_cell(Some(self.created_at)),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of ignores.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct IgnorePageBody {
    ignores: Vec<IgnoreBody>,
    /// Pass it as `cursor`, with the same filters, for the next page; null on the last.
    next: Option<String>,
}

/// A test's settings to set.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestSettingsRequest {
    /// The observation window of the test's runs registered from now on, used as it is (no slack, no
    /// floor), from 1 minute up to `svs.runs.observation_window.ceiling_hours`; null for the computed
    /// window.
    #[serde(default)]
    observation_minutes: Option<i32>,
    /// The test leaves something behind on its hosts, so each run of it registered from now on holds them
    /// until its attribution window ends, not its observation window.
    #[serde(default)]
    holds_host: bool,
}

/// A test's settings.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TestSettingsBody {
    test_guid: Uuid,
    /// Null: the computed window.
    observation_minutes: Option<i32>,
    holds_host: bool,
    set_by: Option<ActorBody>,
    updated_at: DateTime<Utc>,
}

impl From<TestSettings> for TestSettingsBody {
    fn from(s: TestSettings) -> Self {
        TestSettingsBody {
            test_guid: s.test_guid,
            observation_minutes: s.observation_minutes,
            holds_host: s.holds_host,
            set_by: s.set_by.map(ActorBody::from),
            updated_at: s.updated_at,
        }
    }
}

/// Why a test is excluded.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestExclusionRequest {
    /// Why the test doesn't apply, or isn't worth measuring: 1 to 4096 characters, not blank.
    reason: String,
}

/// A test's exclusion.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct TestExclusionBody {
    test_guid: Uuid,
    reason: String,
    excluded_by: ActorBody,
    excluded_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<TestExclusion> for TestExclusionBody {
    fn from(e: TestExclusion) -> Self {
        TestExclusionBody {
            test_guid: e.test_guid,
            reason: e.reason,
            excluded_by: e.excluded_by.into(),
            excluded_at: e.excluded_at,
            updated_at: e.updated_at,
        }
    }
}

/// The expectations' list's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ExpectationsQuery {
    /// Only this test's, by its guid.
    test: Option<String>,
    /// Only those about this platform, such as `windows`.
    platform: Option<String>,
    /// Only this signature's.
    signature: Option<String>,
    /// Only `expected` or only `rejected`.
    state: Option<String>,
    /// Only decisions made or changed at or after this time; the rows then come in (updated_at, id) order,
    /// and none changed in the last few seconds.
    changed_since: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// An export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ExpectationsExportQuery {
    test: Option<String>,
    platform: Option<String>,
    signature: Option<String>,
    state: Option<String>,
    changed_since: Option<String>,
}

/// The ignores' list's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct IgnoresQuery {
    /// Only `global` or only `test` ignores.
    scope: Option<String>,
    /// The ignores that apply to this test, by its guid: its own and the global ones.
    test: Option<String>,
    /// Only this signature's.
    signature: Option<String>,
    /// Only ignores added or changed at or after this time; the rows then come in (updated_at, id) order.
    /// A removed ignore is gone, not listed.
    changed_since: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// An export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct IgnoresExportQuery {
    scope: Option<String>,
    test: Option<String>,
    signature: Option<String>,
    changed_since: Option<String>,
}

fn owned(params: &Params, name: &str) -> Result<Option<String>, ApiError> {
    Ok(params.one(name)?.map(str::to_owned))
}

fn expectation_query(params: &Params) -> Result<ExpectationQuery, ApiError> {
    Ok(ExpectationQuery {
        test: owned(params, "test")?,
        platform: owned(params, "platform")?,
        signature: owned(params, "signature")?,
        state: owned(params, "state")?,
        changed_since: params.time("changed_since")?,
    })
}

fn ignore_query(params: &Params) -> Result<IgnoreQuery, ApiError> {
    Ok(IgnoreQuery {
        scope: owned(params, "scope")?,
        test: owned(params, "test")?,
        signature: owned(params, "signature")?,
        changed_since: params.time("changed_since")?,
    })
}

fn limit_of(params: &Params) -> Result<Option<u32>, ApiError> {
    params.parsed("limit", "a number from 1 to 1000")
}

/// Every test's decided signatures, per platform. Follow `next`, with the same filters, until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/expectations",
    tag = "svs",
    params(ExpectationsQuery),
    responses(
        (status = 200, description = "A page of decisions", body = ExpectationPageBody),
        (status = 400, description = "A state, time, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn expectations(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<ExpectationPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = expectation_query(&params)?;
    let page = web
        .service
        .svs_expectations(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(ExpectationPageBody {
        expectations: page.expectations.into_iter().map(Into::into).collect(),
        next: page.next_cursor,
    }))
}

/// The decisions the list's filters match, as CSV or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/expectations/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), ExpectationsExportQuery),
    responses(
        (status = 200, description = "The decisions, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, state or time that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More decisions than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_expectations(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = expectation_query(&Params::of(raw)?)?;
    let total = service
        .svs_feed_count(&actor, &SvsFeed::Expectations(&query), max)
        .await?;
    let first = service
        .svs_expectations(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first
            .expectations
            .into_iter()
            .map(ExpectationBody::from)
            .collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-expectations",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_expectations(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.expectations
                        .into_iter()
                        .map(ExpectationBody::from)
                        .collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// The ignores. Follow `next`, with the same filters, until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/ignores",
    tag = "svs",
    params(IgnoresQuery),
    responses(
        (status = 200, description = "A page of ignores", body = IgnorePageBody),
        (status = 400, description = "A scope, time, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn ignores(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<IgnorePageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = ignore_query(&params)?;
    let page = web
        .service
        .svs_ignores(&actor, &query, params.one("cursor")?, limit_of(&params)?)
        .await?;
    Ok(Json(IgnorePageBody {
        ignores: page.ignores.into_iter().map(Into::into).collect(),
        next: page.next_cursor,
    }))
}

/// The ignores the list's filters match, as CSV or NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/ignores/export/{format}",
    tag = "svs",
    params(("format" = String, Path, description = "`csv` or `ndjson`"), IgnoresExportQuery),
    responses(
        (status = 200, description = "The ignores, as text/csv or application/x-ndjson", body = String),
        (status = 400, description = "A format, scope or time that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More ignores than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ignores(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let Path(format) = path?;
    let format = format_of(&format)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let query = ignore_query(&Params::of(raw)?)?;
    let total = service
        .svs_feed_count(&actor, &SvsFeed::Ignores(&query), max)
        .await?;
    let first = service
        .svs_ignores(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.ignores.into_iter().map(IgnoreBody::from).collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-ignores",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_ignores(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.ignores.into_iter().map(IgnoreBody::from).collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// Decides a signature for the test's runs on the platform: expected or rejected. With `If-None-Match: *`
/// it applies only while there's no decision yet, and with `If-Match`, the decision's `updated_at` as last
/// read, only while it's unchanged since.
#[utoipa::path(
    put,
    path = "/api/svs/v1/tests/{guid}/expectations/{platform}/{signature_uuid}",
    tag = "svs",
    params(
        ("guid" = String, Path, description = "The test's auto_generated_guid"),
        ("platform" = String, Path, description = "One of the test's platforms, such as windows"),
        ("signature_uuid" = String, Path, description = "The signature"),
        ("If-Match" = Option<String>, Header, description = "The decision's updated_at as last read"),
        ("If-None-Match" = Option<String>, Header, description = "`*`: no decision was seen"),
    ),
    request_body = ExpectationRequest,
    responses(
        (status = 200, description = "The decision", body = ExpectationBody),
        (status = 400, description = "A body, state, signature or precondition that isn't one, a platform the test doesn't support, or a run that isn't one of the test's on the platform", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No test with that guid in the catalog", body = ErrorBody),
        (status = 412, description = "The decision was made, changed or removed since it was read; read it again", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_expectation(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    headers: HeaderMap,
    body: Result<Json<ExpectationRequest>, JsonRejection>,
) -> Result<Json<ExpectationBody>, ApiError> {
    let Path((guid, platform, signature)) = path?;
    let precondition = precondition(&headers)?;
    let Json(body) = body?;
    let run = body
        .run_id
        .as_deref()
        .map(|run| {
            run.parse::<Uuid>()
                .map_err(|_| ApiError::bad_request(format!("{run:?} isn't a run's uuid")))
        })
        .transpose()?;
    let decided = web
        .service
        .set_svs_expectation(
            &actor,
            &guid,
            Some(&platform),
            &signature,
            &body.state,
            body.reason.as_deref(),
            run,
            precondition,
            Utc::now(),
        )
        .await?;
    Ok(Json(decided.into()))
}

/// Removes a decision: the signature is a candidate again the next time a run on the platform fires it.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/tests/{guid}/expectations/{platform}/{signature_uuid}",
    tag = "svs",
    params(
        ("guid" = String, Path, description = "The test's auto_generated_guid"),
        ("platform" = String, Path, description = "The platform the decision is about"),
        ("signature_uuid" = String, Path, description = "The signature"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 400, description = "A signature that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such test, or no decision about the signature there", body = ErrorBody),
    )
)]
pub(crate) async fn remove_expectation(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String, String)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path((guid, platform, signature)) = path?;
    web.service
        .remove_svs_expectation(&actor, &guid, &platform, &signature)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Ignores a signature during the test's runs; setting it again replaces its reason. The preconditions are
/// a decision's.
#[utoipa::path(
    put,
    path = "/api/svs/v1/tests/{guid}/ignores/{signature_uuid}",
    tag = "svs",
    params(
        ("guid" = String, Path, description = "The test's auto_generated_guid"),
        ("signature_uuid" = String, Path, description = "The signature"),
        ("If-Match" = Option<String>, Header, description = "The ignore's updated_at as last read"),
        ("If-None-Match" = Option<String>, Header, description = "`*`: no ignore was seen"),
    ),
    request_body = IgnoreRequest,
    responses(
        (status = 200, description = "The ignore", body = IgnoreBody),
        (status = 400, description = "A body, signature or precondition that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No test with that guid in the catalog", body = ErrorBody),
        (status = 412, description = "The ignore was added, changed or removed since it was read; read it again", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_test_ignore(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
    body: Result<Json<IgnoreRequest>, JsonRejection>,
) -> Result<Json<IgnoreBody>, ApiError> {
    let Path((guid, signature)) = path?;
    let precondition = precondition(&headers)?;
    let Json(body) = body?;
    let ignore = web
        .service
        .set_svs_ignore(
            &actor,
            &signature,
            Some(&guid),
            body.reason.as_deref(),
            precondition,
            Utc::now(),
        )
        .await?;
    Ok(Json(ignore.into()))
}

/// Stops ignoring a signature during the test's runs.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/tests/{guid}/ignores/{signature_uuid}",
    tag = "svs",
    params(
        ("guid" = String, Path, description = "The test's auto_generated_guid"),
        ("signature_uuid" = String, Path, description = "The signature"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 400, description = "A signature that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such test, or the signature isn't ignored for it", body = ErrorBody),
    )
)]
pub(crate) async fn remove_test_ignore(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<(String, String)>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path((guid, signature)) = path?;
    web.service
        .remove_svs_ignore(&actor, &signature, Some(&guid))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Ignores a signature during every test's runs; setting it again replaces its reason. The preconditions
/// are a decision's.
#[utoipa::path(
    put,
    path = "/api/svs/v1/ignores/global/{signature_uuid}",
    tag = "svs",
    params(
        ("signature_uuid" = String, Path, description = "The signature"),
        ("If-Match" = Option<String>, Header, description = "The ignore's updated_at as last read"),
        ("If-None-Match" = Option<String>, Header, description = "`*`: no ignore was seen"),
    ),
    request_body = IgnoreRequest,
    responses(
        (status = 200, description = "The ignore", body = IgnoreBody),
        (status = 400, description = "A body, signature or precondition that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:admin", body = ErrorBody),
        (status = 412, description = "The ignore was added, changed or removed since it was read; read it again", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_global_ignore(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Result<Json<IgnoreRequest>, JsonRejection>,
) -> Result<Json<IgnoreBody>, ApiError> {
    let Path(signature) = path?;
    let precondition = precondition(&headers)?;
    let Json(body) = body?;
    let ignore = web
        .service
        .set_svs_ignore(
            &actor,
            &signature,
            None,
            body.reason.as_deref(),
            precondition,
            Utc::now(),
        )
        .await?;
    Ok(Json(ignore.into()))
}

/// Stops ignoring a signature globally.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/ignores/global/{signature_uuid}",
    tag = "svs",
    params(("signature_uuid" = String, Path, description = "The signature")),
    responses(
        (status = 204, description = "Removed"),
        (status = 400, description = "A signature that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:admin", body = ErrorBody),
        (status = 404, description = "The signature isn't ignored globally", body = ErrorBody),
    )
)]
pub(crate) async fn remove_global_ignore(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(signature) = path?;
    web.service
        .remove_svs_ignore(&actor, &signature, None)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The test's settings; 404 when it has none, and its runs get the computed window.
#[utoipa::path(
    get,
    path = "/api/svs/v1/tests/{guid}/settings",
    tag = "svs",
    params(("guid" = String, Path, description = "The test's auto_generated_guid")),
    responses(
        (status = 200, description = "The settings", body = TestSettingsBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No such test, or it has no settings", body = ErrorBody),
    )
)]
pub(crate) async fn settings(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<TestSettingsBody>, ApiError> {
    let Path(guid) = path?;
    let settings = web
        .service
        .svs_test_settings(&actor, &guid)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                format!("test {guid} has no settings"),
            )
        })?;
    Ok(Json(settings.into()))
}

/// Sets the settings of the test's runs registered from now on, replacing what was set.
#[utoipa::path(
    put,
    path = "/api/svs/v1/tests/{guid}/settings",
    tag = "svs",
    params(("guid" = String, Path, description = "The test's auto_generated_guid")),
    request_body = TestSettingsRequest,
    responses(
        (status = 200, description = "The settings", body = TestSettingsBody),
        (status = 400, description = "A body that isn't one, or minutes outside 1 to the configured ceiling", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No test with that guid in the catalog", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_settings(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<TestSettingsRequest>, JsonRejection>,
) -> Result<Json<TestSettingsBody>, ApiError> {
    let Path(guid) = path?;
    let Json(body) = body?;
    let settings = web
        .service
        .set_svs_test_settings(&actor, &guid, body.observation_minutes, body.holds_host)
        .await?;
    Ok(Json(settings.into()))
}

/// Back to the computed window and `holds_host` false.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/tests/{guid}/settings",
    tag = "svs",
    params(("guid" = String, Path, description = "The test's auto_generated_guid")),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such test, or it has no settings", body = ErrorBody),
    )
)]
pub(crate) async fn remove_settings(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(guid) = path?;
    web.service.remove_svs_test_settings(&actor, &guid).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Who excluded the test, when and why; 404 when it isn't excluded.
#[utoipa::path(
    get,
    path = "/api/svs/v1/tests/{guid}/exclusion",
    tag = "svs",
    params(("guid" = String, Path, description = "The test's auto_generated_guid")),
    responses(
        (status = 200, description = "The exclusion", body = TestExclusionBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No such test, or it isn't excluded", body = ErrorBody),
    )
)]
pub(crate) async fn exclusion(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<TestExclusionBody>, ApiError> {
    let Path(guid) = path?;
    let exclusion = web
        .service
        .svs_test_exclusion(&actor, &guid)
        .await?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                format!("test {guid} is not excluded"),
            )
        })?;
    Ok(Json(exclusion.into()))
}

/// Excludes the test on every platform: from the next coverage refresh it counts toward no coverage row
/// and measures no signature, and registering a run of it is refused. Its runs, decisions and ignores are
/// kept. Excluding it again replaces who, when and why.
#[utoipa::path(
    put,
    path = "/api/svs/v1/tests/{guid}/exclusion",
    tag = "svs",
    params(("guid" = String, Path, description = "The test's auto_generated_guid")),
    request_body = TestExclusionRequest,
    responses(
        (status = 200, description = "The exclusion", body = TestExclusionBody),
        (status = 400, description = "A body that isn't one, or a reason that is blank or longer than 4096 characters", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No test with that guid in the catalog", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn set_exclusion(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    body: Result<Json<TestExclusionRequest>, JsonRejection>,
) -> Result<Json<TestExclusionBody>, ApiError> {
    let Path(guid) = path?;
    let Json(body) = body?;
    let exclusion = web
        .service
        .set_svs_test_exclusion(&actor, &guid, &body.reason, Utc::now())
        .await?;
    Ok(Json(exclusion.into()))
}

/// Brings the test back as it was, with its runs, decisions and ignores.
#[utoipa::path(
    delete,
    path = "/api/svs/v1/tests/{guid}/exclusion",
    tag = "svs",
    params(("guid" = String, Path, description = "The test's auto_generated_guid")),
    responses(
        (status = 204, description = "Included again"),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_manage", body = ErrorBody),
        (status = 404, description = "No such test, or it isn't excluded", body = ErrorBody),
    )
)]
pub(crate) async fn remove_exclusion(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let Path(guid) = path?;
    web.service.remove_svs_test_exclusion(&actor, &guid).await?;
    Ok(StatusCode::NO_CONTENT)
}
