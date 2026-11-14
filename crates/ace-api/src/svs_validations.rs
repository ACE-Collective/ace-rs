//! `/api/svs/v1/yara/validations`: SVS's YARA validations (PLAN.md 7.10 batch 3), ace3's
//! `aceapi_v2/svs/yara/validations` router, over `ace_service`'s `svs_validations`. A validation replays every
//! SVS sample under two commits of a rule repository and reports what the change does to the graded corpus.
//!
//! A rule repository's CI requests one and polls its status with an `svs:validate` key, which reads counts
//! and rule names and uuids only. The list, the reports and their rows name the samples and need
//! `signature:read`; the files need `signature:download`, and come only inside a zip encrypted with AES-256
//! and the password `infected`, as the samples' downloads do. Every request and every download is audited
//! by the service.
//!
//! From ace3: a refused request body is 400, as every route here answers one, where ace3 answers 422; a page
//! is `{validations, next}` and `{results, next}`, as the API's other pages, where ace3's are `{data,
//! next_cursor}`; the report's link is the GUI's `/signatures/validations/{uuid}`, without ace3's `/ace`
//! prefix; and a key with no owner may request one (`ace_service`'s `svs_validations` docs).

use ace_service::filters::{FilterScreen, decode};
use ace_service::{
    CompileProblem, ResultSelection, RuleCount, Validation, ValidationAsk, ValidationDetail,
    ValidationQuery, ValidationResult, ValidationStatus,
};
use axum::Json;
use axum::extract::rejection::{JsonRejection, PathRejection};
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::alerts::{ActorBody, ZipBody};
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::params::Params;

/// What a rule repository's CI asks for: validate `head_sha` against `base_sha`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ValidationRequestBody {
    /// A name in the overlay's `svs.yara.repositories`.
    repository: String,
    /// The full id of the commit to compare against, 40 or 64 hex characters: the pull request's merge base.
    base_sha: String,
    /// The full id of the commit to validate.
    head_sha: String,
    /// The branch `head_sha` is on.
    branch: String,
    /// The pull request, for the report's link back: an http or https URL.
    pr_url: Option<String>,
}

/// The rules with samples in one category.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RuleCountBody {
    rule_uuid: String,
    rule_name: String,
    /// How many samples of the category the rule has in this validation.
    count: i64,
}

impl From<RuleCount> for RuleCountBody {
    fn from(r: RuleCount) -> Self {
        RuleCountBody {
            rule_uuid: r.rule_uuid,
            rule_name: r.rule_name,
            count: r.count,
        }
    }
}

/// A head rule file that doesn't compile; its rules are dropped.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CompileProblemBody {
    /// Relative to the repository's top.
    file: String,
    error: String,
}

impl From<CompileProblem> for CompileProblemBody {
    fn from(p: CompileProblem) -> Self {
        CompileProblemBody {
            file: p.file,
            error: p.error,
        }
    }
}

/// A validation as the CI sees it (`svs:validate`): its state, counts, and rule names and uuids. It never
/// carries a sample's sha256, file name or content.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ValidationStatusBody {
    uuid: Uuid,
    /// `queued`, `running`, `completed` or `failed`.
    state: String,
    /// Why a failed validation couldn't run.
    error: Option<String>,
    repository: String,
    base_sha: String,
    head_sha: String,
    branch: String,
    pr_url: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    /// False when either commit's rules wouldn't load, so nothing was compared.
    diffed: Option<bool>,
    /// Pairs (sample, rule uuid) per category, every category included; set once completed.
    counts: Option<BTreeMap<String, i64>>,
    /// The rules with samples in each listed category, most samples first.
    rules: BTreeMap<String, Vec<RuleCountBody>>,
    /// The head's rule files that don't compile; their rules are dropped.
    compile_errors: Vec<CompileProblemBody>,
    /// Set when the head's rules wouldn't load together: the pools keep the ruleset they have.
    ruleset_error: Option<String>,
    /// The report in the GUI, relative to its host.
    report_path: String,
}

impl From<ValidationStatus> for ValidationStatusBody {
    fn from(s: ValidationStatus) -> Self {
        ValidationStatusBody {
            uuid: s.uuid,
            state: s.state.as_str().to_owned(),
            error: s.error,
            repository: s.repository,
            base_sha: s.base_sha,
            head_sha: s.head_sha,
            branch: s.branch,
            pr_url: s.pr_url,
            created_at: s.created_at,
            started_at: s.started_at,
            finished_at: s.finished_at,
            diffed: s.diffed,
            counts: s.counts,
            rules: s
                .rules
                .into_iter()
                .map(|(c, r)| (c, r.into_iter().map(RuleCountBody::from).collect()))
                .collect(),
            compile_errors: s
                .compile_errors
                .into_iter()
                .map(CompileProblemBody::from)
                .collect(),
            ruleset_error: s.ruleset_error,
            report_path: s.report_path,
        }
    }
}

/// One validation in the list (`signature:read`).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ValidationBody {
    uuid: Uuid,
    repository: String,
    base_sha: String,
    head_sha: String,
    branch: String,
    pr_url: Option<String>,
    /// `queued`, `running`, `completed` or `failed`.
    state: String,
    /// Who asked for it.
    requested_by: ActorBody,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    error: Option<String>,
    diffed: Option<bool>,
    /// regression + regression_unconfirmed.
    regressions: Option<i32>,
    /// new_fp + new_fp_other_rule.
    new_fps: Option<i32>,
    /// The head's rule files that don't compile, plus one if its rules wouldn't load.
    compile_errors: Option<i32>,
    counts: Option<BTreeMap<String, i64>>,
    updated_at: DateTime<Utc>,
}

impl From<Validation> for ValidationBody {
    fn from(v: Validation) -> Self {
        ValidationBody {
            uuid: v.uuid,
            repository: v.repository,
            base_sha: v.base_sha,
            head_sha: v.head_sha,
            branch: v.branch,
            pr_url: v.pr_url,
            state: v.state.as_str().to_owned(),
            requested_by: v.requested_by.into(),
            created_at: v.created_at,
            started_at: v.started_at,
            finished_at: v.finished_at,
            error: v.error,
            diffed: v.diffed,
            regressions: v.regressions,
            new_fps: v.new_fps,
            compile_errors: v.compile_errors,
            counts: v.counts,
            updated_at: v.updated_at,
        }
    }
}

fn cell<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(text)) => text,
        Ok(Value::Null) | Err(_) => String::new(),
        Ok(other) => other.to_string(),
    }
}

/// The CSV export leaves the per-category counts out, as ace3's does.
impl ExportRow for ValidationBody {
    const HEADER: &'static [&'static str] = &[
        "uuid",
        "repository",
        "base_sha",
        "head_sha",
        "branch",
        "pr_url",
        "state",
        "requested_by",
        "created_at",
        "started_at",
        "finished_at",
        "error",
        "diffed",
        "regressions",
        "new_fps",
        "compile_errors",
        "updated_at",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.uuid.to_string(),
            self.repository.clone(),
            self.base_sha.clone(),
            self.head_sha.clone(),
            self.branch.clone(),
            cell(&self.pr_url),
            self.state.clone(),
            self.requested_by.shown(),
            time_cell(Some(self.created_at)),
            time_cell(self.started_at),
            time_cell(self.finished_at),
            cell(&self.error),
            cell(&self.diffed),
            cell(&self.regressions),
            cell(&self.new_fps),
            cell(&self.compile_errors),
            time_cell(Some(self.updated_at)),
        ]
    }
}

/// A page of validations.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ValidationPageBody {
    validations: Vec<ValidationBody>,
    /// Pass it as `cursor`, with the same filters, for the next page; null on the last.
    next: Option<String>,
}

/// One validation with its report (`signature:read`).
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ValidationDetailBody {
    #[serde(flatten)]
    validation: ValidationBody,
    /// How many times a worker claimed it.
    attempts: i32,
    /// The node that ran (or runs) it.
    claimed_by: Option<String>,
    /// What the samples and their labels were when it ran.
    corpus_version: Option<String>,
    /// What decided its results besides the corpus and the commits.
    engine_fingerprint: Option<String>,
    /// How each commit compiled, the rules added, removed and changed, the rules that can't be tested, the
    /// samples skipped and the timings; its listed pairs are its results.
    report: Option<Value>,
}

impl From<ValidationDetail> for ValidationDetailBody {
    fn from(d: ValidationDetail) -> Self {
        ValidationDetailBody {
            validation: d.validation.into(),
            attempts: d.attempts,
            claimed_by: d.claimed_by,
            corpus_version: d.corpus_version,
            engine_fingerprint: d.engine_fingerprint,
            report: d.report,
        }
    }
}

/// One pair (sample, rule uuid) a report lists, with the sample's label when it ran.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ValidationResultBody {
    id: i64,
    sha256: String,
    rule_uuid: String,
    rule_name: String,
    namespace: Option<String>,
    /// `tp`, `fp` or `conflicted`.
    label: Option<String>,
    /// `explicit`, `inherited_single` or `inherited_multi`.
    label_source: Option<String>,
    /// The outcome under base: `match` (the rule would make a detection), `miss` or `error`.
    base: String,
    head: String,
    /// Whether the rule matched under base at all, before `enabled` and the qa and no_alert modifiers.
    raw_base: bool,
    raw_head: bool,
    category: String,
    note: Option<String>,
}

impl From<ValidationResult> for ValidationResultBody {
    fn from(r: ValidationResult) -> Self {
        ValidationResultBody {
            id: r.id,
            sha256: r.sha256,
            rule_uuid: r.rule_uuid,
            rule_name: r.rule_name,
            namespace: r.namespace,
            label: r.label,
            label_source: r.label_source,
            base: r.base,
            head: r.head,
            raw_base: r.raw_base,
            raw_head: r.raw_head,
            category: r.category,
            note: r.note,
        }
    }
}

impl ExportRow for ValidationResultBody {
    const HEADER: &'static [&'static str] = &[
        "id",
        "sha256",
        "rule_uuid",
        "rule_name",
        "namespace",
        "label",
        "label_source",
        "base",
        "head",
        "raw_base",
        "raw_head",
        "category",
        "note",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.id.to_string(),
            self.sha256.clone(),
            self.rule_uuid.clone(),
            self.rule_name.clone(),
            cell(&self.namespace),
            cell(&self.label),
            cell(&self.label_source),
            self.base.clone(),
            self.head.clone(),
            self.raw_base.to_string(),
            self.raw_head.to_string(),
            self.category.clone(),
            cell(&self.note),
        ]
    }
}

/// A page of a report's rows.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ValidationResultPageBody {
    results: Vec<ValidationResultBody>,
    /// Pass it as `cursor`, with the same selection, for the next page; null on the last.
    next: Option<String>,
}

/// The list's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ValidationsQuery {
    /// A filter in the share-link encoding (`[!]slug:v1,v2`) with the validations screen's slugs:
    /// repository, branch, head, state, has_regressions, has_new_fp, compile_errors, created. Repeat it for
    /// more; filters are ANDed, the values of one ORed.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only validations created or changed (queued, run, completed) at or after this time.
    changed_since: Option<String>,
    /// The timezone relative date filters (`-7d`, `@d`) resolve in; UTC when left out.
    tz: Option<String>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// An export's parameters: the list's, with no paging.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ValidationsExportQuery {
    /// A filter, as the list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    changed_since: Option<String>,
    tz: Option<String>,
}

/// A report's rows' parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct ResultsQuery {
    /// Only rows of these categories; repeat it for more. A category that's only counted is refused.
    #[param(style = Form, explode)]
    category: Option<Vec<String>>,
    /// Only rows of these rule uuids; repeat it for more.
    #[param(style = Form, explode)]
    rule_uuid: Option<Vec<String>>,
    /// How many, 1 to 1000; 100 when left out.
    limit: Option<u32>,
    /// The `next` of the previous page.
    cursor: Option<String>,
}

/// A report's selection, for its exports and its download.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct SelectionQuery {
    /// Only rows of these categories; repeat it for more.
    #[param(style = Form, explode)]
    category: Option<Vec<String>>,
    /// Only rows of these rule uuids; repeat it for more.
    #[param(style = Form, explode)]
    rule_uuid: Option<Vec<String>>,
}

fn validation_query(params: &Params) -> Result<ValidationQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::SvsValidations, &params.all("f"), true)?;
    Ok(ValidationQuery {
        filters,
        changed_since: params.time("changed_since")?,
        tz: params.tz()?,
    })
}

fn selection(params: &Params) -> ResultSelection {
    ResultSelection {
        categories: params.all("category"),
        rule_uuids: params.all("rule_uuid"),
    }
}

fn validation_uuid(path: Result<Path<String>, PathRejection>) -> Result<Uuid, ApiError> {
    let Path(text) = path?;
    text.parse()
        .map_err(|_| ApiError::bad_request(format!("{text:?} isn't a validation's uuid")))
}

/// Requests a validation of `head_sha` against `base_sha`: 202 with a new queued validation, or 200 with
/// the one that already answers it (queued or running for the same commits, or completed with the samples,
/// their labels and the scanner unchanged since). Poll its status.
#[utoipa::path(
    post,
    path = "/api/svs/v1/yara/validations",
    tag = "svs",
    request_body = ValidationRequestBody,
    responses(
        (status = 200, description = "An existing validation answers the request", body = ValidationStatusBody),
        (status = 202, description = "A new validation is queued", body = ValidationStatusBody),
        (status = 400, description = "A body that isn't one: a repository not in svs.yara.repositories, a commit that isn't a full id, a pr_url that isn't http or https", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:validate", body = ErrorBody),
        (status = 413, description = "The body is too large", body = ErrorBody),
    )
)]
pub(crate) async fn request(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    body: Result<Json<ValidationRequestBody>, JsonRejection>,
) -> Result<(StatusCode, Json<ValidationStatusBody>), ApiError> {
    let Json(body) = body?;
    let (status, created) = web
        .service
        .request_svs_validation(
            &actor,
            &ValidationAsk {
                repository: body.repository,
                base_sha: body.base_sha,
                head_sha: body.head_sha,
                branch: body.branch,
                pr_url: body.pr_url,
            },
        )
        .await?;
    let code = if created {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((code, Json(status.into())))
}

/// A validation's state and, once completed, its counts per category, the rules with samples in each listed
/// category, and the head's compile errors. It names no sample.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations/{uuid}/status",
    tag = "svs",
    params(("uuid" = String, Path, description = "The validation's uuid")),
    responses(
        (status = 200, description = "The status", body = ValidationStatusBody),
        (status = 400, description = "A uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:validate", body = ErrorBody),
        (status = 404, description = "No validation with that uuid", body = ErrorBody),
    )
)]
pub(crate) async fn status(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<ValidationStatusBody>, ApiError> {
    let uuid = validation_uuid(path)?;
    let status = web.service.svs_validation_status(&actor, uuid).await?;
    Ok(Json(status.into()))
}

/// Validations, newest first, a page at a time. Follow `next` with the same filters until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations",
    tag = "svs",
    params(ValidationsQuery),
    responses(
        (status = 200, description = "A page of validations", body = ValidationPageBody),
        (status = 400, description = "A filter, time, timezone, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<ValidationPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = validation_query(&params)?;
    let page = web
        .service
        .svs_validations(
            &actor,
            &query,
            params.one("cursor")?,
            params.parsed("limit", "a number from 1 to 1000")?,
        )
        .await?;
    Ok(Json(ValidationPageBody {
        validations: page
            .validations
            .into_iter()
            .map(ValidationBody::from)
            .collect(),
        next: page.next_cursor,
    }))
}

async fn export_validations(
    format: Format,
    actor: ace_service::Actor,
    web: Web,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let query = validation_query(&params)?;
    let total = service.svs_validation_count(&actor, &query, max).await?;
    let first = service
        .svs_validations(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first
            .validations
            .into_iter()
            .map(ValidationBody::from)
            .collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-validations",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_validations(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.validations
                        .into_iter()
                        .map(ValidationBody::from)
                        .collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// Every validation the list's filters match, newest first, as CSV, without the per-category counts. A
/// failure part-way ends the file there.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations/export/csv",
    tag = "svs",
    params(ValidationsExportQuery),
    responses(
        (status = 200, description = "The validations", content_type = "text/csv", body = String),
        (status = 400, description = "A filter, time or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 413, description = "More validations than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_validations(Format::Csv, actor, web, raw).await
}

/// Every validation the list's filters match, newest first, as NDJSON: one as the list gives it on each
/// line. A failure part-way ends it with an `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations/export/ndjson",
    tag = "svs",
    params(ValidationsExportQuery),
    responses(
        (status = 200, description = "The validations", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A filter, time or timezone that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 413, description = "More validations than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_validations(Format::Ndjson, actor, web, raw).await
}

/// One validation with its report; the pairs it lists are its results.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations/{uuid}",
    tag = "svs",
    params(("uuid" = String, Path, description = "The validation's uuid")),
    responses(
        (status = 200, description = "The validation", body = ValidationDetailBody),
        (status = 400, description = "A uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No validation with that uuid", body = ErrorBody),
    )
)]
pub(crate) async fn detail(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<ValidationDetailBody>, ApiError> {
    let uuid = validation_uuid(path)?;
    let detail = web.service.svs_validation(&actor, uuid).await?;
    Ok(Json(detail.into()))
}

/// The pairs (sample, rule uuid) the report lists, with each sample's label when it ran, in a stable order,
/// a page at a time. Follow `next` with the same selection until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations/{uuid}/results",
    tag = "svs",
    params(("uuid" = String, Path, description = "The validation's uuid"), ResultsQuery),
    responses(
        (status = 200, description = "A page of rows", body = ValidationResultPageBody),
        (status = 400, description = "A uuid, category, rule uuid, limit or cursor that isn't one, or a category that's only counted", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No validation with that uuid", body = ErrorBody),
    )
)]
pub(crate) async fn results(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Json<ValidationResultPageBody>, ApiError> {
    let uuid = validation_uuid(path)?;
    let params = Params::of(raw)?;
    let page = web
        .service
        .svs_validation_results(
            &actor,
            uuid,
            &selection(&params),
            params.one("cursor")?,
            params.parsed("limit", "a number from 1 to 1000")?,
        )
        .await?;
    Ok(Json(ValidationResultPageBody {
        results: page
            .results
            .into_iter()
            .map(ValidationResultBody::from)
            .collect(),
        next: page.next_cursor,
    }))
}

async fn export_results(
    format: Format,
    actor: ace_service::Actor,
    web: Web,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let uuid = validation_uuid(path)?;
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let selection = selection(&params);
    let total = service
        .svs_validation_result_count(&actor, uuid, &selection, max)
        .await?;
    let first = service
        .svs_validation_results(&actor, uuid, &selection, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first
            .results
            .into_iter()
            .map(ValidationResultBody::from)
            .collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        &format!("svs-validation-{uuid}"),
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, selection) = (service.clone(), actor.clone(), selection.clone());
            async move {
                let page = service
                    .svs_validation_results(
                        &actor,
                        uuid,
                        &selection,
                        Some(&cursor),
                        Some(EXPORT_PAGE),
                    )
                    .await?;
                Ok((
                    page.results
                        .into_iter()
                        .map(ValidationResultBody::from)
                        .collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// The selected rows of a report as CSV.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations/{uuid}/results/export/csv",
    tag = "svs",
    params(("uuid" = String, Path, description = "The validation's uuid"), SelectionQuery),
    responses(
        (status = 200, description = "The rows", content_type = "text/csv", body = String),
        (status = 400, description = "A uuid, category or rule uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No validation with that uuid", body = ErrorBody),
        (status = 413, description = "More rows than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_results_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_results(Format::Csv, actor, web, path, raw).await
}

/// The selected rows of a report as NDJSON.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations/{uuid}/results/export/ndjson",
    tag = "svs",
    params(("uuid" = String, Path, description = "The validation's uuid"), SelectionQuery),
    responses(
        (status = 200, description = "The rows", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A uuid, category or rule uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:read", body = ErrorBody),
        (status = 404, description = "No validation with that uuid", body = ErrorBody),
        (status = 413, description = "More rows than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_results_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_results(Format::Ndjson, actor, web, path, raw).await
}

/// The files of the selected rows, with the match records of every sample of those files and a manifest,
/// as one zip encrypted with AES-256 and the password `infected`. The samples' download limits apply: at
/// most 500 files and 1 GiB. The download is in the audit record.
#[utoipa::path(
    get,
    path = "/api/svs/v1/yara/validations/{uuid}/download",
    tag = "svs",
    params(("uuid" = String, Path, description = "The validation's uuid"), SelectionQuery),
    responses(
        (status = 200, description = "The zip", content_type = "application/zip", body = ZipBody),
        (status = 400, description = "A uuid, category or rule uuid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold signature:download", body = ErrorBody),
        (status = 404, description = "No validation with that uuid, or none of the selected rows' files is stored", body = ErrorBody),
        (status = 413, description = "More files or bytes than a download holds", body = ErrorBody),
    )
)]
pub(crate) async fn download(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let uuid = validation_uuid(path)?;
    let params = Params::of(raw)?;
    let download = web
        .service
        .download_svs_validation(&actor, uuid, &selection(&params))
        .await?;
    crate::svs_samples::zip_response(&web, format!("svs-validation-{uuid}"), download).await
}
