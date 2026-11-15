//! `/api/svs/v1/tests` and `/api/svs/v1/catalog/repositories`: SVS's Atomic Red Team test catalog (PLAN.md
//! 7.10 batch 4), ace3's `aceapi_v2/svs/catalog` router, over `ace_service`'s `svs_catalog`. The tests runs
//! may be registered for, as the scheduler's `svs_catalog_refresh` reads them from the catalog's
//! repositories. Everything here reads, with `svs:run_read`.
//!
//! From ace3: a page is `{tests, next}`, as the API's other pages, where ace3's is `{data, next_cursor}`;
//! and a refused parameter is 400 where ace3 answers 422. Each test carries its state and run history
//! (`test_state`, `run_count` and the rest, batch 8), read for the whole page at once, and one test adds
//! its state on each platform (`platform_states`). The same router's expectations, ignores and settings
//! are `svs_decisions`'.

use ace_service::filters::{FilterScreen, decode};
use ace_service::{CatalogRepository, CatalogTest, CatalogTestDetail, CatalogTestQuery};
use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, RawQuery, State};
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::Web;
use crate::auth::Authenticated;
use crate::error::{ApiError, ErrorBody};
use crate::export::{self, EXPORT_PAGE, ExportRow, Format, time_cell};
use crate::params::Params;

/// An Atomic Red Team test, by its `auto_generated_guid`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CatalogTestBody {
    /// The test's `auto_generated_guid`, lower case.
    guid: Uuid,
    /// The catalog repository it is read from, a name in the overlay's `svs.catalog.repositories`.
    repository: String,
    /// The ATT&CK technique of its atomic file, such as `T1059.001`.
    technique: String,
    technique_name: Option<String>,
    name: String,
    /// Its `supported_platforms`, lower case.
    platforms: Vec<String>,
    /// `command_prompt`, `powershell`, `sh`, `bash` or `manual`.
    executor: Option<String>,
    /// Its atomic file, relative to the repository.
    path: String,
    /// The repository commit this version of the test was first read from.
    commit: String,
    /// The sha256 of the test's entry; it changes exactly when the test does.
    content_hash: String,
    first_seen_at: DateTime<Utc>,
    /// When the test disappeared from its repository; it keeps its runs.
    removed_at: Option<DateTime<Utc>>,
    /// When the catalog row last changed: the `changed_since` key. A change to the test's runs or state
    /// doesn't change it.
    updated_at: DateTime<Utc>,
    /// `never_run`, `awaiting_review`, `no_expectations`, `failing`, `stale` or `validated`: `never_run`
    /// without runs, else the worst of its platforms' states.
    test_state: String,
    run_count: i64,
    last_run_id: Option<Uuid>,
    last_run_at: Option<DateTime<Utc>>,
    last_reviewed_run_id: Option<Uuid>,
    last_reviewed_at: Option<DateTime<Utc>>,
    /// Signatures expected of it on any platform, that no ignore applies to.
    expected_signatures: usize,
    /// Its latest ended or reviewed runs looked at (at most 5).
    recent_runs: i64,
    /// Of those, the runs that missed an expected signature.
    recent_runs_missing: i64,
    #[serde(skip)]
    platform_states: Vec<PlatformStateBody>,
}

/// A test on one platform.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct PlatformStateBody {
    platform: String,
    /// `never_run` (no run or decision on it), `awaiting_review`, `no_expectations`, `failing`, `stale` or
    /// `validated`.
    test_state: String,
    last_reviewed_run_id: Option<Uuid>,
    last_reviewed_at: Option<DateTime<Utc>>,
    /// Signatures expected of it there.
    expected_signatures: usize,
}

impl From<CatalogTest> for CatalogTestBody {
    fn from(t: CatalogTest) -> Self {
        let h = t.history;
        CatalogTestBody {
            test_state: h.state.as_str().to_owned(),
            run_count: h.run_count,
            last_run_id: h.last_run,
            last_run_at: h.last_run_at,
            last_reviewed_run_id: h.last_reviewed_run,
            last_reviewed_at: h.last_reviewed_at,
            expected_signatures: h.expected,
            recent_runs: h.recent_runs,
            recent_runs_missing: h.recent_runs_missing,
            platform_states: h
                .platform_states
                .into_iter()
                .map(|(platform, state)| PlatformStateBody {
                    platform,
                    test_state: state.state.as_str().to_owned(),
                    last_reviewed_run_id: state.last_reviewed_run,
                    last_reviewed_at: state.last_reviewed_at,
                    expected_signatures: state.expected,
                })
                .collect(),
            guid: t.guid,
            repository: t.repository,
            technique: t.technique,
            technique_name: t.technique_name,
            name: t.name,
            platforms: t.platforms,
            executor: t.executor,
            path: t.path,
            commit: t.commit,
            content_hash: t.content_hash,
            first_seen_at: t.first_seen_at,
            removed_at: t.removed_at,
            updated_at: t.updated_at,
        }
    }
}

fn cell(value: &Option<String>) -> String {
    value.clone().unwrap_or_default()
}

impl ExportRow for CatalogTestBody {
    const HEADER: &'static [&'static str] = &[
        "guid",
        "repository",
        "technique",
        "technique_name",
        "name",
        "platforms",
        "executor",
        "path",
        "commit",
        "content_hash",
        "first_seen_at",
        "removed_at",
        "updated_at",
        "test_state",
        "run_count",
        "last_run_id",
        "last_run_at",
        "last_reviewed_run_id",
        "last_reviewed_at",
        "expected_signatures",
        "recent_runs",
        "recent_runs_missing",
    ];

    fn cells(&self) -> Vec<String> {
        vec![
            self.guid.to_string(),
            self.repository.clone(),
            self.technique.clone(),
            cell(&self.technique_name),
            self.name.clone(),
            // joined with ",", as ace3's CSV writes them
            self.platforms.join(","),
            cell(&self.executor),
            self.path.clone(),
            self.commit.clone(),
            self.content_hash.clone(),
            time_cell(Some(self.first_seen_at)),
            time_cell(self.removed_at),
            time_cell(Some(self.updated_at)),
            self.test_state.clone(),
            self.run_count.to_string(),
            self.last_run_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            time_cell(self.last_run_at),
            self.last_reviewed_run_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            time_cell(self.last_reviewed_at),
            self.expected_signatures.to_string(),
            self.recent_runs.to_string(),
            self.recent_runs_missing.to_string(),
        ]
    }
}

/// A page of tests.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CatalogTestPageBody {
    tests: Vec<CatalogTestBody>,
    /// Pass it as `cursor`, with the same filters, for the next page; null on the last.
    next: Option<String>,
}

/// One test with its description and its atomic entry.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CatalogTestDetailBody {
    #[serde(flatten)]
    test: CatalogTestBody,
    /// Its state on each platform: each one it has a run or a decision on, and each one it supports.
    platform_states: Vec<PlatformStateBody>,
    description: Option<String>,
    /// The platforms a run of it can be on: its `supported_platforms` as ATT&CK's platform slugs, sorted.
    platform_slugs: Vec<String>,
    /// The test's entry in its atomic file: executor (commands), input_arguments, dependencies.
    #[schema(value_type = Object)]
    entry: Value,
}

impl From<CatalogTestDetail> for CatalogTestDetailBody {
    fn from(d: CatalogTestDetail) -> Self {
        let test: CatalogTestBody = d.test.into();
        CatalogTestDetailBody {
            platform_states: test.platform_states.clone(),
            test,
            description: d.description,
            platform_slugs: d.platform_slugs,
            entry: d.entry,
        }
    }
}

/// A catalog repository and the commit the catalog reflects.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CatalogRepositoryBody {
    /// Its name in the overlay's `svs.catalog.repositories`.
    name: String,
    /// It is in `svs.catalog.repositories`; one that isn't is listed while it has a row.
    configured: bool,
    /// From its overlay entry, without credentials; null without one.
    git_url: Option<String>,
    branch: Option<String>,
    /// The commit the catalog's tests were last read from; null until it is first read.
    commit: Option<String>,
    /// When that commit was read.
    refreshed_at: Option<DateTime<Utc>>,
    /// The tests read from that commit.
    test_count: i64,
    /// Tests and files that read could not use.
    skipped_count: i64,
    /// Its tests removed from the catalog.
    removed_count: i64,
    /// Why the last refresh failed; null when it succeeded. The catalog keeps the tests of the commit it
    /// last read.
    error: Option<String>,
    /// Taken out of `svs.catalog.repositories`, so its tests were removed.
    retired: bool,
}

impl From<CatalogRepository> for CatalogRepositoryBody {
    fn from(r: CatalogRepository) -> Self {
        CatalogRepositoryBody {
            name: r.name,
            configured: r.configured,
            git_url: r.git_url,
            branch: r.branch,
            commit: r.commit,
            refreshed_at: r.refreshed_at,
            test_count: r.test_count,
            skipped_count: r.skipped_count,
            removed_count: r.removed_count,
            error: r.error,
            retired: r.retired,
        }
    }
}

/// The list's parameters.
#[derive(Debug, IntoParams)]
#[into_params(parameter_in = Query)]
#[allow(dead_code)]
pub(crate) struct CatalogTestsQuery {
    /// A filter in the share-link encoding (`[!]slug:v1,v2`) with the tests screen's slugs: technique
    /// (T1059 also finds its sub-techniques), name, platform, executor, repository, removed. Repeat it for
    /// more; filters are ANDed, the values of one ORed.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    /// Only tests added, changed or removed at or after this time.
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
pub(crate) struct CatalogTestsExportQuery {
    /// A filter, as the list takes it; repeat it for more.
    #[param(style = Form, explode)]
    f: Option<Vec<String>>,
    changed_since: Option<String>,
}

fn test_query(params: &Params) -> Result<CatalogTestQuery, ApiError> {
    let (filters, _) = decode(FilterScreen::SvsTests, &params.all("f"), true)?;
    Ok(CatalogTestQuery {
        filters,
        changed_since: params.time("changed_since")?,
        ..CatalogTestQuery::default()
    })
}

/// The catalog's tests by technique, then name, a page at a time. Follow `next` with the same filters
/// until it's null.
#[utoipa::path(
    get,
    path = "/api/svs/v1/tests",
    tag = "svs",
    params(CatalogTestsQuery),
    responses(
        (status = 200, description = "A page of tests", body = CatalogTestPageBody),
        (status = 400, description = "A filter, time, limit or cursor that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn list(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Json<CatalogTestPageBody>, ApiError> {
    let params = Params::of(raw)?;
    let query = test_query(&params)?;
    let page = web
        .service
        .svs_catalog_tests(
            &actor,
            &query,
            params.one("cursor")?,
            params.parsed("limit", "a number from 1 to 1000")?,
        )
        .await?;
    Ok(Json(CatalogTestPageBody {
        tests: page.tests.into_iter().map(CatalogTestBody::from).collect(),
        next: page.next_cursor,
    }))
}

async fn export_tests(
    format: Format,
    actor: ace_service::Actor,
    web: Web,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    let (service, max) = (web.service, web.config.max_export_rows);
    let params = Params::of(raw)?;
    let query = test_query(&params)?;
    let total = service.svs_catalog_test_count(&actor, &query, max).await?;
    let first = service
        .svs_catalog_tests(&actor, &query, None, Some(EXPORT_PAGE))
        .await?;
    let first = (
        first.tests.into_iter().map(CatalogTestBody::from).collect(),
        first.next_cursor,
    );
    export::respond(
        format,
        "svs-tests",
        max,
        total,
        first,
        move |cursor: String| {
            let (service, actor, query) = (service.clone(), actor.clone(), query.clone());
            async move {
                let page = service
                    .svs_catalog_tests(&actor, &query, Some(&cursor), Some(EXPORT_PAGE))
                    .await?;
                Ok((
                    page.tests.into_iter().map(CatalogTestBody::from).collect(),
                    page.next_cursor,
                ))
            }
        },
    )
}

/// Every test the list's filters match, by technique, then name, as CSV, its platforms joined with `,`. A
/// failure part-way ends the file there.
#[utoipa::path(
    get,
    path = "/api/svs/v1/tests/export/csv",
    tag = "svs",
    params(CatalogTestsExportQuery),
    responses(
        (status = 200, description = "The tests", content_type = "text/csv", body = String),
        (status = 400, description = "A filter or time that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More tests than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_csv(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_tests(Format::Csv, actor, web, raw).await
}

/// Every test the list's filters match, by technique, then name, as NDJSON: one as the list gives it on
/// each line. A failure part-way ends it with an `{"error": ...}` line.
#[utoipa::path(
    get,
    path = "/api/svs/v1/tests/export/ndjson",
    tag = "svs",
    params(CatalogTestsExportQuery),
    responses(
        (status = 200, description = "The tests", content_type = "application/x-ndjson", body = String),
        (status = 400, description = "A filter or time that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 413, description = "More tests than an export holds", body = ErrorBody),
    )
)]
pub(crate) async fn export_ndjson(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    raw: RawQuery,
) -> Result<Response, ApiError> {
    export_tests(Format::Ndjson, actor, web, raw).await
}

/// One test with its description and its atomic entry: commands, input arguments, dependencies.
#[utoipa::path(
    get,
    path = "/api/svs/v1/tests/{guid}",
    tag = "svs",
    params(("guid" = String, Path, description = "The test's auto_generated_guid")),
    responses(
        (status = 200, description = "The test", body = CatalogTestDetailBody),
        (status = 400, description = "A guid that isn't one", body = ErrorBody),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
        (status = 404, description = "No test with that guid in the catalog", body = ErrorBody),
    )
)]
pub(crate) async fn detail(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<CatalogTestDetailBody>, ApiError> {
    let Path(guid) = path?;
    let detail = web.service.svs_catalog_test(&actor, &guid).await?;
    Ok(Json(detail.into()))
}

/// Each catalog repository with the commit the catalog reflects, when it was read, its test count and its
/// last error, by name: what `ace svs catalog status` prints. A launcher checks out that commit to run the
/// tests as the catalog has them.
#[utoipa::path(
    get,
    path = "/api/svs/v1/catalog/repositories",
    tag = "svs",
    responses(
        (status = 200, description = "The repositories", body = Vec<CatalogRepositoryBody>),
        (status = 401, description = "No credential, or one that isn't valid", body = ErrorBody),
        (status = 403, description = "The actor doesn't hold svs:run_read", body = ErrorBody),
    )
)]
pub(crate) async fn repositories(
    Authenticated(actor): Authenticated,
    State(web): State<Web>,
) -> Result<Json<Vec<CatalogRepositoryBody>>, ApiError> {
    let repositories = web.service.svs_catalog_repositories(&actor).await?;
    Ok(Json(
        repositories
            .into_iter()
            .map(CatalogRepositoryBody::from)
            .collect(),
    ))
}
