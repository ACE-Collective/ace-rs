//! SVS's Atomic Red Team test catalog (PLAN.md 7.10 batch 4): ace3's `aceapi_v2/svs/catalog/service.py` and
//! the refresh of `saq/svs/catalog.py`, over `ace_core::svs::catalog`.
//!
//! **Reading** needs `svs:run_read`, as in ace3: the tests by technique and then name, a page at a time
//! with ace3's tests screen (`FilterScreen::SvsTests`), each with its state and run history, one test with
//! its description and its atomic entry, and each catalog repository's status.
//!
//! **The refresh** needs `svs:catalog_refresh`, which only the scheduler's `svs_catalog_refresh` holds;
//! `ace svs catalog refresh` acts as that component. `refresh_svs_catalog` fetches each repository in the
//! overlay's `svs.catalog.repositories`, reads its tests when its commit changed (or when forced, or when
//! its last refresh failed), and removes the tests of every repository taken out of the overlay. Git runs
//! outside any transaction, on a blocking thread. What a refresh writes, it writes under its repository's
//! row lock, with one audit row for each write:
//! - `store_svs_catalog`: a commit's tests, with the counts of what it added, changed and removed;
//! - `record_svs_catalog_error`: why a refresh failed, once: a failure that repeats writes nothing, so a
//!   repository that stays broken doesn't add a row every five minutes;
//! - `retire_svs_catalog_repository`: a repository's tests removed.
//!
//! A failure of one repository is recorded on its row and returned in its result; the others are still
//! read.
//!
//! What differs from ace3's:
//! - Each test carries its state and run history (`svs_test_state`, batch 8), read for the whole page at
//!   once, as ace3's does: `history`, and its `exclusion` (batch 10). One test adds its state on each
//!   platform. The screen's `excluded` filter finds the tests a person excluded.
//! - ace3's refresh is not audited; here each write of it is.
//! - Two replicas may refresh at once: each reads its own mirror and the row lock orders their writes. One
//!   that fetched an older commit can store it after the other stored a newer one; the next refresh sees
//!   the commit differ and reads the newer one again.

use ace_core::svs::catalog::{
    self, CatalogConfig, ParseResult, RefreshResult, RepositoryStatus, Skipped,
};
use ace_core::svs::test_state::TestHistory;
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::alerts::page_limit;
use crate::filters::{FilterEntry, FilterScreen, Resolved};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SVS_CATALOG_REFRESH, SVS_RUN_READ};
use crate::svs_decisions::TestExclusion;
use crate::svs_test_state::{StateTest, catalog_histories};
use crate::{Actor, Service, ServiceError};

/// The most tests one page holds.
pub const MAX_CATALOG_TESTS_PAGE: u32 = 1000;
/// How many of a refresh's skipped tests and files its audit row lists; the count is always whole.
const AUDITED_SKIPS: usize = 50;

/// An Atomic Red Team test, by its `auto_generated_guid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogTest {
    pub guid: Uuid,
    /// The catalog repository it is read from.
    pub repository: String,
    /// The ATT&CK technique of its atomic file, such as `T1059.001`.
    pub technique: String,
    pub technique_name: Option<String>,
    pub name: String,
    /// Its `supported_platforms`, lower case.
    pub platforms: Vec<String>,
    pub executor: Option<String>,
    /// Its atomic file, relative to the repository.
    pub path: String,
    /// The repository commit this version of the test was first read from.
    pub commit: String,
    /// The sha256 of the test's entry; it changes exactly when the test does.
    pub content_hash: String,
    pub first_seen_at: DateTime<Utc>,
    /// When the test disappeared from its repository; it keeps its runs.
    pub removed_at: Option<DateTime<Utc>>,
    /// When the catalog row last changed: the `changed_since` key. A change to the test's runs or state
    /// doesn't change it.
    pub updated_at: DateTime<Utc>,
    /// Its state and run history (`ace_core::svs::test_state`): excluded while it is excluded, never_run
    /// without runs, else the worst of its platforms' states. One test's detail has each platform's in
    /// `platform_states`.
    pub history: TestHistory,
    /// Who excluded it, when and why; None while it isn't excluded. Excluding a test doesn't change its
    /// row, so not its `updated_at`.
    pub exclusion: Option<TestExclusion>,
}

/// One test with its description and its entry.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogTestDetail {
    pub test: CatalogTest,
    pub description: Option<String>,
    /// The platforms a run of it can be on: its `supported_platforms` as ATT&CK's platform slugs, sorted.
    pub platform_slugs: Vec<String>,
    /// The test's entry in its atomic file: executor (commands), input arguments, dependencies.
    pub entry: Value,
}

/// Which tests to list.
#[derive(Debug, Clone)]
pub struct CatalogTestQuery {
    pub filters: Vec<FilterEntry>,
    /// Only tests added, changed or removed at or after this.
    pub changed_since: Option<DateTime<Utc>>,
    /// The timezone relative date filters resolve in; the tests screen has none, so it only checks.
    pub tz: Tz,
}

impl Default for CatalogTestQuery {
    fn default() -> Self {
        CatalogTestQuery {
            filters: Vec::new(),
            changed_since: None,
            tz: Tz::UTC,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogTestPage {
    pub tests: Vec<CatalogTest>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListCursor {
    technique: String,
    name: String,
    id: i64,
}

fn encode(cursor: &ListCursor) -> String {
    hex::encode(serde_json::to_vec(cursor).unwrap_or_default())
}

fn decode(text: &str) -> Result<ListCursor, ServiceError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| ServiceError::InvalidRequest(format!("{text:?} isn't a cursor")))
}

/// The tests screen's filters as the list's SQL takes them: each filter's values and its inverse's.
struct Params {
    techniques: [Option<Vec<String>>; 2],
    names: [Option<Vec<String>>; 2],
    platforms: [Option<Vec<String>>; 2],
    executors: [Option<Vec<String>>; 2],
    repositories: [Option<Vec<String>>; 2],
    removed: [Option<Vec<String>>; 2],
    excluded: [Option<Vec<String>>; 2],
}

fn params(query: &CatalogTestQuery) -> Result<Params, ServiceError> {
    let f = Resolved::new(FilterScreen::SvsTests, &query.filters, Utc::now(), query.tz)?;
    Ok(Params {
        techniques: [f.names("technique", false), f.names("technique", true)],
        names: [
            f.patterns("name", false, false),
            f.patterns("name", true, false),
        ],
        platforms: [f.names("platform", false), f.names("platform", true)],
        executors: [f.names("executor", false), f.names("executor", true)],
        repositories: [
            f.patterns("repository", false, false),
            f.patterns("repository", true, false),
        ],
        removed: [f.names("removed", false), f.names("removed", true)],
        excluded: [f.names("excluded", false), f.names("excluded", true)],
    })
}

/// A flag filter as ace3's condition reads it: `true` or `false` when it holds only that, `both` when it
/// holds both, which filters nothing (and so its inverse matches nothing), and None when unset.
fn flag(values: &Option<Vec<String>>) -> Option<&'static str> {
    match values.as_deref() {
        None => None,
        Some([one]) if one == "true" => Some("true"),
        Some([one]) if one == "false" => Some("false"),
        Some(_) => Some("both"),
    }
}

struct ListRow {
    id: i64,
    guid: Uuid,
    repository: String,
    technique: String,
    technique_name: Option<String>,
    name: String,
    platforms: Vec<String>,
    executor: Option<String>,
    path: String,
    commit: String,
    content_hash: String,
    first_seen_at: DateTime<Utc>,
    removed_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl ListRow {
    fn state_test(&self) -> StateTest {
        StateTest {
            guid: self.guid,
            content_hash: self.content_hash.clone(),
            platforms: self.platforms.clone(),
        }
    }

    fn test(self, history: TestHistory, exclusion: Option<TestExclusion>) -> CatalogTest {
        CatalogTest {
            history,
            exclusion,
            guid: self.guid,
            repository: self.repository,
            technique: self.technique,
            technique_name: self.technique_name,
            name: self.name,
            platforms: self.platforms,
            executor: self.executor,
            path: self.path,
            commit: self.commit,
            content_hash: self.content_hash,
            first_seen_at: self.first_seen_at,
            removed_at: self.removed_at,
            updated_at: self.updated_at,
        }
    }
}

/// The tests `p` matches, by technique, then name, in code point order (T1059.003 before T10590, whatever
/// the database's collation), after `after`. Each filter's values are ORed and the
/// filters ANDed; an inverse matches exactly the rows its filter doesn't, a NULL executor included, as
/// ace3's CASE does. A technique matches its sub-techniques too: T1059 finds T1059.001.
async fn list(
    conn: &mut sqlx::PgConnection,
    p: &Params,
    changed_since: Option<DateTime<Utc>>,
    after: Option<&ListCursor>,
    limit: i64,
    settle: f64,
) -> Result<Vec<ListRow>, sqlx::Error> {
    let (after_technique, after_name, after_id) = match after {
        Some(c) => (
            Some(c.technique.as_str()),
            Some(c.name.as_str()),
            Some(c.id),
        ),
        None => (None, None, None),
    };
    sqlx::query_as!(
        ListRow,
        r#"SELECT id, guid, repository, technique, technique_name, name, platforms, executor, path, commit,
                  content_hash, first_seen_at, removed_at, updated_at
           FROM svs.catalog_tests t
           WHERE ($1::text[] IS NULL OR EXISTS (
                   SELECT FROM unnest($1::text[]) v
                   WHERE t.technique = v OR (strpos(v, '.') = 0 AND starts_with(t.technique, v || '.'))))
             AND ($2::text[] IS NULL OR NOT EXISTS (
                   SELECT FROM unnest($2::text[]) v
                   WHERE t.technique = v OR (strpos(v, '.') = 0 AND starts_with(t.technique, v || '.'))))
             AND ($3::text[] IS NULL OR t.name ILIKE ANY ($3))
             AND ($4::text[] IS NULL OR NOT t.name ILIKE ANY ($4))
             AND ($5::text[] IS NULL OR t.platforms && $5)
             AND ($6::text[] IS NULL OR NOT t.platforms && $6)
             AND ($7::text[] IS NULL OR COALESCE(t.executor = ANY ($7), false))
             AND ($8::text[] IS NULL OR NOT COALESCE(t.executor = ANY ($8), false))
             AND ($9::text[] IS NULL OR t.repository ILIKE ANY ($9))
             AND ($10::text[] IS NULL OR NOT t.repository ILIKE ANY ($10))
             AND ($11::text IS NULL OR $11 = 'both'
                  OR CASE $11 WHEN 'true' THEN t.removed_at IS NOT NULL ELSE t.removed_at IS NULL END)
             AND ($12::text IS NULL OR $12 <> 'both'
                  AND NOT CASE $12 WHEN 'true' THEN t.removed_at IS NOT NULL ELSE t.removed_at IS NULL END)
             AND ($13::timestamptz IS NULL
                  OR (t.updated_at >= $13 AND t.updated_at < now() - make_interval(secs => $18)))
             AND ($14::text IS NULL
                  OR (t.technique COLLATE "C", t.name COLLATE "C", t.id) > ($14, $15::text, $16::bigint))
             AND ($19::text IS NULL OR $19 = 'both'
                  OR (EXISTS (SELECT FROM svs.test_exclusions x WHERE x.test_guid = t.guid)) = ($19 = 'true'))
             AND ($20::text IS NULL OR $20 <> 'both'
                  AND (EXISTS (SELECT FROM svs.test_exclusions x WHERE x.test_guid = t.guid)) <> ($20 = 'true'))
           ORDER BY t.technique COLLATE "C", t.name COLLATE "C", t.id
           LIMIT $17"#,
        p.techniques[0].as_deref(),
        p.techniques[1].as_deref(),
        p.names[0].as_deref(),
        p.names[1].as_deref(),
        p.platforms[0].as_deref(),
        p.platforms[1].as_deref(),
        p.executors[0].as_deref(),
        p.executors[1].as_deref(),
        p.repositories[0].as_deref(),
        p.repositories[1].as_deref(),
        flag(&p.removed[0]),
        flag(&p.removed[1]),
        changed_since,
        after_technique,
        after_name,
        after_id,
        limit,
        settle,
        flag(&p.excluded[0]),
        flag(&p.excluded[1]),
    )
    .fetch_all(conn)
    .await
}

/// What a stored commit's audit row keeps of the repository before it.
#[derive(Serialize)]
struct RepositoryBefore<'a> {
    commit: Option<&'a str>,
    tests: i32,
}

impl Recorded for RepositoryBefore<'_> {}

/// What a stored commit's audit row keeps of what it did.
#[derive(Serialize)]
struct RepositoryAfter<'a> {
    commit: &'a str,
    tests: i64,
    added: i64,
    changed: i64,
    removed: i64,
    skipped: usize,
    /// The first of what it skipped; `skipped` counts them all.
    skipped_first: &'a [Skipped],
}

impl Recorded for RepositoryAfter<'_> {}

#[derive(Serialize)]
struct RepositoryError<'a> {
    error: Option<&'a str>,
}

impl Recorded for RepositoryError<'_> {}

#[derive(Serialize)]
struct RepositoryRetired {
    removed: i64,
}

impl Recorded for RepositoryRetired {}

fn no_test(guid: &str) -> ServiceError {
    ServiceError::NotFound(format!("test {guid} in the catalog"))
}

impl Service {
    /// The service with the catalog's settings, the overlay's `svs.catalog` (PLAN.md 7.10 batch 4).
    pub fn with_catalog(mut self, config: CatalogConfig) -> Self {
        self.catalog = std::sync::Arc::new(config);
        self
    }

    /// The catalog's settings.
    pub fn catalog_config(&self) -> std::sync::Arc<CatalogConfig> {
        self.catalog.clone()
    }

    /// A page of the catalog's tests by technique, then name, after where `cursor` left off. It needs
    /// `svs:run_read`.
    pub async fn svs_catalog_tests(
        &self,
        actor: &Actor,
        query: &CatalogTestQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<CatalogTestPage, ServiceError> {
        let limit = page_limit(limit, MAX_CATALOG_TESTS_PAGE)?;
        let after = &cursor.map(decode).transpose()?;
        let p = &params(query)?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_catalog_tests", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let mut rows = list(
                        tx.conn(),
                        p,
                        changed_since,
                        after.as_ref(),
                        limit + 1,
                        settle,
                    )
                    .await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last().map(|last| {
                            encode(&ListCursor {
                                technique: last.technique.clone(),
                                name: last.name.clone(),
                                id: last.id,
                            })
                        })
                    } else {
                        None
                    };
                    // each test's state and run history, for the whole page at once
                    let state_tests: Vec<StateTest> =
                        rows.iter().map(ListRow::state_test).collect();
                    let mut histories = catalog_histories(tx.conn(), &state_tests).await?;
                    Ok(CatalogTestPage {
                        tests: rows
                            .into_iter()
                            .map(|row| {
                                let (history, exclusion) = histories
                                    .remove(&row.guid)
                                    .unwrap_or_else(|| (TestHistory::never_run(), None));
                                row.test(history, exclusion)
                            })
                            .collect(),
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// How many tests `query` matches, counting up to `max` + 1, for an export to refuse one too large
    /// before it starts. It needs `svs:run_read`.
    pub async fn svs_catalog_test_count(
        &self,
        actor: &Actor,
        query: &CatalogTestQuery,
        max: i64,
    ) -> Result<i64, ServiceError> {
        let p = &params(query)?;
        let (changed_since, settle) = (query.changed_since, self.feed_settle_seconds());
        self.gate
            .read(actor, "svs_catalog_test_count", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let rows = list(
                        tx.conn(),
                        p,
                        changed_since,
                        None,
                        max.saturating_add(1),
                        settle,
                    )
                    .await?;
                    Ok(rows.len() as i64)
                })
            })
            .await
    }

    /// One test with its description and its atomic entry: commands, input arguments, dependencies. `guid`
    /// that isn't a uuid is `InvalidRequest`, and one the catalog doesn't have `NotFound`. It needs
    /// `svs:run_read`.
    pub async fn svs_catalog_test(
        &self,
        actor: &Actor,
        guid: &str,
    ) -> Result<CatalogTestDetail, ServiceError> {
        let parsed: Uuid = guid
            .parse()
            .map_err(|_| ServiceError::InvalidRequest(format!("invalid test guid {guid:?}")))?;
        self.gate
            .read(actor, "svs_catalog_test", &SVS_RUN_READ, &|tx| {
                Box::pin(async move {
                    let row = sqlx::query!(
                        "SELECT id, guid, repository, technique, technique_name, name, description,
                                platforms, executor, test, path, commit, content_hash, first_seen_at,
                                removed_at, updated_at
                         FROM svs.catalog_tests WHERE guid = $1",
                        parsed,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .ok_or_else(|| no_test(guid))?;
                    let (history, exclusion) = catalog_histories(
                        tx.conn(),
                        &[StateTest {
                            guid: row.guid,
                            content_hash: row.content_hash.clone(),
                            platforms: row.platforms.clone(),
                        }],
                    )
                    .await?
                    .remove(&row.guid)
                    .unwrap_or_else(|| (TestHistory::never_run(), None));
                    Ok(CatalogTestDetail {
                        platform_slugs: catalog::platform_slugs(&row.platforms),
                        description: row.description,
                        entry: row.test,
                        test: CatalogTest {
                            guid: row.guid,
                            repository: row.repository,
                            technique: row.technique,
                            technique_name: row.technique_name,
                            name: row.name,
                            platforms: row.platforms,
                            executor: row.executor,
                            path: row.path,
                            commit: row.commit,
                            content_hash: row.content_hash,
                            first_seen_at: row.first_seen_at,
                            removed_at: row.removed_at,
                            updated_at: row.updated_at,
                            history,
                            exclusion,
                        },
                    })
                })
            })
            .await
    }

    /// Each catalog repository with the commit the catalog reflects, when it was read, its test count and
    /// its last error, by name: every repository in `svs.catalog.repositories`, and every one that has a
    /// row. A launcher checks out that commit to run the tests as the catalog has them. It needs
    /// `svs:run_read`.
    pub async fn svs_catalog_repositories(
        &self,
        actor: &Actor,
    ) -> Result<Vec<RepositoryStatus>, ServiceError> {
        let config = &self.catalog_config();
        self.gate
            .read(actor, "svs_catalog_repositories", &SVS_RUN_READ, &|tx| {
                Box::pin(async move { Ok(catalog::repository_status(tx.conn(), config).await?) })
            })
            .await
    }

    /// Stores `parsed`, the tests of `repository`'s `commit`, as the catalog's (the module's docs), and
    /// returns what it did. It needs `svs:catalog_refresh`, and records the refresh.
    pub async fn store_svs_catalog(
        &self,
        actor: &Actor,
        repository: &str,
        commit: &str,
        parsed: &ParseResult,
    ) -> Result<RefreshResult, ServiceError> {
        self.gate
            .write(actor, "store_svs_catalog", &SVS_CATALOG_REFRESH, &|tx| {
                Box::pin(async move {
                    let before = catalog::repository_row(tx.conn(), repository).await?;
                    let mut result = RefreshResult {
                        repository: repository.to_owned(),
                        commit: Some(commit.to_owned()),
                        ..RefreshResult::default()
                    };
                    catalog::store(tx.conn(), repository, commit, parsed, &mut result).await?;
                    let change = Change::updated(
                        Target::svs_catalog_repository(repository),
                        &RepositoryBefore {
                            commit: before.as_ref().and_then(|row| row.commit.as_deref()),
                            tests: before.as_ref().map_or(0, |row| row.test_count),
                        },
                        &RepositoryAfter {
                            commit,
                            tests: result.tests,
                            added: result.added,
                            changed: result.changed,
                            removed: result.removed,
                            skipped: result.skipped.len(),
                            skipped_first: &result.skipped
                                [..result.skipped.len().min(AUDITED_SKIPS)],
                        },
                    )?;
                    Ok(Audited::changed(result, change))
                })
            })
            .await
    }

    /// Puts why a refresh of `repository` failed on its row, and returns whether the row changed: a
    /// failure it already holds writes nothing. It needs `svs:catalog_refresh`, and records the change.
    pub async fn record_svs_catalog_error(
        &self,
        actor: &Actor,
        repository: &str,
        error: &str,
    ) -> Result<bool, ServiceError> {
        self.gate
            .write(
                actor,
                "record_svs_catalog_error",
                &SVS_CATALOG_REFRESH,
                &|tx| {
                    Box::pin(async move {
                        let before = catalog::repository_row(tx.conn(), repository).await?;
                        if !catalog::record_error(tx.conn(), repository, error).await? {
                            return Ok(Audited::unchanged(false));
                        }
                        let after = catalog::repository_row(tx.conn(), repository).await?;
                        let change = Change::updated(
                            Target::svs_catalog_repository(repository),
                            &RepositoryError {
                                error: before.as_ref().and_then(|row| row.error.as_deref()),
                            },
                            &RepositoryError {
                                error: after.as_ref().and_then(|row| row.error.as_deref()),
                            },
                        )?;
                        Ok(Audited::changed(true, change))
                    })
                },
            )
            .await
    }

    /// Removes the tests of `repository`, which is no longer in `svs.catalog.repositories`; they keep their
    /// rows and runs. A repository the overlay still lists is `InvalidRequest`. It needs
    /// `svs:catalog_refresh`, and records the removal.
    pub async fn retire_svs_catalog_repository(
        &self,
        actor: &Actor,
        repository: &str,
    ) -> Result<RefreshResult, ServiceError> {
        if self.catalog.repositories.contains_key(repository) {
            return Err(ServiceError::InvalidRequest(format!(
                "{repository} is in svs.catalog.repositories"
            )));
        }
        self.gate
            .write(
                actor,
                "retire_svs_catalog_repository",
                &SVS_CATALOG_REFRESH,
                &|tx| {
                    Box::pin(async move {
                        let removed = catalog::retire(tx.conn(), repository).await?;
                        let result = RefreshResult {
                            repository: repository.to_owned(),
                            retired: true,
                            removed,
                            ..RefreshResult::default()
                        };
                        let change = Change::removed(
                            Target::svs_catalog_repository(repository),
                            &RepositoryRetired { removed },
                        )?;
                        Ok(Audited::changed(result, change))
                    })
                },
            )
            .await
    }

    /// Refreshes the catalog: ace3's `refresh_catalog`, or its `refresh_repository` when `only` names one.
    /// Each repository in `svs.catalog.repositories` is fetched and, when its commit changed since the last
    /// refresh (or `force`, or its last refresh failed), its tests are read and stored; then every other
    /// repository that still has tests in the catalog is retired. A failure is recorded on the
    /// repository's row and returned in its result's `error`. It needs `svs:catalog_refresh`.
    pub async fn refresh_svs_catalog(
        &self,
        actor: &Actor,
        only: Option<&str>,
        force: bool,
    ) -> Result<Vec<RefreshResult>, ServiceError> {
        if !self.gate.allowed(actor, &SVS_CATALOG_REFRESH).await? {
            tracing::warn!(%actor, permission = %SVS_CATALOG_REFRESH, "permission denied");
            return Err(ServiceError::PermissionDenied {
                actor: actor.to_string(),
                permission: SVS_CATALOG_REFRESH,
            });
        }
        let config = self.catalog_config();
        let names: Vec<String> = match only {
            Some(name) => vec![name.to_owned()],
            None => config.repositories.keys().cloned().collect(),
        };
        let mut results = Vec::with_capacity(names.len());
        for name in &names {
            results.push(self.refresh_repository(actor, &config, name, force).await);
        }
        if only.is_some() {
            return Ok(results);
        }
        let configured: Vec<String> = config.repositories.keys().cloned().collect();
        let unconfigured = {
            let mut conn = self.gate.db().pool().acquire().await?;
            catalog::unconfigured(&mut conn, &configured).await?
        };
        for repository in unconfigured {
            match self.retire_svs_catalog_repository(actor, &repository).await {
                Ok(result) => {
                    tracing::warn!(
                        repository,
                        removed = result.removed,
                        "svs catalog repository {repository} is no longer in svs.catalog.repositories: \
                         {} tests removed",
                        result.removed
                    );
                    results.push(result);
                }
                Err(e) => {
                    tracing::error!(
                        repository,
                        "unable to retire the svs catalog repository {repository}: {e}"
                    );
                    results.push(RefreshResult {
                        repository,
                        retired: true,
                        error: Some(format!("retire failed: {e}")),
                        ..RefreshResult::default()
                    });
                }
            }
        }
        Ok(results)
    }

    /// One repository's refresh: ace3's `refresh_repository`. It never fails: what went wrong is in the
    /// result's `error`, and on the repository's row when that could be written.
    async fn refresh_repository(
        &self,
        actor: &Actor,
        config: &std::sync::Arc<CatalogConfig>,
        repository: &str,
        force: bool,
    ) -> RefreshResult {
        let mut result = RefreshResult {
            repository: repository.to_owned(),
            ..RefreshResult::default()
        };
        let outcome = self
            .read_and_store(actor, config, repository, force, &mut result)
            .await;
        let error = match outcome {
            Ok(()) => {
                if result.refreshed {
                    for skipped in &result.skipped {
                        tracing::warn!(
                            repository,
                            path = skipped.path,
                            test_name = skipped.name,
                            reason = skipped.reason,
                            "svs catalog skipped a test of {repository}: {}",
                            skipped.reason
                        );
                    }
                    tracing::info!(
                        repository,
                        commit = result.commit,
                        tests = result.tests,
                        added = result.added,
                        changed = result.changed,
                        removed = result.removed,
                        skipped = result.skipped.len(),
                        "svs catalog of {repository} refreshed"
                    );
                }
                return result;
            }
            // what the repository itself did wrong is said as it is; anything else is a failed refresh
            Err(RefreshFailure::Catalog(e)) => e.0,
            Err(RefreshFailure::Other(e)) => format!("refresh failed: {e}"),
        };
        // git's words may be the remote's: nothing of them reaches a terminal or a log as a control code
        let error = catalog::printable(&error);
        tracing::error!(
            repository,
            commit = result.commit,
            "svs catalog refresh of {repository} failed: {error}"
        );
        if let Err(e) = self
            .record_svs_catalog_error(actor, repository, &error)
            .await
        {
            tracing::error!(
                repository,
                "unable to record the svs catalog error of {repository}: {e}"
            );
        }
        result.error = Some(error);
        result
    }

    async fn read_and_store(
        &self,
        actor: &Actor,
        config: &std::sync::Arc<CatalogConfig>,
        repository: &str,
        force: bool,
        result: &mut RefreshResult,
    ) -> Result<(), RefreshFailure> {
        let current = {
            let mut conn = self.gate.db().pool().acquire().await.map_err(other)?;
            catalog::repository_row(&mut conn, repository)
                .await
                .map_err(other)?
        };
        // the commit already read isn't read again, unless forced or its last refresh failed
        let already_read = current
            .filter(|row| !force && row.error.is_none())
            .and_then(|row| row.commit);
        let read = {
            let (config, repository) = (config.clone(), repository.to_owned());
            tokio::task::spawn_blocking(move || {
                catalog::read_repository(&config, &repository, already_read.as_deref())
            })
            .await
            .map_err(other)?
            .map_err(RefreshFailure::Catalog)?
        };
        result.commit = Some(read.commit.clone());
        let Some(parsed) = read.parsed else {
            return Ok(());
        };
        *result = self
            .store_svs_catalog(actor, repository, &read.commit, &parsed)
            .await
            .map_err(other)?;
        Ok(())
    }
}

enum RefreshFailure {
    Catalog(catalog::CatalogError),
    Other(String),
}

fn other(error: impl std::fmt::Display) -> RefreshFailure {
    RefreshFailure::Other(error.to_string())
}
