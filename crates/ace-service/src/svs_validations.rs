//! SVS's YARA validations (PLAN.md 7.10 batch 3), for the `svs/yara/validations` routes and the signatures
//! area's validations pages: ace3's `aceapi_v2/svs/yara/validations/service.py`, `saq/svs/validations.py`'s
//! requests and retention, and `validation_filters.py`. The queue and its workers are
//! `ace_core::svs::validations`; migration 0049 holds the tables.
//!
//! **Two audiences.** A rule repository's CI holds `svs:validate` only: it requests a validation and reads
//! its status, which carries counts and rule names and uuids, never a sample's sha256, file name or content.
//! Everyone with `signature:read` reads the list, the reports and their rows, which name the samples; their
//! files need `signature:download`, and that download is audited.
//!
//! **Requests.** A request is answered by a validation queued or running for the same commits, else by a
//! completed one whose corpus version and engine fingerprint are still current, else by a new queued one. A
//! failed validation is never reused. Every request has an audit row, a new validation's `added` and an
//! answered one's `read`, as ace3 logs an AUDIT line either way.
//!
//! **Retention.** `prune_svs_validations` removes the finished validations older than
//! `svs.yara.retention_days` with their rows, in batches of `prune_batch_size`, each a transaction with its
//! audit row: the scheduler's `svs_validations_prune`, under `svs:validation_prune`, which only that task's
//! component holds.
//!
//! From ace3, and what differs:
//! - Who asked is the actor, so a key with no owner may ask, where ace3 refuses one with 422, as batch 2's
//!   sample writes take any actor.
//! - The list's `requested_by` is the actor's recorded name, where ace3 joins the user's.
//! - A download names each file by its sha256 inside the zip, as the samples' downloads do; there's no node,
//!   so none is skipped for being on another node's pool.

use std::collections::BTreeMap;

use ace_core::svs::validations::{
    NEW_FP_CATEGORIES, REGRESSION_CATEGORIES, ValidationRequest, ValidationState,
    corpus_version_in, engine_fingerprint, request_validation,
};
use ace_core::svs::yara::diff::Category;
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::alerts::{RecordedActor, page_limit};
use crate::filters::{FilterEntry, FilterScreen, Resolved, split};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::{SIGNATURE_DOWNLOAD, SIGNATURE_READ, SVS_VALIDATE, SVS_VALIDATION_PRUNE};
use crate::svs_samples::{
    MAX_SAMPLE_DOWNLOAD_BYTES, MAX_SAMPLE_DOWNLOAD_FILES, SampleDownload, download_of,
};
use crate::{Actor, Service, ServiceError};

/// The most validations or result rows one page holds, ace3's `LISTING_MAX_PAGE_SIZE`.
pub const MAX_VALIDATIONS_PAGE: u32 = 1000;

/// Where the GUI shows a validation's report, relative to its host: ace3's `report_path`.
pub fn validation_report_path(uuid: Uuid) -> String {
    format!("/signatures/validations/{uuid}")
}

/// What a rule repository's CI asks for: validate `head_sha` against `base_sha`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationAsk {
    /// A name in the overlay's `svs.yara.repositories`.
    pub repository: String,
    /// Full commit ids: an abbreviation would make two requests for one commit differ.
    pub base_sha: String,
    pub head_sha: String,
    /// The branch `head_sha` is on.
    pub branch: String,
    /// The pull request, for the report's link back.
    pub pr_url: Option<String>,
}

/// The rules with samples in one category, most samples first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleCount {
    pub rule_uuid: String,
    pub rule_name: String,
    pub count: i64,
}

/// A head rule file that doesn't compile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompileProblem {
    pub file: String,
    pub error: String,
}

/// A validation as the CI sees it (`svs:validate`): its state, counts, rule names and uuids. It never
/// carries a sample's sha256, file name or content.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ValidationStatus {
    pub uuid: Uuid,
    pub state: ValidationState,
    pub error: Option<String>,
    pub repository: String,
    pub base_sha: String,
    pub head_sha: String,
    pub branch: String,
    pub pr_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub diffed: Option<bool>,
    /// Pairs per category, every category included, once completed.
    pub counts: Option<BTreeMap<String, i64>>,
    /// The rules with samples in each listed category.
    pub rules: BTreeMap<String, Vec<RuleCount>>,
    pub compile_errors: Vec<CompileProblem>,
    pub ruleset_error: Option<String>,
    pub report_path: String,
}

/// One validation in the list (`signature:read`).
#[derive(Debug, Clone, PartialEq)]
pub struct Validation {
    pub uuid: Uuid,
    pub repository: String,
    pub base_sha: String,
    pub head_sha: String,
    pub branch: String,
    pub pr_url: Option<String>,
    pub state: ValidationState,
    pub requested_by: RecordedActor,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub diffed: Option<bool>,
    /// regression + regression_unconfirmed.
    pub regressions: Option<i32>,
    /// new_fp + new_fp_other_rule.
    pub new_fps: Option<i32>,
    /// The head's rule files that don't compile, plus one if its rules wouldn't load.
    pub compile_errors: Option<i32>,
    pub counts: Option<BTreeMap<String, i64>>,
    pub updated_at: DateTime<Utc>,
}

/// One validation with its report.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationDetail {
    pub validation: Validation,
    /// How many times a worker claimed it.
    pub attempts: i32,
    /// The node that ran (or runs) it.
    pub claimed_by: Option<String>,
    pub corpus_version: Option<String>,
    pub engine_fingerprint: Option<String>,
    /// How each commit compiled, the rules added, removed and changed, the rules that can't be tested, the
    /// samples skipped and the timings; its listed pairs are its results.
    pub report: Option<Value>,
}

/// Which validations to list.
#[derive(Debug, Clone)]
pub struct ValidationQuery {
    pub filters: Vec<FilterEntry>,
    /// Only validations created or changed at or after this.
    pub changed_since: Option<DateTime<Utc>>,
    /// The timezone relative date filters resolve in.
    pub tz: Tz,
}

impl Default for ValidationQuery {
    fn default() -> Self {
        ValidationQuery {
            filters: Vec::new(),
            changed_since: None,
            tz: Tz::UTC,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidationPage {
    pub validations: Vec<Validation>,
    pub next_cursor: Option<String>,
}

/// One pair a report lists, with the sample's label when it ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidationResult {
    pub id: i64,
    pub sha256: String,
    pub rule_uuid: String,
    pub rule_name: String,
    pub namespace: Option<String>,
    pub label: Option<String>,
    pub label_source: Option<String>,
    pub base: String,
    pub head: String,
    pub raw_base: bool,
    pub raw_head: bool,
    pub category: String,
    pub note: Option<String>,
}

/// Which of a report's rows: its categories and rule uuids, none meaning all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ResultSelection {
    pub categories: Vec<String>,
    pub rule_uuids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ValidationResultPage {
    pub results: Vec<ValidationResult>,
    pub next_cursor: Option<String>,
}

/// What a prune removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ValidationsPruned {
    pub removed: u64,
    pub batches: u64,
}

// ---- audit records ----

#[derive(Serialize)]
struct RequestRecord<'a> {
    repository: &'a str,
    base_sha: &'a str,
    head_sha: &'a str,
    branch: &'a str,
    pr_url: Option<&'a str>,
    answered_by: &'a str,
}

impl Recorded for RequestRecord<'_> {}

#[derive(Serialize)]
struct ResultsDownloadRecord<'a> {
    categories: &'a [String],
    rule_uuids: &'a [String],
    sha256s: Vec<&'a str>,
}

impl Recorded for ResultsDownloadRecord<'_> {}

#[derive(Serialize)]
struct PruneRecord {
    retention_days: u32,
    validations: Vec<Uuid>,
}

impl Recorded for PruneRecord {}

// ---- cursors ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListCursor {
    created_at: DateTime<Utc>,
    id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultCursor {
    id: i64,
}

fn encode<T: Serialize>(cursor: &T) -> String {
    hex::encode(serde_json::to_vec(cursor).unwrap_or_default())
}

fn decode<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T, ServiceError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| ServiceError::InvalidRequest(format!("{text:?} isn't a cursor")))
}

// ---- checks ----

fn check_commit(name: &str, sha: &str) -> Result<String, ServiceError> {
    let lower = sha.to_ascii_lowercase();
    if matches!(lower.len(), 40 | 64) && lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(lower)
    } else {
        Err(ServiceError::InvalidRequest(format!(
            "{name} must be a full commit id, 40 or 64 hex characters"
        )))
    }
}

fn check_ask(ask: &ValidationAsk) -> Result<ValidationAsk, ServiceError> {
    let invalid = |m: &str| Err(ServiceError::InvalidRequest(m.to_owned()));
    if ask.repository.is_empty() || ask.repository.chars().count() > 256 {
        return invalid("repository must be 1 to 256 characters");
    }
    if ask.branch.is_empty() || ask.branch.chars().count() > 256 {
        return invalid("branch must be 1 to 256 characters");
    }
    if let Some(url) = &ask.pr_url {
        let lower = url.to_ascii_lowercase();
        if url.chars().count() > 2048
            || !(lower.starts_with("https://") || lower.starts_with("http://"))
        {
            return invalid("pr_url must be an http or https URL of at most 2048 characters");
        }
    }
    Ok(ValidationAsk {
        base_sha: check_commit("base_sha", &ask.base_sha)?,
        head_sha: check_commit("head_sha", &ask.head_sha)?,
        ..ask.clone()
    })
}

fn check_selection(selection: &ResultSelection) -> Result<(), ServiceError> {
    for category in &selection.categories {
        let listed = Category::parse(category).is_some_and(|c| !c.counted_only());
        if !listed {
            return Err(ServiceError::InvalidRequest(format!(
                "{category:?} isn't a category a report lists: {}",
                Category::listed()
                    .map(Category::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    for rule_uuid in &selection.rule_uuids {
        if rule_uuid.is_empty() || rule_uuid.chars().count() > 256 {
            return Err(ServiceError::InvalidRequest(format!(
                "{rule_uuid:?} isn't a rule's uuid"
            )));
        }
    }
    Ok(())
}

fn no_validation(uuid: Uuid) -> ServiceError {
    ServiceError::NotFound(format!("validation {uuid}"))
}

// ---- rows ----

struct ValidationRow {
    id: i64,
    uuid: Uuid,
    repository: String,
    base_sha: String,
    head_sha: String,
    branch: String,
    pr_url: Option<String>,
    state: ValidationState,
    requested_by: Value,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    error: Option<String>,
    diffed: Option<bool>,
    regressions: Option<i32>,
    new_fps: Option<i32>,
    compile_errors: Option<i32>,
    counts: Option<Value>,
    report: Option<Value>,
    attempts: i32,
    claimed_by: Option<String>,
    corpus_version: Option<String>,
    engine_fingerprint: Option<String>,
    updated_at: DateTime<Utc>,
}

fn counts_of(value: Option<Value>) -> Option<BTreeMap<String, i64>> {
    value.and_then(|v| serde_json::from_value(v).ok())
}

impl ValidationRow {
    fn validation(&self) -> Result<Validation, ServiceError> {
        Ok(Validation {
            uuid: self.uuid,
            repository: self.repository.clone(),
            base_sha: self.base_sha.clone(),
            head_sha: self.head_sha.clone(),
            branch: self.branch.clone(),
            pr_url: self.pr_url.clone(),
            state: self.state,
            requested_by: RecordedActor::from_row(Some(self.requested_by.clone()))?
                .expect("a recorded actor"),
            created_at: self.created_at,
            started_at: self.started_at,
            finished_at: self.finished_at,
            error: self.error.clone(),
            diffed: self.diffed,
            regressions: self.regressions,
            new_fps: self.new_fps,
            compile_errors: self.compile_errors,
            counts: counts_of(self.counts.clone()),
            updated_at: self.updated_at,
        })
    }
}

async fn validation_row(
    conn: &mut sqlx::PgConnection,
    uuid: Uuid,
) -> Result<Option<ValidationRow>, sqlx::Error> {
    sqlx::query_as!(
        ValidationRow,
        r#"SELECT id, uuid, repository, base_sha, head_sha, branch, pr_url,
                  state AS "state: ValidationState", requested_by AS "requested_by!: Value",
                  created_at, started_at, finished_at, error, diffed, regressions, new_fps,
                  compile_errors, counts, report, attempts, claimed_by, corpus_version,
                  engine_fingerprint, updated_at
           FROM svs.validations WHERE uuid = $1"#,
        uuid,
    )
    .fetch_optional(conn)
    .await
}

async fn status_of(
    conn: &mut sqlx::PgConnection,
    uuid: Uuid,
) -> Result<ValidationStatus, ServiceError> {
    let row = validation_row(&mut *conn, uuid)
        .await?
        .ok_or_else(|| no_validation(uuid))?;
    let listed: Vec<String> = Category::listed().map(|c| c.as_str().to_owned()).collect();
    let rules = sqlx::query!(
        r#"SELECT category, rule_uuid, rule_name, count(*) AS "count!"
           FROM svs.validation_results WHERE validation_id = $1
           GROUP BY category, rule_uuid, rule_name
           ORDER BY count(*) DESC, rule_name, rule_uuid"#,
        row.id,
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut by_category: BTreeMap<String, Vec<RuleCount>> = BTreeMap::new();
    for rule in rules {
        if listed.contains(&rule.category) {
            by_category
                .entry(rule.category)
                .or_default()
                .push(RuleCount {
                    rule_uuid: rule.rule_uuid,
                    rule_name: rule.rule_name,
                    count: rule.count,
                });
        }
    }
    let head = row
        .report
        .as_ref()
        .map(|r| r["head"].clone())
        .unwrap_or(Value::Null);
    let compile_errors = head["file_errors"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|e| CompileProblem {
            file: e["file"].as_str().unwrap_or_default().to_owned(),
            error: e["error"].as_str().unwrap_or_default().to_owned(),
        })
        .collect();
    Ok(ValidationStatus {
        uuid: row.uuid,
        state: row.state,
        error: row.error,
        repository: row.repository,
        base_sha: row.base_sha,
        head_sha: row.head_sha,
        branch: row.branch,
        pr_url: row.pr_url,
        created_at: row.created_at,
        started_at: row.started_at,
        finished_at: row.finished_at,
        diffed: row.diffed,
        counts: counts_of(row.counts),
        rules: by_category,
        compile_errors,
        ruleset_error: head["ruleset_error"].as_str().map(str::to_owned),
        report_path: validation_report_path(row.uuid),
    })
}

/// The validations screen's parameters.
struct Params {
    texts: [Option<Vec<String>>; 6],
    states: [Option<Vec<String>>; 2],
    flags: [Option<Vec<String>>; 6],
    windows: [Option<Vec<DateTime<Utc>>>; 4],
}

fn params(query: &ValidationQuery) -> Result<Params, ServiceError> {
    let f = Resolved::new(
        FilterScreen::SvsValidations,
        &query.filters,
        Utc::now(),
        query.tz,
    )?;
    let ((w1, w2), (w3, w4)) = (
        split(f.windows("created", false)?),
        split(f.windows("created", true)?),
    );
    let prefixes = |values: Option<Vec<String>>| {
        values.map(|values| {
            values
                .iter()
                .map(|v| format!("{}%", like_escape(&v.to_ascii_lowercase())))
                .collect()
        })
    };
    Ok(Params {
        texts: [
            f.patterns("repository", false, false),
            f.patterns("repository", true, false),
            f.patterns("branch", false, false),
            f.patterns("branch", true, false),
            prefixes(f.names("head", false)),
            prefixes(f.names("head", true)),
        ],
        states: [f.names("state", false), f.names("state", true)],
        flags: [
            f.names("has_regressions", false),
            f.names("has_regressions", true),
            f.names("has_new_fp", false),
            f.names("has_new_fp", true),
            f.names("compile_errors", false),
            f.names("compile_errors", true),
        ],
        windows: [w1, w2, w3, w4],
    })
}

fn like_escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// A flag filter as ace3's `flag_condition` reads it: `true` or `false` when it holds only that, `both`
/// when it holds both, which filters nothing (and so its inverse matches nothing), and None when unset.
fn flag(values: &Option<Vec<String>>) -> Option<&'static str> {
    match values.as_deref() {
        None => None,
        Some([one]) if one == "true" => Some("true"),
        Some([one]) if one == "false" => Some("false"),
        Some(_) => Some("both"),
    }
}

impl Service {
    /// The validation that answers `ask`, and whether it's new (module docs). A repository that isn't in
    /// `svs.yara.repositories` is `InvalidRequest`, as are commits that aren't full ids. It needs
    /// `svs:validate`, and records the request.
    pub async fn request_svs_validation(
        &self,
        actor: &Actor,
        ask: &ValidationAsk,
    ) -> Result<(ValidationStatus, bool), ServiceError> {
        let ask = &check_ask(ask)?;
        let config = &self.validation_config();
        let (tp, fp) = &self.disposition_classes().lists();
        let requested_by = &serde_json::to_value(actor)
            .map_err(|e| ServiceError::from(ace_core::DbError::Decode(e.to_string())))?;
        self.gate
            .write(actor, "request_svs_validation", &SVS_VALIDATE, &|tx| {
                Box::pin(async move {
                    let fingerprint = engine_fingerprint(config, &ask.repository, tp, fp)
                        .map_err(ServiceError::InvalidRequest)?;
                    let version = corpus_version_in(tx.conn()).await?;
                    let (uuid, created) = request_validation(
                        tx.conn(),
                        &ValidationRequest {
                            repository: &ask.repository,
                            base_sha: &ask.base_sha,
                            head_sha: &ask.head_sha,
                            branch: &ask.branch,
                            pr_url: ask.pr_url.as_deref(),
                            requested_by,
                        },
                        &version,
                        &fingerprint,
                    )
                    .await?;
                    let status = status_of(tx.conn(), uuid).await?;
                    let answered_by = if created {
                        "queued".to_owned()
                    } else {
                        format!("an existing {} validation", status.state.as_str())
                    };
                    let record = RequestRecord {
                        repository: &ask.repository,
                        base_sha: &ask.base_sha,
                        head_sha: &ask.head_sha,
                        branch: &ask.branch,
                        pr_url: ask.pr_url.as_deref(),
                        answered_by: &answered_by,
                    };
                    let target = Target::svs_validation(uuid);
                    let change = if created {
                        Change::added(target, &record)?
                    } else {
                        Change::read(target, &record)?
                    };
                    Ok(Audited::changed((status, created), change))
                })
            })
            .await
    }

    /// A validation's state and, once completed, its counts, the rules with samples in each listed
    /// category and the head's compile errors. It names no sample. It needs `svs:validate`.
    pub async fn svs_validation_status(
        &self,
        actor: &Actor,
        uuid: Uuid,
    ) -> Result<ValidationStatus, ServiceError> {
        self.gate
            .read(actor, "svs_validation_status", &SVS_VALIDATE, &|tx| {
                Box::pin(async move { status_of(tx.conn(), uuid).await })
            })
            .await
    }

    /// A page of validations, newest first, after where `cursor` left off. It needs `signature:read`.
    pub async fn svs_validations(
        &self,
        actor: &Actor,
        query: &ValidationQuery,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<ValidationPage, ServiceError> {
        let limit = page_limit(limit, MAX_VALIDATIONS_PAGE)?;
        let after = cursor.map(decode::<ListCursor>).transpose()?;
        let p = &params(query)?;
        let changed_since = query.changed_since;
        let after = &after;
        self.gate
            .read(actor, "svs_validations", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let mut rows =
                        list(tx.conn(), p, changed_since, after.as_ref(), limit + 1).await?;
                    let next_cursor = if rows.len() as i64 > limit {
                        rows.truncate(limit as usize);
                        rows.last().map(|last| {
                            encode(&ListCursor {
                                created_at: last.created_at,
                                id: last.id,
                            })
                        })
                    } else {
                        None
                    };
                    let validations = rows
                        .iter()
                        .map(ValidationRow::validation)
                        .collect::<Result<_, _>>()?;
                    Ok(ValidationPage {
                        validations,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// How many validations `query` matches, counting up to `max` + 1, for an export to refuse one too
    /// large before it starts. It needs `signature:read`.
    pub async fn svs_validation_count(
        &self,
        actor: &Actor,
        query: &ValidationQuery,
        max: i64,
    ) -> Result<i64, ServiceError> {
        let p = &params(query)?;
        let changed_since = query.changed_since;
        self.gate
            .read(actor, "svs_validation_count", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let rows =
                        list(tx.conn(), p, changed_since, None, max.saturating_add(1)).await?;
                    Ok(rows.len() as i64)
                })
            })
            .await
    }

    /// How many rows of a report `selection` selects, counting up to `max` + 1. It needs `signature:read`.
    pub async fn svs_validation_result_count(
        &self,
        actor: &Actor,
        uuid: Uuid,
        selection: &ResultSelection,
        max: i64,
    ) -> Result<i64, ServiceError> {
        check_selection(selection)?;
        self.gate
            .read(
                actor,
                "svs_validation_result_count",
                &SIGNATURE_READ,
                &|tx| {
                    Box::pin(async move {
                        let row = validation_row(tx.conn(), uuid)
                            .await?
                            .ok_or_else(|| no_validation(uuid))?;
                        let rows =
                            results(tx.conn(), row.id, selection, None, max.saturating_add(1))
                                .await?;
                        Ok(rows.len() as i64)
                    })
                },
            )
            .await
    }

    /// One validation with its report. It needs `signature:read`.
    pub async fn svs_validation(
        &self,
        actor: &Actor,
        uuid: Uuid,
    ) -> Result<ValidationDetail, ServiceError> {
        self.gate
            .read(actor, "svs_validation", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let row = validation_row(tx.conn(), uuid)
                        .await?
                        .ok_or_else(|| no_validation(uuid))?;
                    Ok(ValidationDetail {
                        validation: row.validation()?,
                        attempts: row.attempts,
                        claimed_by: row.claimed_by,
                        corpus_version: row.corpus_version,
                        engine_fingerprint: row.engine_fingerprint,
                        report: row.report,
                    })
                })
            })
            .await
    }

    /// A page of the pairs a report lists, in a stable order, after where `cursor` left off. A category
    /// that's only counted is `InvalidRequest`. It needs `signature:read`.
    pub async fn svs_validation_results(
        &self,
        actor: &Actor,
        uuid: Uuid,
        selection: &ResultSelection,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<ValidationResultPage, ServiceError> {
        check_selection(selection)?;
        let limit = page_limit(limit, MAX_VALIDATIONS_PAGE)?;
        let after = cursor
            .map(decode::<ResultCursor>)
            .transpose()?
            .map(|c| c.id);
        self.gate
            .read(actor, "svs_validation_results", &SIGNATURE_READ, &|tx| {
                Box::pin(async move {
                    let row = validation_row(tx.conn(), uuid)
                        .await?
                        .ok_or_else(|| no_validation(uuid))?;
                    let mut results =
                        results(tx.conn(), row.id, selection, after, limit + 1).await?;
                    let next_cursor = if results.len() as i64 > limit {
                        results.truncate(limit as usize);
                        results
                            .last()
                            .map(|last| encode(&ResultCursor { id: last.id }))
                    } else {
                        None
                    };
                    Ok(ValidationResultPage {
                        results,
                        next_cursor,
                    })
                })
            })
            .await
    }

    /// Lets an actor download the files of a report's selected rows, with the match records of every
    /// sample of those files, and records that they did. The samples' download limits apply; a selection
    /// none of whose files is stored is `NotFound`. It needs `signature:download`.
    pub async fn download_svs_validation(
        &self,
        actor: &Actor,
        uuid: Uuid,
        selection: &ResultSelection,
    ) -> Result<SampleDownload, ServiceError> {
        check_selection(selection)?;
        self.gate
            .write(actor, "download_svs_validation", &SIGNATURE_DOWNLOAD, &|tx| {
                Box::pin(async move {
                    let row = validation_row(tx.conn(), uuid)
                        .await?
                        .ok_or_else(|| no_validation(uuid))?;
                    let selected = results(tx.conn(), row.id, selection, None, i64::MAX).await?;
                    let mut sha256s: Vec<String> =
                        selected.into_iter().map(|r| r.sha256).collect();
                    sha256s.sort();
                    sha256s.dedup();
                    let pairs: Vec<(String, String)> = sqlx::query!(
                        r#"SELECT DISTINCT sha256 AS "sha256!", rule_uuid AS "rule_uuid!"
                           FROM svs.yara_captures WHERE sha256 = ANY ($1)
                           ORDER BY 1, 2"#,
                        &sha256s,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|r| (r.sha256, r.rule_uuid))
                    .collect();
                    let download = download_of(tx, &pairs).await?;
                    if download.files.is_empty() {
                        return Err(ServiceError::NotFound(
                            "none of the selected rows' files is stored".to_owned(),
                        ));
                    }
                    if download.files.len() > MAX_SAMPLE_DOWNLOAD_FILES {
                        return Err(ServiceError::TooLarge(format!(
                            "more than {MAX_SAMPLE_DOWNLOAD_FILES} files; narrow the selection"
                        )));
                    }
                    let bytes: i64 = download.files.iter().filter_map(|f| f.file_size).sum();
                    if bytes > MAX_SAMPLE_DOWNLOAD_BYTES {
                        return Err(ServiceError::TooLarge(format!(
                            "{bytes} bytes is more than {MAX_SAMPLE_DOWNLOAD_BYTES}; narrow the selection"
                        )));
                    }
                    let change = Change::read(
                        Target::svs_validation(uuid),
                        &ResultsDownloadRecord {
                            categories: &selection.categories,
                            rule_uuids: &selection.rule_uuids,
                            sha256s: download.files.iter().map(|f| f.sha256.as_str()).collect(),
                        },
                    )?;
                    Ok(Audited::changed(download, change))
                })
            })
            .await
    }

    /// How many finished validations are older than `svs.yara.retention_days`: what a prune would
    /// remove. It needs `svs:validation_prune`.
    pub async fn prunable_svs_validations(&self, actor: &Actor) -> Result<i64, ServiceError> {
        let days = f64::from(self.validation_config().retention_days);
        self.gate
            .read(
                actor,
                "prunable_svs_validations",
                &SVS_VALIDATION_PRUNE,
                &|tx| {
                    Box::pin(async move {
                        Ok(sqlx::query_scalar!(
                            r#"SELECT count(*) AS "count!" FROM svs.validations
                           WHERE state IN ('completed', 'failed')
                             AND finished_at < now() - make_interval(days => $1::float8::int)"#,
                            days,
                        )
                        .fetch_one(tx.conn())
                        .await?)
                    })
                },
            )
            .await
    }

    /// Removes the finished validations older than `svs.yara.retention_days`, with their rows, in batches
    /// (module docs). It needs `svs:validation_prune`.
    pub async fn prune_svs_validations(
        &self,
        actor: &Actor,
    ) -> Result<ValidationsPruned, ServiceError> {
        let config = self.validation_config();
        let retention_days = config.retention_days;
        let batch = i64::from(config.prune_batch_size);
        let mut pruned = ValidationsPruned::default();
        loop {
            let removed = self
                .gate
                .write(
                    actor,
                    "prune_svs_validations",
                    &SVS_VALIDATION_PRUNE,
                    &|tx| {
                        Box::pin(async move {
                            let removed: Vec<Uuid> = sqlx::query_scalar!(
                                r#"DELETE FROM svs.validations
                                   WHERE id IN (
                                       SELECT id FROM svs.validations
                                       WHERE state IN ('completed', 'failed')
                                         AND finished_at < now() - make_interval(days => $1)
                                       ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED)
                                   RETURNING uuid"#,
                                i32::try_from(retention_days).unwrap_or(i32::MAX),
                                batch,
                            )
                            .fetch_all(tx.conn())
                            .await?;
                            let count = removed.len();
                            if removed.is_empty() {
                                return Ok(Audited::unchanged(count));
                            }
                            let change = Change::removed(
                                Target::expired_svs_validations(),
                                &PruneRecord {
                                    retention_days,
                                    validations: removed,
                                },
                            )?;
                            Ok(Audited::changed(count, change))
                        })
                    },
                )
                .await?;
            pruned.removed += removed as u64;
            if removed > 0 {
                pruned.batches += 1;
            }
            if (removed as i64) < batch {
                if pruned.removed > 0 {
                    tracing::info!(
                        removed = pruned.removed,
                        retention_days,
                        "pruned svs validations"
                    );
                }
                return Ok(pruned);
            }
        }
    }
}

struct ListRow {
    id: i64,
    uuid: Uuid,
    repository: String,
    base_sha: String,
    head_sha: String,
    branch: String,
    pr_url: Option<String>,
    state: ValidationState,
    requested_by: Value,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    error: Option<String>,
    diffed: Option<bool>,
    regressions: Option<i32>,
    new_fps: Option<i32>,
    compile_errors: Option<i32>,
    counts: Option<Value>,
    report: Option<Value>,
    attempts: i32,
    claimed_by: Option<String>,
    corpus_version: Option<String>,
    engine_fingerprint: Option<String>,
    updated_at: DateTime<Utc>,
}

impl From<ListRow> for ValidationRow {
    fn from(r: ListRow) -> Self {
        ValidationRow {
            id: r.id,
            uuid: r.uuid,
            repository: r.repository,
            base_sha: r.base_sha,
            head_sha: r.head_sha,
            branch: r.branch,
            pr_url: r.pr_url,
            state: r.state,
            requested_by: r.requested_by,
            created_at: r.created_at,
            started_at: r.started_at,
            finished_at: r.finished_at,
            error: r.error,
            diffed: r.diffed,
            regressions: r.regressions,
            new_fps: r.new_fps,
            compile_errors: r.compile_errors,
            counts: r.counts,
            report: r.report,
            attempts: r.attempts,
            claimed_by: r.claimed_by,
            corpus_version: r.corpus_version,
            engine_fingerprint: r.engine_fingerprint,
            updated_at: r.updated_at,
        }
    }
}

async fn list(
    conn: &mut sqlx::PgConnection,
    p: &Params,
    changed_since: Option<DateTime<Utc>>,
    after: Option<&ListCursor>,
    limit: i64,
) -> Result<Vec<ValidationRow>, sqlx::Error> {
    let [t0, t1, t2, t3, t4, t5] = &p.texts;
    let [s0, s1] = &p.states;
    let [f0, f1, f2, f3, f4, f5] = &p.flags;
    let [w0, w1, w2, w3] = &p.windows;
    let (after_created, after_id) = match after {
        Some(c) => (Some(c.created_at), Some(c.id)),
        None => (None, None),
    };
    // an inverse matches exactly the rows its filter doesn't, a NULL count included, as ace3's CASE does
    let rows = sqlx::query_as!(
        ListRow,
        r#"SELECT id, uuid, repository, base_sha, head_sha, branch, pr_url,
                  state AS "state: ValidationState", requested_by AS "requested_by!: Value",
                  created_at, started_at, finished_at, error, diffed, regressions, new_fps,
                  compile_errors, counts, NULL::jsonb AS report, attempts, claimed_by, corpus_version,
                  engine_fingerprint, updated_at
           FROM svs.validations v
           WHERE ($1::text[] IS NULL OR v.repository ILIKE ANY ($1))
             AND ($2::text[] IS NULL OR NOT v.repository ILIKE ANY ($2))
             AND ($3::text[] IS NULL OR v.branch ILIKE ANY ($3))
             AND ($4::text[] IS NULL OR NOT v.branch ILIKE ANY ($4))
             AND ($5::text[] IS NULL OR v.head_sha LIKE ANY ($5))
             AND ($6::text[] IS NULL OR NOT v.head_sha LIKE ANY ($6))
             AND ($7::text[] IS NULL OR v.state::text = ANY ($7))
             AND ($8::text[] IS NULL OR NOT v.state::text = ANY ($8))
             AND ($9::text IS NULL OR $9 = 'both'
                  OR COALESCE(CASE $9 WHEN 'true' THEN v.regressions > 0 ELSE v.regressions = 0 END, false))
             AND ($10::text IS NULL OR $10 <> 'both'
                  AND NOT COALESCE(CASE $10 WHEN 'true' THEN v.regressions > 0 ELSE v.regressions = 0 END, false))
             AND ($11::text IS NULL OR $11 = 'both'
                  OR COALESCE(CASE $11 WHEN 'true' THEN v.new_fps > 0 ELSE v.new_fps = 0 END, false))
             AND ($12::text IS NULL OR $12 <> 'both'
                  AND NOT COALESCE(CASE $12 WHEN 'true' THEN v.new_fps > 0 ELSE v.new_fps = 0 END, false))
             AND ($13::text IS NULL OR $13 = 'both'
                  OR COALESCE(CASE $13 WHEN 'true' THEN v.compile_errors > 0 ELSE v.compile_errors = 0 END, false))
             AND ($14::text IS NULL OR $14 <> 'both'
                  AND NOT COALESCE(CASE $14 WHEN 'true' THEN v.compile_errors > 0 ELSE v.compile_errors = 0 END, false))
             AND ($15::timestamptz[] IS NULL OR EXISTS (
                   SELECT FROM unnest($15::timestamptz[], $16::timestamptz[]) w(b, e)
                   WHERE v.created_at BETWEEN w.b AND w.e))
             AND ($17::timestamptz[] IS NULL OR NOT EXISTS (
                   SELECT FROM unnest($17::timestamptz[], $18::timestamptz[]) w(b, e)
                   WHERE v.created_at BETWEEN w.b AND w.e))
             AND ($19::timestamptz IS NULL OR v.updated_at >= $19 OR v.created_at >= $19)
             AND ($20::timestamptz IS NULL OR (v.created_at, v.id) < ($20, $21::bigint))
           ORDER BY v.created_at DESC, v.id DESC
           LIMIT $22"#,
        t0.as_deref(),
        t1.as_deref(),
        t2.as_deref(),
        t3.as_deref(),
        t4.as_deref(),
        t5.as_deref(),
        s0.as_deref(),
        s1.as_deref(),
        flag(f0),
        flag(f1),
        flag(f2),
        flag(f3),
        flag(f4),
        flag(f5),
        w0.as_deref(),
        w1.as_deref(),
        w2.as_deref(),
        w3.as_deref(),
        changed_since,
        after_created,
        after_id,
        limit,
    )
    .fetch_all(conn)
    .await?;
    Ok(rows.into_iter().map(ValidationRow::from).collect())
}

async fn results(
    conn: &mut sqlx::PgConnection,
    validation_id: i64,
    selection: &ResultSelection,
    after: Option<i64>,
    limit: i64,
) -> Result<Vec<ValidationResult>, sqlx::Error> {
    let categories = (!selection.categories.is_empty()).then_some(&selection.categories[..]);
    let rules = (!selection.rule_uuids.is_empty()).then_some(&selection.rule_uuids[..]);
    sqlx::query_as!(
        ValidationResult,
        r#"SELECT id, sha256, rule_uuid, rule_name, namespace, label, label_source, base, head,
                  raw_base, raw_head, category, note
           FROM svs.validation_results
           WHERE validation_id = $1
             AND ($2::text[] IS NULL OR category = ANY ($2))
             AND ($3::text[] IS NULL OR rule_uuid = ANY ($3))
             AND ($4::bigint IS NULL OR id > $4)
           ORDER BY id
           LIMIT $5"#,
        validation_id,
        categories,
        rules,
        after,
        limit,
    )
    .fetch_all(conn)
    .await
}

/// The categories whose counts add up to a validation's regressions and new false positives, for a
/// caller that shows them.
pub fn regression_categories() -> [&'static str; 2] {
    REGRESSION_CATEGORIES.map(Category::as_str)
}

pub fn new_fp_categories() -> [&'static str; 2] {
    NEW_FP_CATEGORIES.map(Category::as_str)
}

/// The categories a report lists rows for, in its bands' order.
pub fn listed_categories() -> Vec<&'static str> {
    Category::listed().map(Category::as_str).collect()
}
