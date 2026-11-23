//! The YARA validation queue and its workers: ace3's `saq/svs/validations.py` and `service.py`'s validation
//! workers (ace3's `docs/SVS_VALIDATION.md`, *The svs service*). Migration 0049 holds the tables, and only
//! this module writes them, but for the prune, which `ace_service` audits.
//!
//! A validation is requested through the service (`request_validation`), waits in `svs.validations` as
//! `queued`, and is run by a worker of `ace serve` that holds a lease on it:
//!
//! - `claim` takes the oldest queued validation, or a running one whose worker stopped heartbeating and has
//!   attempts left, with one conditional update under `FOR UPDATE SKIP LOCKED`, so two workers (in one
//!   process or two replicas) never both win;
//! - `heartbeat` keeps the lease; a worker that loses it (another one took over) stops, and its work is void;
//! - `complete` stores the report and its rows, `fail` the reason it couldn't run, and `release` puts it
//!   back in the queue when `ace serve` stops, without counting the attempt;
//! - `fail_abandoned` gives up on a validation whose workers stopped `max_attempts` times while running it.
//!
//! Lease times come from the database's clock, never the worker's. A completed validation answers a later
//! request for the same commits while the corpus version (what the samples and their labels are) and the
//! engine fingerprint (what decides the results) are unchanged.
//!
//! What differs from ace3: ace3 runs the workers on its primary node only; here every replica of `ace serve`
//! runs `max_concurrent_validations` of them and the claim shares the queue out, as the scheduler's claims
//! share its tasks.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;

use super::yara::ValidationConfig;
use super::yara::diff::Category;
use super::yara::replay::{Replay, ReplayError, ReplayRequest, ReplayResult};
use crate::db::{Db, DbError};

/// What a failed validation says when the cause was unexpected: the cause is in `ace serve`'s log.
pub const INTERNAL_ERROR: &str = "internal error; see the ace serve log";
/// Result rows inserted per statement.
const RESULT_BATCH: usize = 1000;

/// A validation's state: ace3's `ValidationState`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, sqlx::Type,
)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "svs.validation_state", rename_all = "snake_case")]
pub enum ValidationState {
    Queued,
    Running,
    Completed,
    Failed,
}

impl ValidationState {
    pub const ALL: [ValidationState; 4] = [
        ValidationState::Queued,
        ValidationState::Running,
        ValidationState::Completed,
        ValidationState::Failed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ValidationState::Queued => "queued",
            ValidationState::Running => "running",
            ValidationState::Completed => "completed",
            ValidationState::Failed => "failed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == text)
    }
}

/// A validation a worker holds the lease on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub id: i64,
    pub uuid: Uuid,
    pub repository: String,
    pub base_sha: String,
    pub head_sha: String,
    pub branch: String,
    pub token: Uuid,
    pub attempts: i32,
}

/// Why `complete` stored nothing.
#[derive(Debug, thiserror::Error)]
pub enum CompleteError {
    #[error("validation {0} is no longer held by this worker")]
    LeaseLost(Uuid),
    #[error(transparent)]
    Db(#[from] DbError),
}

impl From<sqlx::Error> for CompleteError {
    fn from(e: sqlx::Error) -> Self {
        CompleteError::Db(e.into())
    }
}

/// The sha256 of `value` as Python's `json.dumps(value, sort_keys=True)` writes it, as ace3's `_digest`.
fn digest(value: &Value) -> String {
    hex(&Sha256::digest(python_json(value).as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `value` in Python's `json.dumps` form: `, ` and `: ` between items, keys sorted, non-ASCII escaped.
fn python_json(value: &Value) -> String {
    match value {
        Value::Array(items) => format!(
            "[{}]",
            items.iter().map(python_json).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|k| format!(
                        "{}: {}",
                        python_json(&Value::String(k.clone())),
                        python_json(&map[k])
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Value::String(s) => {
            let mut out = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                        let mut units = [0u16; 2];
                        for unit in c.encode_utf16(&mut units) {
                            out.push_str(&format!("\\u{unit:04x}"));
                        }
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        other => other.to_string(),
    }
}

/// The key an identical request shares while the validation waits or runs: ace3's `active_key`, the same
/// in every process.
pub fn active_key(repository: &str, base_sha: &str, head_sha: &str) -> String {
    digest(&json!([repository, base_sha, head_sha]))
}

/// A digest of what the corpus and its labels are: the greatest change time and the number of rows of every
/// input, read in one transaction. The counts catch what bumps no change time: a cleared verdict, a deleted
/// alert, a deleted capture. ace3's `corpus_version`, with ace-rs's inputs: the stored captures, the verdicts'
/// history, the retirements, the deletions, the captures' alerts (their dispositions and detections) and
/// the test runs they're attributed to, whose review decides whether their verdicts count.
pub async fn corpus_version(db: &Db) -> Result<String, DbError> {
    let mut tx = db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(tx.conn())
        .await?;
    let version = corpus_version_in(tx.conn()).await?;
    tx.commit().await?;
    Ok(version)
}

/// `corpus_version` on `conn`, in its transaction.
pub async fn corpus_version_in(conn: &mut sqlx::PgConnection) -> Result<String, DbError> {
    let statements = [
        (
            "captures",
            "SELECT max(updated_at)::text, count(*)::text FROM svs.yara_captures WHERE state = 'stored'",
        ),
        (
            "verdicts",
            "SELECT max(changed_at)::text, count(*)::text FROM analysis.detection_verdict_history",
        ),
        (
            "retirements",
            "SELECT max(updated_at)::text, count(*)::text FROM svs.sample_retirements",
        ),
        (
            "deletions",
            "SELECT max(updated_at)::text, count(*)::text FROM svs.sample_deletions",
        ),
        (
            "alerts",
            "SELECT max(greatest(r.dispositioned_at, r.alerted_at))::text || '/' || coalesce(max(r.disposition), ''),
                    count(*)::text
             FROM analysis.roots r
             WHERE r.id IN (SELECT root_id FROM svs.yara_captures WHERE state = 'stored')",
        ),
        (
            "detections",
            "SELECT max(d.id)::text, count(*)::text FROM analysis.detections d
             WHERE d.root_id IN (SELECT root_id FROM svs.yara_captures WHERE state = 'stored')",
        ),
        (
            "attributions",
            "SELECT max(a.updated_at)::text || '/' || coalesce(max(r.updated_at)::text, ''), count(*)::text
             FROM svs.attributions a JOIN svs.runs r ON r.id = a.run_id
             WHERE a.root_id IN (SELECT root_id FROM svs.yara_captures WHERE state = 'stored')",
        ),
    ];
    let mut inputs = serde_json::Map::new();
    for (name, statement) in statements {
        let (changed, count): (Option<String>, Option<String>) =
            sqlx::query_as(statement).fetch_one(&mut *conn).await?;
        inputs.insert(name.to_owned(), json!([changed, count]));
    }
    Ok(digest(&Value::Object(inputs)))
}

/// A digest of what decides a validation's results besides the corpus and the commits: the replay's code
/// (`ace_yara::replay::engine_digest` and this crate's comparison), how dispositions classify, the per-file
/// scan timeout and which directory of the repository is loaded. ace3's `engine_fingerprint`. Fails for a
/// repository that isn't configured.
pub fn engine_fingerprint(
    config: &ValidationConfig,
    repository: &str,
    tp: &[String],
    fp: &[String],
) -> Result<String, String> {
    let layout = config.layout(repository)?;
    let mut sources = Sha256::new();
    for source in [
        include_str!("yara/corpus.rs"),
        include_str!("yara/diff.rs"),
        include_str!("yara/layout.rs"),
        include_str!("yara/replay.rs"),
        include_str!("yara/repository.rs"),
    ] {
        sources.update(source.as_bytes());
    }
    let mut tp = tp.to_vec();
    let mut fp = fp.to_vec();
    tp.sort();
    fp.sort();
    Ok(digest(&json!({
        "engine": ace_yara::replay::engine_digest(),
        "sources": hex(&sources.finalize()),
        "disposition_classification": {"tp": tp, "fp": fp},
        "file_timeout": config.file_timeout.as_secs_f64(),
        "layout": {"repository": layout.repository, "signature_dir": layout.signature_dir},
    })))
}

/// A request for a validation: ace3's `request_validation`'s arguments.
#[derive(Debug, Clone)]
pub struct ValidationRequest<'a> {
    pub repository: &'a str,
    pub base_sha: &'a str,
    pub head_sha: &'a str,
    pub branch: &'a str,
    pub pr_url: Option<&'a str>,
    /// The actor, as a `service.actor`.
    pub requested_by: &'a Value,
}

/// The validation that answers `request`, and whether it's new: one queued or running for the same
/// commits, else a completed one whose corpus version and fingerprint are `version` and `fingerprint`, else
/// a new queued one. A failed validation is never reused. In `tx`, which the caller audits.
pub async fn request_validation(
    tx: &mut sqlx::PgConnection,
    request: &ValidationRequest<'_>,
    version: &str,
    fingerprint: &str,
) -> Result<(Uuid, bool), DbError> {
    let key = active_key(request.repository, request.base_sha, request.head_sha);
    let active: Option<Uuid> =
        sqlx::query_scalar("SELECT uuid FROM svs.validations WHERE active_key = $1")
            .bind(&key)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(uuid) = active {
        return Ok((uuid, false));
    }
    let cached: Option<Uuid> = sqlx::query_scalar(
        "SELECT uuid FROM svs.validations
         WHERE repository = $1 AND base_sha = $2 AND head_sha = $3 AND state = 'completed'
           AND corpus_version = $4 AND engine_fingerprint = $5
         ORDER BY finished_at DESC, id DESC LIMIT 1",
    )
    .bind(request.repository)
    .bind(request.base_sha)
    .bind(request.head_sha)
    .bind(version)
    .bind(fingerprint)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(uuid) = cached {
        return Ok((uuid, false));
    }
    // An identical request may insert its row first; its key wins, and this one answers with that row.
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO svs.validations
             (uuid, repository, base_sha, head_sha, branch, pr_url, requested_by, active_key)
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8)
         ON CONFLICT (active_key) DO NOTHING
         RETURNING uuid",
    )
    .bind(Uuid::new_v4())
    .bind(request.repository)
    .bind(request.base_sha)
    .bind(request.head_sha)
    .bind(request.branch)
    .bind(request.pr_url)
    .bind(request.requested_by)
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?;
    match inserted {
        Some(uuid) => Ok((uuid, true)),
        None => {
            let uuid: Uuid =
                sqlx::query_scalar("SELECT uuid FROM svs.validations WHERE active_key = $1")
                    .bind(&key)
                    .fetch_one(&mut *tx)
                    .await?;
            Ok((uuid, false))
        }
    }
}

const CLAIMABLE: &str = "(state = 'queued'
     OR (state = 'running' AND heartbeat_at < clock_timestamp() - make_interval(secs => $1)
         AND attempts < $2))";

/// Takes the lease on the oldest validation that is queued, or running under an expired lease with
/// attempts left. None when there's nothing to run.
pub async fn claim(
    db: &Db,
    node: &str,
    lease: Duration,
    max_attempts: u32,
) -> Result<Option<Claim>, DbError> {
    let statement = format!(
        "UPDATE svs.validations
         SET state = 'running', claim_token = $3, claimed_by = $4, heartbeat_at = clock_timestamp(),
             attempts = attempts + 1, started_at = now(), error = NULL
         WHERE id = (SELECT id FROM svs.validations WHERE {CLAIMABLE}
                     ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
           AND {CLAIMABLE}
         RETURNING id, uuid, repository, base_sha, head_sha, branch, claim_token, attempts"
    );
    type Row = (i64, Uuid, String, String, String, String, Uuid, i32);
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(statement))
        .bind(lease.as_secs_f64())
        .bind(i32::try_from(max_attempts).unwrap_or(i32::MAX))
        .bind(Uuid::new_v4())
        .bind(node)
        .fetch_optional(db.pool())
        .await?;
    Ok(row.map(
        |(id, uuid, repository, base_sha, head_sha, branch, token, attempts)| Claim {
            id,
            uuid,
            repository,
            base_sha,
            head_sha,
            branch,
            token,
            attempts,
        },
    ))
}

const OWNED: &str = "id = $1 AND claim_token = $2 AND state = 'running'";

/// Extends the lease. False when the worker no longer holds it.
pub async fn heartbeat(db: &Db, claim: &Claim) -> Result<bool, DbError> {
    let done = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE svs.validations SET heartbeat_at = clock_timestamp() WHERE {OWNED}"
    )))
    .bind(claim.id)
    .bind(claim.token)
    .execute(db.pool())
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Puts a validation the stopping worker was running back in the queue, without counting the attempt: a
/// shutdown isn't the validation's fault.
pub async fn release(db: &Db, claim: &Claim) -> Result<bool, DbError> {
    let done = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE svs.validations
         SET state = 'queued', claim_token = NULL, claimed_by = NULL, heartbeat_at = NULL,
             started_at = NULL, attempts = greatest(attempts - 1, 0)
         WHERE {OWNED}"
    )))
    .bind(claim.id)
    .bind(claim.token)
    .execute(db.pool())
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Records that the validation couldn't run, and why. False when the worker no longer held it.
pub async fn fail(db: &Db, claim: &Claim, message: &str) -> Result<bool, DbError> {
    let done = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE svs.validations
         SET state = 'failed', error = $3, claim_token = NULL, active_key = NULL, finished_at = now()
         WHERE {OWNED}"
    )))
    .bind(claim.id)
    .bind(claim.token)
    .bind(message)
    .execute(db.pool())
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Fails the running validations whose lease expired after `max_attempts` claims: their workers stopped
/// (or died) every time they ran them. Returns how many.
pub async fn fail_abandoned(db: &Db, lease: Duration, max_attempts: u32) -> Result<u64, DbError> {
    let done = sqlx::query(
        "UPDATE svs.validations
         SET state = 'failed', claim_token = NULL, active_key = NULL, finished_at = now(),
             error = $3
         WHERE state = 'running' AND heartbeat_at < clock_timestamp() - make_interval(secs => $1)
           AND attempts >= $2",
    )
    .bind(lease.as_secs_f64())
    .bind(i32::try_from(max_attempts).unwrap_or(i32::MAX))
    .bind(format!(
        "its workers stopped {max_attempts} times while running it"
    ))
    .execute(db.pool())
    .await?;
    if done.rows_affected() > 0 {
        tracing::warn!(
            count = done.rows_affected(),
            "failed abandoned svs validations"
        );
    }
    Ok(done.rows_affected())
}

/// The categories each count adds up.
pub const REGRESSION_CATEGORIES: [Category; 2] =
    [Category::Regression, Category::RegressionUnconfirmed];
pub const NEW_FP_CATEGORIES: [Category; 2] = [Category::NewFp, Category::NewFpOtherRule];

fn count_of(result: &ReplayResult, categories: &[Category]) -> i64 {
    categories
        .iter()
        .map(|c| result.counts.get(c.as_str()).copied().unwrap_or(0) as i64)
        .sum()
}

/// Stores the report and its rows and marks the validation completed, in one transaction. Fails with
/// `LeaseLost`, storing nothing, when the worker no longer holds the lease.
pub async fn complete(
    db: &Db,
    claim: &Claim,
    result: &ReplayResult,
    corpus_version: &str,
    engine_fingerprint: &str,
) -> Result<(), CompleteError> {
    let compile_errors = result.head.file_errors.len() as i64 + i64::from(!result.head.loads);
    let mut tx = db.begin().await?;
    let updated = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE svs.validations
         SET state = 'completed', claim_token = NULL, active_key = NULL, finished_at = now(),
             corpus_version = $3, engine_fingerprint = $4, counts = $5, report = $6,
             regressions = $7, new_fps = $8, compile_errors = $9, diffed = $10
         WHERE {OWNED}"
    )))
    .bind(claim.id)
    .bind(claim.token)
    .bind(corpus_version)
    .bind(engine_fingerprint)
    .bind(sqlx::types::Json(&result.counts))
    .bind(result.report())
    .bind(i32::try_from(count_of(result, &REGRESSION_CATEGORIES)).unwrap_or(i32::MAX))
    .bind(i32::try_from(count_of(result, &NEW_FP_CATEGORIES)).unwrap_or(i32::MAX))
    .bind(i32::try_from(compile_errors).unwrap_or(i32::MAX))
    .bind(result.diffed)
    .execute(tx.conn())
    .await?;
    if updated.rows_affected() != 1 {
        return Err(CompleteError::LeaseLost(claim.uuid));
    }
    for rows in result.rows.chunks(RESULT_BATCH) {
        let column =
            |f: &dyn Fn(&super::yara::diff::ResultRow) -> Option<String>| -> Vec<Option<String>> {
                rows.iter().map(f).collect()
            };
        sqlx::query(
            "INSERT INTO svs.validation_results
                 (validation_id, sha256, rule_uuid, rule_name, namespace, label, label_source, base,
                  head, raw_base, raw_head, category, note)
             SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
                                      $7::text[], $8::text[], $9::text[], $10::bool[], $11::bool[],
                                      $12::text[], $13::text[])",
        )
        .bind(claim.id)
        .bind(column(&|r| Some(r.sha256.clone())))
        .bind(column(&|r| Some(r.rule_uuid.clone())))
        .bind(column(&|r| Some(r.rule_name.chars().take(256).collect())))
        .bind(column(&|r| r.namespace.clone()))
        .bind(column(&|r| r.label.clone()))
        .bind(column(&|r| r.label_source.clone()))
        .bind(column(&|r| Some(r.base.as_str().to_owned())))
        .bind(column(&|r| Some(r.head.as_str().to_owned())))
        .bind(rows.iter().map(|r| r.raw_base).collect::<Vec<_>>())
        .bind(rows.iter().map(|r| r.raw_head).collect::<Vec<_>>())
        .bind(column(&|r| Some(r.category.as_str().to_owned())))
        .bind(column(&|r| r.note.clone()))
        .execute(tx.conn())
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// The `(sha256, rule uuid)` pairs retired now: ace3's `retired_pairs`.
pub async fn retired_pairs(db: &Db) -> Result<BTreeSet<(String, String)>, DbError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT sha256, rule_uuid FROM svs.sample_retirements WHERE unretired_at IS NULL",
    )
    .fetch_all(db.pool())
    .await?;
    Ok(rows.into_iter().collect())
}

/// The workers of one `ace serve`: ace3's `ValidationWorker`s.
#[derive(Clone)]
pub struct Workers {
    pub db: Db,
    pub config: ValidationConfig,
    pub replay: Arc<dyn Replay>,
    /// The dispositions' classes, for the engine fingerprint.
    pub tp: Vec<String>,
    pub fp: Vec<String>,
    /// The name a claim records.
    pub node: String,
}

impl Workers {
    /// Runs `max_concurrent_validations` workers until `stop`, each claiming and running validations one
    /// at a time. A validation running at the stop goes back to the queue. Returns once every worker has.
    pub async fn run(self, stop: CancellationToken) {
        super::yara::replay::sweep_work_dir(&self.config);
        let mut workers = tokio::task::JoinSet::new();
        for index in 0..self.config.max_concurrent_validations {
            let this = self.clone();
            let stop = stop.clone();
            workers.spawn(async move {
                tracing::info!(worker = index, "svs validation worker started");
                while !stop.is_cancelled() {
                    let ran = match this.run_once(&stop).await {
                        Ok(ran) => ran,
                        Err(e) => {
                            tracing::error!("svs validation worker failed: {e}");
                            false
                        }
                    };
                    if !ran {
                        tokio::select! {
                            () = stop.cancelled() => {}
                            () = tokio::time::sleep(this.config.poll_interval) => {}
                        }
                    }
                }
            });
        }
        while workers.join_next().await.is_some() {}
    }

    /// Runs every waiting validation, one at a time, then returns: ace3's `start_single_threaded`.
    pub async fn drain(&self, stop: &CancellationToken) -> Result<u64, DbError> {
        let mut ran = 0;
        while !stop.is_cancelled() && self.run_once(stop).await? {
            ran += 1;
        }
        Ok(ran)
    }

    /// Runs one validation if one is waiting. Returns whether it did.
    pub async fn run_once(&self, stop: &CancellationToken) -> Result<bool, DbError> {
        fail_abandoned(&self.db, self.config.lease, self.config.max_attempts).await?;
        let Some(claimed) = claim(
            &self.db,
            &self.node,
            self.config.lease,
            self.config.max_attempts,
        )
        .await?
        else {
            return Ok(false);
        };
        self.execute(&claimed, stop).await;
        Ok(true)
    }

    /// Runs a claimed validation to its end, keeping its lease while it runs.
    pub async fn execute(&self, claimed: &Claim, stop: &CancellationToken) {
        let cancel = stop.child_token();
        let lost = CancellationToken::new();
        let done = CancellationToken::new();
        let keeper = {
            let (db, claimed, cancel, lost, done) = (
                self.db.clone(),
                claimed.clone(),
                cancel.clone(),
                lost.clone(),
                done.clone(),
            );
            let every = self.config.heartbeat_interval;
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = done.cancelled() => return,
                        () = tokio::time::sleep(every) => {}
                    }
                    match heartbeat(&db, &claimed).await {
                        Ok(true) => {}
                        Ok(false) => {
                            lost.cancel();
                            cancel.cancel();
                            return;
                        }
                        // a failed heartbeat isn't a lost lease; the next one may succeed
                        Err(e) => tracing::warn!(
                            validation = %claimed.uuid,
                            "unable to renew the lease on an svs validation: {e}"
                        ),
                    }
                }
            })
        };

        let span = tracing::info_span!(
            "svs_validation",
            svs_validation = %claimed.uuid,
            repository = %claimed.repository,
            base_sha = %claimed.base_sha,
            head_sha = %claimed.head_sha,
            attempt = claimed.attempts,
        );
        async {
        tracing::info!("running svs validation {}", claimed.uuid);
        let outcome = self.replay_claim(claimed, &cancel).await;
        match outcome {
            Ok((result, version, fingerprint)) => {
                match complete(&self.db, claimed, &result, &version, &fingerprint).await {
                    Ok(()) => tracing::info!(
                        diffed = result.diffed,
                        counts = ?result.counts,
                        "svs validation {} completed in {:.0}s",
                        claimed.uuid,
                        result.duration_seconds
                    ),
                    Err(CompleteError::LeaseLost(_)) => tracing::warn!(
                        "svs validation {} was taken over by another worker before it completed",
                        claimed.uuid
                    ),
                    Err(CompleteError::Db(e)) => {
                        tracing::error!("unable to store svs validation {}: {e}", claimed.uuid);
                        self.record_failure(claimed, INTERNAL_ERROR).await;
                    }
                }
            }
            Err(ReplayError::Cancelled) => {
                if lost.is_cancelled() {
                    tracing::warn!("svs validation {} was taken over by another worker", claimed.uuid);
                } else {
                    match release(&self.db, claimed).await {
                        Ok(true) => tracing::info!(
                            "svs validation {} returned to the queue: ace serve is stopping",
                            claimed.uuid
                        ),
                        Ok(false) => {}
                        Err(e) => tracing::warn!(
                            "unable to return svs validation {} to the queue: {e}",
                            claimed.uuid
                        ),
                    }
                }
            }
            Err(ReplayError::Failed(message)) => {
                tracing::warn!("svs validation {} failed: {message}", claimed.uuid);
                self.record_failure(claimed, &message).await;
            }
            Err(ReplayError::Internal(message)) => {
                tracing::error!("svs validation {} failed: {message}", claimed.uuid);
                self.record_failure(claimed, INTERNAL_ERROR).await;
            }
        }
        }
        .instrument(span)
        .await;
        done.cancel();
        if tokio::time::timeout(Duration::from_secs(5), keeper)
            .await
            .is_err()
        {
            tracing::warn!(
                "the lease keeper of svs validation {} didn't stop",
                claimed.uuid
            );
        }
    }

    /// Records why a claimed validation failed, logging when that can't be written.
    async fn record_failure(&self, claimed: &Claim, message: &str) {
        match fail(&self.db, claimed, message).await {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                "svs validation {} was taken over before its failure was recorded",
                claimed.uuid
            ),
            Err(e) => tracing::error!(
                "unable to record svs validation {}'s failure: {e}",
                claimed.uuid
            ),
        }
    }

    async fn replay_claim(
        &self,
        claimed: &Claim,
        cancel: &CancellationToken,
    ) -> Result<(ReplayResult, String, String), ReplayError> {
        // taken before the replay reads the corpus, so a change while it runs makes the next request run
        // again
        let version = corpus_version(&self.db)
            .await
            .map_err(|e| ReplayError::Internal(format!("reading the corpus version: {e}")))?;
        let fingerprint = engine_fingerprint(&self.config, &claimed.repository, &self.tp, &self.fp)
            .map_err(ReplayError::Failed)?;
        let retired = retired_pairs(&self.db)
            .await
            .map_err(|e| ReplayError::Internal(format!("reading the retired samples: {e}")))?;
        let request = ReplayRequest {
            repository: claimed.repository.clone(),
            base_sha: claimed.base_sha.clone(),
            head_sha: claimed.head_sha.clone(),
            branch: Some(claimed.branch.clone()),
            retired,
        };
        let result = self.replay.replay(&request, cancel).await?;
        Ok((result, version, fingerprint))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test_validations.py's `test_an_identical_request_shares_the_queued_validation`, its key: the sha256
    /// of the JSON `["svs_rules", "a" * 40, "b" * 40]`, computed outside ACE, so every process shares it.
    #[test]
    fn the_active_key_is_ace3_s() {
        assert_eq!(
            active_key("svs_rules", &"a".repeat(40), &"b".repeat(40)),
            "e59ce04f87ba60c144f48f4908d4ff0b8772decf7fc1cbc807136670b50d2a6b"
        );
    }
}
