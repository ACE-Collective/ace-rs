//! The analysis cache (PLAN.md decision 26, docs/decisions/0004): ace3's analysis result cache
//! (`saq/analysis/cache.py`), with what a module opts into in `ace_sdk::cache`.
//!
//! **Where it is checked.** Where eligibility would queue a cacheable component's task on an
//! observable, the core makes the key and looks it up first, in the same transaction
//! (`Orchestrator::queue_eligible`). A row that hasn't expired is a hit: its result is written as
//! the component's, through the same code as a task's end (`Orchestrator::land_result`), marked with
//! when the task that made it ended (`analysis.results.cached_at`), and no task is queued: no lease,
//! no pool, no process. A miss queues the task, and its end keeps its result when it may be kept.
//!
//! One case waits: a module that names the files it adds after the path it analyzed
//! (`CachePaths::Named`) needs that path, and a file's path is settled only once nothing nearer the
//! root could still add one (`Api::held_for_path`, PLAN.md decision 15). When it can't be settled yet,
//! the task is queued, and its lease, which waits for the path, looks the key up again once the path is
//! settled: a hit then ends the task with the kept result and nothing goes to a pool (`Api::leased`),
//! as a type step whose bytes were typed before ends there. The same lookup at the lease finds what
//! another root kept after this task was queued. Either way the result is the same as a run's.
//!
//! **The key** (`ace_sdk::cache::key`) holds the observable's type and value, the module's name,
//! instance, `Cache::version` and analysis type, its settings block, and its extended version: the
//! entries of each list it reads that haven't expired, as they are now, and the versions of its
//! tools, files and libraries. Those are its pool's (`ace_pool::cache`): a task's end sends them, the
//! result is kept under them, and they are kept here (`cache.probes`) for the next lookup. Until a
//! task of the module has ended with them, a module with any has no key, and nothing is looked up.
//! ace3's key is made the same way, with each node probing its own tools.
//!
//! **What is kept**, and what isn't (`refusal`): ace3's rules, on ace4's envelope. ace3 has to find
//! what a module did by diffing the tree around its run; here the envelope is what it did, so it is
//! what is kept, with the sha256 of each file it adds. Each file is held in the bucket by its row
//! until the row expires (a hold `cache`, `<row id>`, with the row's expiry), so the bucket's
//! collector keeps it as it keeps a root's, and lets it go once nothing holds it.
//!
//! **Expiry.** A row's `expires_at` is its creation plus the component's time to live; a lookup takes
//! only the newest row that hasn't expired, which is what makes a time to live exact. Rows are never
//! deleted one by one: they are in a partition a day, and the scheduler's `analysis_cache_partitions`
//! task drops each day `retention_days` after it ends (35, ace3's `partition_retention_days`), which
//! must be longer than any time to live, and makes the days ahead (`maintain`).

use std::collections::BTreeMap;
use std::io::Write as _;

use ace_results::ResultEnvelope;
use ace_sdk::Component;
use ace_sdk::cache::{CachePaths, KeyParts, MAX_COMPRESSED_BYTES};
use ace_sdk::overlay::AnalysisCacheSection;
use chrono::{DateTime, Duration as ChronoDuration, NaiveDate, NaiveDateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bucket::ALERT_FILES;
use crate::db::{Db, DbError, Tx};

/// The cache's settings: the overlay's `analysis_cache:`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheSettings {
    /// False turns the whole cache off: nothing is looked up or kept.
    pub enabled: bool,
    /// How many days after a day ends its rows are dropped.
    pub retention_days: u32,
}

impl Default for CacheSettings {
    fn default() -> Self {
        CacheSettings::from_section(&AnalysisCacheSection::default())
    }
}

impl CacheSettings {
    pub fn from_section(section: &AnalysisCacheSection) -> CacheSettings {
        CacheSettings {
            enabled: section.enabled,
            retention_days: section.retention_days,
        }
    }

    /// The cache off, as the comparison with ace3 runs.
    pub fn off() -> CacheSettings {
        CacheSettings {
            enabled: false,
            ..CacheSettings::default()
        }
    }

    /// Why these settings can't keep `components`' results, or None: a day is dropped only after
    /// the longest time to live has passed.
    pub fn check<'a>(&self, components: impl IntoIterator<Item = &'a Component>) -> Option<String> {
        let retention = std::time::Duration::from_secs(u64::from(self.retention_days) * 86_400);
        components.into_iter().find_map(|component| {
            let ttl = component.cache_ttl?;
            (ttl >= retention).then(|| {
                format!(
                    "analysis_cache.retention_days is {}, which isn't longer than {}'s time to live of \
                     {} s, so its rows would be dropped while they are live",
                    self.retention_days,
                    component.key,
                    ttl.as_secs()
                )
            })
        })
    }
}

/// True when `component`'s results are looked up and kept under `settings`.
pub fn caches(settings: &CacheSettings, component: &Component) -> bool {
    settings.enabled && component.cache_ttl.is_some() && component.manifest.cache.is_some()
}

/// A kept result.
#[derive(Debug, Clone)]
pub struct Kept {
    pub id: i64,
    pub envelope: ResultEnvelope<Value>,
    pub file_paths: Vec<i32>,
    pub files: Vec<String>,
    /// When the task that made it ended.
    pub created_at: DateTime<Utc>,
}

/// `component`'s extended version as the core holds it now for an observable with `value`: its
/// lists' entries, its keyed reads' answers and, with `probes` or else the ones its pool last sent,
/// its tools', files' and libraries' versions. None when a version it needs isn't known yet, so it
/// has no key.
pub async fn extended(
    tx: &mut Tx<'_>,
    component: &Component,
    value: &str,
    probes: Option<&BTreeMap<String, String>>,
) -> Result<Option<BTreeMap<String, String>>, DbError> {
    let Some(cache) = component.manifest.cache else {
        return Ok(None);
    };
    let mut extended = BTreeMap::new();
    for list in cache.lists {
        extended.insert(
            format!("list:{}", list.name),
            list_version(tx, list.name).await?,
        );
    }
    for read in cache.reads {
        let answer = match read.name {
            "newly-registered" => crate::nrd::answer_for(tx.conn(), value).await?,
            // `ace_sdk::cache::refusal` refuses a module keyed on any other
            _ => return Ok(None),
        };
        extended.insert(format!("read:{}", read.name), answer.to_string());
    }
    let reported = match probes {
        Some(_) => None,
        None => reported_probes(tx, &component.key).await?,
    };
    let none = BTreeMap::new();
    let probes = probes.or(reported.as_ref()).unwrap_or(&none);
    let needed = cache
        .tools
        .iter()
        .map(|tool| format!("tool:{tool}"))
        .chain(cache.files.iter().map(|file| format!("file:{file}")));
    for name in needed {
        if !probes.contains_key(&name) {
            return Ok(None);
        }
    }
    for (name, version) in probes {
        if name.starts_with("tool:") || name.starts_with("file:") || name.starts_with("library:") {
            extended.insert(name.clone(), version.clone());
        }
    }
    Ok(Some(extended))
}

/// The key of `component`'s result on an observable, with `extended` (`extended`).
pub fn key(
    component: &Component,
    kind: &str,
    value: &str,
    extended: &BTreeMap<String, String>,
) -> Option<[u8; 32]> {
    let cache = component.manifest.cache?;
    // a shared connection's settings are keyed by its identity alone (a tenant, not a timeout), so
    // the module's settings are keyed without them
    let settings = component.own_settings();
    let connections = component.connection_identities();
    Some(ace_sdk::cache::key(
        kind,
        value,
        &KeyParts {
            module: component.manifest.name,
            instance: &component.key,
            version: cache.version,
            output: (
                component.manifest.output.name,
                component.manifest.output.version,
            ),
            settings: settings.as_ref(),
            extended,
            connections: &connections,
        },
    ))
}

/// A list's entries that haven't expired, as a sha256: what of the list a module's result can
/// depend on now.
async fn list_version(tx: &mut Tx<'_>, list: &str) -> Result<String, DbError> {
    let entries = sqlx::query!(
        r#"SELECT match, value, ignore_case, observable_type FROM lists.entries
           WHERE list = $1 AND (expires_at IS NULL OR expires_at > now())
           ORDER BY observable_type NULLS FIRST, match, ignore_case, value"#,
        list,
    )
    .fetch_all(tx.conn())
    .await?;
    let mut hash = Sha256::new();
    for entry in entries {
        let line = serde_json::json!([
            entry.observable_type,
            entry.r#match,
            entry.ignore_case,
            entry.value
        ]);
        hash.update(line.to_string().as_bytes());
        hash.update(b"\n");
    }
    Ok(hex(&hash.finalize()))
}

async fn reported_probes(
    tx: &mut Tx<'_>,
    module: &str,
) -> Result<Option<BTreeMap<String, String>>, DbError> {
    let probes = sqlx::query_scalar!("SELECT probes FROM cache.probes WHERE module = $1", module)
        .fetch_optional(tx.conn())
        .await?;
    Ok(probes.and_then(|probes: Value| serde_json::from_value(probes).ok()))
}

/// Keeps the versions a component's pool sent with a result, for the next lookup's key.
pub async fn record_probes(
    tx: &mut Tx<'_>,
    module: &str,
    probes: &BTreeMap<String, String>,
) -> Result<(), DbError> {
    let probes = serde_json::to_value(probes).map_err(|e| DbError::Decode(e.to_string()))?;
    sqlx::query!(
        "INSERT INTO cache.probes (module, probes) VALUES ($1, $2)
         ON CONFLICT (module) DO UPDATE SET probes = EXCLUDED.probes, reported_at = now()
         WHERE cache.probes.probes IS DISTINCT FROM EXCLUDED.probes",
        module,
        probes,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The newest row kept under `key` that hasn't expired.
pub async fn find(tx: &mut Tx<'_>, key: &[u8; 32]) -> Result<Option<Kept>, DbError> {
    let row = sqlx::query!(
        r#"SELECT id, envelope, file_paths, files, created_at FROM cache.results
           WHERE key = $1 AND expires_at > now()
           ORDER BY created_at DESC, id DESC LIMIT 1"#,
        &key[..],
    )
    .fetch_optional(tx.conn())
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    match serde_json::from_value(row.envelope) {
        Ok(envelope) => Ok(Some(Kept {
            id: row.id,
            envelope,
            file_paths: row.file_paths,
            files: row.files,
            created_at: row.created_at,
        })),
        // a row an older build kept in a form this one doesn't read is a miss
        Err(e) => {
            tracing::warn!(row = row.id, "a kept result doesn't read: {e}");
            Ok(None)
        }
    }
}

/// Why `result` can't be kept, or each of its files' places among the paths its module names files
/// at for `analyzed`, the path its task analyzed (`CachePaths::Named`), and its size compressed. `writes` is whether the task
/// made writes to ACE's data.
pub fn refusal(
    component: &Component,
    result: &ResultEnvelope<Value>,
    writes: bool,
    analyzed: Option<&str>,
) -> Result<(Vec<i32>, usize), String> {
    let Some(cache) = component.manifest.cache else {
        return Err("the module isn't cacheable".to_owned());
    };
    if result.error.is_some() {
        return Err("the module said it failed (error)".to_owned());
    }
    if writes {
        return Err("it wrote to ACE's data".to_owned());
    }
    if !result.others.is_empty() || !result.redirected.is_empty() {
        return Err("it adds to observables it didn't analyze or add".to_owned());
    }
    if result.root.is_some() {
        return Err("it changes its root".to_owned());
    }
    if !result.stored.is_empty() {
        return Err("it stores files for its root".to_owned());
    }
    let mut places = Vec::with_capacity(result.files.len());
    if !result.files.is_empty() {
        let CachePaths::Named(names) = cache.paths else {
            return Err(
                "it adds files, and doesn't name them after its input (CachePaths)".to_owned(),
            );
        };
        let Some(analyzed) = analyzed else {
            return Err("it adds files, and analyzed no file".to_owned());
        };
        let names = names(analyzed);
        for file in &result.files {
            let place = names
                .iter()
                .position(|name| name == file.path.as_str())
                .ok_or_else(|| {
                    format!(
                        "it adds {:?}, which isn't a path it names after {analyzed:?}",
                        file.path.as_str()
                    )
                })?;
            places.push(i32::try_from(place).map_err(|_| "too many paths".to_owned())?);
        }
    }
    let size = compressed_size(result)?;
    if size > MAX_COMPRESSED_BYTES {
        return Err(format!(
            "it is {size} bytes compressed, past {MAX_COMPRESSED_BYTES}"
        ));
    }
    Ok((places, size))
}

/// The result's JSON, deflated, in bytes: what ace3's 1 MiB limit is of.
fn compressed_size(result: &ResultEnvelope<Value>) -> Result<usize, String> {
    let json = serde_json::to_vec(result).map_err(|e| e.to_string())?;
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&json).map_err(|e| e.to_string())?;
    Ok(encoder.finish().map_err(|e| e.to_string())?.len())
}

/// What to keep: a result its task ended with, under its key.
pub struct Keep<'a> {
    pub key: [u8; 32],
    pub module: &'a str,
    pub observable_type: &'a str,
    pub observable_value: &'a str,
    pub result: &'a ResultEnvelope<Value>,
    pub file_paths: Vec<i32>,
    pub ttl: std::time::Duration,
}

/// Keeps a result and holds its files for as long as it lives. Returns the row's id.
pub async fn keep(tx: &mut Tx<'_>, keep: &Keep<'_>) -> Result<i64, DbError> {
    let envelope = serde_json::to_value(keep.result).map_err(|e| DbError::Decode(e.to_string()))?;
    let files: Vec<String> = keep
        .result
        .files
        .iter()
        .map(|f| f.sha256.to_hex())
        .collect();
    let ttl = ChronoDuration::from_std(keep.ttl)
        .map_err(|_| DbError::Decode("a time to live past chrono's".to_owned()))?;
    let row = sqlx::query!(
        "INSERT INTO cache.results
             (key, module, observable_type, observable_value, envelope, file_paths, files, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now() + $8::interval)
         RETURNING id, expires_at",
        &keep.key[..],
        keep.module,
        keep.observable_type,
        keep.observable_value,
        envelope,
        &keep.file_paths,
        &files,
        sqlx::postgres::types::PgInterval::try_from(ttl)
            .map_err(|e| DbError::Decode(format!("a time to live: {e}")))?,
    )
    .fetch_one(tx.conn())
    .await?;
    let mut held = Vec::new();
    for sha256 in &files {
        if held.contains(sha256) {
            continue;
        }
        held.push(sha256.clone());
        sqlx::query!(
            "INSERT INTO store.holds (pool, sha256, holder_kind, holder_id, expires_at)
             VALUES ($1, $2, 'cache', $3, $4)
             ON CONFLICT (pool, sha256, holder_kind, holder_id)
             DO UPDATE SET expires_at = EXCLUDED.expires_at",
            ALERT_FILES,
            sha256,
            row.id.to_string(),
            row.expires_at,
        )
        .execute(tx.conn())
        .await?;
        sqlx::query!(
            "UPDATE store.objects SET last_held_at = now() WHERE pool = $1 AND sha256 = $2",
            ALERT_FILES,
            sha256,
        )
        .execute(tx.conn())
        .await?;
    }
    Ok(row.id)
}

/// Holds a kept result's files for `root`, as a task's end does for the files its result adds.
/// False when one is gone from the bucket, or going, which makes the row a miss.
pub async fn hold_files(tx: &mut Tx<'_>, root: uuid::Uuid, kept: &Kept) -> Result<bool, DbError> {
    let holder = root.to_string();
    for sha256 in &kept.files {
        let present = sqlx::query_scalar!(
            r#"SELECT state = 'present' AS "present!" FROM store.objects
               WHERE pool = $1 AND sha256 = $2 FOR UPDATE"#,
            ALERT_FILES,
            sha256,
        )
        .fetch_optional(tx.conn())
        .await?;
        if present != Some(true) {
            return Ok(false);
        }
        sqlx::query!(
            "INSERT INTO store.holds (pool, sha256, holder_kind, holder_id, expires_at)
             VALUES ($1, $2, 'root', $3, NULL)
             ON CONFLICT (pool, sha256, holder_kind, holder_id) DO UPDATE SET expires_at = NULL",
            ALERT_FILES,
            sha256,
            holder,
        )
        .execute(tx.conn())
        .await?;
        sqlx::query!(
            "UPDATE store.objects SET last_held_at = now() WHERE pool = $1 AND sha256 = $2",
            ALERT_FILES,
            sha256,
        )
        .execute(tx.conn())
        .await?;
    }
    Ok(true)
}

/// The kept result as `component`'s result for an observable analyzed under `analyzed`: each file
/// at its place among the paths the module names after it. None when a place isn't there, which
/// makes the row a miss.
pub fn for_path(
    component: &Component,
    kept: &Kept,
    analyzed: Option<&str>,
) -> Option<ResultEnvelope<Value>> {
    let mut envelope = kept.envelope.clone();
    if envelope.files.is_empty() {
        return Some(envelope);
    }
    let CachePaths::Named(names) = component.manifest.cache?.paths else {
        return None;
    };
    let names = names(analyzed?);
    if kept.file_paths.len() != envelope.files.len() {
        return None;
    }
    for (file, place) in envelope.files.iter_mut().zip(&kept.file_paths) {
        let name = names.get(usize::try_from(*place).ok()?)?;
        file.path = ace_results::AlertPath::new(name.clone()).ok()?;
    }
    Some(envelope)
}

/// What a lookup or a keep did, for the module's metrics event (`crate::metrics`): ace3's
/// per-(root, module) `cache_hit_count`, `cache_miss_count` and `cache_write_count_insert`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Hit,
    Miss,
    /// A result kept, with its size compressed.
    Kept {
        bytes: usize,
    },
}

/// Counts what a lookup or a keep did in the root's current pass, with how long a lookup took.
pub async fn count(
    tx: &mut Tx<'_>,
    root: uuid::Uuid,
    module: &str,
    activity: Activity,
    lookup: std::time::Duration,
) -> Result<(), DbError> {
    let (hits, misses, writes, bytes) = match activity {
        Activity::Hit => (1, 0, 0, 0),
        Activity::Miss => (0, 1, 0, 0),
        Activity::Kept { bytes } => (0, 0, 1, i64::try_from(bytes).unwrap_or(i64::MAX)),
    };
    let seconds = if matches!(activity, Activity::Kept { .. }) {
        0.0
    } else {
        lookup.as_secs_f64()
    };
    sqlx::query!(
        "INSERT INTO cache.activity
             (root_id, pass, module, hits, misses, writes, write_bytes, lookup_seconds,
              lookup_max_seconds)
         SELECT id, pass, $2, $3, $4, $5, $6, $7, $7 FROM analysis.roots WHERE id = $1
         ON CONFLICT (root_id, pass, module) DO UPDATE SET
             hits = cache.activity.hits + EXCLUDED.hits,
             misses = cache.activity.misses + EXCLUDED.misses,
             writes = cache.activity.writes + EXCLUDED.writes,
             write_bytes = cache.activity.write_bytes + EXCLUDED.write_bytes,
             lookup_seconds = cache.activity.lookup_seconds + EXCLUDED.lookup_seconds,
             lookup_max_seconds = GREATEST(cache.activity.lookup_max_seconds,
                                           EXCLUDED.lookup_max_seconds)",
        root,
        module,
        hits,
        misses,
        writes,
        bytes,
        seconds,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// How many days past today's are made ahead.
pub const DAYS_AHEAD: i64 = 3;

/// What one run of the partitions' maintenance did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Maintenance {
    pub dropped: Vec<String>,
    pub created: Vec<String>,
    /// What needs attention: a catchall holding rows of a day, or a table busy past the lock timeout.
    pub problems: Vec<String>,
}

/// A day's partition name.
pub fn partition_name(day: NaiveDate) -> String {
    format!("results_p{}", day.format("%Y%m%d"))
}

fn day_of_name(name: &str) -> Option<NaiveDate> {
    let digits = name.strip_prefix("results_p")?;
    (digits.len() == 8 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| NaiveDate::parse_from_str(digits, "%Y%m%d").ok())
        .flatten()
}

/// Drops each day `retention_days` after it ends and makes the days from today to `DAYS_AHEAD`
/// ahead, at `now`, as ace3's `ace partitions maintain` keeps its cache's
/// (`ace3/docs/ANALYSIS_CACHING.md` §A8). With `dry_run`, says what it would do and changes nothing.
pub async fn maintain(
    db: &Db,
    settings: &CacheSettings,
    now: DateTime<Utc>,
    dry_run: bool,
) -> Result<Maintenance, DbError> {
    let mut done = Maintenance::default();
    let existing: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i
         JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = to_regclass('cache.results')
         ORDER BY c.relname",
    )
    .fetch_all(db.pool())
    .await?;
    let today = now.date_naive();
    let cutoff = now.naive_utc() - ChronoDuration::days(i64::from(settings.retention_days));
    for name in &existing {
        let Some(day) = day_of_name(name) else {
            continue;
        };
        let end = midnight(day) + ChronoDuration::days(1);
        if end > cutoff {
            continue;
        }
        if !dry_run && let Err(problem) = ddl(db, format!("DROP TABLE cache.{name}")).await? {
            done.problems.push(format!("{name}: {problem}"));
            continue;
        }
        done.dropped.push(name.clone());
    }
    for ahead in 0..=DAYS_AHEAD {
        let day = today + ChronoDuration::days(ahead);
        let name = partition_name(day);
        if existing.contains(&name) {
            continue;
        }
        let (start, end) = (midnight(day), midnight(day) + ChronoDuration::days(1));
        let held: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM cache.results_p_catchall
                            WHERE created_at >= $1 AND created_at < $2)",
        )
        .bind(start.and_utc())
        .bind(end.and_utc())
        .fetch_one(db.pool())
        .await?;
        if held {
            done.problems.push(format!(
                "results_p_catchall holds rows of the day {name} would hold, so it isn't made; they \
                 go when the catchall's rows have all expired and it is emptied by hand"
            ));
        } else if dry_run {
            done.created.push(name);
        } else {
            let statement = format!(
                "CREATE TABLE cache.{name} PARTITION OF cache.results \
                 FOR VALUES FROM ('{start}+00') TO ('{end}+00')"
            );
            match ddl(db, statement).await? {
                Ok(()) => done.created.push(name),
                Err(problem) => done.problems.push(format!("{name}: {problem}")),
            }
        }
    }
    Ok(done)
}

fn midnight(day: NaiveDate) -> NaiveDateTime {
    day.and_hms_opt(0, 0, 0).expect("midnight")
}

/// One DDL statement with a short lock timeout, as the email archive's maintenance runs each. Its
/// names are made from a date, never input.
async fn ddl(db: &Db, statement: String) -> Result<Result<(), String>, DbError> {
    let mut tx = db.begin().await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(tx.conn())
        .await?;
    match sqlx::query(sqlx::AssertSqlSafe(statement))
        .execute(tx.conn())
        .await
    {
        Ok(_) => {
            tx.commit().await?;
            Ok(Ok(()))
        }
        Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("55P03") => {
            Ok(Err("table busy, will try again next run".to_owned()))
        }
        Err(sqlx::Error::Database(e)) => Ok(Err(e.message().to_owned())),
        Err(e) => Err(e.into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_day_is_named_by_its_date() {
        let day = NaiveDate::from_ymd_opt(2026, 11, 18).expect("a day");
        assert_eq!(partition_name(day), "results_p20261118");
        assert_eq!(day_of_name("results_p20261118"), Some(day));
        assert_eq!(day_of_name("results_p_catchall"), None);
        assert_eq!(day_of_name("results_p2026111"), None);
    }
}
