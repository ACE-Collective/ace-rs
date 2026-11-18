//! The newly registered domains list (PLAN.md 7.4): ace3's `saq/nrd/`, in Postgres.
//!
//! ace3 keeps the list in a SQLite file on each node, `data/external/nrd/nrd_index.db`, which its
//! `nrd-refresh` cron job builds from the configured feeds and swaps in whole with `os.replace`, and
//! which `NRDAnalyzer` opens read-only. Here the list is migration 0039's `nrd.domains`, with its
//! meta row in `nrd.state`, so every node reads one list and a worker reads it through the core's
//! `newly-registered` read (`reads.md`). `ace serve`'s `nrd_refresh` task rebuilds it in one
//! transaction (`Rebuild`), so a read sees the old list or the new one, never half of one, as ace3's
//! swap gives it.
//!
//! The names are normalized as ace3 normalizes them, by `ace_sdk::nrd`, which the module uses too:
//! a feed's line with `normalize_line`, and a value the module asks about with `normalize_lookup`
//! and `candidates`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::db::{Db, DbError, Tx};

pub use ace_sdk::nrd::{candidates, normalize_line, normalize_lookup, registrable_domain};

// ---- the list ----

/// ace3's meta table: what the last rebuild recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListState {
    /// The SHA-256 of the configured primary URLs, sorted (`_compute_config_hash`).
    pub config_hash: String,
    pub last_refreshed_at: DateTime<Utc>,
    pub row_count: i64,
    /// One per configured list, as ace3's `sources`.
    pub sources: Vec<Source>,
}

/// What one list's fetch recorded, ace3's per-source meta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// The list's primary URL.
    pub url: String,
    /// The URL it came from: the primary or a backup.
    pub fetched_from: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_length: Option<i64>,
    /// The distinct domains the list gave.
    pub row_count: i64,
}

/// The list's state, or None before the first rebuild (ace3's missing database).
pub async fn state(db: &Db) -> Result<Option<ListState>, DbError> {
    let row = sqlx::query!(
        "SELECT config_hash, last_refreshed_at, row_count, sources FROM nrd.state WHERE id"
    )
    .fetch_optional(db.pool())
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    // sources that don't read are none, as ace3 reads an unparseable `sources` as []
    let sources = serde_json::from_value(row.sources).unwrap_or_default();
    Ok(Some(ListState {
        config_hash: row.config_hash,
        last_refreshed_at: row.last_refreshed_at,
        row_count: row.row_count,
        sources,
    }))
}

/// Whether any of `names` is in the list.
pub async fn listed(db: &Db, names: &[String]) -> Result<bool, DbError> {
    listed_in(db.pool(), names).await
}

/// `listed`, on any connection, such as the transaction that makes an analysis cache key
/// (`crate::cache`).
pub async fn listed_in<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    names: &[String],
) -> Result<bool, DbError> {
    let found = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM nrd.domains WHERE domain = ANY($1))",
        names,
    )
    .fetch_one(executor)
    .await?;
    Ok(found.unwrap_or(false))
}

/// The `newly-registered` read's answer for an observable of `kind` and `value`, as
/// `ace_core::reads` gives it to the task, without its checks of who asks: false for a value that
/// normalizes to nothing.
pub async fn answer_for<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    value: &str,
) -> Result<bool, DbError> {
    let normalized = ace_sdk::nrd::normalize_lookup(value);
    if normalized.is_empty() {
        return Ok(false);
    }
    listed_in(executor, &ace_sdk::nrd::candidates(&normalized)).await
}

/// The list's domains, sorted, for tests and checks.
pub async fn domains(db: &Db) -> Result<Vec<String>, DbError> {
    Ok(
        sqlx::query_scalar!("SELECT domain FROM nrd.domains ORDER BY domain COLLATE \"C\"")
            .fetch_all(db.pool())
            .await?,
    )
}

/// A rebuild of the list: one transaction that empties it, takes each feed's domains, and records
/// the state, so a read sees the old list until it commits. Dropped without `commit`, it leaves
/// the old list as it was, as ace3 leaves its database when a refresh aborts.
pub struct Rebuild {
    tx: Tx<'static>,
    /// Whether a list's attempt is open, as a savepoint.
    attempt: bool,
}

/// How many domains go in one insert, ace3's `INSERT_BATCH_SIZE`.
pub const INSERT_BATCH: usize = 10_000;

impl Rebuild {
    pub async fn begin(db: &Db) -> Result<Rebuild, DbError> {
        let mut tx = db.begin().await?;
        sqlx::query!("DELETE FROM nrd.domains")
            .execute(tx.conn())
            .await?;
        Ok(Rebuild { tx, attempt: false })
    }

    /// Starts one attempt at one list's URL, which `abandon` undoes and `keep` keeps.
    pub async fn attempt(&mut self) -> Result<(), DbError> {
        sqlx::query!("SAVEPOINT nrd_list")
            .execute(self.tx.conn())
            .await?;
        self.attempt = true;
        Ok(())
    }

    /// Adds domains, already normalized; one the list has already is kept once.
    pub async fn add(&mut self, domains: &[String]) -> Result<(), DbError> {
        for batch in domains.chunks(INSERT_BATCH) {
            sqlx::query!(
                "INSERT INTO nrd.domains (domain) SELECT unnest($1::text[]) ON CONFLICT DO NOTHING",
                batch,
            )
            .execute(self.tx.conn())
            .await?;
        }
        Ok(())
    }

    /// Undoes what the open attempt added, as ace3 rolls back a list whose stream failed.
    pub async fn abandon(&mut self) -> Result<(), DbError> {
        if self.attempt {
            sqlx::query!("ROLLBACK TO SAVEPOINT nrd_list")
                .execute(self.tx.conn())
                .await?;
            self.attempt = false;
        }
        Ok(())
    }

    /// Keeps what the open attempt added.
    pub async fn keep(&mut self) -> Result<(), DbError> {
        if self.attempt {
            sqlx::query!("RELEASE SAVEPOINT nrd_list")
                .execute(self.tx.conn())
                .await?;
            self.attempt = false;
        }
        Ok(())
    }

    /// Records the state with the list's row count and commits, returning the state.
    pub async fn commit(
        mut self,
        config_hash: &str,
        sources: Vec<Source>,
    ) -> Result<ListState, DbError> {
        let row_count = sqlx::query_scalar!(r#"SELECT count(*) AS "count!" FROM nrd.domains"#)
            .fetch_one(self.tx.conn())
            .await?;
        let sources_json: Value =
            serde_json::to_value(&sources).map_err(|e| DbError::Decode(e.to_string()))?;
        let refreshed = sqlx::query_scalar!(
            "INSERT INTO nrd.state (id, config_hash, last_refreshed_at, row_count, sources)
             VALUES (true, $1, now(), $2, $3)
             ON CONFLICT (id) DO UPDATE SET config_hash = $1, last_refreshed_at = now(),
                 row_count = $2, sources = $3
             RETURNING last_refreshed_at",
            config_hash,
            row_count,
            sources_json,
        )
        .fetch_one(self.tx.conn())
        .await?;
        self.tx.commit().await?;
        Ok(ListState {
            config_hash: config_hash.to_owned(),
            last_refreshed_at: refreshed,
            row_count,
            sources,
        })
    }
}
