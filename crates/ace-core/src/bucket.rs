//! The bucket with its index: pools, holds and retention, carried over from ace3's CAS
//! (`docs/CAS.md` and the `cas:` section of `etc/saq.default.yaml`).
//!
//! `ace_store::Store` moves bytes; this module decides what exists. A pool names a retention
//! mode. In a `held` pool an object lives while something holds it, plus the pool's grace
//! period after the last hold went; a `permanent` pool keeps everything. GC deletes what no
//! longer qualifies, in batches in key order with a pause between them, and never lists the
//! bucket. ace3's weekly orphan sweep and verify come with the scheduler (PLAN.md 6.7): `orphans`
//! is the one operation that lists the bucket, for bytes a put uploaded before its transaction
//! failed to commit, and `verify` re-hashes a sample.
//!
//! A put is one transaction, as in ace3: it inserts the object's row if it is new, locks it,
//! uploads the bytes while holding the lock unless the bucket has them, and takes the hold.
//! GC claims an object by flipping its row to `deleting` only while nothing holds it, so a put
//! or a hold and GC's claim serialize on that row. A put that finds the object `deleting`
//! waits for GC to finish and puts it again.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use ace_results::Sha256;
use ace_store::{CachedFile, Spooled, Store, StoreError};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::{Db, DbError, Tx};

/// How long a pool keeps an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// While a hold is live, and for `grace` after the last one went.
    Held { grace: Duration },
    /// Always. Nothing in this module deletes from it.
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    pub retention: Retention,
}

/// The bucket's settings: ace3's `cas:` values, without the ones for backends, encryption and
/// the `ttl` mode, which aren't carried over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketSettings {
    /// Rows per GC transaction.
    pub gc_batch_size: i64,
    pub gc_batch_pause: Duration,
    /// How long a put waits for GC to finish deleting the object it wants to put again.
    pub put_deleting_wait: Duration,
    /// How old bytes with no index row must be before the orphan sweep removes them, so a put
    /// still in its transaction is never taken for one: ace3's `orphan_grace_seconds`.
    pub orphan_grace: Duration,
    /// Objects per pool one verify re-hashes: ace3's `verify_sample_size`.
    pub verify_sample: i64,
    pub pools: BTreeMap<String, PoolConfig>,
}

/// ace3's `default_grace_seconds`.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(86_400);

impl Default for BucketSettings {
    /// ace3's defaults. `svs_samples` keeps its retention, `alert_files`, the pool CAS.md plans
    /// for alert files, holds each file for the roots it is in and the QA matches it is in
    /// (PLAN.md 2.27), and `yara_rulesets` keeps every ruleset the core built (2.25). ace3's
    /// `yara_qa` pool isn't carried over: a QA match holds the file where it already is.
    /// `email_archive` holds each archived email, sealed, while its archive rows last (7.5 batch 9),
    /// where ace3 keeps it on its node's disk.
    fn default() -> Self {
        let held = PoolConfig {
            retention: Retention::Held {
                grace: DEFAULT_GRACE,
            },
        };
        BucketSettings {
            gc_batch_size: 500,
            gc_batch_pause: Duration::from_millis(500),
            put_deleting_wait: Duration::from_secs(30),
            orphan_grace: Duration::from_secs(86_400),
            verify_sample: 1000,
            pools: [
                (ALERT_FILES.to_owned(), held),
                (
                    crate::rulesets::RULESETS.to_owned(),
                    PoolConfig {
                        retention: Retention::Permanent,
                    },
                ),
                ("svs_samples".to_owned(), held),
                (crate::email_archive::EMAIL_ARCHIVE.to_owned(), held),
            ]
            .into(),
        }
    }
}

impl BucketSettings {
    pub fn with_pool(mut self, name: impl Into<String>, config: PoolConfig) -> Self {
        self.pools.insert(name.into(), config);
        self
    }
}

/// The pool for the files in alerts.
pub const ALERT_FILES: &str = "alert_files";

/// Something that keeps an object, such as a root its file is in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    pub kind: String,
    pub id: String,
    /// None holds until released.
    pub expires_at: Option<DateTime<Utc>>,
}

impl Hold {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Hold {
            kind: kind.into(),
            id: id.into(),
            expires_at: None,
        }
    }

    /// The hold a root keeps on each of its files.
    pub fn root(root: Uuid) -> Self {
        Hold::new("root", root.to_string())
    }

    pub fn until(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }
}

/// An object's index row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub pool: String,
    pub sha256: Sha256,
    pub size: u64,
    pub mime_type: String,
    pub created_at: DateTime<Utc>,
    pub last_held_at: DateTime<Utc>,
}

/// What a put did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Put {
    pub object: ObjectInfo,
    /// False when the bucket already had the bytes.
    pub uploaded: bool,
}

/// What a GC run of one pool did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct GcStats {
    /// Objects deleted, including ones an earlier run left `deleting`.
    pub deleted: u64,
    /// Expired hold rows removed.
    pub holds_pruned: u64,
}

/// What an orphan sweep of one pool did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct OrphanStats {
    /// Keys listed under the pool.
    pub scanned: u64,
    /// Keys with no index row, deleted or not.
    pub orphaned: u64,
    /// Orphans younger than the grace, left for a later sweep.
    pub within_grace: u64,
    pub deleted: u64,
    pub bytes_reclaimed: u64,
    /// Keys the bucket's naming doesn't make, left as they are.
    pub unrecognized: u64,
}

/// What a verify of one pool found.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct VerifyStats {
    pub checked: u64,
    /// Intact, with `verified_at` recorded.
    pub verified: u64,
    /// Deleted by GC since the sample was taken.
    pub removed: u64,
    /// In the index and not in the bucket.
    pub missing: Vec<Sha256>,
    /// In the bucket with bytes that hash to something else.
    pub corrupt: Vec<Sha256>,
}

impl VerifyStats {
    /// True when an object was missing or corrupt.
    pub fn failed(&self) -> bool {
        !self.missing.is_empty() || !self.corrupt.is_empty()
    }
}

/// The sha256 a pool's key names: `<pool>/<sha[0..2]>/<sha[2..4]>/<sha>`, as `Store::key` makes it.
fn sha256_of_key(pool: &str, key: &str) -> Option<Sha256> {
    let sha256: Sha256 = key.rsplit('/').next()?.parse().ok()?;
    (Store::key(pool, &sha256).ok()? == key).then_some(sha256)
}

/// 32 random bytes, for the point a verify's sample starts at.
fn rand_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

#[derive(Debug, thiserror::Error)]
pub enum BucketError {
    #[error("no pool named {0:?} is configured")]
    UnknownPool(String),
    #[error("{pool}/{sha256} isn't in the bucket")]
    NotFound { pool: String, sha256: Sha256 },
    #[error("{pool}/{sha256} is being deleted; put it again instead of holding it")]
    Deleting { pool: String, sha256: Sha256 },
    #[error(transparent)]
    Db(#[from] DbError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for BucketError {
    fn from(error: sqlx::Error) -> Self {
        BucketError::Db(DbError::Sqlx(error))
    }
}

/// The bucket, its index and this node's cache.
#[derive(Debug, Clone)]
pub struct Bucket {
    db: Db,
    store: Store,
    settings: BucketSettings,
}

impl Bucket {
    pub fn new(db: Db, store: Store, settings: BucketSettings) -> Self {
        Bucket {
            db,
            store,
            settings,
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    fn pool(&self, pool: &str) -> Result<PoolConfig, BucketError> {
        self.settings
            .pools
            .get(pool)
            .copied()
            .ok_or_else(|| BucketError::UnknownPool(pool.to_owned()))
    }

    /// Puts `bytes` in `pool` and takes `hold` on them in the same step.
    pub async fn put_bytes(
        &self,
        pool: &str,
        bytes: &[u8],
        hold: Option<&Hold>,
    ) -> Result<Put, BucketError> {
        self.pool(pool)?;
        let spooled = self.store.spool_bytes(bytes).await?;
        self.put(pool, spooled, hold).await
    }

    /// Puts a copy of the file at `path` in `pool` and takes `hold` on it in the same step.
    pub async fn put_file(
        &self,
        pool: &str,
        path: &Path,
        hold: Option<&Hold>,
    ) -> Result<Put, BucketError> {
        self.pool(pool)?;
        let spooled = self.store.spool_file(path).await?;
        self.put(pool, spooled, hold).await
    }

    /// Downloads a file a worker uploaded for `task` and checks that its bytes match `sha256`.
    /// The upload stays until `remove_upload`, so a transaction that puts it can run again.
    /// Bytes that don't match their name are removed at once and never reach a pool.
    pub async fn fetch_upload(&self, task: i64, sha256: &Sha256) -> Result<Spooled, BucketError> {
        let key = Store::upload_key(task, sha256);
        let spooled = self.store.spool_key(&key, sha256).await;
        if let Err(StoreError::Integrity { .. }) = &spooled {
            self.store.delete_key(&key).await?;
        }
        Ok(spooled?)
    }

    /// Removes an upload once what it held is in a pool.
    pub async fn remove_upload(&self, task: i64, sha256: &Sha256) -> Result<(), BucketError> {
        Ok(self
            .store
            .delete_key(&Store::upload_key(task, sha256))
            .await?)
    }

    /// `fetch_upload` for a file an action collected (`Store::action_upload_key`).
    pub async fn fetch_action_upload(
        &self,
        action: i64,
        sha256: &Sha256,
    ) -> Result<Spooled, BucketError> {
        let key = Store::action_upload_key(action, sha256);
        let spooled = self.store.spool_key(&key, sha256).await;
        if let Err(StoreError::Integrity { .. }) = &spooled {
            self.store.delete_key(&key).await?;
        }
        Ok(spooled?)
    }

    /// `remove_upload` for a file an action collected.
    pub async fn remove_action_upload(
        &self,
        action: i64,
        sha256: &Sha256,
    ) -> Result<(), BucketError> {
        Ok(self
            .store
            .delete_key(&Store::action_upload_key(action, sha256))
            .await?)
    }

    /// Puts spooled bytes in `pool` and takes `hold` on them inside the caller's transaction:
    /// inserts the object's row if it is new, locks it, uploads the bytes while holding the
    /// lock unless the bucket has them, and takes the hold. An object GC is deleting fails with
    /// `Deleting`; put it again later.
    pub async fn put_in(
        &self,
        tx: &mut Tx<'_>,
        pool: &str,
        spooled: &Spooled,
        hold: Option<&Hold>,
    ) -> Result<bool, BucketError> {
        self.pool(pool)?;
        let sha256 = spooled.sha256.to_hex();
        sqlx::query!(
            "INSERT INTO store.objects (pool, sha256, size, mime_type) VALUES ($1, $2, $3, $4)
             ON CONFLICT (pool, sha256) DO NOTHING",
            pool,
            sha256,
            i64::try_from(spooled.size).unwrap_or(i64::MAX),
            spooled.mime_type,
        )
        .execute(tx.conn())
        .await?;
        let state = sqlx::query_scalar!(
            r#"SELECT state AS "state: ObjectState" FROM store.objects
               WHERE pool = $1 AND sha256 = $2 FOR UPDATE"#,
            pool,
            sha256,
        )
        .fetch_one(tx.conn())
        .await?;
        if state == ObjectState::Deleting {
            return Err(BucketError::Deleting {
                pool: pool.to_owned(),
                sha256: spooled.sha256,
            });
        }
        // under the row's lock, so GC can't remove the bytes between the check and the hold
        let uploaded = if self.store.exists(pool, &spooled.sha256).await? {
            false
        } else {
            self.store.upload(pool, spooled).await?;
            true
        };
        if let Some(hold) = hold {
            take_hold(tx, pool, &sha256, hold).await?;
        }
        Ok(uploaded)
    }

    async fn put(
        &self,
        pool: &str,
        spooled: Spooled,
        hold: Option<&Hold>,
    ) -> Result<Put, BucketError> {
        let waited_since = Instant::now();
        loop {
            let mut tx = self.db.begin().await?;
            let uploaded = match self.put_in(&mut tx, pool, &spooled, hold).await {
                Ok(uploaded) => uploaded,
                Err(BucketError::Deleting { .. })
                    if waited_since.elapsed() < self.settings.put_deleting_wait =>
                {
                    drop(tx);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            tx.commit().await?;
            let object =
                self.object(pool, &spooled.sha256)
                    .await?
                    .ok_or_else(|| BucketError::NotFound {
                        pool: pool.to_owned(),
                        sha256: spooled.sha256,
                    })?;
            // this node has the bytes already, so they go in its cache
            self.store.keep(pool, spooled).await?;
            return Ok(Put { object, uploaded });
        }
    }

    /// Takes a hold on an object that is already in the bucket, or renews its expiry.
    pub async fn hold(&self, pool: &str, sha256: &Sha256, hold: &Hold) -> Result<(), BucketError> {
        let mut tx = self.db.begin().await?;
        self.hold_in(&mut tx, pool, sha256, hold).await?;
        tx.commit().await?;
        Ok(())
    }

    /// `hold`, inside the caller's transaction. The object's row stays locked until it ends, so
    /// GC can't claim the object in between.
    pub async fn hold_in(
        &self,
        tx: &mut Tx<'_>,
        pool: &str,
        sha256: &Sha256,
        hold: &Hold,
    ) -> Result<(), BucketError> {
        self.pool(pool)?;
        let hex = sha256.to_hex();
        let state = sqlx::query_scalar!(
            r#"SELECT state AS "state: ObjectState" FROM store.objects
               WHERE pool = $1 AND sha256 = $2 FOR UPDATE"#,
            pool,
            hex,
        )
        .fetch_optional(tx.conn())
        .await?;
        match state {
            None => Err(BucketError::NotFound {
                pool: pool.to_owned(),
                sha256: *sha256,
            }),
            Some(ObjectState::Deleting) => Err(BucketError::Deleting {
                pool: pool.to_owned(),
                sha256: *sha256,
            }),
            Some(ObjectState::Present) => take_hold(tx, pool, &hex, hold).await,
        }
    }

    /// Releases a hold, which starts the object's grace period again. False when there was no
    /// such hold.
    pub async fn release(
        &self,
        pool: &str,
        sha256: &Sha256,
        hold: &Hold,
    ) -> Result<bool, BucketError> {
        let mut tx = self.db.begin().await?;
        let released = release_in(&mut tx, pool, sha256, hold).await?;
        tx.commit().await?;
        Ok(released)
    }

    /// The object's index row, if the pool has it.
    pub async fn object(
        &self,
        pool: &str,
        sha256: &Sha256,
    ) -> Result<Option<ObjectInfo>, BucketError> {
        let row = sqlx::query!(
            "SELECT size, mime_type, created_at, last_held_at FROM store.objects
             WHERE pool = $1 AND sha256 = $2 AND state = 'present'",
            pool,
            sha256.to_hex(),
        )
        .fetch_optional(self.db.pool())
        .await?;
        Ok(row.map(|row| ObjectInfo {
            pool: pool.to_owned(),
            sha256: *sha256,
            size: u64::try_from(row.size).unwrap_or_default(),
            mime_type: row.mime_type,
            created_at: row.created_at,
            last_held_at: row.last_held_at,
        }))
    }

    /// The object's bytes, from this node's cache or from the bucket into it.
    pub async fn get(&self, pool: &str, sha256: &Sha256) -> Result<CachedFile, BucketError> {
        if self.object(pool, sha256).await?.is_none() {
            return Err(BucketError::NotFound {
                pool: pool.to_owned(),
                sha256: *sha256,
            });
        }
        Ok(self.store.get(pool, sha256).await?)
    }

    /// Deletes what the pool's retention no longer keeps. Finishes deletions an earlier run
    /// left halfway first, and prunes expired holds last, in batches in key order.
    pub async fn gc(&self, pool: &str) -> Result<GcStats, BucketError> {
        let grace = match self.pool(pool)?.retention {
            Retention::Permanent => return Ok(GcStats::default()),
            Retention::Held { grace } => grace.as_secs_f64(),
        };
        let batch = self.settings.gc_batch_size;
        let mut stats = GcStats::default();

        // objects an earlier run or a crash left halfway
        loop {
            let deleting = sqlx::query_scalar!(
                "SELECT sha256 FROM store.objects WHERE pool = $1 AND state = 'deleting'
                 ORDER BY sha256 LIMIT $2",
                pool,
                batch,
            )
            .fetch_all(self.db.pool())
            .await?;
            for sha256 in &deleting {
                self.finish_deleting(pool, sha256).await?;
                stats.deleted += 1;
            }
            if (deleting.len() as i64) < batch {
                break;
            }
            tokio::time::sleep(self.settings.gc_batch_pause).await;
        }

        // unheld objects past their grace
        loop {
            let candidates = sqlx::query_scalar!(
                "SELECT o.sha256 FROM store.objects o
                 WHERE o.pool = $1 AND o.state = 'present'
                   AND o.last_held_at < now() - make_interval(secs => $2)
                   AND NOT EXISTS (
                       SELECT 1 FROM store.holds h
                       WHERE h.pool = o.pool AND h.sha256 = o.sha256
                         AND (h.expires_at IS NULL OR h.expires_at > now()))
                 ORDER BY o.sha256 LIMIT $3",
                pool,
                grace,
                batch,
            )
            .fetch_all(self.db.pool())
            .await?;
            for sha256 in &candidates {
                // the claim checks again, so a hold taken since the scan keeps the object
                let mut tx = self.db.begin().await?;
                let claimed = sqlx::query!(
                    "UPDATE store.objects o SET state = 'deleting'
                     WHERE o.pool = $1 AND o.sha256 = $2 AND o.state = 'present'
                       AND o.last_held_at < now() - make_interval(secs => $3)
                       AND NOT EXISTS (
                           SELECT 1 FROM store.holds h
                           WHERE h.pool = o.pool AND h.sha256 = o.sha256
                             AND (h.expires_at IS NULL OR h.expires_at > now()))",
                    pool,
                    sha256,
                    grace,
                )
                .execute(tx.conn())
                .await?
                .rows_affected()
                    > 0;
                tx.commit().await?;
                if claimed {
                    self.finish_deleting(pool, sha256).await?;
                    stats.deleted += 1;
                }
            }
            if (candidates.len() as i64) < batch {
                break;
            }
            tokio::time::sleep(self.settings.gc_batch_pause).await;
        }

        // expired holds, which would otherwise stay on an object another hold keeps
        loop {
            let mut tx = self.db.begin().await?;
            let pruned = sqlx::query!(
                "DELETE FROM store.holds WHERE (pool, sha256, holder_kind, holder_id) IN (
                     SELECT pool, sha256, holder_kind, holder_id FROM store.holds
                     WHERE pool = $1 AND expires_at <= now()
                     ORDER BY sha256, holder_kind, holder_id LIMIT $2)",
                pool,
                batch,
            )
            .execute(tx.conn())
            .await?
            .rows_affected();
            tx.commit().await?;
            stats.holds_pruned += pruned;
            if (pruned as i64) < batch {
                break;
            }
            tokio::time::sleep(self.settings.gc_batch_pause).await;
        }
        Ok(stats)
    }

    /// The pools this bucket has, in name order.
    pub fn pools(&self) -> impl Iterator<Item = (&str, Retention)> {
        self.settings
            .pools
            .iter()
            .map(|(name, config)| (name.as_str(), config.retention))
    }

    /// ace3's `cas orphans`: lists the pool's keys in the bucket and deletes the bytes no index row
    /// names, once they're older than `orphan_grace`, so a put still in its transaction, which uploads
    /// before it commits, isn't taken for one. A key the bucket's naming doesn't make is counted and
    /// left. This is the one operation that lists the bucket, so it runs weekly, as in ace3.
    pub async fn orphans(&self, pool: &str) -> Result<OrphanStats, BucketError> {
        self.pool(pool)?;
        let prefix = format!("{pool}/");
        let cutoff = Utc::now().timestamp()
            - i64::try_from(self.settings.orphan_grace.as_secs()).unwrap_or(i64::MAX);
        let mut stats = OrphanStats::default();
        let listed = self.store.list_entries(&prefix).await?;
        let batch = usize::try_from(self.settings.gc_batch_size.max(1)).unwrap_or(500);
        for chunk in listed.chunks(batch) {
            let mut named = Vec::new();
            for entry in chunk {
                stats.scanned += 1;
                match sha256_of_key(pool, &entry.key) {
                    Some(sha256) => named.push((entry, sha256)),
                    None => {
                        tracing::warn!(pool, key = %entry.key, "a key the bucket's naming doesn't make");
                        stats.unrecognized += 1;
                    }
                }
            }
            let hexes: Vec<String> = named.iter().map(|(_, sha256)| sha256.to_hex()).collect();
            // any state: an object GC is deleting isn't an orphan, GC finishes it
            let present: std::collections::BTreeSet<String> = sqlx::query_scalar!(
                "SELECT sha256 FROM store.objects WHERE pool = $1 AND sha256 = ANY($2)",
                pool,
                &hexes,
            )
            .fetch_all(self.db.pool())
            .await?
            .into_iter()
            .collect();
            for (entry, sha256) in named {
                if present.contains(&sha256.to_hex()) {
                    continue;
                }
                stats.orphaned += 1;
                if entry.modified_seconds >= cutoff {
                    stats.within_grace += 1;
                    continue;
                }
                self.store.delete(pool, &sha256).await?;
                stats.deleted += 1;
                stats.bytes_reclaimed += entry.size;
            }
        }
        if stats.deleted > 0 {
            tracing::info!(
                pool,
                deleted = stats.deleted,
                bytes = stats.bytes_reclaimed,
                "removed bytes with no index row"
            );
        }
        Ok(stats)
    }

    /// ace3's `cas verify`: re-hashes up to `verify_sample` of the pool's objects, from a random
    /// point in hash order and round, downloading each past the node's cache, and records
    /// `verified_at` on the intact ones. A corrupt or missing object is listed and logged, never
    /// deleted. One GC deleted since the sample was taken isn't a failure.
    pub async fn verify(&self, pool: &str) -> Result<VerifyStats, BucketError> {
        self.pool(pool)?;
        let start = Sha256(rand_bytes()).to_hex();
        let sample = self.settings.verify_sample;
        let mut sampled = sqlx::query_scalar!(
            "SELECT sha256 FROM store.objects WHERE pool = $1 AND state = 'present' AND sha256 >= $2
             ORDER BY sha256 LIMIT $3",
            pool,
            start,
            sample,
        )
        .fetch_all(self.db.pool())
        .await?;
        let rest = sample - i64::try_from(sampled.len()).unwrap_or(i64::MAX);
        if rest > 0 {
            sampled.extend(
                sqlx::query_scalar!(
                    "SELECT sha256 FROM store.objects
                     WHERE pool = $1 AND state = 'present' AND sha256 < $2
                     ORDER BY sha256 LIMIT $3",
                    pool,
                    start,
                    rest,
                )
                .fetch_all(self.db.pool())
                .await?,
            );
        }
        let mut stats = VerifyStats::default();
        for hex in sampled {
            stats.checked += 1;
            let sha256: Sha256 = hex
                .parse()
                .map_err(|e| DbError::Decode(format!("store.objects sha256 {hex}: {e}")))?;
            match self.store.verify(pool, &sha256).await {
                Ok(()) => {
                    sqlx::query!(
                        "UPDATE store.objects SET verified_at = now() WHERE pool = $1 AND sha256 = $2",
                        pool,
                        hex,
                    )
                    .execute(self.db.pool())
                    .await?;
                    stats.verified += 1;
                }
                Err(StoreError::NotFound { .. }) if self.object(pool, &sha256).await?.is_none() => {
                    stats.removed += 1;
                }
                Err(StoreError::NotFound { .. }) => {
                    tracing::error!(pool, %sha256, "an object in the index isn't in the bucket");
                    stats.missing.push(sha256);
                }
                Err(StoreError::Integrity { actual, .. }) => {
                    tracing::error!(pool, %sha256, %actual, "an object's bytes don't match its name");
                    stats.corrupt.push(sha256);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(stats)
    }

    /// Deletes a claimed object's bytes, then its row.
    /// Finishes a purge `claim_purge_in` claimed: deletes the bytes, then the object's row. A purge
    /// that fails here leaves the object `deleting`, which a later purge, or GC, finishes.
    pub async fn finish_purge(&self, pool: &str, sha256: &Sha256) -> Result<(), BucketError> {
        self.pool(pool)?;
        self.finish_deleting(pool, &sha256.to_hex()).await
    }

    async fn finish_deleting(&self, pool: &str, sha256: &str) -> Result<(), BucketError> {
        let parsed: Sha256 = sha256
            .parse()
            .map_err(|e| DbError::Decode(format!("store.objects sha256 {sha256}: {e}")))?;
        self.store.delete(pool, &parsed).await?;
        let mut tx = self.db.begin().await?;
        sqlx::query!(
            "DELETE FROM store.objects WHERE pool = $1 AND sha256 = $2 AND state = 'deleting'",
            pool,
            sha256,
        )
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "store.object_state", rename_all = "snake_case")]
enum ObjectState {
    Present,
    Deleting,
}

/// Claims an object for a purge inside the caller's transaction, as ace3's `CASPool.purge` does: every
/// hold on it goes and it turns `deleting`, so nothing can hold it again, whatever held it. Its bytes go
/// with `Bucket::finish_purge` once the transaction commits. False when the pool has no such object;
/// one already `deleting` is claimed again, so a purge that didn't finish can be retried.
pub async fn claim_purge_in(
    tx: &mut Tx<'_>,
    pool: &str,
    sha256: &Sha256,
) -> Result<bool, BucketError> {
    let hex = sha256.to_hex();
    let claimed = sqlx::query!(
        "UPDATE store.objects SET state = 'deleting' WHERE pool = $1 AND sha256 = $2",
        pool,
        hex,
    )
    .execute(tx.conn())
    .await?
    .rows_affected()
        > 0;
    if claimed {
        sqlx::query!(
            "DELETE FROM store.holds WHERE pool = $1 AND sha256 = $2",
            pool,
            hex,
        )
        .execute(tx.conn())
        .await?;
    }
    Ok(claimed)
}

/// `Bucket::release`, inside the caller's transaction, so a row that holds an object and its hold
/// go together. Only this hold goes: an object another hold keeps, such as a root's, stays, and
/// one that nothing holds any more lives for its pool's grace from now. False when there was no
/// such hold.
pub async fn release_in(
    tx: &mut Tx<'_>,
    pool: &str,
    sha256: &Sha256,
    hold: &Hold,
) -> Result<bool, BucketError> {
    let hex = sha256.to_hex();
    let released = sqlx::query!(
        "DELETE FROM store.holds
         WHERE pool = $1 AND sha256 = $2 AND holder_kind = $3 AND holder_id = $4",
        pool,
        hex,
        hold.kind,
        hold.id,
    )
    .execute(tx.conn())
    .await?
    .rows_affected()
        > 0;
    if released {
        sqlx::query!(
            "UPDATE store.objects SET last_held_at = now() WHERE pool = $1 AND sha256 = $2",
            pool,
            hex,
        )
        .execute(tx.conn())
        .await?;
    }
    Ok(released)
}

async fn take_hold(
    tx: &mut Tx<'_>,
    pool: &str,
    sha256: &str,
    hold: &Hold,
) -> Result<(), BucketError> {
    sqlx::query!(
        "INSERT INTO store.holds (pool, sha256, holder_kind, holder_id, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (pool, sha256, holder_kind, holder_id)
         DO UPDATE SET expires_at = EXCLUDED.expires_at",
        pool,
        sha256,
        hold.kind,
        hold.id,
        hold.expires_at,
    )
    .execute(tx.conn())
    .await?;
    sqlx::query!(
        "UPDATE store.objects SET last_held_at = now() WHERE pool = $1 AND sha256 = $2",
        pool,
        sha256,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}
