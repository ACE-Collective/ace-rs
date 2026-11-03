//! The bucket with its index: pools, holds and retention, carried over from ace3's CAS
//! (`docs/CAS.md` and the `cas:` section of `etc/saq.default.yaml`).
//!
//! `ace_store::Store` moves bytes; this module decides what exists. A pool names a retention
//! mode. In a `held` pool an object lives while something holds it, plus the pool's grace
//! period after the last hold went; a `permanent` pool keeps everything. GC deletes what no
//! longer qualifies, in batches in key order with a pause between them, and never lists the
//! bucket.
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

use crate::db::{Db, DbError};

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
    pub pools: BTreeMap<String, PoolConfig>,
}

/// ace3's `default_grace_seconds`.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(86_400);

impl Default for BucketSettings {
    /// ace3's defaults. Its two pools, `yara_qa` and `svs_samples`, keep their retention, and
    /// `alert_files`, the pool CAS.md plans for alert files, holds each file for the roots it
    /// is in.
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
            pools: [
                (ALERT_FILES.to_owned(), held),
                ("yara_qa".to_owned(), held),
                ("svs_samples".to_owned(), held),
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcStats {
    /// Objects deleted, including ones an earlier run left `deleting`.
    pub deleted: u64,
    /// Expired hold rows removed.
    pub holds_pruned: u64,
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

    /// Moves a file a worker uploaded for `task` into `pool` and takes `hold` on it, once its
    /// bytes match `sha256`. The upload is removed either way it ends: bytes that don't match
    /// their name never reach the pool.
    pub async fn adopt_upload(
        &self,
        pool: &str,
        task: i64,
        sha256: &Sha256,
        hold: Option<&Hold>,
    ) -> Result<Put, BucketError> {
        self.pool(pool)?;
        let key = Store::upload_key(task, sha256);
        let spooled = self.store.spool_key(&key, sha256).await;
        if let Err(StoreError::Integrity { .. }) = &spooled {
            self.store.delete_key(&key).await?;
        }
        let put = self.put(pool, spooled?, hold).await?;
        self.store.delete_key(&key).await?;
        Ok(put)
    }

    async fn put(
        &self,
        pool: &str,
        spooled: Spooled,
        hold: Option<&Hold>,
    ) -> Result<Put, BucketError> {
        let sha256 = spooled.sha256.to_hex();
        let waited_since = Instant::now();
        loop {
            let mut tx = self.db.begin().await?;
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
                drop(tx);
                if waited_since.elapsed() >= self.settings.put_deleting_wait {
                    return Err(BucketError::Deleting {
                        pool: pool.to_owned(),
                        sha256: spooled.sha256,
                    });
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            // under the row's lock, so GC can't remove the bytes between the check and the hold
            let uploaded = if self.store.exists(pool, &spooled.sha256).await? {
                false
            } else {
                self.store.upload(pool, &spooled).await?;
                true
            };
            if let Some(hold) = hold {
                take_hold(&mut tx, pool, &sha256, hold).await?;
            }
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
        self.pool(pool)?;
        let hex = sha256.to_hex();
        let mut tx = self.db.begin().await?;
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
            Some(ObjectState::Present) => {
                take_hold(&mut tx, pool, &hex, hold).await?;
                tx.commit().await?;
                Ok(())
            }
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
        let hex = sha256.to_hex();
        let mut tx = self.db.begin().await?;
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

    /// Deletes a claimed object's bytes, then its row.
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

async fn take_hold(
    tx: &mut crate::db::Tx<'_>,
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
