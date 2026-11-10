//! The bucket's scheduled maintenance (PLAN.md 6.7): ace3's hourly `ace cas gc`, weekly `ace cas
//! orphans` and weekly `ace cas verify`, and the email archive's daily `ace partitions maintain`
//! (`maintain_email_archive`, 7.5 batch 9), which the scheduler in `ace serve` calls, each as a component
//! of its own (`scheduler:bucket_gc`, `scheduler:bucket_orphans`, `scheduler:bucket_verify`), which
//! migration 0036 grants `bucket:gc` or `bucket:verify` and nothing else.
//!
//! Each checks its permission before it touches anything, and a refusal is
//! `ServiceError::PermissionDenied`, as through `Gate::write`. None writes an audit row, and why:
//! - GC deletes only objects no hold has kept for their pool's grace. What let each go is already
//!   recorded where it happened: a purge's or a prune's audit row released a QA match's hold, and a
//!   hold with an expiry lapsed as its writer set it. GC is the retention the index says, applied,
//!   and in ace3 it's audited nowhere either (`cas_purges` audits a forced purge, which ace4 doesn't have).
//! - The orphan sweep deletes bytes no index row names. They were never an object anything held:
//!   what a put left when its transaction didn't commit.
//! - The verify deletes nothing. It records `verified_at`, and lists what's missing or corrupt.
//!
//! Each run's counts are in its row of `scheduler.runs`, which is the record of what ran.
//! They work in the core's own transactions (`ace_core::bucket`), batch by batch, since they delete
//! from the bucket and the index together and an S3 call can't join a transaction.

use std::collections::BTreeMap;

use ace_core::bucket::{Bucket, GcStats, OrphanStats, Retention, VerifyStats};

use crate::permission::{
    BUCKET_GC, BUCKET_VERIFY, EMAIL_ARCHIVE_MAINTAIN, NRD_REFRESH, PermissionName,
};
use crate::{Actor, Service, ServiceError};

/// What GC did, by pool.
pub type PoolGc = BTreeMap<String, GcStats>;
/// What the orphan sweep did, by pool.
pub type PoolOrphans = BTreeMap<String, OrphanStats>;
/// What the verify found, by pool.
pub type PoolVerify = BTreeMap<String, VerifyStats>;

impl Service {
    /// GC of every held pool (`Bucket::gc`): objects nothing has held for the pool's grace, the
    /// deletions an earlier run left halfway, and expired holds. A permanent pool is skipped. Needs
    /// `bucket:gc`.
    pub async fn collect_bucket_garbage(
        &self,
        actor: &Actor,
        bucket: &Bucket,
    ) -> Result<PoolGc, ServiceError> {
        self.require(actor, "collect_bucket_garbage", &BUCKET_GC)
            .await?;
        let mut done = PoolGc::new();
        let held: Vec<String> = bucket
            .pools()
            .filter(|(_, retention)| matches!(retention, Retention::Held { .. }))
            .map(|(name, _)| name.to_owned())
            .collect();
        for pool in held {
            let stats = bucket.gc(&pool).await?;
            done.insert(pool, stats);
        }
        Ok(done)
    }

    /// The orphan sweep of every pool (`Bucket::orphans`). Needs `bucket:gc`.
    pub async fn remove_bucket_orphans(
        &self,
        actor: &Actor,
        bucket: &Bucket,
    ) -> Result<PoolOrphans, ServiceError> {
        self.require(actor, "remove_bucket_orphans", &BUCKET_GC)
            .await?;
        let mut done = PoolOrphans::new();
        let pools: Vec<String> = bucket.pools().map(|(name, _)| name.to_owned()).collect();
        for pool in pools {
            let stats = bucket.orphans(&pool).await?;
            done.insert(pool, stats);
        }
        Ok(done)
    }

    /// The verify of a sample of every pool (`Bucket::verify`). Needs `bucket:verify`. What's missing
    /// or corrupt is in what it returns, for the caller to fail on.
    pub async fn verify_bucket(
        &self,
        actor: &Actor,
        bucket: &Bucket,
    ) -> Result<PoolVerify, ServiceError> {
        self.require(actor, "verify_bucket", &BUCKET_VERIFY).await?;
        let mut done = PoolVerify::new();
        let pools: Vec<String> = bucket.pools().map(|(name, _)| name.to_owned()).collect();
        for pool in pools {
            let stats = bucket.verify(&pool).await?;
            done.insert(pool, stats);
        }
        Ok(done)
    }

    /// The email archive's partitions (PLAN.md 7.5 batch 9): the weeks past retention dropped and the
    /// weeks ahead made, as ace3's `ace partitions maintain` keeps its email archive's. Needs
    /// `email_archive:maintain`. No audit row: dropping a week is the retention its configuration says,
    /// applied, as GC is, and ace3 audits it nowhere; what each run dropped and made is in its row.
    pub async fn maintain_email_archive(
        &self,
        actor: &Actor,
        config: &ace_core::email_archive::ArchiveConfig,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<ace_core::email_archive::partitions::TableMaintenance>, ServiceError> {
        self.require(actor, "maintain_email_archive", &EMAIL_ARCHIVE_MAINTAIN)
            .await?;
        Ok(
            ace_core::email_archive::partitions::maintain(self.gate.db(), config, now, false)
                .await?,
        )
    }

    /// The newly registered domains list's state, for deciding whether to rebuild it (PLAN.md 7.4).
    /// Needs `nrd:refresh`.
    pub async fn nrd_state(
        &self,
        actor: &Actor,
    ) -> Result<Option<ace_core::nrd::ListState>, ServiceError> {
        self.require(actor, "nrd_state", &NRD_REFRESH).await?;
        Ok(ace_core::nrd::state(self.gate.db()).await?)
    }

    /// Starts a rebuild of the newly registered domains list, which lands when it commits. Needs
    /// `nrd:refresh`. No audit row: the list is a feed's copy, ace3 audits its refresh nowhere, and
    /// what each rebuild took is in its state and its run's row.
    pub async fn nrd_rebuild(&self, actor: &Actor) -> Result<ace_core::nrd::Rebuild, ServiceError> {
        self.require(actor, "nrd_rebuild", &NRD_REFRESH).await?;
        Ok(ace_core::nrd::Rebuild::begin(self.gate.db()).await?)
    }

    /// Refuses an actor without `permission`, as `Gate::write` does, for work that runs in the core's
    /// own transactions.
    async fn require(
        &self,
        actor: &Actor,
        action: &'static str,
        permission: &PermissionName,
    ) -> Result<(), ServiceError> {
        if self.gate.allowed(actor, permission).await? {
            return Ok(());
        }
        tracing::warn!(%actor, %permission, action, "permission denied");
        Err(ServiceError::PermissionDenied {
            actor: actor.to_string(),
            permission: permission.clone(),
        })
    }
}
