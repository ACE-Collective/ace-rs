//! The bucket's scheduled maintenance (PLAN.md 6.7): ace3's hourly `ace cas gc`, weekly `ace cas
//! orphans` and weekly `ace cas verify`, and the email archive's daily `ace partitions maintain`
//! (`maintain_email_archive`, 7.5 batch 9) and the analysis cache's (`maintain_analysis_cache`, decision
//! 26), which the scheduler in `ace serve` calls, each as a component
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
//! `clean_up_roots` (PLAN.md decision 56) is ace3's `cleanup` of an analysis mode, run as
//! `scheduler:root_cleanup` under `analysis:cleanup` (migration 0085); it writes no audit row either, and
//! its docs say why.
//!
//! Each run's counts are in its row of `scheduler.runs`, which is the record of what ran.
//! They work in the core's own transactions (`ace_core::bucket`), batch by batch, since they delete
//! from the bucket and the index together and an S3 call can't join a transaction.

use std::collections::BTreeMap;

use ace_core::bucket::{Bucket, GcStats, OrphanStats, Retention, VerifyStats};

use crate::permission::{
    ANALYSIS_CACHE_MAINTAIN, ANALYSIS_CLEANUP, BUCKET_GC, BUCKET_VERIFY, EMAIL_ARCHIVE_MAINTAIN,
    NRD_REFRESH, PermissionName,
};
use crate::{Actor, Service, ServiceError};

/// What GC did, by pool.
pub type PoolGc = BTreeMap<String, GcStats>;
/// What the orphan sweep did, by pool.
pub type PoolOrphans = BTreeMap<String, OrphanStats>;
/// What the verify found, by pool.
pub type PoolVerify = BTreeMap<String, VerifyStats>;

/// What one run of the cleanup of roots that never became alerts did (`Service::clean_up_roots`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct RootsCleaned {
    /// The modes it cleaned up.
    pub modes: Vec<String>,
    pub deleted: u64,
    pub batches: u64,
    /// The holds on the bucket's objects the deleted roots had.
    pub holds_released: u64,
    /// True when it stopped at its bound with more left, for the next run.
    pub more: bool,
}

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

    /// The analysis cache's partitions (PLAN.md decision 26): the days past retention dropped and the
    /// days ahead made, as ace3's `ace partitions maintain` keeps its cache's. Needs
    /// `analysis_cache:maintain`. No audit row, as for the email archive's: dropping a day is the
    /// retention its configuration says, applied, and what each run dropped and made is in its row.
    pub async fn maintain_analysis_cache(
        &self,
        actor: &Actor,
        settings: &ace_core::cache::CacheSettings,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ace_core::cache::Maintenance, ServiceError> {
        self.require(actor, "maintain_analysis_cache", &ANALYSIS_CACHE_MAINTAIN)
            .await?;
        Ok(ace_core::cache::maintain(self.gate.db(), settings, now, false).await?)
    }

    /// The finished roots that never became alerts in a mode that cleans up, deleted with their holds on
    /// the bucket's objects (`ace_core::cleanup`, PLAN.md decision 56): at most `cleanup::BATCH` a
    /// transaction and `cleanup::MAX_BATCHES` a run, a pause between batches. The modes are the
    /// orchestrator's (`Modes::cleans_up`). Needs `analysis:cleanup`. No audit row: deleting them is ace3's
    /// `cleanup` of their mode, applied, which ace3 audits nowhere either (its engine removes the storage
    /// directory); how many each run deleted is in its row, and each root deleted is in the log at debug.
    pub async fn clean_up_roots(
        &self,
        actor: &Actor,
        bucket: &Bucket,
        grace: std::time::Duration,
    ) -> Result<RootsCleaned, ServiceError> {
        use ace_core::cleanup;
        self.require(actor, "clean_up_roots", &ANALYSIS_CLEANUP)
            .await?;
        let modes: Vec<String> = self
            .orchestrator
            .modes()
            .cleanup_modes()
            .into_iter()
            .map(str::to_owned)
            .collect();
        let pools: Vec<String> = bucket.pools().map(|(name, _)| name.to_owned()).collect();
        let mut done = RootsCleaned {
            modes: modes.clone(),
            ..RootsCleaned::default()
        };
        for batch in 0..cleanup::MAX_BATCHES {
            if batch > 0 {
                tokio::time::sleep(cleanup::BATCH_PAUSE).await;
            }
            let deleted =
                cleanup::delete_batch(self.gate.db(), &modes, grace, cleanup::BATCH, &pools)
                    .await?;
            for root in &deleted.roots {
                tracing::debug!(%root, "deleted a finished root that never became an alert");
            }
            done.deleted += deleted.roots.len() as u64;
            done.holds_released += deleted.holds;
            if !deleted.roots.is_empty() {
                done.batches += 1;
            }
            if (deleted.roots.len() as i64) < cleanup::BATCH {
                return Ok(done);
            }
        }
        done.more = true;
        Ok(done)
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
