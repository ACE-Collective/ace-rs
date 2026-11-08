//! The bucket's scheduled maintenance (PLAN.md 6.7): ace3's hourly `ace cas gc`, weekly `ace cas
//! orphans` and weekly `ace cas verify`, which the scheduler in `ace serve` calls, each as a component
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

use crate::permission::{BUCKET_GC, BUCKET_VERIFY, PermissionName};
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
