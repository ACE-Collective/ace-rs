//! `ace serve`: the lease API workers call (PLAN.md 2.14), and the reaper that takes back
//! tasks whose lease expired.
//!
//! It reads `ACE4_DATABASE_URL`, the `ACE4_BUCKET_*` variables, the pools and their tokens
//! (`ACE4_POOLS`, `ACE4_POOL_TOKEN_<POOL>`, see `ApiConfig::from_env`), `ACE4_API_LISTEN`
//! (default `0.0.0.0:8080`) and `ACE4_CACHE_DIR` for the node's bucket cache.

use std::process::ExitCode;
use std::time::Duration;

use ace_core::api::{Api, ApiConfig};
use ace_core::bucket::{Bucket, BucketSettings};
use ace_core::db::{Db, DbConfig};
use ace_core::eligibility::Catalog;
use ace_core::modes::Modes;
use ace_core::orchestrator::Orchestrator;
use ace_core::queue::run_reaper;
use ace_store::{BucketConfig, DEFAULT_CACHE_MAX_BYTES, NodeCache, Store};
use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

/// The modules this binary knows: the five ported in phase 1.
pub fn manifests() -> Vec<ace_sdk::Manifest> {
    vec![
        ace_mod_email::MANIFEST,
        ace_mod_rdap::MANIFEST,
        ace_mod_archive::MANIFEST,
        ace_mod_yara::MANIFEST,
        ace_mod_splunk::MANIFEST,
    ]
}

pub fn run() -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(serve())
}

async fn serve() -> Result<ExitCode> {
    let db = Db::connect(&DbConfig::from_env("ace")?)
        .await
        .context("connecting to Postgres")?;
    db.migrate().await.context("migrating")?;
    let cache_dir = std::env::var("ACE4_CACHE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("ace4-cache"));
    let store = Store::new(
        &BucketConfig::from_env()?,
        NodeCache::new(&cache_dir, DEFAULT_CACHE_MAX_BYTES)
            .with_context(|| format!("the cache in {}", cache_dir.display()))?,
    );
    let bucket = Bucket::new(db.clone(), store, BucketSettings::default());
    let orchestrator = Orchestrator::new(Catalog::new(manifests()), Modes::ace3());
    let config = ApiConfig::from_env();
    for pool in &config.pools {
        tracing::info!(pool = %pool.name, modules = ?pool.modules, "serving a pool");
    }
    let api = Api::new(db.clone(), bucket, orchestrator, config).await?;
    let listen = std::env::var("ACE4_API_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    eprintln!("ace: the lease API listens on {listen}");

    let stop = CancellationToken::new();
    let reaper = tokio::spawn(run_reaper(db, Duration::from_secs(5), stop.clone()));
    let stopping = stop.clone();
    ace_core::api::serve(listener, api, async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("waiting for a signal failed: {e}");
        }
        stopping.cancel();
    })
    .await
    .context("serving")?;
    stop.cancel();
    if tokio::time::timeout(Duration::from_secs(10), reaper)
        .await
        .is_err()
    {
        tracing::warn!("the reaper didn't stop within 10 seconds");
    }
    Ok(ExitCode::SUCCESS)
}
