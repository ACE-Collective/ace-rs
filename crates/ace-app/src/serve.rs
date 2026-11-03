//! `ace serve`: the lease API workers call (PLAN.md 2.14) and the submit endpoint (2.28), the
//! reaper that takes back tasks
//! whose lease expired, the recorder of YARA QA matches (2.27), and the ruleset builder (2.25)
//! when `ACE4_SIGNATURES_REPO` names the
//! signatures repository's checkout (`SignatureRepo::from_env`), every
//! `ACE4_RULESET_POLL_SECONDS` (60).
//!
//! It reads `ACE4_DATABASE_URL`, the `ACE4_BUCKET_*` variables, the pools and their tokens
//! (`ACE4_POOLS`, by default the binary's own; `ACE4_POOL_TOKEN_<POOL>`, see
//! `ApiConfig::from_env`), the submit token
//! (`ACE4_SUBMIT_TOKEN`), `ACE4_API_LISTEN`
//! (default `0.0.0.0:8080`), `ACE4_CACHE_DIR` for the node's bucket cache, and the site overlay
//! at `ACE4_OVERLAY` (`site`).

use std::process::ExitCode;
use std::time::Duration;

use ace_core::api::{Api, ApiConfig};
use ace_core::bucket::{Bucket, BucketSettings};
use ace_core::db::{Db, DbConfig};
use ace_core::eligibility::Catalog;
use ace_core::orchestrator::Orchestrator;
use ace_core::queue::run_reaper;
use ace_core::rulesets::{SignatureRepo, run_builder};
use ace_store::{BucketConfig, DEFAULT_CACHE_MAX_BYTES, NodeCache, Store};
use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use crate::App;

/// How long `ace serve` waits at shutdown for open requests: a little over the longest a lease
/// request waits.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(25);

pub fn run(app: &App, telemetry: &mut ace_pool::telemetry::Telemetry) -> Result<ExitCode> {
    telemetry.start_export().context("starting span export")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    let code = runtime.block_on(serve(app));
    // a ruleset compile still running on a blocking thread doesn't hold the exit up
    runtime.shutdown_timeout(Duration::from_secs(5));
    code
}

async fn serve(app: &App) -> Result<ExitCode> {
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
    let signatures = SignatureRepo::from_env();
    let components = crate::cli::components(&app.registry(), &crate::cli::overlay()?)?;
    let orchestrator = Orchestrator::new(Catalog::of(components), app.modes());
    // a pool that lists a module leases its overlay instances too
    let config = ApiConfig::from_env(&app.pool_list()).with_instances(orchestrator.catalog());
    for pool in &config.pools {
        tracing::info!(pool = %pool.name, modules = ?pool.modules, "serving a pool");
    }
    let api = Api::new(db.clone(), bucket.clone(), orchestrator, config).await?;
    let stopping_api = api.clone();
    let listen = std::env::var("ACE4_API_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    eprintln!("ace: the lease API listens on {listen}");

    let stop = CancellationToken::new();
    let reaper = tokio::spawn(run_reaper(db.clone(), Duration::from_secs(5), stop.clone()));
    let recorder = tokio::spawn(ace_core::yara_qa::run_recorder(
        ace_core::yara_qa::recorder_worker(db.clone()),
        bucket.clone(),
        Duration::from_secs(5),
        stop.clone(),
    ));
    let builder = signatures.map(|repo| {
        let every = std::env::var("ACE4_RULESET_POLL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60);
        tracing::info!(repo = %repo.repo.display(), every, "building rulesets");
        tokio::spawn(run_builder(
            db,
            bucket,
            repo,
            Duration::from_secs(every),
            stop.clone(),
        ))
    });
    let stopping = stop.clone();
    let server = tokio::spawn(ace_core::api::serve(listener, api, async move {
        stopping.cancelled().await;
    }));
    // Compose and Docker stop a container with SIGTERM, a terminal with SIGINT
    wait_for_stop().await;
    stopping_api.shut_down();
    stop.cancel();
    // a lease request may wait up to its limit for a task; shutdown waits no longer than this
    match tokio::time::timeout(SHUTDOWN_DEADLINE, server).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => tracing::error!("serving failed: {e}"),
        Ok(Err(e)) => tracing::error!("the server's task failed: {e}"),
        Err(_) => tracing::warn!("requests were still open at the shutdown deadline"),
    }
    if tokio::time::timeout(Duration::from_secs(5), reaper)
        .await
        .is_err()
    {
        tracing::warn!("the reaper didn't stop within 5 seconds");
    }
    if tokio::time::timeout(Duration::from_secs(5), recorder)
        .await
        .is_err()
    {
        tracing::warn!("the QA recorder didn't stop within 5 seconds");
    }
    if let Some(builder) = builder
        && tokio::time::timeout(Duration::from_secs(5), builder)
            .await
            .is_err()
    {
        tracing::warn!("the ruleset builder didn't stop within 5 seconds");
    }
    Ok(ExitCode::SUCCESS)
}

/// Returns at SIGTERM or SIGINT.
async fn wait_for_stop() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(e) => {
            tracing::error!("no SIGTERM handler: {e}");
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!("waiting for a signal failed: {e}");
            }
        }
    }
    tracing::info!("stopping");
}
