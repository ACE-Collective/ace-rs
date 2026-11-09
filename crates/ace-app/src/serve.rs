//! `ace serve`: the lease API workers call (PLAN.md 2.14), the JSON API people and their scripts call
//! (5.5, `ace-api`), the reaper that takes back tasks whose lease expired, the recorder of YARA QA
//! matches (2.27), the scheduler of ace3's maintenance tasks (6.7, `crate::scheduler`), and the ruleset
//! builder (2.25) when `ACE4_SIGNATURES_REPO` names the signatures repository's checkout
//! (`SignatureRepo::from_env`), every `ACE4_RULESET_POLL_SECONDS` (60).
//!
//! The scheduler is here, not a process of its own: its tasks need the database and the bucket, which
//! `ace serve` already holds, and no data source's secret. Every replica runs it, and the tasks'
//! rows in Postgres give each due run to one of them.
//!
//! It reads `ACE4_DATABASE_URL`, the `ACE4_BUCKET_*` variables, the pools and their tokens
//! (`ACE4_POOLS`, by default the binary's own; `ACE4_POOL_TOKEN_<POOL>`, see `ApiConfig::from_env`),
//! `ACE4_API_LISTEN` for the lease API (default `0.0.0.0:8080`), `ACE4_WEB_LISTEN` for the JSON API and
//! the GUI (default `0.0.0.0:8000`), `ACE4_WEB_TLS` (`false`), `ACE4_MAX_SUBMISSION_BYTES` (1 GiB), `ACE4_CACHE_DIR` for the node's bucket
//! cache, and the site overlay at `ACE4_OVERLAY` (`site`).
//!
//! The two APIs listen apart. A pool holds a token for the lease API and nothing else, and the lease
//! API's dev tokens are defaults in this repository, while the JSON API takes 5.4's keys and sessions.
//! So Compose publishes only the JSON API's port, and the lease API is reachable only on the stack's
//! own network; a deployment can put TLS and a proxy in front of the one people use, and keep the
//! other private. The cost is a second port and a second server to stop. One listener with two path
//! prefixes would expose the lease API, and its `/api/admin/v1` replay, wherever people reach ACE.
//! 5.7's GUI (`ace-gui`) joins the JSON API's listener, so its pages and the API share an origin and a
//! cookie. Its session cookie is `Transport::Plain` until TLS comes (PLAN.md's Deferred), and then
//! `ACE4_WEB_TLS=true` (`WebConfig::transport`) turns on `Secure` for both.

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
    let overlay = crate::cli::overlay()?;
    let components = crate::cli::components(&app.registry(), &overlay)?;
    let scheduled = crate::scheduler::configure(&app.scheduled_tasks(), &overlay.scheduler)
        .map_err(anyhow::Error::msg)
        .context("the overlay's scheduler section")?;
    let modes = app.modes_with(&components);
    let orchestrator = Orchestrator::new(Catalog::of(components), modes);
    // a pool that lists a module leases its overlay instances too
    let config = ApiConfig::from_env(&app.pool_list()).with_instances(orchestrator.catalog());
    for pool in &config.pools {
        tracing::info!(pool = %pool.name, modules = ?pool.modules, "serving a pool");
    }
    let service = ace_service::Service::new(db.clone(), orchestrator.clone());
    let scheduler =
        crate::scheduler::Scheduler::new(db.clone(), service.clone(), bucket.clone(), scheduled)
            .with_overlay(overlay.clone());
    let web_config = ace_api::WebConfig::from_env().map_err(anyhow::Error::msg)?;
    for (module, name, version) in app.modules_without_a_view() {
        tracing::warn!(
            module,
            name,
            version,
            "a module's results have no analysis view, so they draw as JSON"
        );
    }
    let gui = ace_gui::Gui::new(service.clone(), web_config.transport)
        .with_views(app.views().clone())
        .with_actions(app.actions().clone());
    let web =
        ace_api::Web::new(service, bucket.clone(), web_config).with_hunts(ace_api::HuntSupport {
            types: app.hunt_types().to_vec(),
            email: ace_mod_email::py::normalize_email_address,
            valid_type: |t| t.parse::<ace_results::ObservableKind>().is_ok(),
            command_types: std::sync::Arc::new(app.command_types()),
        });
    let api = Api::new(db.clone(), bucket.clone(), orchestrator, config).await?;
    let stopping_api = api.clone();
    let listen = std::env::var("ACE4_API_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".to_owned());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    eprintln!("ace: the lease API listens on {listen}");
    let web_listen = std::env::var("ACE4_WEB_LISTEN").unwrap_or_else(|_| "0.0.0.0:8000".to_owned());
    let web_listener = tokio::net::TcpListener::bind(&web_listen)
        .await
        .with_context(|| format!("binding {web_listen}"))?;
    eprintln!("ace: the JSON API and the GUI listen on {web_listen}");

    let stop = CancellationToken::new();
    let reaper = tokio::spawn(run_reaper(db.clone(), Duration::from_secs(5), stop.clone()));
    let recorder = tokio::spawn(ace_core::yara_qa::run_recorder(
        ace_core::yara_qa::recorder_worker(db.clone()),
        bucket.clone(),
        Duration::from_secs(5),
        stop.clone(),
    ));
    let scheduler = tokio::spawn(scheduler.run(stop.clone()));
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
    let stopping = stop.clone();
    let web_server = tokio::spawn(ace_api::serve(
        web_listener,
        web.router().merge(gui.router()),
        async move {
            stopping.cancelled().await;
        },
    ));
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
    match tokio::time::timeout(Duration::from_secs(5), web_server).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => tracing::error!("serving the JSON API failed: {e}"),
        Ok(Err(e)) => tracing::error!("the JSON API's task failed: {e}"),
        Err(_) => tracing::warn!("JSON API requests were still open 5 seconds after the deadline"),
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
    // the scheduler stops its running tasks and waits STOP_WAIT for their ends to be recorded
    if tokio::time::timeout(
        crate::scheduler::STOP_WAIT + Duration::from_secs(5),
        scheduler,
    )
    .await
    .is_err()
    {
        tracing::warn!("the scheduler didn't stop in time");
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
pub(crate) async fn wait_for_stop() {
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
