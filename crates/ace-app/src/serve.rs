//! `ace serve`: the lease API workers call (PLAN.md 2.14), the JSON API people and their scripts call
//! (5.5, `ace-api`), the reaper that takes back tasks whose lease expired, the recorder of YARA QA
//! matches (2.27), the worker that runs the core's hooks at the end of a root's pass (7.6,
//! `ace_core::hooks`), the worker that routes an alert to its queue when its pass completes (7.13,
//! `ace_service::routing`), the indexer that keeps an alert's text searchable (7.11, `ace_search`,
//! `ace_service::search`) when `ACE4_SEARCH_MODEL` names the embedding model's directory, the
//! scheduler of ace3's maintenance tasks (6.7, `crate::scheduler`), and the ruleset
//! builder (2.25) when `ACE4_SIGNATURES_REPO` names the signatures repository's checkout
//! (`SignatureRepo::from_env`), every `ACE4_RULESET_POLL_SECONDS` (60), and SVS's YARA validation workers
//! (7.10 batch 3, `ace_core::svs::validations`) when the overlay's `svs.yara` names a repository, each
//! validation's scans in this binary again, contained.
//!
//! The scheduler is here, not a process of its own: its tasks need the database and the bucket, which
//! `ace serve` already holds, and no data source's secret. Every replica runs it, and the tasks'
//! rows in Postgres give each due run to one of them.
//!
//! It reads `ACE4_DATABASE_URL`, the `ACE4_BUCKET_*` variables, the pools and their tokens
//! (`ACE4_POOLS`, by default the binary's own; `ACE4_POOL_TOKEN_<POOL>`, see `ApiConfig::from_env`),
//! `ACE4_API_LISTEN` for the lease API (default `0.0.0.0:8080`), `ACE4_WEB_LISTEN` for the JSON API and
//! the GUI (default `0.0.0.0:8000`), `ACE4_WEB_TLS` (`false`), `ACE4_MAX_SUBMISSION_BYTES` (1 GiB), `ACE4_CACHE_DIR` for the node's bucket
//! cache, the site overlay at `ACE4_OVERLAY` (`site`), and the email archive's key in
//! `ACE4_ENCRYPTION_KEY`, 64 hex digits, with its retention (`ace_core::email_archive::ArchiveConfig`).
//! Only this process holds the key: the core seals and opens archived emails for the workers, which
//! never see it.
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
    // the email archive's key stays in this process: workers ask the core to seal and open
    let archive_config = ace_core::email_archive::ArchiveConfig::from_env()
        .map_err(anyhow::Error::msg)
        .context("the email archive's settings")?;
    if archive_config.key.is_none() {
        tracing::warn!(
            "ACE4_ENCRYPTION_KEY isn't set: the email archive can't archive or open an email"
        );
    }
    let archive = ace_core::email_archive::EmailArchive::new(
        db.clone(),
        bucket.clone(),
        archive_config.clone(),
    );
    let signatures = SignatureRepo::from_env();
    let overlay = crate::cli::overlay()?;
    let components = crate::cli::components(&app.registry(), &overlay)?;
    let scheduled = crate::scheduler::configure(&app.scheduled_tasks(), &overlay.scheduler)
        .map_err(anyhow::Error::msg)
        .context("the overlay's scheduler section")?;
    let modes = app.modes_with(&components);
    let hooks = ace_core::hooks::Hooks::from_section(&overlay.hooks)
        .context("the overlay's hooks section")?;
    // the YARA export of the detections (PLAN.md 7.16), checked even when no repository is built
    let yara_export = ace_core::rulesets::export_config(&overlay.yara_export)
        .map_err(anyhow::Error::msg)
        .context("the overlay's yara_export section")?;
    let dispositions = ace_service::Dispositions::configured(&overlay)
        .map_err(anyhow::Error::msg)
        .context("the overlay's disposition sections")?;
    let (tp, fp) = dispositions.classes().lists();
    let set_by_ace = dispositions.classes().set_by_ace_list();
    let names = dispositions.names();
    // changing it relabels every detection at once, so a site's own is a warning, as ace3 logs it
    if dispositions == ace_service::Dispositions::ace3() {
        tracing::info!(
            ?names,
            ?tp,
            ?fp,
            ?set_by_ace,
            "dispositions and their classification in effect: ace3's"
        );
    } else {
        tracing::warn!(
            ?names,
            ?tp,
            ?fp,
            ?set_by_ace,
            "dispositions and their classification in effect: the overlay's"
        );
    }
    // the run page's link to the site's log search (PLAN.md 7.10)
    let log_search =
        ace_core::svs::log_search::LogSearchTemplate::parse(overlay.svs.log_search_url.as_deref())
            .map_err(anyhow::Error::msg)
            .context("the overlay's svs section")?;
    // YARA validation (PLAN.md 7.10 batch 3): its repositories, bounds and workers
    let validation = ace_core::svs::yara::ValidationConfig::from_section(&overlay.svs.yara)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.yara section")?;
    // the repositories' SSH keys, and no other secret (PLAN.md 2.24)
    let validation = crate::svs::with_ssh_keys(validation, &overlay);
    for (name, repository) in &validation.repositories {
        tracing::info!(repository = name, branch = %repository.branch, "svs validates this repository");
    }
    // the Atomic Red Team catalog and the ATT&CK release (PLAN.md 7.10 batch 4): a release this build has
    // no extract of stops startup, as ace3's config refuses one whose file is missing
    let attack = ace_core::svs::attack::attack_catalog(&overlay.svs.attack_release)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.attack_release")?;
    let catalog = ace_core::svs::catalog::CatalogConfig::from_section(&overlay.svs.catalog)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.catalog section")?;
    let catalog = crate::svs::catalog_with_ssh_keys(catalog, &overlay);
    let runs = ace_core::svs::runs::RunsConfig::from_section(&overlay.svs.runs)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.runs section")?;
    // SVS's hook, ace3's `svs_alert_tagger`, judges an alert at the end of a pass (PLAN.md 7.10 batch 6)
    let hooks = hooks.with_svs(ace_core::svs::attribution::HookConfig {
        attribution_extra: runs.windows.attribution_extra,
    });
    for name in hooks.names() {
        tracing::info!(hook = name, "running a hook in the core");
    }
    for (name, repository) in &catalog.repositories {
        tracing::info!(repository = name, branch = %repository.branch, "svs reads its test catalog from this repository");
    }
    // alert routing (PLAN.md 7.13): the built-in router, the binary's and the overlay's
    let routers = app
        .alert_routers(&overlay)
        .map_err(anyhow::Error::msg)
        .context("the overlay's alert_routers section")?;
    for (name, priority) in routers.names() {
        tracing::info!(router = name, priority, "routing alerts with this router");
    }
    // the modules' declarations of what they take, applied or only audited (PLAN.md decision 23)
    let takes = ace_core::takes::TakesMode::from_env().map_err(anyhow::Error::msg)?;
    if takes == ace_core::takes::TakesMode::Audit {
        tracing::warn!(
            "ACE4_TAKES_AUDIT is set: every task is queued, and the ones a module's declaration declines are marked"
        );
    }
    for component in components.iter().filter(|c| !c.takes.is_everything()) {
        tracing::info!(module = %component.key, takes = %component.takes, "the module declares what it takes");
    }
    // the observables no module analyzes, ace3's `observable_exclusions`
    let exclusions = crate::cli::exclusions(&overlay)?;
    for (kind, values) in exclusions.iter() {
        tracing::info!(r#type = kind, values = ?values, "no module analyzes these observables");
    }
    // the analysis cache, ace3's `analysis_cache` (PLAN.md decision 26)
    let cache = crate::cli::analysis_cache(&overlay, &components)?;
    let orchestrator = Orchestrator::new(Catalog::of(components), modes)
        .with_hooks(hooks)
        .with_takes(takes)
        .with_exclusions(exclusions)
        .with_cache(cache);
    // a pool that lists a module leases its overlay instances too
    // the remediators, probes and collectors the pools host decide their actions' tries (PLAN.md 7.9)
    let actions = app
        .action_catalog()
        .map_err(anyhow::Error::msg)
        .context("the action handlers")?;
    let config = ApiConfig::from_env(&app.pool_list())
        .with_instances(orchestrator.catalog())
        .archive(archive_config.clone())
        .actions(actions.clone())
        // what SVS's capture reads as graded (PLAN.md 7.10)
        .classified(tp.iter().chain(&fp).cloned());
    for pool in &config.pools {
        tracing::info!(pool = %pool.name, modules = ?pool.modules, "serving a pool");
    }
    let service = ace_service::Service::new(db.clone(), orchestrator.clone())
        .with_actions(actions)
        .with_dispositions(dispositions)
        .with_log_search(log_search)
        // the GUI's deletion of an SVS sample purges its bytes (PLAN.md 7.10)
        .with_bucket(bucket.clone())
        .with_validation(validation.clone())
        .with_catalog(catalog)
        // coverage is computed against the pinned ATT&CK release (PLAN.md 7.10 batch 8)
        .with_attack_catalog(attack)
        .with_runs(runs)
        .with_routers(routers);
    // the AI investigation API (PLAN.md 7.15) is `ace serve-ai`'s, a process of its own
    crate::ai::custody::not_ace_serve_s(&overlay).map_err(anyhow::Error::msg)?;
    // search (PLAN.md 7.11): the index in Postgres, with the embedding model the image carries. The
    // model is read here once, each file checked against its pinned hash, and nothing is downloaded.
    // With no model named, alerts aren't indexed and a search runs its exact lane and its listings.
    let search_model = tokio::task::spawn_blocking(ace_search::Model::from_env)
        .await
        .context("loading the embedding model")?
        .with_context(|| format!("the embedding model {} names", ace_search::model::MODEL_VAR))?;
    let indexing = search_model.is_some();
    let service = match search_model {
        Some(model) => {
            tracing::info!(
                model = ace_search::model::MODEL_NAME,
                "search embeds with this model, in this process"
            );
            service.with_search(
                std::sync::Arc::new(ace_search::PgIndex::new(
                    db.clone(),
                    Some(bucket.clone()),
                    model,
                )),
                ace_service::search::SearchConfig::default(),
            )
        }
        None => {
            tracing::warn!(
                "{} isn't set: alerts aren't indexed, and a search finds exact matches only",
                ace_search::model::MODEL_VAR
            );
            service
        }
    };
    // each scan runs in this binary again, contained (`ace yara replay --contained`)
    let validators = (!validation.repositories.is_empty())
        .then(|| -> Result<ace_core::svs::validations::Workers> {
            let replayer = ace_core::svs::yara::replay::Replayer {
                db: db.clone(),
                bucket: bucket.clone(),
                config: validation.clone(),
                tp: tp.clone(),
                fp: fp.clone(),
                child: ace_core::svs::yara::replay::Child::this_binary()
                    .map_err(anyhow::Error::msg)?,
            };
            let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "core".to_owned());
            Ok(ace_core::svs::validations::Workers {
                db: db.clone(),
                config: validation.clone(),
                replay: std::sync::Arc::new(replayer),
                tp: tp.clone(),
                fp: fp.clone(),
                node: format!("{host}/{}", std::process::id()),
            })
        })
        .transpose()?;
    let scheduler =
        crate::scheduler::Scheduler::new(db.clone(), service.clone(), bucket.clone(), scheduled)
            .with_overlay(overlay.clone())
            .with_archive(archive_config);
    let web_config = ace_api::WebConfig::from_env().map_err(anyhow::Error::msg)?;
    for (module, name, version) in app.modules_without_a_view() {
        tracing::warn!(
            module,
            name,
            version,
            "a module's results have no analysis view, so they draw as JSON"
        );
    }
    let routing_service = service.clone();
    let indexing_service = service.clone();
    let gui = ace_gui::Gui::new(service.clone(), web_config.transport)
        .with_views(app.views().clone())
        .with_actions(app.actions().clone())
        .with_summaries(app.alert_summaries().clone());
    let web = ace_api::Web::new(service, bucket.clone(), web_config)
        .with_email_archive(archive)
        .with_hunts(ace_api::HuntSupport {
            types: app.hunt_types().to_vec(),
            email: ace_mod_email::py::normalize_email_address,
            valid_type: |t| t.parse::<ace_results::ObservableKind>().is_ok(),
            command_types: std::sync::Arc::new(app.command_types()),
        });
    let hooks_orchestrator = orchestrator.clone();
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
    // a file's type step whose lease runs out on its last attempt ends as any other end of it does
    let reaper = tokio::spawn(run_reaper(
        db.clone(),
        Duration::from_secs(5),
        stop.clone(),
        Some(api.type_step_ended()),
    ));
    let recorder = tokio::spawn(ace_core::yara_qa::run_recorder(
        ace_core::yara_qa::recorder_worker(db.clone()),
        bucket.clone(),
        Duration::from_secs(5),
        stop.clone(),
    ));
    let hook_runner = tokio::spawn(ace_core::hooks::run_worker(
        hooks_orchestrator,
        ace_core::hooks::hooks_worker(db.clone()),
        Duration::from_secs(5),
        stop.clone(),
    ));
    let router = tokio::spawn(ace_service::routing::run_worker(
        routing_service,
        Duration::from_secs(5),
        stop.clone(),
    ));
    let indexer = indexing.then(|| {
        tokio::spawn(ace_service::search::run_worker(
            indexing_service,
            Duration::from_secs(5),
            stop.clone(),
        ))
    });
    let scheduler = tokio::spawn(scheduler.run(stop.clone()));
    let validators = validators.map(|workers| tokio::spawn(workers.run(stop.clone())));
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
            yara_export,
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
    if tokio::time::timeout(Duration::from_secs(5), hook_runner)
        .await
        .is_err()
    {
        tracing::warn!("the hooks worker didn't stop within 5 seconds");
    }
    if tokio::time::timeout(Duration::from_secs(5), router)
        .await
        .is_err()
    {
        tracing::warn!("the routing worker didn't stop within 5 seconds");
    }
    // an alert the indexer was embedding stays due: its claim lapses, and the next start takes it
    if let Some(indexer) = indexer
        && tokio::time::timeout(Duration::from_secs(5), indexer)
            .await
            .is_err()
    {
        tracing::warn!("the search indexer didn't stop within 5 seconds");
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
    // a running validation's scan is killed and the validation goes back to the queue
    if let Some(validators) = validators
        && tokio::time::timeout(Duration::from_secs(10), validators)
            .await
            .is_err()
    {
        tracing::warn!("the svs validation workers didn't stop within 10 seconds");
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
