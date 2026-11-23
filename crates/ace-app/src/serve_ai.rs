//! `ace serve-ai`: the AI investigation API (PLAN.md 7.15) as a process of its own, as ace3 serves its
//! `aceapi_ai` from the `http-api-ai` container.
//!
//! **Why apart.** The key this API takes belongs to an AI agent that reads alert text, which is
//! whatever an attacker sent. So the process that answers it holds nothing of value to the rest of
//! ACE: `ace serve` holds the email archive's key, the pools' tokens, the admin token, the bucket's
//! credential and a database role that owns the schema, and this holds none of them. It can't be
//! handed one by mistake either: [`crate::ai::custody`] checks what the process holds when it starts,
//! and it doesn't start if it holds more than it needs.
//!
//! **What it holds.**
//! - `ACE4_DATABASE_URL`, as a login that is a member of the role `ace4_ai` (migration 0064,
//!   `ace_service::ai::role`): alerts, events and the search index to read, API keys and grants to
//!   check, an audit row to insert, the rate limiter's tables to keep. No session, no password hash,
//!   no email archive, no write to anything else. It never migrates: it refuses a database that isn't
//!   at the migration this binary was built with, and `ace serve` is what brings one there.
//! - `ACE4_OVERLAY`, an overlay of its own with `ai_api`, `secrets`, `dispositions` and
//!   `disposition_classification` and no other section, as ace3's container has `etc/saq.ai.yaml`
//!   alone. With none, or with `ai_api.enabled` false, it serves and every route answers 404 saying
//!   the API is off, once the caller's key is found to hold the route's permission.
//! - The secrets its enabled backends list, from where `secrets:` says, and no other.
//! - `ACE4_SEARCH_MODEL`, the embedding model's directory, for the two search routes. Without it a
//!   search runs its exact lane and its listings, as in `ace serve`.
//! - `ACE4_AI_LISTEN`, where it listens: `0.0.0.0:8001` by default.
//!
//! It serves `/api/ai/v1`, the ping and its own `GET /api/openapi.json` (`ace_api::AiWeb`), and
//! nothing else: no other route of the JSON API, no GUI, no lease API. `ace serve` doesn't serve
//! `/api/ai/v1`, and stops if its own overlay has an `ai_api` section, which would otherwise be a
//! setting that quietly did nothing.

use std::process::ExitCode;
use std::time::Duration;

use ace_core::db::{Db, DbConfig};
use ace_core::eligibility::Catalog;
use ace_core::orchestrator::Orchestrator;
use ace_sdk::Overlay;
use ace_service::Service;
use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use crate::App;
use crate::ai::custody::{self, Environment, Holdings};

/// The variable that names where the AI API listens.
pub const LISTEN_VAR: &str = "ACE4_AI_LISTEN";
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8001";

pub fn run(app: &App, telemetry: &mut ace_pool::telemetry::Telemetry) -> Result<ExitCode> {
    telemetry.start_export().context("starting span export")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    let code = runtime.block_on(serve(app));
    runtime.shutdown_timeout(Duration::from_secs(5));
    code
}

/// The overlay's text and what it parses to: the file `ACE4_OVERLAY` names, or none.
fn overlay(app: &App) -> Result<(String, Overlay)> {
    let Some(path) = std::env::var_os("ACE4_OVERLAY").filter(|path| !path.is_empty()) else {
        return Ok((String::new(), Overlay::default()));
    };
    let path = std::path::PathBuf::from(path);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading the overlay {}", path.display()))?;
    let overlay =
        Overlay::from_yaml(&text).with_context(|| format!("the overlay {}", path.display()))?;
    app.check_overlay(&overlay).map_err(anyhow::Error::msg)?;
    Ok((text, overlay))
}

/// The service `ace serve-ai` answers with: reads of alerts and events, the dispositions' classes,
/// the search index when there is a model, and the AI surface the overlay asks for. No bucket, no
/// actions, no routers, no validation: nothing the API doesn't use. The error is the surface's, a
/// backend that can't be built among them.
pub fn service(
    app: &App,
    overlay: &Overlay,
    db: Db,
    env: &dyn Fn(&str) -> Option<String>,
    model: Option<std::sync::Arc<ace_search::Model>>,
) -> Result<Service, String> {
    let components = overlay
        .components(&app.registry().manifests())
        .map_err(|e| format!("the overlay's modules: {e}"))?;
    let modes = app.modes_with(&components, overlay);
    let exclusions = ace_sdk::exclusions::Exclusions::from_section(&overlay.observable_exclusions)
        .map_err(|(path, message)| format!("the overlay's {path}: {message}"))?;
    let orchestrator =
        Orchestrator::new(Catalog::of(components), modes).with_exclusions(exclusions);
    let dispositions = ace_service::Dispositions::configured(overlay)
        .map_err(|e| format!("the overlay's disposition sections: {e}"))?;
    let mut service = Service::new(db.clone(), orchestrator).with_dispositions(dispositions);
    if let Some(model) = model {
        service = service.with_search(
            std::sync::Arc::new(ace_search::PgIndex::new(db.clone(), None, model)),
            ace_service::search::SearchConfig::default(),
        );
    }
    let surface = crate::ai::surface(&app.ai_backend_types(), overlay, db, env)
        .map_err(|e| format!("the overlay's ai_api section: {e}"))?;
    Ok(match surface {
        Some(surface) => service.with_ai(surface),
        None => service,
    })
}

async fn serve(app: &App) -> Result<ExitCode> {
    let env = Environment::of_process();
    let (text, overlay) = overlay(app)?;
    let sections = Overlay::sections(&text).context("the overlay")?;
    let db = Db::connect(&DbConfig::from_env("ace-ai")?)
        .await
        .context("connecting to Postgres")?;
    let role = ace_service::ai::role::role_privileges(&db)
        .await
        .context("reading what the database role can do")?;
    let holdings = Holdings {
        env: env.clone(),
        sections,
        role,
    };
    // the model before the service, so a search embeds in this process. Nothing is downloaded.
    let model = tokio::task::spawn_blocking(ace_search::Model::from_env)
        .await
        .context("loading the embedding model")?
        .with_context(|| format!("the embedding model {} names", ace_search::model::MODEL_VAR))?;
    let embedding = model.is_some();
    // building the service builds each enabled backend with the secrets it lists: one that can't be
    // built is a custody failure, reported with the rest
    let built = service(app, &overlay, db.clone(), &|name| env.get(name), model);
    let (service, backends) = match built {
        Ok(service) => (Some(service), Ok(())),
        Err(error) => (None, Err(error)),
    };
    let passed = custody::run(&holdings, &overlay, backends).map_err(anyhow::Error::msg)?;
    let service = service.context("the service was built")?;
    for path in &passed.warnings {
        tracing::warn!(
            "ai startup: {path} looks like a credential written in the overlay; a backend's \
             credential belongs in secrets:, as env: or file:"
        );
    }
    tracing::info!(
        role = %holdings.role.user,
        declared = ?passed.declared,
        "AI API custody checks passed ({} declared read-only credential(s))",
        passed.declared.len()
    );

    // the schema this binary was built for, which only `ace serve` migrates to
    let expected = ace_core::db::latest_migration();
    let found = ace_service::ai::role::schema_version(&db)
        .await
        .context("reading the database's migration")?;
    if found != Some(expected) {
        anyhow::bail!(
            "the database is at migration {}, and this binary was built for {expected}: `ace serve` \
             migrates it, and `ace serve-ai` starts after",
            found.map_or_else(|| "none".to_owned(), |version| version.to_string())
        );
    }

    match service.ai_surface() {
        Some(surface) => tracing::info!(
            backends = ?surface.backend_names(),
            "the AI investigation API is on"
        ),
        None => tracing::warn!(
            "the overlay's ai_api section doesn't enable the API: every route answers that it's off"
        ),
    }
    if !embedding {
        tracing::warn!(
            "{} isn't set: a search finds exact matches only",
            ace_search::model::MODEL_VAR
        );
    }

    let web = ace_api::AiWeb::new(service, &ace_api::WebConfig::default());
    let listen = std::env::var(LISTEN_VAR).unwrap_or_else(|_| DEFAULT_LISTEN.to_owned());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    eprintln!("ace: the AI investigation API listens on {listen}");

    let stop = CancellationToken::new();
    let stopping = stop.clone();
    let server = tokio::spawn(ace_api::serve(listener, web.router(), async move {
        stopping.cancelled().await;
    }));
    crate::serve::wait_for_stop().await;
    stop.cancel();
    // a query may run for its backend's longest timeout; shutdown doesn't wait for it
    match tokio::time::timeout(Duration::from_secs(10), server).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => tracing::error!("serving the AI API failed: {e}"),
        Ok(Err(e)) => tracing::error!("the AI API's task failed: {e}"),
        Err(_) => tracing::warn!("AI API requests were still open 10 seconds after the stop"),
    }
    Ok(ExitCode::SUCCESS)
}
