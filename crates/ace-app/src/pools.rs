//! The pool binaries (PLAN.md 2.29): a parser pool runs its modules one contained process per
//! task, and a network pool runs its lookups as async tasks in one contained process
//! (DESIGN.md's *Modules and pools*).
//!
//! What they share: the site overlay at `ACE4_OVERLAY`, read through `Registry::start`'s rules
//! (only the pool's own modules' sections, and only the secrets its modules declare); a stop on
//! SIGTERM or SIGINT; and a heartbeat file the container's healthcheck reads.
//!
//! A parser pool's supervisor reads `ACE4_API_URL`, `ACE4_POOL_TOKEN`, `ACE4_OVERLAY`,
//! `ACE4_TASK_USER` (`ace4-task`, whom task processes run as), `ACE4_CONCURRENCY` (4) and
//! `ACE4_HEALTH_FILE`, and with YARA rulesets `ACE4_RULESET_DIR` (`/var/lib/ace4/rulesets`) and
//! `ACE4_RULESET_POLL_SECONDS` (30). It runs each task as
//!
//! ```text
//! <binary> task [--overlay PATH] [--rulesets DIR]
//! ```
//!
//! which gets the overlay's path and the ruleset directory as arguments, since it starts with
//! an empty environment. A pool whose image carries tools (`ParserPool::tools`, PLAN.md 7.3) runs
//! each of its tasks' tools as `<binary> tool`, which contains itself and execs the tool
//! (`ace_pool::tools`). A pool that runs GUI commands (`ParserPool::commands`, PLAN.md 5.12) also
//! leases those, `ACE4_COMMAND_CONCURRENCY` (3) at once, and runs each as `<binary> command`, contained
//! with no paths and no ports (`ace_pool::commands`), on `ace`'s own command line (`cli::run_contained`).
//!
//! A network pool reads `ACE4_API_URL`, `ACE4_POOL_TOKEN`, `ACE4_OVERLAY`, the variables and
//! files the overlay's `secrets:` names for its modules' and its action handlers' secrets,
//! `ACE4_CONCURRENCY` (16), `ACE4_ACTION_CONCURRENCY` (4, the actions it runs at once, PLAN.md 7.9) and
//! `ACE4_HEALTH_FILE`. It contains itself before its runtime starts a thread: it may connect only
//! to its modules' and its handlers' TCP ports, the lease API's and the collector's.
//!
//! A scanner pool (PLAN.md 7.7) reads `ACE4_API_URL`, `ACE4_POOL_TOKEN`, `ACE4_STACK` (`ace4`), which
//! its containers' labels and names carry, `ACE4_DOCKER_SOCKET` (`/var/run/docker.sock`),
//! `ACE4_CONCURRENCY` (4), each scanner's image and network variables (`ace_sdk::scanners`) and
//! `ACE4_HEALTH_FILE`. It holds the Docker socket and parses nothing a scanner wrote
//! (`ace_pool::scanners`).
//!
//! All run until SIGTERM.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ace_pool::client::LeaseClient;
use ace_pool::commands::{CommandConfig, DEFAULT_CONCURRENCY};
use ace_pool::modules::{Modules, Registry, StartError};
use ace_pool::pool::{AsyncPool, POOL_ADDRESS_SPACE, PoolDefinition};
use ace_pool::rulesets::RulesetWatcher;
use ace_pool::supervisor::{EXIT_SETUP, Supervisor, SupervisorConfig};
use ace_sdk::{Component, Overlay};
use tokio_util::sync::CancellationToken;

use crate::{LookupPool, ParserPool, Rulesets, ScannerPool};

/// The overlay at `path`, or none.
fn overlay(path: Option<&Path>) -> Result<Overlay, String> {
    match path {
        Some(path) => Overlay::read(path).map_err(|e| e.to_string()),
        None => Ok(Overlay::default()),
    }
}

/// The overlay's path from `ACE4_OVERLAY`, if it's set.
fn overlay_path() -> Option<PathBuf> {
    std::env::var_os("ACE4_OVERLAY")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

/// The pool's components from the overlay, with the ruleset module's `rulesets` set to the
/// pool's own directory, `dir`, whatever the overlay says: the pool keeps that directory on the
/// core's ruleset, so the site overlay needn't know where it is.
fn components(
    registry: &Registry,
    overlay: &Overlay,
    rulesets: Option<(Rulesets, &Path)>,
) -> Result<Vec<Component>, StartError> {
    let manifests = registry.manifests();
    let mut components = overlay.for_pool(&manifests).components(&manifests)?;
    if let Some((rulesets, dir)) = rulesets {
        for component in &mut components {
            if component.manifest.name == rulesets.module {
                let mut settings = component
                    .settings
                    .take()
                    .unwrap_or_else(|| serde_json::json!({}));
                if let Some(object) = settings.as_object_mut() {
                    object.insert(
                        "rulesets".to_owned(),
                        serde_json::Value::String(dir.display().to_string()),
                    );
                }
                component.settings = Some(settings);
            }
        }
    }
    Ok(components)
}

/// Builds the pool's modules: its components, with the secrets their manifests declare read
/// through `env`.
fn modules(
    pool: &str,
    registry: &Registry,
    overlay: &Overlay,
    rulesets: Option<(Rulesets, &Path)>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Modules, StartError> {
    let components = components(registry, overlay, rulesets)?;
    let manifests: Vec<_> = components.iter().map(|c| c.manifest).collect();
    let secrets = ace_pool::secrets::resolve(pool, &manifests, overlay, env);
    Ok(registry.build(&components, &secrets)?)
}

/// A variable's value, or `default` when it isn't set.
fn var(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

/// A variable's number, or `default`.
fn number(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Where the heartbeat goes, `ACE4_HEALTH_FILE`; in the temporary directory, which a contained
/// network pool may write.
fn health_file() -> PathBuf {
    std::env::var_os("ACE4_HEALTH_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("ace4-health"))
}

/// This process's name as a worker: the host's name, which is the container's id in Compose,
/// and the process id.
fn worker_name() -> String {
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    format!("{}-{}", host.trim(), std::process::id())
}

/// How often the heartbeat is written. The healthcheck allows a few missed beats.
const HEARTBEAT: Duration = Duration::from_secs(5);

/// Writes the time to `path` every `HEARTBEAT` until `stop` fires, so a healthcheck can tell
/// that the pool's runtime still runs.
async fn heartbeat(path: PathBuf, stop: CancellationToken) {
    loop {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        if let Err(e) = tokio::fs::write(&path, format!("{now}\n")).await {
            tracing::warn!(path = %path.display(), "writing the heartbeat failed: {e}");
        }
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(HEARTBEAT) => {}
        }
    }
}

/// A token that fires on SIGTERM or SIGINT.
fn stop_on_signal() -> CancellationToken {
    let stop = CancellationToken::new();
    let stopping = stop.clone();
    tokio::spawn(async move {
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
        stopping.cancel();
    });
    stop
}

/// Runs `work` on a new multi-threaded runtime.
fn with_runtime(work: impl std::future::Future<Output = ExitCode>) -> ExitCode {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(work),
        Err(e) => {
            eprintln!("no runtime: {e}");
            ExitCode::from(2)
        }
    }
}

/// Waits up to 5 seconds for each of `handles`, warning about one that doesn't stop.
async fn join_all(handles: Vec<(&str, tokio::task::JoinHandle<()>)>) {
    for (name, handle) in handles {
        if tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .is_err()
        {
            tracing::warn!("the {name} didn't stop within 5 seconds");
        }
    }
}

/// A parser pool's binary: its supervisor, a task process when the first argument is `task`, or a
/// GUI command's process when it's `command` (PLAN.md 5.12).
pub fn parser_main(pool: &ParserPool) -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("task") => parser_task(pool, args.collect()),
        Some("command") if pool.commands => {
            ace_pool::commands::process_main(&crate::cli::run_contained)
        }
        // the sandbox runner's tool process (PLAN.md 7.3), which must still be one thread
        Some("tool") if !pool.tools.is_empty() => ace_pool::tools::tool_main(),
        _ => supervisor(pool),
    }
}

/// A task process: builds the modules as the supervisor did, then runs the task on stdin.
fn parser_task(pool: &ParserPool, args: Vec<String>) -> ExitCode {
    let setup = u8::try_from(EXIT_SETUP).unwrap_or(u8::MAX);
    let mut overlay_at: Option<PathBuf> = None;
    let mut rulesets: Option<PathBuf> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--overlay", Some(path)) => overlay_at = Some(path.into()),
            ("--rulesets", Some(dir)) => rulesets = Some(dir.into()),
            (other, _) => {
                eprintln!("setup failed: unknown argument {other}");
                return ExitCode::from(setup);
            }
        }
    }
    let with_rulesets = pool.rulesets.zip(rulesets.as_deref());
    let built = overlay(overlay_at.as_deref()).and_then(|overlay| {
        // a task process has no environment, so its modules' secrets resolve to none
        modules(&pool.name, &pool.registry, &overlay, with_rulesets, &|_| {
            None
        })
        .map_err(|e| e.to_string())
    });
    match built {
        Ok(modules) => ace_pool::task_process::main(&modules),
        Err(e) => {
            eprintln!("setup failed: {e}");
            ExitCode::from(setup)
        }
    }
}

fn supervisor(pool: &ParserPool) -> ExitCode {
    let mut telemetry = ace_pool::telemetry::init(&format!("ace4-{}", pool.name), "info");
    let overlay_at = overlay_path();
    let rulesets = match pool.rulesets {
        Some(rulesets) => {
            let dir = PathBuf::from(var("ACE4_RULESET_DIR", "/var/lib/ace4/rulesets"));
            if let Err(e) = std::fs::create_dir_all(&dir) {
                eprintln!("the ruleset directory {}: {e}", dir.display());
                return ExitCode::from(2);
            }
            Some((rulesets, dir))
        }
        None => None,
    };
    let with_rulesets = rulesets.as_ref().map(|(r, dir)| (*r, dir.as_path()));
    let modules = match overlay(overlay_at.as_deref()).and_then(|overlay| {
        modules(
            &pool.name,
            &pool.registry,
            &overlay,
            with_rulesets,
            &ace_pool::secrets::process_env,
        )
        .map_err(|e| e.to_string())
    }) {
        Ok(modules) => modules.with_tools(&pool.tools),
        Err(e) => {
            eprintln!("setup failed: {e}");
            return ExitCode::from(2);
        }
    };
    let missing = modules.missing_tools();
    if !missing.is_empty() {
        eprintln!(
            "setup failed: these modules run tools the pool doesn't carry: {}",
            missing.join(", ")
        );
        return ExitCode::from(2);
    }
    // each tool, its libraries and its data, as this image has them
    let tools = match ace_pool::tools::ToolTable::resolve(&pool.tools) {
        Ok(tools) => Arc::new(tools),
        Err(e) => {
            eprintln!("setup failed: {e}");
            return ExitCode::from(2);
        }
    };
    let modules = Arc::new(modules);
    let user_name = var("ACE4_TASK_USER", "ace4-task");
    let Some(user) = ace_pool::supervisor::user_ids(&user_name) else {
        eprintln!("no user {user_name} for task processes");
        return ExitCode::from(2);
    };
    let program = match std::env::current_exe() {
        Ok(program) => program,
        Err(e) => {
            eprintln!("this binary's path: {e}");
            return ExitCode::from(2);
        }
    };
    let mut task_args = vec!["task".to_owned()];
    if let Some(path) = &overlay_at {
        task_args.extend(["--overlay".to_owned(), path.display().to_string()]);
    }
    if let Some((_, dir)) = &rulesets {
        task_args.extend(["--rulesets".to_owned(), dir.display().to_string()]);
    }
    let client = match LeaseClient::from_env(&worker_name()) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = telemetry.start_export() {
        eprintln!("no span export: {e}");
    }
    let config = SupervisorConfig {
        program: program.clone(),
        args: task_args,
        user: Some(user),
        concurrency: number("ACE4_CONCURRENCY", 4),
        read_paths: Vec::new(),
        tools,
        tool_args: Vec::new(),
    };
    let poll = Duration::from_secs(number("ACE4_RULESET_POLL_SECONDS", 30) as u64);
    let watcher = rulesets.map(|(rulesets, dir)| {
        RulesetWatcher::new(client.clone(), dir, Arc::new(rulesets.check)).every(poll)
    });
    let mut supervisor = Supervisor::new(client, modules, config);
    if pool.commands {
        let mut commands = CommandConfig::new(program, vec!["command".to_owned()], Some(user));
        commands.concurrency = number("ACE4_COMMAND_CONCURRENCY", DEFAULT_CONCURRENCY);
        supervisor = supervisor.with_commands(commands);
    }
    with_runtime(async move {
        let stop = stop_on_signal();
        let mut handles = vec![(
            "heartbeat",
            tokio::spawn(heartbeat(health_file(), stop.clone())),
        )];
        if let Some(watcher) = watcher {
            tracing::info!("waiting for the core's first YARA ruleset before leasing");
            if watcher.first(&stop).await.is_none() {
                return ExitCode::SUCCESS;
            }
            tracing::info!("the first ruleset loaded; leasing");
            let stopping = stop.clone();
            handles.push((
                "ruleset watcher",
                tokio::spawn(async move { watcher.run(stopping).await }),
            ));
        }
        let stats = supervisor.run(stop).await;
        tracing::info!(tasks = stats.tasks, errors = stats.errors, "stopped");
        join_all(handles).await;
        ExitCode::SUCCESS
    })
}

/// Builds a network pool's action handlers (PLAN.md 7.9): each with its overlay entry's settings and the
/// secrets its spec declares, read through `env`.
fn handlers(
    pool: &LookupPool,
    overlay: &Overlay,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<ace_pool::actions::Handlers, String> {
    let mut handlers = ace_pool::actions::Handlers::new();
    for (spec, build) in &pool.actions {
        let entry = format!("{}/{}", spec.kind, spec.name);
        let secrets = ace_pool::secrets::resolve_names(&pool.name, spec.secrets, overlay, env);
        let setup = crate::ActionSetup {
            settings: overlay.actions.get(&entry).and_then(|a| a.settings.clone()),
            secrets,
        };
        let handler = build(&setup).map_err(|e| format!("{entry}: {e}"))?;
        let built = handler.spec();
        if built.kind != spec.kind || built.name != spec.name {
            return Err(format!(
                "{entry} built a handler for {}",
                built.pool_entry()
            ));
        }
        handlers = handlers.with(handler)?;
    }
    if let Some(unknown) = overlay.actions.keys().find(|key| {
        !pool
            .actions
            .iter()
            .any(|(spec, _)| **key == format!("{}/{}", spec.kind, spec.name))
    }) {
        tracing::warn!(pool = %pool.name, "the overlay has settings for {unknown}, which this pool doesn't host");
    }
    Ok(handlers)
}

/// A network pool's binary.
pub fn lookup_main(pool: &LookupPool) -> ExitCode {
    let mut telemetry = ace_pool::telemetry::init(&format!("ace4-{}", pool.name), "info");
    // the modules, their secrets and the client before any thread starts, so containment can
    // follow
    let built = overlay(overlay_path().as_deref()).and_then(|overlay| {
        let modules = modules(
            &pool.name,
            &pool.registry,
            &overlay,
            None,
            &ace_pool::secrets::process_env,
        )
        .map_err(|e| e.to_string())?;
        let handlers = handlers(pool, &overlay, &ace_pool::secrets::process_env)?;
        Ok((modules, handlers))
    });
    let (modules, handlers) = match built {
        Ok((modules, handlers)) => (Arc::new(modules), Arc::new(handlers)),
        Err(e) => {
            eprintln!("setup failed: {e}");
            return ExitCode::from(2);
        }
    };
    let client = match LeaseClient::from_env(&worker_name()) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let Some(port) = client.api_port() else {
        eprintln!("no port in ACE4_API_URL");
        return ExitCode::from(2);
    };
    let mut profile = PoolDefinition::lookup_sandbox(&modules, port, POOL_ADDRESS_SPACE);
    for spec in handlers.specs() {
        for &port in spec.tcp_ports {
            profile = profile.allow_port(port);
        }
    }
    match ace_pool::contain_pool(&profile) {
        Ok(contained) => eprintln!(
            "contained: {contained:?}, TCP ports {:?}",
            profile.tcp_ports
        ),
        Err(e) => {
            eprintln!("containment failed: {e}");
            return ExitCode::from(3);
        }
    }
    if let Err(e) = telemetry.start_export() {
        eprintln!("no span export: {e}");
    }
    let definition = PoolDefinition {
        name: pool.name.clone(),
        modules,
        concurrency: number("ACE4_CONCURRENCY", 16),
        sandbox: profile,
    };
    let action_concurrency = number("ACE4_ACTION_CONCURRENCY", 4);
    with_runtime(async move {
        let stop = stop_on_signal();
        let mut handles = vec![(
            "heartbeat",
            tokio::spawn(heartbeat(health_file(), stop.clone())),
        )];
        if !handlers.is_empty() {
            let actions = ace_pool::actions::ActionPool::new(
                client.as_worker(&format!("{}-actions", client.worker())),
                handlers,
                action_concurrency,
            );
            let stopping = stop.clone();
            handles.push((
                "action loop",
                tokio::spawn(async move {
                    let stats = actions.run(stopping).await;
                    tracing::info!(
                        ended = stats.ended,
                        stopped = stats.stopped,
                        errors = stats.errors,
                        "the action loop stopped"
                    );
                }),
            ));
        }
        let stats = AsyncPool::new(client, &definition).run(stop).await;
        tracing::info!(tasks = stats.tasks, errors = stats.errors, "stopped");
        join_all(handles).await;
        ExitCode::SUCCESS
    })
}

/// A scanner pool's binary.
pub fn scanner_main(pool: &ScannerPool) -> ExitCode {
    let mut telemetry = ace_pool::telemetry::init(&format!("ace4-{}", pool.name), "info");
    let client = match LeaseClient::from_env(&worker_name()) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = telemetry.start_export() {
        eprintln!("no span export: {e}");
    }
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let mut config = ace_pool::scanners::ScannerPoolConfig::new(
        &var("ACE4_STACK", "ace4"),
        host.trim(),
        &pool.scanners,
        &|name| std::env::var(name).ok(),
    );
    config.socket = PathBuf::from(var("ACE4_DOCKER_SOCKET", "/var/run/docker.sock"));
    config.concurrency = number("ACE4_CONCURRENCY", 4);
    with_runtime(async move {
        let stop = stop_on_signal();
        let beating = tokio::spawn(heartbeat(health_file(), stop.clone()));
        let stats = ace_pool::scanners::ScannerPool::new(client, config)
            .run(stop)
            .await;
        tracing::info!(scans = stats.scans, errors = stats.errors, "stopped");
        join_all(vec![("heartbeat", beating)]).await;
        ExitCode::SUCCESS
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ruleset_module_gets_the_pools_ruleset_directory() {
        let pool = ParserPool::new("parsers")
            .module::<ace_mod_email::EmailAnalyzer>()
            .module::<ace_mod_yara::YaraScanner>()
            .yara_rulesets::<ace_mod_yara::YaraScanner>(ace_mod_yara::check_ruleset);
        let overlay = Overlay::from_yaml(
            "modules:\n  yara_scanner_v3_4:\n    settings:\n      blacklist: [noisy]\n  rdap_analyzer:\n    settings:\n      request_timeout_seconds: 5\n",
        )
        .expect("reads");
        let rulesets = pool.rulesets.expect("rulesets");
        let components = components(
            &pool.registry,
            &overlay,
            Some((rulesets, Path::new("/var/lib/ace4/rulesets"))),
        )
        .expect("components");
        let yara = components
            .iter()
            .find(|c| c.key == "yara_scanner_v3_4")
            .expect("the YARA module");
        assert_eq!(
            yara.settings,
            Some(serde_json::json!({
                "blacklist": ["noisy"],
                "rulesets": "/var/lib/ace4/rulesets",
            }))
        );
        // the network pool's section isn't the parser pool's, so it's skipped
        let keys: Vec<&str> = components.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["email_analyzer", "yara_scanner_v3_4"]);
    }
}
