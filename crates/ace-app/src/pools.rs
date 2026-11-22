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
//! `ACE4_RULESET_POLL_SECONDS` (30). When it starts it reads the overlay and builds every module
//! of the pool, so a setting that doesn't load, an instance that isn't allowed or a module whose
//! `init` fails stops the pool then, with the module's name (PLAN.md 2.23), and not a task later.
//! It runs each task as
//!
//! ```text
//! <binary> task [--overlay PATH]
//! ```
//!
//! which starts with an empty environment and builds one module: the one its task names, from
//! the settings block the supervisor sends with the task, which is the block the supervisor
//! itself built that module from. So a task runs on the overlay as it was when the pool started,
//! and a change to the overlay takes a restart of the pool, as it does for a network pool. The
//! overlay's path is an argument for the one thing a task process still reads there: the
//! sources of the secrets its own module declares.
//!
//! A pool whose image carries tools (`ParserPool::tools`, PLAN.md 7.3) runs
//! each of its tasks' tools as `<binary> tool`, which contains itself and execs the tool
//! (`ace_pool::tools`). A pool that runs GUI commands (`ParserPool::commands`, PLAN.md 5.12) also
//! leases those, `ACE4_COMMAND_CONCURRENCY` (3) at once, and runs each as `<binary> command`, contained
//! with no paths and no ports (`ace_pool::commands`), on `ace`'s own command line (`cli::run_contained`).
//!
//! A network pool reads `ACE4_API_URL`, `ACE4_POOL_TOKEN`, `ACE4_OVERLAY`, the variables and
//! files the overlay's `secrets:` names for its modules' and its action handlers' secrets,
//! `ACE4_CONCURRENCY` (16), `ACE4_ACTION_CONCURRENCY` (4, the actions it runs at once, PLAN.md 7.9) and
//! `ACE4_HEALTH_FILE`, and `ACE4_BUCKET_ENDPOINT` (the core's, for its port; without one, AWS S3's
//! 443) when one of its modules adds files it fetched (`Module::ADDS_FETCHED_FILES`). It contains
//! itself before its runtime starts a thread: it may connect only to its modules' and its
//! handlers' TCP ports, the lease API's and the collector's, and the bucket's only when one of its
//! modules adds files it fetched, which it uploads to the core's presigned URLs (PLAN.md decision
//! 28).
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

/// Builds the pool's modules: its components, with the secrets their manifests declare and their
/// connections name, read through `env`.
fn modules(
    pool: &str,
    registry: &Registry,
    overlay: &Overlay,
    rulesets: Option<(Rulesets, &Path)>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Modules, StartError> {
    let components = components(registry, overlay, rulesets)?;
    let secrets = ace_pool::secrets::resolve_components(pool, &components, overlay, env);
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

/// A task process: reads the task on stdin and builds its one module (`ace_pool::task_process`).
/// The module's settings come with the task, from the supervisor's read of the overlay, so this
/// process reads the overlay only for a module that declares secrets, and then only their sources.
fn parser_task(pool: &ParserPool, args: Vec<String>) -> ExitCode {
    let setup = u8::try_from(EXIT_SETUP).unwrap_or(u8::MAX);
    let mut overlay_at: Option<PathBuf> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--overlay", Some(path)) => overlay_at = Some(path.into()),
            (other, _) => {
                eprintln!("setup failed: unknown argument {other}");
                return ExitCode::from(setup);
            }
        }
    }
    ace_pool::task_process::main(&pool.registry, &|manifest| {
        task_secrets(&pool.name, manifest, overlay_at.as_deref())
    })
}

/// The secrets a task process gives the module of `manifest`: the ones it declares, from the
/// overlay's sources (PLAN.md 2.24). A task process has no environment, so a secret the overlay
/// reads from a variable isn't set for it, and one it reads from a file is, when the task's user
/// can read the file. A module that declares none, as every open-source parser does, has none
/// and the overlay isn't opened.
fn task_secrets(
    pool: &str,
    manifest: &ace_sdk::Manifest,
    overlay_at: Option<&Path>,
) -> Result<ace_sdk::Secrets, String> {
    if manifest.secrets.is_empty() {
        return Ok(ace_sdk::Secrets::new());
    }
    let overlay = overlay(overlay_at)?;
    Ok(ace_pool::secrets::resolve(
        pool,
        std::slice::from_ref(manifest),
        &overlay,
        &|_| None,
    ))
}

/// What a parser pool's supervisor checks and builds when it starts, before it leases a task:
/// every component the overlay makes of the pool's modules, built, with the pool's tools. This
/// is where the pool refuses its overlay (PLAN.md 2.23), with the module's name in the error: a
/// settings key the module hasn't (#858) or a value of the wrong type, an instance with a bad
/// name, a clashing name or an input its module doesn't take, settings for a module that runs
/// only as instances, a module whose `init` fails on its settings, and a module that runs a
/// tool the pool doesn't carry. A section for a module the pool hasn't is skipped (#901, #916),
/// and a module with no section runs on its defaults (#1044).
///
/// A task process repeats none of it. It builds the task's one module again from the block
/// that passed here (`ace_pool::task_process`), so the only failure left to it is that module's
/// `init` failing on something that changed since, such as a file it reads having gone.
fn parser_modules(
    pool: &ParserPool,
    overlay: &Overlay,
    rulesets: Option<(Rulesets, &Path)>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Modules, String> {
    let modules = modules(&pool.name, &pool.registry, overlay, rulesets, env)
        .map_err(|e| e.to_string())?
        .with_tools(&pool.tools);
    let missing = modules.missing_tools();
    if !missing.is_empty() {
        return Err(format!(
            "these modules run tools the pool doesn't carry: {}",
            missing.join(", ")
        ));
    }
    Ok(modules)
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
        parser_modules(
            pool,
            &overlay,
            with_rulesets,
            &ace_pool::secrets::process_env,
        )
    }) {
        Ok(modules) => modules,
        Err(e) => {
            eprintln!("setup failed: {e}");
            return ExitCode::from(2);
        }
    };
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
    // a task process gets its module's settings with its task; the overlay's path is for the
    // secrets of a module that declares some
    let mut task_args = vec!["task".to_owned()];
    if let Some(path) = &overlay_at {
        task_args.extend(["--overlay".to_owned(), path.display().to_string()]);
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
    let cache_probes = Arc::new(ace_pool::cache::probe_modules(&modules, &pool.tools));
    let config = SupervisorConfig {
        program: program.clone(),
        args: task_args,
        user: Some(user),
        concurrency: number("ACE4_CONCURRENCY", 4),
        read_paths: Vec::new(),
        tools,
        tool_args: Vec::new(),
        cache_probes,
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

/// Builds a network pool's action handlers (PLAN.md 7.9): each with its overlay entry's settings, the
/// secrets its spec declares, and the shared connections its entry binds with theirs, read through `env`.
fn handlers(
    pool: &LookupPool,
    overlay: &Overlay,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<ace_pool::actions::Handlers, String> {
    let mut handlers = ace_pool::actions::Handlers::new();
    for (spec, build) in &pool.actions {
        let entry = spec.overlay_entry();
        if !spec.is_enabled(overlay) {
            // off by default, and the overlay has no entry for it: not built, so not run (decision 28)
            tracing::info!(pool = %pool.name, "{entry} is off unless the overlay's actions: has an entry for it, and it has none");
            continue;
        }
        let section = overlay.actions.get(&entry).cloned().unwrap_or_default();
        let bindings = overlay
            .bind(
                &format!("actions.{entry}.connections"),
                spec.connections,
                &section.connections,
            )
            .map_err(|e| e.to_string())?;
        let names: Vec<&str> = spec
            .secrets
            .iter()
            .copied()
            .chain(ace_sdk::connections::secret_names(&bindings))
            .collect();
        let resolved = ace_pool::secrets::resolve_names(&pool.name, &names, overlay, env);
        let setup = crate::ActionSetup {
            settings: section.settings,
            secrets: resolved.only(spec.secrets),
            connections: ace_sdk::Connections::resolve(&bindings, &resolved),
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
            .any(|(spec, _)| **key == spec.overlay_entry())
    }) {
        tracing::warn!(pool = %pool.name, "the overlay has settings for {unknown}, which this pool doesn't host");
    }
    Ok(handlers)
}

/// The ports the connections a network pool's modules and handlers bind reach beyond their own,
/// such as a proxy's (`ace_sdk::ConnectionType::tcp_ports`, PLAN.md decision 35): a connection
/// bound by none of them adds none, nor does a handler the overlay leaves off.
pub fn connection_ports(pool: &LookupPool, overlay: &Overlay) -> Result<Vec<u16>, String> {
    let mut bindings = Vec::new();
    for component in components(&pool.registry, overlay, None).map_err(|e| e.to_string())? {
        bindings.extend(component.connections);
    }
    for (spec, _) in &pool.actions {
        if !spec.is_enabled(overlay) {
            continue;
        }
        let entry = spec.overlay_entry();
        let section = overlay.actions.get(&entry).cloned().unwrap_or_default();
        bindings.extend(
            overlay
                .bind(
                    &format!("actions.{entry}.connections"),
                    spec.connections,
                    &section.connections,
                )
                .map_err(|e| e.to_string())?,
        );
    }
    Ok(ace_sdk::connections::tcp_ports(&bindings))
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
        let ports = connection_ports(pool, &overlay)?;
        Ok((modules, handlers, ports))
    });
    let (modules, handlers, connection_ports) = match built {
        Ok((modules, handlers, ports)) => (Arc::new(modules), Arc::new(handlers), ports),
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
    let endpoint = std::env::var(ace_pool::pool::BUCKET_ENDPOINT_VAR).ok();
    let mut profile = match PoolDefinition::lookup_sandbox_with(
        &modules,
        handlers.collects_files(),
        port,
        endpoint.as_deref(),
        &connection_ports,
        POOL_ADDRESS_SPACE,
    ) {
        Ok(profile) => profile,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
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

    /// A remediator off by default (PLAN.md decision 28), which writes to nothing.
    struct OffRemediator;

    static OFF: ace_sdk::actions::ActionSpec = ace_sdk::actions::ActionSpec::new(
        ace_sdk::actions::ActionKind::Remediation,
        "off_mailbox",
        "Off Mailbox",
        "a remediator off by default",
        "email_delivery",
    )
    .off_by_default();

    impl ace_sdk::actions::Remediator for OffRemediator {
        fn spec(&self) -> &'static ace_sdk::actions::ActionSpec {
            &OFF
        }

        fn remove<'a>(
            &'a self,
            _: &'a ace_sdk::actions::LeasedAction,
        ) -> ace_sdk::actions::ActionFuture<'a, ace_sdk::actions::RemediatorResult> {
            unreachable!("never run")
        }

        fn restore<'a>(
            &'a self,
            _: &'a ace_sdk::actions::LeasedAction,
        ) -> ace_sdk::actions::ActionFuture<'a, ace_sdk::actions::RemediatorResult> {
            unreachable!("never run")
        }
    }

    fn with_off_remediator() -> crate::App {
        crate::App::new().lookup_pool(
            LookupPool::new("lookups")
                .action(&ace_sdk::actions::TEST_REMEDIATOR, |_| {
                    Ok(crate::ActionHandler::Remediator(Arc::new(
                        ace_sdk::actions::TestRemediator,
                    )))
                })
                .action(&OFF, |_| {
                    Ok(crate::ActionHandler::Remediator(Arc::new(OffRemediator)))
                }),
        )
    }

    /// PLAN.md decision 28: a remediator off by default is in `ace serve`'s catalog, and built by its
    /// pool, only when the overlay's `actions:` has an entry for it, empty or not; one on by default,
    /// such as ace4's test remediator, is in both either way.
    #[test]
    fn a_remediator_off_by_default_runs_only_with_an_overlay_entry() {
        use ace_sdk::actions::ActionKind::Remediation;
        let app = with_off_remediator();
        let pool = &app.lookup_pools[0];
        let env = |_: &str| None;
        let none = Overlay::default();
        let on = Overlay::from_yaml("actions:\n  remediation/off_mailbox: {}\n").expect("loads");

        let catalog = app.action_catalog_for(&none).expect("a catalog");
        assert!(catalog.get(Remediation, "test").is_some());
        assert!(catalog.get(Remediation, "off_mailbox").is_none());
        let built = handlers(pool, &none, &env).expect("handlers");
        assert!(built.get(Remediation, "test").is_some());
        assert!(built.get(Remediation, "off_mailbox").is_none());

        let catalog = app.action_catalog_for(&on).expect("a catalog");
        assert!(catalog.get(Remediation, "test").is_some());
        assert!(catalog.get(Remediation, "off_mailbox").is_some());
        let built = handlers(pool, &on, &env).expect("handlers");
        assert!(built.get(Remediation, "off_mailbox").is_some());

        // every handler the binary has, whatever an overlay says
        let all = app.action_catalog().expect("a catalog");
        assert!(all.get(Remediation, "off_mailbox").is_some());
    }

    /// PLAN.md decision 35 for Splunk: an instance's port comes from its `base_url`, so a lookups
    /// pool whose `splunk_api` instance binds one on 9443 reaches it, beside the module's own 8089
    /// and 443; an instance no module binds adds nothing.
    #[test]
    fn a_splunk_instance_s_port_joins_the_lookups_pool_s_sandbox() {
        let pool = LookupPool::new("lookups").module::<ace_mod_splunk::SplunkAnalyzer>();
        let overlay = Overlay::from_yaml(
            "\
connections:
  default:
    type: splunk
    settings: {base_url: 'https://splunk.site.example:9443', username: ace}
    secrets: {password: splunk_default_password}
  other:
    type: splunk
    settings: {base_url: 'https://other.site.example:7089', username: ace}
modules:
  splunk_api:
    instances:
      proxy_domain_lookup:
        inputs: [fqdn]
        connections: {splunk: default}
        settings:
          question: Was this domain seen?
          summary: Proxy correlation
          query: index=proxy hostname=\"<O_VALUE>\"
secrets:
  splunk_default_password: env:ACE4_TEST_UNSET
",
        )
        .expect("an overlay");
        let ports = connection_ports(&pool, &overlay).expect("the ports");
        assert_eq!(ports, [9443]);
        let modules = modules(&pool.name, &pool.registry, &overlay, None, &|_| None)
            .expect("the pool's modules");
        let profile = PoolDefinition::lookup_sandbox_with(
            &modules,
            false,
            8080,
            None,
            &ports,
            POOL_ADDRESS_SPACE,
        )
        .expect("a sandbox");
        for port in [9443, 8089, 443, 8080] {
            assert!(
                profile.tcp_ports.contains(&port),
                "{port}: {:?}",
                profile.tcp_ports
            );
        }
        assert!(
            !profile.tcp_ports.contains(&7089),
            "{:?}",
            profile.tcp_ports
        );
    }

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

    use ace_results::{AnalysisType, ObservableKind};
    use ace_sdk::{Module, ModuleError, Outcome, Parser, TaskContext};

    /// A parser of the test's own: its `init` refuses a `limit` of 0, as a real module's refuses a
    /// setting it can't run on, and it declares a secret.
    struct Picky;

    #[derive(
        Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
    )]
    #[serde(deny_unknown_fields)]
    struct PickyAnalysis {}

    impl AnalysisType for PickyAnalysis {
        const NAME: &'static str = "test_picky_analysis";
        const VERSION: u32 = 1;
        const MODULE: &'static str = Picky::NAME;
    }

    #[derive(Debug, Clone, PartialEq, serde::Deserialize, schemars::JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    struct PickySettings {
        limit: u32,
    }

    impl Default for PickySettings {
        fn default() -> Self {
            PickySettings { limit: 1 }
        }
    }

    impl Module for Picky {
        const NAME: &'static str = "test_picky";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const SECRETS: &'static [&'static str] = &["picky_token"];
        type Output = PickyAnalysis;
        type Settings = PickySettings;

        fn init(settings: &PickySettings) -> Result<Self, ModuleError> {
            if settings.limit == 0 {
                return Err(ModuleError::other("limit must be at least 1"));
            }
            Ok(Picky)
        }
    }

    impl Parser for Picky {
        fn analyze(
            &self,
            _: &TaskContext<PickySettings>,
        ) -> Result<Outcome<PickyAnalysis>, ModuleError> {
            Ok(Outcome::Skipped("a test module".to_owned()))
        }
    }

    /// A parser with one setting and nothing else of note.
    struct Plain;

    #[derive(
        Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
    )]
    #[serde(deny_unknown_fields)]
    struct PlainAnalysis {}

    impl AnalysisType for PlainAnalysis {
        const NAME: &'static str = "test_plain_analysis";
        const VERSION: u32 = 1;
        const MODULE: &'static str = Plain::NAME;
    }

    #[derive(Debug, Clone, Default, PartialEq, serde::Deserialize, schemars::JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    struct PlainSettings {
        max_bytes: u64,
    }

    impl Module for Plain {
        const NAME: &'static str = "test_plain";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        type Output = PlainAnalysis;
        type Settings = PlainSettings;

        fn init(_: &PlainSettings) -> Result<Self, ModuleError> {
            Ok(Plain)
        }
    }

    impl Parser for Plain {
        fn analyze(
            &self,
            _: &TaskContext<PlainSettings>,
        ) -> Result<Outcome<PlainAnalysis>, ModuleError> {
            Ok(Outcome::Skipped("a test module".to_owned()))
        }
    }

    /// A parser that runs a tool.
    struct ToolUser;

    #[derive(
        Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
    )]
    #[serde(deny_unknown_fields)]
    struct ToolUserAnalysis {}

    impl AnalysisType for ToolUserAnalysis {
        const NAME: &'static str = "test_tool_user_analysis";
        const VERSION: u32 = 1;
        const MODULE: &'static str = ToolUser::NAME;
    }

    impl Module for ToolUser {
        const NAME: &'static str = "test_tool_user";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const TOOLS: &'static [&'static str] = &["tesseract"];
        type Output = ToolUserAnalysis;
        type Settings = PlainSettings;

        fn init(_: &Self::Settings) -> Result<Self, ModuleError> {
            Ok(ToolUser)
        }
    }

    impl Parser for ToolUser {
        fn analyze(
            &self,
            _: &TaskContext<Self::Settings>,
        ) -> Result<Outcome<ToolUserAnalysis>, ModuleError> {
            Ok(Outcome::Skipped("a test module".to_owned()))
        }
    }

    fn picky_pool() -> ParserPool {
        ParserPool::new("parsers")
            .module::<Picky>()
            .module::<Plain>()
    }

    /// What `pool` does with `yaml` when it starts: its modules' names, or its refusal.
    fn start(pool: &ParserPool, yaml: &str) -> Result<Vec<String>, String> {
        let overlay = Overlay::from_yaml(yaml).map_err(|e| e.to_string())?;
        parser_modules(pool, &overlay, None, &|_| None).map(|modules| modules.names())
    }

    /// PLAN.md 2.23 and ace3 #858: a setting that doesn't load stops the pool when it starts, and
    /// the error names the module and the key. A task process no longer reads the overlay, so
    /// this is the one place it is checked.
    #[test]
    fn a_setting_that_does_not_load_stops_the_pool_at_its_start() {
        let pool = picky_pool();
        let unknown_key = start(
            &pool,
            "modules:\n  test_picky:\n    settings:\n      limt: 3\n",
        )
        .unwrap_err();
        assert_eq!(
            unknown_key,
            "the overlay's modules.test_picky.settings: unknown settings key limt"
        );
        let wrong_type = start(
            &pool,
            "modules:\n  test_picky:\n    settings:\n      limit: many\n",
        )
        .unwrap_err();
        assert!(
            wrong_type
                .starts_with("the overlay's modules.test_picky.settings: invalid setting limit"),
            "{wrong_type}"
        );
        // the second module's block is checked too, though no task has named it
        let second = start(
            &pool,
            "modules:\n  test_plain:\n    settings:\n      max_byte: 3\n",
        )
        .unwrap_err();
        assert_eq!(
            second,
            "the overlay's modules.test_plain.settings: unknown settings key max_byte"
        );
        // a key the overlay itself hasn't is refused where it is read
        let unknown_section = start(&pool, "moduls: {}\n").unwrap_err();
        assert!(unknown_section.contains("moduls"), "{unknown_section}");
    }

    /// A module whose `init` fails on its settings stops the pool when it starts, by name. Before
    /// a task process built only its own module, every task process hit the same failure; now
    /// only this check does.
    #[test]
    fn a_module_that_does_not_build_stops_the_pool_at_its_start() {
        let refused = start(
            &picky_pool(),
            "modules:\n  test_picky:\n    settings:\n      limit: 0\n",
        )
        .unwrap_err();
        assert_eq!(refused, "module test_picky: limit must be at least 1");
        // an instance's settings are built as the module's own are
        let instance = start(
            &picky_pool(),
            "modules:\n  test_picky:\n    instances:\n      picky_two:\n        settings:\n          limit: 0\n",
        )
        .unwrap_err();
        assert_eq!(instance, "module test_picky: limit must be at least 1");
    }

    /// The overlay's rules for instances (PLAN.md 2.23) are refused at the pool's start too.
    #[test]
    fn an_instance_the_overlay_may_not_declare_stops_the_pool_at_its_start() {
        let pool = picky_pool();
        let bad_name = start(
            &pool,
            "modules:\n  test_picky:\n    instances:\n      Picky-Two: {}\n",
        )
        .unwrap_err();
        assert!(bad_name.contains("Picky-Two"), "{bad_name}");
        let clash = start(
            &pool,
            "modules:\n  test_picky:\n    instances:\n      test_plain: {}\n",
        )
        .unwrap_err();
        assert_eq!(
            clash,
            "the overlay's instance test_plain of test_picky has a module's or another instance's \
             name"
        );
        let input = start(
            &pool,
            "modules:\n  test_picky:\n    instances:\n      picky_two:\n        inputs: [fqdn]\n",
        )
        .unwrap_err();
        assert_eq!(
            input,
            "the overlay's instance picky_two of test_picky takes fqdn, which test_picky doesn't"
        );
        let both = start(
            &pool,
            "modules:\n  test_picky:\n    settings:\n      limit: 2\n    instances:\n      picky_two: {}\n",
        )
        .unwrap_err();
        assert!(
            both.contains("modules.test_picky.settings")
                && both.contains("takes its settings in each instance"),
            "{both}"
        );
    }

    /// A module that runs a tool its pool doesn't carry stops the pool when it starts (PLAN.md 7.3).
    #[test]
    fn a_module_whose_tool_the_pool_lacks_stops_the_pool_at_its_start() {
        let without = ParserPool::new("sandbox").module::<ToolUser>();
        assert_eq!(
            start(&without, "").unwrap_err(),
            "these modules run tools the pool doesn't carry: test_tool_user: tesseract"
        );
        let with = ParserPool::new("sandbox")
            .tools(ace_sdk::tools::SANDBOX_TOOLS)
            .module::<ToolUser>();
        assert_eq!(start(&with, "").expect("starts"), ["test_tool_user"]);
    }

    /// What starts all the same (PLAN.md 2.23): a module with no section runs on its defaults
    /// (#1044), a section for a module the binary no longer has is skipped (#901, #916), and so is
    /// another pool's module's, whatever its settings say.
    #[test]
    fn a_missing_section_and_a_removed_module_do_not_stop_the_pool() {
        let pool = picky_pool();
        assert_eq!(
            start(&pool, "").expect("starts"),
            ["test_picky", "test_plain"]
        );
        let removed = "modules:\n  a_module_removed_last_year:\n    settings:\n      anything: 1\n  \
                       rdap_analyzer:\n    settings:\n      no_such_key: 5\n";
        assert_eq!(
            start(&pool, removed).expect("starts"),
            ["test_picky", "test_plain"]
        );
    }

    /// The supervisor sends a task process the block it built the task's module from, so a task
    /// runs on exactly what the start check passed: the overlay's block, the pool's ruleset
    /// directory for the ruleset module, an instance's own block, and nothing for a module on its
    /// defaults.
    #[test]
    fn a_task_process_gets_the_block_its_module_was_built_from_at_the_start() {
        let pool = picky_pool()
            .module::<ace_mod_yara::YaraScanner>()
            .yara_rulesets::<ace_mod_yara::YaraScanner>(ace_mod_yara::check_ruleset);
        let overlay = Overlay::from_yaml(
            "modules:\n  test_picky:\n    instances:\n      picky_two:\n        settings:\n          limit: 2\n      picky_nine:\n        settings:\n          limit: 9\n  yara_scanner_v3_4:\n    settings:\n      blacklist: [noisy]\n",
        )
        .expect("reads");
        let dir = tempfile::tempdir().expect("a directory");
        let rulesets = pool.rulesets.expect("rulesets");
        let modules = parser_modules(&pool, &overlay, Some((rulesets, dir.path())), &|_| None)
            .expect("starts");
        let block = |key: &str| {
            modules
                .parser(key)
                .unwrap_or_else(|| panic!("no {key}"))
                .settings()
                .cloned()
        };
        assert_eq!(block("picky_two"), Some(serde_json::json!({"limit": 2})));
        assert_eq!(block("picky_nine"), Some(serde_json::json!({"limit": 9})));
        assert_eq!(block("test_plain"), None);
        assert_eq!(
            block("yara_scanner_v3_4"),
            Some(serde_json::json!({
                "blacklist": ["noisy"],
                "rulesets": dir.path().display().to_string(),
            }))
        );
        // an instance's tasks name the instance, and its process builds the module it is made of
        assert_eq!(
            modules.parser("picky_two").map(|p| p.manifest().name),
            Some("test_picky")
        );
    }

    /// PLAN.md 2.24: a task process resolves the secrets its own module declares and no other's,
    /// and opens the overlay only for a module that declares one. With no environment, a secret
    /// from a variable isn't set for it.
    #[test]
    fn a_task_process_resolves_only_its_own_modules_secrets() {
        let dir = tempfile::tempdir().expect("a directory");
        let (token, other) = (dir.path().join("token"), dir.path().join("other"));
        std::fs::write(&token, "picky-secret\n").expect("writes");
        std::fs::write(&other, "another-modules-secret\n").expect("writes");
        let overlay_at = dir.path().join("overlay.yaml");
        std::fs::write(
            &overlay_at,
            format!(
                "secrets:\n  picky_token: file:{}\n  resolver_token: file:{}\n  splunk_default_password: env:HOME\n",
                token.display(),
                other.display()
            ),
        )
        .expect("writes");
        let picky = ace_sdk::Manifest::parser::<Picky>();
        let secrets = task_secrets("parsers", &picky, Some(&overlay_at)).expect("resolves");
        assert_eq!(secrets.names(), ["picky_token"]);
        // a module that declares none has none, and the overlay isn't read: this one isn't there
        let counter = ace_sdk::Manifest::parser::<Plain>();
        let missing = dir.path().join("no-overlay.yaml");
        let none = task_secrets("parsers", &counter, Some(&missing)).expect("nothing to read");
        assert!(none.names().is_empty());
        // where one that declares a secret does read it, and says when it can't
        let unread = task_secrets("parsers", &picky, Some(&missing)).unwrap_err();
        assert!(unread.contains("no-overlay.yaml"), "{unread}");
    }
}
