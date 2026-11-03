//! The parser pool: the email, archive and YARA modules, one contained task process per task
//! (PLAN.md 2.17, 2.18), with the YARA module on the core's current ruleset (2.26).
//!
//! ```text
//! ace-parsers
//!     the supervisor: lease tasks and run each in a task process, until SIGTERM
//! ace-parsers task [--overlay PATH] --rulesets DIR
//!     a task process, which the supervisor starts with an empty environment
//! ```
//!
//! The supervisor reads `ACE4_API_URL`, `ACE4_POOL_TOKEN`, `ACE4_OVERLAY`, `ACE4_RULESET_DIR`
//! (`/var/lib/ace4/rulesets`), `ACE4_TASK_USER` (`ace4-task`, whom task processes run as),
//! `ACE4_CONCURRENCY` (4), `ACE4_RULESET_POLL_SECONDS` (30) and `ACE4_HEALTH_FILE`. A task
//! process gets the overlay's path and the ruleset directory as arguments, since it has no
//! environment.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ace_pool::client::LeaseClient;
use ace_pool::rulesets::RulesetWatcher;
use ace_pool::supervisor::{Supervisor, SupervisorConfig};
use ace_pools::{health_file, heartbeat, number, overlay, overlay_path, var, worker_name};

const POOL: &str = "parsers";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("task") {
        return task(args.collect());
    }
    supervisor()
}

/// A task process: builds the modules as the supervisor did, then runs the task on stdin.
fn task(args: Vec<String>) -> ExitCode {
    let mut overlay_at: Option<PathBuf> = None;
    let mut rulesets: Option<PathBuf> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--overlay", Some(path)) => overlay_at = Some(path.into()),
            ("--rulesets", Some(dir)) => rulesets = Some(dir.into()),
            (other, _) => {
                eprintln!("setup failed: unknown argument {other}");
                return ExitCode::from(10);
            }
        }
    }
    let built = overlay(overlay_at.as_deref()).and_then(|overlay| {
        // a task process has no environment, and the parsers declare no secrets
        ace_pools::modules(
            POOL,
            &ace_pools::parser_registry(),
            &overlay,
            rulesets.as_deref(),
            &|_| None,
        )
        .map_err(|e| e.to_string())
    });
    match built {
        Ok(modules) => ace_pool::task_process::main(&modules),
        Err(e) => {
            eprintln!("setup failed: {e}");
            ExitCode::from(10)
        }
    }
}

fn supervisor() -> ExitCode {
    let mut telemetry = ace_pool::telemetry::init("ace4-parsers", "info");
    let overlay_at = overlay_path();
    let rulesets = PathBuf::from(var("ACE4_RULESET_DIR", "/var/lib/ace4/rulesets"));
    if let Err(e) = std::fs::create_dir_all(&rulesets) {
        eprintln!("the ruleset directory {}: {e}", rulesets.display());
        return ExitCode::from(2);
    }
    let modules = match overlay(overlay_at.as_deref()).and_then(|overlay| {
        ace_pools::modules(
            POOL,
            &ace_pools::parser_registry(),
            &overlay,
            Some(&rulesets),
            &ace_pool::secrets::process_env,
        )
        .map_err(|e| e.to_string())
    }) {
        Ok(modules) => Arc::new(modules),
        Err(e) => {
            eprintln!("setup failed: {e}");
            return ExitCode::from(2);
        }
    };
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
    task_args.extend(["--rulesets".to_owned(), rulesets.display().to_string()]);
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
        program,
        args: task_args,
        user: Some(user),
        concurrency: number("ACE4_CONCURRENCY", 4),
        read_paths: Vec::new(),
    };
    let poll = Duration::from_secs(number("ACE4_RULESET_POLL_SECONDS", 30) as u64);
    let watcher = RulesetWatcher::new(
        client.clone(),
        rulesets,
        Arc::new(ace_mod_yara::check_ruleset),
    )
    .every(poll);
    let supervisor = Supervisor::new(client, modules, config);
    ace_pools::with_runtime(async move {
        let stop = ace_pools::stop_on_signal();
        let beating = tokio::spawn(heartbeat(health_file(), stop.clone()));
        tracing::info!("waiting for the core's first YARA ruleset before leasing");
        if watcher.first(&stop).await.is_none() {
            return ExitCode::SUCCESS;
        }
        tracing::info!("the first ruleset loaded; leasing");
        let stopping = stop.clone();
        let watching = tokio::spawn(async move { watcher.run(stopping).await });
        let stats = supervisor.run(stop).await;
        tracing::info!(tasks = stats.tasks, errors = stats.errors, "stopped");
        for (name, handle) in [("ruleset watcher", watching), ("heartbeat", beating)] {
            if tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .is_err()
            {
                tracing::warn!("the {name} didn't stop within 5 seconds");
            }
        }
        ExitCode::SUCCESS
    })
}
