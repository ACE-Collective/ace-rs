//! A pool of test modules, for ace-pool's tests (feature `test-pools`). It holds only the lease
//! API's URL (`ACE4_API_URL`) and its pool's token (`ACE4_POOL_TOKEN`).
//!
//! ```text
//! test-pool once [--settings JSON]
//!     lease one task, run it in this process, and exit
//! test-pool lookups [--contained] [--concurrency N] [--settings JSON]
//!     run as an async pool until SIGTERM; --contained applies contain_pool first
//! test-pool parsers [--task-user NAME] [--concurrency N] [--read PATH]... [--settings JSON]
//!                  [--rulesets DIR [--ruleset-poll-ms N]]
//!     run as a parser pool's supervisor until SIGTERM, one task process per task; with
//!     --rulesets, keep DIR on the core's current YARA ruleset, and lease nothing until the
//!     first has loaded
//! test-pool parsers ... --commands
//!     the same, also leasing GUI commands and running each as `test-pool command`
//! test-pool command
//!     a GUI command's process: read a command on stdin, contain, run one of
//!     `testing::run_test_command`'s commands
//! test-pool tool
//!     the sandbox runner's tool process: read what to run on stdin, contain, exec it
//! test-pool parsers ... --tool NAME=PATH
//!     the same, with a tool its modules may run, PATH run as NAME with no data of its own
//! test-pool task
//!     a task process: read a task on stdin, build its module from the settings it carries,
//!     contain, run it, write its end on stdout
//! test-pool replay ID [--settings JSON]
//!     replay task ID uncontained, with ACE4_ADMIN_TOKEN, and print how it ended
//! ```
//!
//! `once` exits 0 when it ran a task, 1 when there was none to lease, and 2 on an error.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ace_pool::client::LeaseClient;
use ace_pool::modules::Modules;
use ace_pool::pool::{AsyncPool, POOL_ADDRESS_SPACE, PoolDefinition};
use ace_pool::rulesets::RulesetWatcher;
use ace_pool::run::run_in_process;
use ace_pool::supervisor::{Supervisor, SupervisorConfig};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

struct Args {
    mode: String,
    settings: Value,
    contained: bool,
    concurrency: usize,
    task_user: Option<String>,
    read_paths: Vec<std::path::PathBuf>,
    rulesets: Option<std::path::PathBuf>,
    ruleset_poll: Duration,
    commands: bool,
    tools: Vec<ace_sdk::tools::ToolSpec>,
}

fn parse() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut mode = args.next().ok_or("no mode")?;
    if mode == "replay" {
        mode = format!("replay:{}", args.next().ok_or("replay takes a task id")?);
    }
    let mut parsed = Args {
        mode,
        settings: Value::Object(Default::default()),
        contained: false,
        concurrency: 4,
        task_user: None,
        read_paths: Vec::new(),
        rulesets: None,
        ruleset_poll: ace_pool::rulesets::DEFAULT_EVERY,
        commands: false,
        // the dev image's, which are the sandbox image's
        tools: ace_sdk::tools::SANDBOX_TOOLS.to_vec(),
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--settings" => {
                let text = args.next().ok_or("--settings takes JSON")?;
                parsed.settings = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            }
            "--contained" => parsed.contained = true,
            "--commands" => parsed.commands = true,
            "--tool" => {
                let spec = args.next().ok_or("--tool takes NAME=PATH")?;
                let (name, path) = spec.split_once('=').ok_or("--tool takes NAME=PATH")?;
                parsed.tools.push(ace_pool::testing::test_tool(
                    name.to_owned(),
                    path.to_owned(),
                ));
            }
            "--task-user" => {
                parsed.task_user = Some(args.next().ok_or("--task-user takes a name")?)
            }
            "--read" => parsed
                .read_paths
                .push(args.next().ok_or("--read takes a path")?.into()),
            "--rulesets" => {
                parsed.rulesets = Some(args.next().ok_or("--rulesets takes a directory")?.into())
            }
            "--ruleset-poll-ms" => {
                parsed.ruleset_poll = Duration::from_millis(
                    args.next()
                        .and_then(|n| n.parse().ok())
                        .ok_or("--ruleset-poll-ms takes a number")?,
                );
            }
            "--concurrency" => {
                parsed.concurrency = args
                    .next()
                    .and_then(|n| n.parse().ok())
                    .ok_or("--concurrency takes a number")?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(parsed)
}

fn main() -> ExitCode {
    // a command's process reads its request on stdin, and nothing else
    if std::env::args().nth(1).as_deref() == Some("command") {
        return ace_pool::commands::process_main(&ace_pool::testing::run_test_command);
    }
    // a tool's: it must still be one thread
    if std::env::args().nth(1).as_deref() == Some("tool") {
        return ace_pool::tools::tool_main();
    }
    // logs now; span export, which starts threads, once any containment is in place
    let mut telemetry = ace_pool::telemetry::init("ace4-test-pool", "info");
    // a task's process builds the one module its task names, with the settings the task carries
    if std::env::args().nth(1).as_deref() == Some("task") {
        return ace_pool::task_process::main(&ace_pool::testing::registry(), &|_| {
            Ok(ace_sdk::Secrets::new())
        });
    }
    let args = match parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!(
                "{e}\nusage: test-pool once|lookups [--contained] [--concurrency N] [--settings JSON]"
            );
            return ExitCode::from(2);
        }
    };
    // modules and the client are built before any thread starts, so containment can follow
    let modules = match ace_pool::testing::modules(&args.settings) {
        Ok(modules) => Arc::new(modules.with_tools(&args.tools)),
        Err(e) => {
            eprintln!("setup failed: {e}");
            return ExitCode::from(2);
        }
    };
    if let Some(id) = args.mode.strip_prefix("replay:") {
        return with_runtime(replay(id.to_owned(), modules));
    }
    let client = match LeaseClient::from_env(&format!("test-pool-{}", std::process::id())) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    // a lookups pool starts it below, after it contains itself
    if args.mode != "lookups"
        && let Err(e) = telemetry.start_export()
    {
        eprintln!("no span export: {e}");
    }
    match args.mode.as_str() {
        "once" => with_runtime(once(client, modules)),
        "lookups" => {
            if args.contained {
                let Some(port) = client.api_port() else {
                    eprintln!("no port in ACE4_API_URL");
                    return ExitCode::from(2);
                };
                let endpoint = std::env::var(ace_pool::pool::BUCKET_ENDPOINT_VAR).ok();
                let profile = match PoolDefinition::lookup_sandbox(
                    &modules,
                    false,
                    port,
                    endpoint.as_deref(),
                    POOL_ADDRESS_SPACE,
                ) {
                    Ok(profile) => profile,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(2);
                    }
                };
                match ace_pool::contain_pool(&profile) {
                    Ok(contained) => {
                        eprintln!("contained: {contained:?}, ports {:?}", profile.tcp_ports)
                    }
                    Err(e) => {
                        eprintln!("containment failed: {e}");
                        return ExitCode::from(3);
                    }
                }
            }
            if let Err(e) = telemetry.start_export() {
                eprintln!("no span export: {e}");
            }
            let definition = PoolDefinition {
                name: "test".to_owned(),
                modules,
                concurrency: args.concurrency,
                sandbox: Default::default(),
            };
            with_runtime(lookups(client, definition))
        }
        "parsers" => {
            let user = match &args.task_user {
                Some(name) => match ace_pool::supervisor::user_ids(name) {
                    Some(ids) => Some(ids),
                    None => {
                        eprintln!("no user {name}");
                        return ExitCode::from(2);
                    }
                },
                None => None,
            };
            let program = match std::env::current_exe() {
                Ok(program) => program,
                Err(e) => {
                    eprintln!("this binary's path: {e}");
                    return ExitCode::from(2);
                }
            };
            let config = SupervisorConfig {
                program: program.clone(),
                args: vec!["task".to_owned()],
                user,
                concurrency: args.concurrency,
                read_paths: args.read_paths,
                tools: match ace_pool::tools::ToolTable::resolve(&args.tools) {
                    Ok(table) => Arc::new(table),
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(2);
                    }
                },
                tool_args: Vec::new(),
                cache_probes: Arc::new(ace_pool::cache::probe_modules(&modules, &args.tools)),
            };
            let watcher = args.rulesets.map(|dir| {
                RulesetWatcher::new(client.clone(), dir, Arc::new(ace_mod_yara::check_ruleset))
                    .every(args.ruleset_poll)
            });
            let mut supervisor = Supervisor::new(client, modules, config);
            if args.commands {
                supervisor = supervisor.with_commands(ace_pool::commands::CommandConfig::new(
                    program,
                    vec!["command".to_owned()],
                    user,
                ));
            }
            with_runtime(parsers(supervisor, watcher))
        }
        other => {
            eprintln!("unknown mode {other}");
            ExitCode::from(2)
        }
    }
}

async fn replay(id: String, modules: Arc<Modules>) -> ExitCode {
    let (Ok(base), Ok(token), Ok(id)) = (
        std::env::var("ACE4_API_URL"),
        std::env::var("ACE4_ADMIN_TOKEN"),
        id.parse::<i64>(),
    ) else {
        eprintln!("replay needs a task id, ACE4_API_URL and ACE4_ADMIN_TOKEN");
        return ExitCode::from(2);
    };
    let client = match LeaseClient::new(&base, &token, "replay") {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let dir = match tempfile::Builder::new().prefix("ace4-replay-").tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match ace_pool::replay::replay(&client, &modules, id, dir.path()).await {
        Ok(end) => {
            println!("{}", serde_json::to_string(&end).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("replay failed: {e}");
            ExitCode::from(2)
        }
    }
}

async fn parsers(supervisor: Supervisor, watcher: Option<RulesetWatcher>) -> ExitCode {
    let stop = stop_on_signal();
    let watching = match watcher {
        Some(watcher) => {
            if watcher.first(&stop).await.is_none() {
                return ExitCode::SUCCESS;
            }
            let stopping = stop.clone();
            Some(tokio::spawn(async move { watcher.run(stopping).await }))
        }
        None => None,
    };
    let stats = supervisor
        .lease_wait(Duration::from_secs(2))
        .run(stop)
        .await;
    println!("ran {} tasks, {} errors", stats.tasks, stats.errors);
    if let Some(watching) = watching
        && tokio::time::timeout(Duration::from_secs(5), watching)
            .await
            .is_err()
    {
        eprintln!("the ruleset watcher didn't stop within 5 seconds");
    }
    ExitCode::SUCCESS
}

/// A token that fires on SIGTERM or SIGINT.
fn stop_on_signal() -> CancellationToken {
    let stop = CancellationToken::new();
    let stopping = stop.clone();
    tokio::spawn(async move {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(e) => {
                    eprintln!("no SIGTERM handler: {e}");
                    return;
                }
            };
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
        stopping.cancel();
    });
    stop
}

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

async fn once(client: LeaseClient, modules: Arc<Modules>) -> ExitCode {
    match client.lease(&[], Duration::from_secs(10)).await {
        Ok(Some(task)) => {
            let (id, module) = (task.id, task.module.clone());
            match run_in_process(&client, &modules, task, &CancellationToken::new()).await {
                Ok(end) => {
                    println!("task {id} ({module}): {}", outcome_name(&end));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("task {id}: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Ok(None) => ExitCode::from(1),
        Err(e) => {
            eprintln!("leasing failed: {e}");
            ExitCode::from(2)
        }
    }
}

async fn lookups(client: LeaseClient, definition: PoolDefinition) -> ExitCode {
    let stop = stop_on_signal();
    let pool = AsyncPool::new(client, &definition).lease_wait(Duration::from_secs(2));
    let stats = pool.run(stop).await;
    println!("ran {} tasks, {} errors", stats.tasks, stats.errors);
    ExitCode::SUCCESS
}

fn outcome_name(end: &ace_sdk::wire::TaskEnd) -> &'static str {
    use ace_sdk::wire::TaskEnd;
    match end {
        TaskEnd::Done { .. } => "done",
        TaskEnd::Incomplete { .. } => "incomplete",
        TaskEnd::Skipped { .. } => "skipped",
        TaskEnd::Delay { .. } => "delayed",
        TaskEnd::Failed { .. } => "failed",
        TaskEnd::Cancelled => "cancelled",
    }
}
