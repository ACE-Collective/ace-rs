//! A pool of test modules, for ace-pool's tests (feature `test-pools`). It holds only the lease
//! API's URL (`ACE4_API_URL`) and its pool's token (`ACE4_POOL_TOKEN`).
//!
//! ```text
//! test-pool once [--settings JSON]
//!     lease one task, run it in this process, and exit
//! test-pool lookups [--contained] [--concurrency N] [--settings JSON]
//!     run as an async pool until SIGTERM; --contained applies contain_pool first
//! ```
//!
//! `once` exits 0 when it ran a task, 1 when there was none to lease, and 2 on an error.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ace_pool::client::LeaseClient;
use ace_pool::modules::Modules;
use ace_pool::pool::{AsyncPool, POOL_ADDRESS_SPACE, PoolDefinition};
use ace_pool::run::run_in_process;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

struct Args {
    mode: String,
    settings: Value,
    contained: bool,
    concurrency: usize,
}

fn parse() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or("no mode")?;
    let mut parsed = Args {
        mode,
        settings: Value::Object(Default::default()),
        contained: false,
        concurrency: 4,
    };
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--settings" => {
                let text = args.next().ok_or("--settings takes JSON")?;
                parsed.settings = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            }
            "--contained" => parsed.contained = true,
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
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ACE4_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
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
        Ok(modules) => Arc::new(modules),
        Err(e) => {
            eprintln!("setup failed: {e}");
            return ExitCode::from(2);
        }
    };
    let client = match LeaseClient::from_env(&format!("test-pool-{}", std::process::id())) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match args.mode.as_str() {
        "once" => with_runtime(once(client, modules)),
        "lookups" => {
            if args.contained {
                let Some(port) = client.api_port() else {
                    eprintln!("no port in ACE4_API_URL");
                    return ExitCode::from(2);
                };
                let profile = PoolDefinition::lookup_sandbox(&modules, port, POOL_ADDRESS_SPACE);
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
            let definition = PoolDefinition {
                name: "test".to_owned(),
                modules,
                concurrency: args.concurrency,
                sandbox: Default::default(),
                secrets: Vec::new(),
            };
            with_runtime(lookups(client, definition))
        }
        other => {
            eprintln!("unknown mode {other}");
            ExitCode::from(2)
        }
    }
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
            match run_in_process(&client, &modules, task).await {
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
    let pool = AsyncPool::new(client, &definition).lease_wait(Duration::from_secs(2));
    let stats = pool.run(stop).await;
    println!("ran {} tasks, {} errors", stats.tasks, stats.errors);
    ExitCode::SUCCESS
}

fn outcome_name(end: &ace_sdk::wire::TaskEnd) -> &'static str {
    use ace_sdk::wire::TaskEnd;
    match end {
        TaskEnd::Done { .. } => "done",
        TaskEnd::Skipped { .. } => "skipped",
        TaskEnd::Delay { .. } => "delayed",
        TaskEnd::Failed { .. } => "failed",
        TaskEnd::Cancelled => "cancelled",
    }
}
