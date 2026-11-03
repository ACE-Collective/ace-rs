//! A pool of test modules, for ace-pool's tests (feature `test-pools`). It holds only the lease
//! API's URL (`ACE4_API_URL`) and its pool's token (`ACE4_POOL_TOKEN`).
//!
//! ```text
//! test-pool once [--settings JSON]    lease one task, run it in this process, and exit
//! ```
//!
//! `once` exits 0 when it ran a task, 1 when there was none to lease, and 2 on an error.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ace_pool::client::LeaseClient;
use ace_pool::run::run_in_process;
use serde_json::Value;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("ACE4_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let settings = match args.iter().position(|a| a == "--settings") {
        Some(i) => match args.get(i + 1).map(|s| serde_json::from_str::<Value>(s)) {
            Some(Ok(settings)) => settings,
            _ => {
                eprintln!("--settings takes a JSON object");
                return ExitCode::from(2);
            }
        },
        None => Value::Object(Default::default()),
    };
    match args.first().map(String::as_str) {
        Some("once") => once(&settings),
        _ => {
            eprintln!("usage: test-pool once [--settings JSON]");
            ExitCode::from(2)
        }
    }
}

fn once(settings: &Value) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("no runtime: {e}");
            return ExitCode::from(2);
        }
    };
    runtime.block_on(async {
        let modules = match ace_pool::testing::modules(settings) {
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
    })
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
