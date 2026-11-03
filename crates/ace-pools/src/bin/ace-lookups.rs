//! The network pool: the RDAP and Splunk modules, many lookups at once as async tasks in one
//! process (PLAN.md 2.16), contained before its runtime starts a thread: it may connect only to
//! its modules' TCP ports, the lease API's and the collector's.
//!
//! It reads `ACE4_API_URL`, `ACE4_POOL_TOKEN`, `ACE4_OVERLAY`, the variables and files the
//! overlay's `secrets:` names for its modules' secrets, `ACE4_CONCURRENCY` (16) and
//! `ACE4_HEALTH_FILE`, and runs until SIGTERM.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ace_pool::client::LeaseClient;
use ace_pool::pool::{AsyncPool, POOL_ADDRESS_SPACE, PoolDefinition};
use ace_pools::{health_file, heartbeat, number, overlay, overlay_path, worker_name};

const POOL: &str = "lookups";

fn main() -> ExitCode {
    let mut telemetry = ace_pool::telemetry::init("ace4-lookups", "info");
    // the modules, their secrets and the client before any thread starts, so containment can
    // follow
    let modules = match overlay(overlay_path().as_deref()).and_then(|overlay| {
        ace_pools::modules(
            POOL,
            &ace_pools::lookup_registry(),
            &overlay,
            None,
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
    let profile = PoolDefinition::lookup_sandbox(&modules, port, POOL_ADDRESS_SPACE);
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
        name: POOL.to_owned(),
        modules,
        concurrency: number("ACE4_CONCURRENCY", 16),
        sandbox: profile,
    };
    ace_pools::with_runtime(async move {
        let stop = ace_pools::stop_on_signal();
        let beating = tokio::spawn(heartbeat(health_file(), stop.clone()));
        let stats = AsyncPool::new(client, &definition).run(stop).await;
        tracing::info!(tasks = stats.tasks, errors = stats.errors, "stopped");
        if tokio::time::timeout(Duration::from_secs(5), beating)
            .await
            .is_err()
        {
            tracing::warn!("the heartbeat didn't stop within 5 seconds");
        }
        ExitCode::SUCCESS
    })
}
