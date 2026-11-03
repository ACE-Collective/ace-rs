//! A pool's definition, and the async pool (PLAN.md 2.16): one process that runs many lookups
//! at once, up to its concurrency limit, which replaces ace3's `network-semaphore` service.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::client::LeaseClient;
use crate::containment::SandboxProfile;
use crate::modules::Modules;
use crate::run::run_in_process;

/// What a pool is: the modules it runs, how many tasks it runs at once, what its processes may
/// touch, and the secrets it resolves. Its container sets the pool's resource limits.
pub struct PoolDefinition {
    pub name: String,
    pub modules: Arc<Modules>,
    pub concurrency: usize,
    pub sandbox: SandboxProfile,
    pub secrets: Vec<String>,
}

/// Files a pool process reads to resolve names and verify certificates, where they exist.
const NETWORK_READ_PATHS: &[&str] = &[
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/usr/share/ca-certificates",
];

/// The address space an async pool's process may map by default. Every tokio thread reserves a
/// stack and glibc reserves an arena per thread, so this counts far more than the heap.
pub const POOL_ADDRESS_SPACE: u64 = 4 << 30;

impl PoolDefinition {
    /// The sandbox of an async pool's process: connects to its modules' TCP ports and to the
    /// lease API's, reads the files name resolution and TLS need, and maps at most
    /// `address_space_bytes`.
    pub fn lookup_sandbox(
        modules: &Modules,
        api_port: u16,
        address_space_bytes: u64,
    ) -> SandboxProfile {
        let mut profile = SandboxProfile {
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            tcp_ports: Vec::new(),
            address_space_bytes,
            cpu_seconds: 0,
        };
        for manifest in modules.manifests() {
            if let ace_sdk::Sandbox::Network { tcp_ports } = manifest.sandbox {
                for &port in tcp_ports {
                    profile = profile.allow_port(port);
                }
            }
        }
        profile = profile.allow_port(api_port);
        for path in NETWORK_READ_PATHS {
            profile = profile.allow_read_if_exists(Path::new(path));
        }
        // the task directories run_in_process makes
        profile.allow_write(std::env::temp_dir())
    }
}

/// How an async pool's run went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolStats {
    pub tasks: u64,
    pub errors: u64,
}

/// An async pool: leases tasks for its lookups and runs up to `concurrency` of them at once on
/// one runtime. A panic in one task fails that task; the process keeps serving.
pub struct AsyncPool {
    client: LeaseClient,
    modules: Arc<Modules>,
    concurrency: usize,
    /// How long one lease request waits for a task.
    lease_wait: Duration,
}

impl AsyncPool {
    pub fn new(client: LeaseClient, definition: &PoolDefinition) -> AsyncPool {
        AsyncPool {
            client,
            modules: definition.modules.clone(),
            concurrency: definition.concurrency.max(1),
            lease_wait: Duration::from_secs(10),
        }
    }

    pub fn lease_wait(mut self, wait: Duration) -> Self {
        self.lease_wait = wait;
        self
    }

    /// Leases and runs tasks until `stop` fires, then waits for the running ones to end.
    pub async fn run(&self, stop: CancellationToken) -> PoolStats {
        let slots = Arc::new(Semaphore::new(self.concurrency));
        let mut running: JoinSet<bool> = JoinSet::new();
        let mut stats = PoolStats::default();
        loop {
            // a slot first, so a leased task always has somewhere to run
            let slot = tokio::select! {
                biased;
                () = stop.cancelled() => break,
                slot = slots.clone().acquire_owned() => match slot {
                    Ok(slot) => slot,
                    Err(_) => break,
                },
            };
            while let Some(finished) = running.try_join_next() {
                count(&mut stats, finished);
            }
            let leased = tokio::select! {
                biased;
                () = stop.cancelled() => break,
                leased = self.client.lease(&[], self.lease_wait) => leased,
            };
            match leased {
                Ok(Some(task)) => {
                    let (client, modules) = (self.client.clone(), self.modules.clone());
                    running.spawn(async move {
                        let _slot = slot;
                        let (id, module) = (task.id, task.module.clone());
                        match run_in_process(&client, &modules, task).await {
                            Ok(_) => true,
                            Err(e) => {
                                tracing::error!(task = id, %module, "the task's end wasn't sent: {e}");
                                false
                            }
                        }
                    });
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("leasing failed: {e}");
                    stats.errors += 1;
                    tokio::select! {
                        () = stop.cancelled() => break,
                        () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            }
        }
        while let Some(finished) = running.join_next().await {
            count(&mut stats, finished);
        }
        stats
    }
}

fn count(stats: &mut PoolStats, finished: Result<bool, tokio::task::JoinError>) {
    stats.tasks += 1;
    if !matches!(finished, Ok(true)) {
        stats.errors += 1;
    }
}
