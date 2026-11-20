//! A pool's definition, and the async pool (PLAN.md 2.16): one process that runs many lookups
//! at once, up to its concurrency limit, which replaces ace3's `network-semaphore` service.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ace_sdk::wire::LeasedTask;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::client::LeaseClient;
use crate::containment::SandboxProfile;

/// The target of the lease's timing events (`ace_core::api::LEASE_TIMING`): a pool logs one a
/// lease request, at debug, with its round trip, the slots it had free and the tasks it got.
pub const LEASE_TIMING: &str = "ace_lease";
use crate::modules::Modules;
use crate::run::run_in_process;

/// What a pool is: the modules it runs, how many tasks it runs at once and what its processes
/// may touch. The secrets it resolves are the ones its modules' manifests declare
/// (`Registry::start`). Its container sets the pool's resource limits.
pub struct PoolDefinition {
    pub name: String,
    pub modules: Arc<Modules>,
    pub concurrency: usize,
    pub sandbox: SandboxProfile,
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

/// The variable that names the bucket's endpoint, as the core's (`ace_store::BucketConfig`), which
/// a network pool reads for its port when one of its modules adds files it fetched.
pub const BUCKET_ENDPOINT_VAR: &str = "ACE4_BUCKET_ENDPOINT";

/// The port a URL's scheme and authority name: its own, or 80 for `http` and 443 for `https`.
pub fn url_port(url: &str) -> Option<u16> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    let host_port = authority.rsplit('@').next()?;
    match host_port.rsplit_once(':') {
        // an IPv6 address without a port is all colons inside its brackets
        Some((host, port)) if !port.contains(']') && !host.is_empty() => port.parse().ok(),
        _ => match scheme {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        },
    }
}

/// The bucket's port, from its endpoint as the core has it (`ACE4_BUCKET_ENDPOINT`): with none,
/// the core signs for AWS S3 over HTTPS, so 443. An endpoint whose port can't be read is refused.
pub fn bucket_port(endpoint: Option<&str>) -> Result<u16, String> {
    match endpoint.map(str::trim).filter(|e| !e.is_empty()) {
        None => Ok(443),
        Some(endpoint) => url_port(endpoint)
            .ok_or_else(|| format!("{BUCKET_ENDPOINT_VAR} names no port: {endpoint:?}")),
    }
}

impl PoolDefinition {
    /// Whether one of `modules` adds files it fetched (`Module::ADDS_FETCHED_FILES`), so its pool
    /// uploads them and needs the bucket's port.
    pub fn adds_fetched_files(modules: &Modules) -> bool {
        modules.manifests().iter().any(|m| m.adds_fetched_files)
    }

    /// The sandbox of an async pool's process: connects to its modules' TCP ports and to the
    /// lease API's, and to the bucket's, the port of `bucket_endpoint` (`bucket_port`), only when
    /// one of its modules adds files it fetched or `collects_files`, the pool hosting a file
    /// collector, which uploads the file it fetched (PLAN.md decision 28); reads the files name
    /// resolution and TLS need, and maps at most `address_space_bytes`. An endpoint whose port
    /// can't be read is refused only when the port is needed. The handlers' own ports are the
    /// caller's to add.
    pub fn lookup_sandbox(
        modules: &Modules,
        collects_files: bool,
        api_port: u16,
        bucket_endpoint: Option<&str>,
        address_space_bytes: u64,
    ) -> Result<SandboxProfile, String> {
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
        if collects_files || Self::adds_fetched_files(modules) {
            profile = profile.allow_port(bucket_port(bucket_endpoint)?);
        }
        if let Some(port) = crate::telemetry::otlp_port() {
            profile = profile.allow_port(port);
        }
        for path in NETWORK_READ_PATHS {
            profile = profile.allow_read_if_exists(Path::new(path));
        }
        // the task directories run_in_process makes
        Ok(profile.allow_write(std::env::temp_dir()))
    }
}

/// How a pool's run went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PoolStats {
    pub tasks: u64,
    pub errors: u64,
    /// Lease requests the core answered with tasks. Fewer than `tasks` when requests brought
    /// several.
    pub leases: u64,
    /// Tasks still running at the shutdown deadline, whose leases were given back.
    pub released_at_deadline: u64,
}

/// How long a pool waits at shutdown for its running tasks to stop, by default.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
/// How long one call that gives a lease back at shutdown may take.
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

/// Runs one leased task to its end, stopping when the token fires.
pub type Runner = Arc<
    dyn Fn(LeasedTask, CancellationToken) -> Pin<Box<dyn Future<Output = bool> + Send>>
        + Send
        + Sync,
>;

/// A pool's lease loop: whenever a slot is free it asks the core for as many tasks as it has free
/// slots, in one request, and starts each that comes back at once, until `stop` fires. One request
/// is in flight at a time.
///
/// A lease is a promise the pool can keep. It takes the free slots before it asks and asks for
/// that many, so every task it is given has a slot and starts when the answer arrives: none waits
/// here behind a task that is running while another replica could run it, and a slow task delays
/// none that came with it, since each runs in its own slot. The pool therefore never holds more
/// leases than `concurrency`, running tasks and a request's answer together, which is also the
/// most a pool that is killed or frozen takes with it; their leases run out and the core's reaper
/// queues them again. Slots it asked for and got no task for are free again for the next request.
/// A request asks for the slots that are free when it is sent, so one that waits while running
/// tasks finish brings no more than it asked for, and the slots freed meanwhile are asked for by
/// the next, one round trip later.
///
/// At `stop` it leases no more, stops the running tasks, which give their leases back, and waits
/// up to `grace` for them (PLAN.md 2.21). A task still running then is abandoned and its lease is
/// given back here, each call bounded, so shutdown ends by `grace` plus the release calls,
/// whatever an upstream does. A request in flight at `stop` is dropped, and the core gives back
/// what it had claimed for it, but for a task whose lease it was deciding just then, which comes
/// back when its lease runs out (`ace_core::api`'s `InHand`).
pub async fn lease_loop(
    client: &LeaseClient,
    concurrency: usize,
    lease_wait: Duration,
    grace: Duration,
    stop: CancellationToken,
    run: Runner,
) -> PoolStats {
    let slots = Arc::new(Semaphore::new(concurrency.max(1)));
    // fires at shutdown; each running task's token is its child
    let tasks = CancellationToken::new();
    let held: Arc<Mutex<BTreeSet<i64>>> = Arc::default();
    let mut running: JoinSet<bool> = JoinSet::new();
    let mut stats = PoolStats::default();
    loop {
        // a slot first, and every other that is free now, so each leased task has somewhere to run
        let first = tokio::select! {
            biased;
            () = stop.cancelled() => break,
            slot = slots.clone().acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_) => break,
            },
        };
        let mut free = vec![first];
        while let Ok(slot) = slots.clone().try_acquire_owned() {
            free.push(slot);
        }
        while let Some(finished) = running.try_join_next() {
            count(&mut stats, finished);
        }
        let asked = std::time::Instant::now();
        let leased = tokio::select! {
            biased;
            () = stop.cancelled() => break,
            leased = client.lease_up_to(&[], lease_wait, free.len()) => leased,
        };
        tracing::debug!(
            target: LEASE_TIMING,
            free = free.len(),
            tasks = leased.as_ref().map_or(0, Vec::len),
            round_trip_us = u64::try_from(asked.elapsed().as_micros()).unwrap_or(u64::MAX),
            "a lease request"
        );
        match leased {
            Ok(leased) => {
                if !leased.is_empty() {
                    stats.leases += 1;
                }
                for task in leased {
                    let id = task.id;
                    let Some(slot) = free.pop() else {
                        // more than was asked for: there is nowhere to run it, so it goes back
                        tracing::error!(task = id, "the core leased a task no slot was free for");
                        stats.errors += 1;
                        if let Err(e) = client.release(id).await {
                            tracing::warn!(task = id, "giving the task back failed: {e}");
                        }
                        continue;
                    };
                    lock(&held).insert(id);
                    // every span of the task's run in this process is a child of this one
                    let span = tracing::info_span!(
                        "pool.task",
                        task = id,
                        module = %task.module,
                        root = %task.root,
                    );
                    let (run, token, held) = (run.clone(), tasks.child_token(), held.clone());
                    running.spawn(
                        async move {
                            let _slot = slot;
                            let ended = run(task, token).await;
                            lock(&held).remove(&id);
                            ended
                        }
                        .instrument(span),
                    );
                }
            }
            Err(e) => {
                tracing::warn!("leasing failed: {e}");
                stats.errors += 1;
                // the slots are free while it waits, though nothing takes them but this loop
                drop(free);
                tokio::select! {
                    () = stop.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
    }

    tasks.cancel();
    let deadline = tokio::time::Instant::now() + grace;
    loop {
        match tokio::time::timeout_at(deadline, running.join_next()).await {
            Ok(Some(finished)) => count(&mut stats, finished),
            Ok(None) => break,
            Err(_) => {
                tracing::warn!(
                    tasks = running.len(),
                    "tasks still running at the shutdown deadline; abandoning them"
                );
                running.abort_all();
                break;
            }
        }
    }
    let abandoned: Vec<i64> = lock(&held).iter().copied().collect();
    for id in abandoned {
        stats.released_at_deadline += 1;
        match tokio::time::timeout(RELEASE_TIMEOUT, client.release(id)).await {
            Ok(Ok(())) => tracing::info!(task = id, "gave the task back"),
            Ok(Err(e)) => tracing::warn!(task = id, "giving the task back failed: {e}"),
            Err(_) => tracing::warn!(task = id, "giving the task back timed out"),
        }
    }
    stats
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn count(stats: &mut PoolStats, finished: Result<bool, tokio::task::JoinError>) {
    stats.tasks += 1;
    if !matches!(finished, Ok(true)) {
        stats.errors += 1;
    }
}

/// An async pool: leases tasks for its lookups and runs up to `concurrency` of them at once on
/// one runtime. A panic in one task fails that task; the process keeps serving.
pub struct AsyncPool {
    client: LeaseClient,
    modules: Arc<Modules>,
    concurrency: usize,
    /// How long one lease request waits for a task.
    lease_wait: Duration,
    grace: Duration,
}

impl AsyncPool {
    pub fn new(client: LeaseClient, definition: &PoolDefinition) -> AsyncPool {
        AsyncPool {
            client,
            modules: definition.modules.clone(),
            concurrency: definition.concurrency.max(1),
            lease_wait: Duration::from_secs(10),
            grace: SHUTDOWN_GRACE,
        }
    }

    pub fn lease_wait(mut self, wait: Duration) -> Self {
        self.lease_wait = wait;
        self
    }

    /// How long shutdown waits for running tasks before it gives their leases back.
    pub fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Leases and runs tasks until `stop` fires, then shuts down as `lease_loop` does.
    pub async fn run(&self, stop: CancellationToken) -> PoolStats {
        let (client, modules) = (self.client.clone(), self.modules.clone());
        let run: Runner = Arc::new(move |task, shutdown| {
            let (client, modules) = (client.clone(), modules.clone());
            Box::pin(async move {
                let (id, module) = (task.id, task.module.clone());
                match run_in_process(&client, &modules, task, &shutdown).await {
                    Ok(_) => true,
                    Err(e) => {
                        tracing::error!(task = id, %module, "the task's end wasn't sent: {e}");
                        false
                    }
                }
            })
        });
        lease_loop(
            &self.client,
            self.concurrency,
            self.lease_wait,
            self.grace,
            stop,
            run,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_s_port_is_its_own_or_its_scheme_s() {
        assert_eq!(url_port("http://bucket:8333"), Some(8333));
        assert_eq!(url_port("http://bucket:8333/path"), Some(8333));
        assert_eq!(url_port("https://s3.us-east-1.amazonaws.com"), Some(443));
        assert_eq!(url_port("http://ace"), Some(80));
        assert_eq!(url_port("http://user:secret@bucket:9000"), Some(9000));
        assert_eq!(url_port("http://[::1]:8333"), Some(8333));
        assert_eq!(url_port("http://[::1]"), Some(80));
        assert_eq!(url_port("bucket:8333"), None);
        assert_eq!(url_port("ftp://bucket"), None);
    }

    /// With no endpoint the core signs for AWS S3 over HTTPS; one with no readable port is refused.
    #[test]
    fn the_bucket_s_port_comes_from_its_endpoint() {
        assert_eq!(bucket_port(None), Ok(443));
        assert_eq!(bucket_port(Some("")), Ok(443));
        assert_eq!(bucket_port(Some("http://bucket:8333")), Ok(8333));
        let refused = bucket_port(Some("bucket")).expect_err("no port");
        assert!(refused.contains(BUCKET_ENDPOINT_VAR), "{refused}");
    }

    /// PLAN.md decision 28: a pool's sandbox allows the bucket's port only when one of its modules
    /// adds files it fetched or it hosts a file collector, and reads the endpoint only then.
    #[cfg(feature = "test-pools")]
    #[test]
    fn the_bucket_s_port_is_allowed_only_for_a_module_that_adds_fetched_files() {
        use serde_json::json;
        let without = crate::testing::modules(&json!({})).expect("the test modules");
        let with =
            crate::testing::modules(&json!({"test_fetches": null})).expect("the test modules");
        assert!(!PoolDefinition::adds_fetched_files(&without));
        assert!(PoolDefinition::adds_fetched_files(&with));
        let endpoint = Some("http://bucket:8333");
        let profile =
            PoolDefinition::lookup_sandbox(&without, false, 8080, endpoint, POOL_ADDRESS_SPACE)
                .expect("a profile");
        assert!(profile.tcp_ports.contains(&8080));
        assert!(!profile.tcp_ports.contains(&8333));
        // a pool hosting a file collector uploads what it fetched
        let profile =
            PoolDefinition::lookup_sandbox(&without, true, 8080, endpoint, POOL_ADDRESS_SPACE)
                .expect("a profile");
        assert!(profile.tcp_ports.contains(&8333));
        let profile =
            PoolDefinition::lookup_sandbox(&with, false, 8080, endpoint, POOL_ADDRESS_SPACE)
                .expect("a profile");
        assert!(profile.tcp_ports.contains(&8333));
        // an endpoint whose port can't be read fails only the pool that needs it
        assert!(
            PoolDefinition::lookup_sandbox(
                &without,
                false,
                8080,
                Some("bucket"),
                POOL_ADDRESS_SPACE
            )
            .is_ok()
        );
        assert!(
            PoolDefinition::lookup_sandbox(&with, false, 8080, Some("bucket"), POOL_ADDRESS_SPACE)
                .is_err()
        );
    }
}
