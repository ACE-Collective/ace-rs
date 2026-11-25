//! The scanner pool (PLAN.md 7.7): the one process that holds the host's Docker socket, which runs
//! ace3's phishkit and js-deobfuscator scanner images for the scans modules ask for
//! (`ace_sdk::scanners`), and replaces their Celery managers, RabbitMQ and Redis (#1100).
//!
//! Whoever holds the socket has root on the host, so this process parses nothing a scanner wrote,
//! and nothing from a hostile file. It leases a scan, downloads the scan's inputs from the bucket,
//! packs them into a tar under names the core checked (`ScanRequest::refusal`), creates the scanner's
//! container with its spec's image, command, network and limits, copies the tar in and starts it. It
//! waits for the container to exit, renewing the scan's lease meanwhile, and stops it at the deadline
//! (SIGTERM, then SIGKILL after the spec's grace), or kills it when the renewal says the root was
//! cancelled. Then it copies out Docker's tar of the output directory and the container's two log
//! streams, each into a file up to the spec's limit without reading it, packs the three into one tar
//! (`ace_sdk::scanners::OUTPUT_ARCHIVE`, `STDOUT`, `STDERR`), uploads it, ends the scan with the exit
//! code Docker gave, and removes the container. The JSON it reads is Docker's and the core's. The
//! module's next run, a contained parser, is the first to open the archive.
//!
//! Containers carry labels: the stack (`ACE_RS_STACK`), this pool's host, the scanner, the scan and
//! the deadline. ace3's managers reap only containers labelled `phishkit.stack=<theirs>`, and this
//! pool only ones labelled `ace-rs.scanner.stack=<ours>`, so neither touches the other's, nor another
//! ace-rs stack's. When the pool starts it removes every container its host left, which a crash of the
//! pool leaves running; and every `SWEEP` it removes any of its stack's whose deadline passed more
//! than `SWEEP_GRACE` ago, which a pool whose container was recreated, with a new host name, leaves.
//! The core ends the scans such a pool held as abandoned when their leases expire (`ace_core::scans`).

pub mod docker;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ace_sdk::scanners::{
    LeasedScan, OUTPUT_ARCHIVE, STDERR, STDOUT, ScanEnd, ScanOutcome, ScanOutputRecord,
    ScannerNetwork, ScannerSpec,
};
use serde_json::json;
use sha2::Digest;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::client::{ClientError, LeaseClient};
use docker::{Docker, DockerError};

/// The labels a scan's container carries.
pub const LABEL_STACK: &str = "ace-rs.scanner.stack";
pub const LABEL_HOST: &str = "ace-rs.scanner.host";
pub const LABEL_SCANNER: &str = "ace-rs.scanner.name";
pub const LABEL_SCAN: &str = "ace-rs.scanner.scan";
/// When the scan's deadline is, in seconds since the epoch.
pub const LABEL_DEADLINE: &str = "ace-rs.scanner.deadline";

/// How often the pool looks for its stack's containers left past their deadline.
pub const SWEEP: Duration = Duration::from_secs(60);
/// How long past its deadline, and its stop's grace, a container may be before a sweep removes it.
pub const SWEEP_GRACE: Duration = Duration::from_secs(120);
/// The most a scan's inputs may hold, together.
pub const MAX_INPUT_BYTES: u64 = 256 << 20;
/// How long a lease request waits for a scan.
const LEASE_WAIT: Duration = Duration::from_secs(20);
/// How long the pool waits before leasing again after the API failed.
const BACKOFF: Duration = Duration::from_secs(5);

/// What a scanner pool runs and as whom.
#[derive(Debug, Clone)]
pub struct ScannerPoolConfig {
    /// The Compose stack, `ACE_RS_STACK`, which every container's labels and name carry.
    pub stack: String,
    /// This pool's host, which its containers' labels carry, so that it can tell its own.
    pub host: String,
    pub specs: Vec<ScannerSpec>,
    /// Docker's socket.
    pub socket: PathBuf,
    pub concurrency: usize,
    /// Each spec's image and network, by spec, after the environment's say.
    pub images: Vec<(String, String)>,
    pub networks: Vec<(String, String)>,
    /// Each spec's proxy URL, credentials and all, for the specs that take one and whose variable
    /// is set (`ScannerSpec::proxy`). It goes to the scanner as its argument and nowhere else.
    pub proxies: Vec<(String, String)>,
}

impl ScannerPoolConfig {
    /// The pool for `specs` in stack `stack` on host `host`, with each spec's image and network
    /// from the variable it names, if set.
    pub fn new(
        stack: &str,
        host: &str,
        specs: &[ScannerSpec],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Self {
        let images = specs
            .iter()
            .map(|s| {
                let image = env(s.image_variable)
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| s.image.to_owned());
                (s.name.to_owned(), image)
            })
            .collect();
        let networks = specs
            .iter()
            .map(|s| {
                let network = match s.network {
                    ScannerNetwork::None => "none".to_owned(),
                    ScannerNetwork::Default { variable } => env(variable)
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| "bridge".to_owned()),
                };
                (s.name.to_owned(), network)
            })
            .collect();
        let proxies = specs
            .iter()
            .filter_map(|s| {
                let url = env(s.proxy?.variable).filter(|v| !v.trim().is_empty())?;
                Some((s.name.to_owned(), url.trim().to_owned()))
            })
            .collect();
        ScannerPoolConfig {
            stack: stack.to_owned(),
            host: host.to_owned(),
            specs: specs.to_vec(),
            socket: PathBuf::from("/var/run/docker.sock"),
            concurrency: 4,
            images,
            networks,
            proxies,
        }
    }

    /// The proxy a scan of `spec` goes through when it asks for one: its argument and URL.
    fn proxy(&self, spec: &ScannerSpec) -> Option<(&'static str, &str)> {
        let arg = spec.proxy?.arg;
        self.proxies
            .iter()
            .find(|(name, _)| name == spec.name)
            .map(|(_, url)| (arg, url.as_str()))
    }

    /// The proxy a scan goes through, without credentials, or None for direct.
    fn proxied(&self, spec: &ScannerSpec, scan: &LeasedScan) -> Option<String> {
        scan.proxy
            .then(|| self.proxy(spec))
            .flatten()
            .map(|(_, url)| ace_sdk::scanners::proxy_for_display(url))
    }

    fn spec(&self, name: &str) -> Option<&ScannerSpec> {
        ace_sdk::scanners::find(&self.specs, name)
    }

    fn image(&self, name: &str) -> &str {
        lookup(&self.images, name)
    }

    fn network(&self, name: &str) -> &str {
        lookup(&self.networks, name)
    }

    /// The labels that select this stack's containers, and this host's.
    fn stack_label(&self) -> String {
        format!("{LABEL_STACK}={}", self.stack)
    }

    fn host_label(&self) -> String {
        format!("{LABEL_HOST}={}", self.host)
    }
}

fn lookup<'a>(pairs: &'a [(String, String)], name: &str) -> &'a str {
    pairs
        .iter()
        .find(|(n, _)| n == name)
        .map_or("", |(_, v)| v.as_str())
}

/// What a pool's run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScannerStats {
    pub scans: u64,
    pub errors: u64,
}

/// A scanner pool: its lease client, Docker and its config.
pub struct ScannerPool {
    client: LeaseClient,
    docker: Docker,
    config: Arc<ScannerPoolConfig>,
}

impl ScannerPool {
    pub fn new(client: LeaseClient, config: ScannerPoolConfig) -> Self {
        ScannerPool {
            client,
            docker: Docker::new(&config.socket),
            config: Arc::new(config),
        }
    }

    /// Removes every container this host left (`reap_own`).
    pub async fn reap_own(&self) -> Result<usize, DockerError> {
        reap_own(&self.docker, &self.config).await
    }

    /// Removes this stack's containers past their deadline (`sweep`).
    pub async fn sweep(&self) -> Result<usize, DockerError> {
        sweep(&self.docker, &self.config).await
    }

    /// Leases and runs scans, `concurrency` at once, until `stop` fires. Each scan that's running
    /// then is killed and ended as failed, and its container removed.
    pub async fn run(self, stop: CancellationToken) -> ScannerStats {
        let mut stats = ScannerStats::default();
        match self.reap_own().await {
            Ok(0) => {}
            Ok(n) => tracing::warn!(removed = n, "removed scanner containers left by a crash"),
            Err(e) => tracing::error!("couldn't look for containers a crash left: {e}"),
        }
        for spec in &self.config.specs {
            let image = self.config.image(spec.name);
            match self.docker.image_id(image).await {
                Ok(Some(id)) => tracing::info!(scanner = spec.name, image, id, "scanner image"),
                Ok(None) => tracing::error!(
                    scanner = spec.name,
                    image,
                    "the daemon doesn't have the scanner's image; its scans will fail"
                ),
                Err(e) => tracing::error!(scanner = spec.name, "inspecting the image: {e}"),
            }
        }
        let sweeper = {
            let (docker, config, stop) = (self.docker.clone(), self.config.clone(), stop.clone());
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = stop.cancelled() => return,
                        () = tokio::time::sleep(SWEEP) => {}
                    }
                    if let Err(e) = sweep(&docker, &config).await {
                        tracing::warn!("the sweep failed: {e}");
                    }
                }
            })
        };
        let slots = Arc::new(Semaphore::new(self.config.concurrency.max(1)));
        let mut running = JoinSet::new();
        loop {
            let permit = tokio::select! {
                () = stop.cancelled() => break,
                permit = slots.clone().acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
            };
            let leased = tokio::select! {
                () = stop.cancelled() => break,
                leased = self.client.lease_scan(LEASE_WAIT) => leased,
            };
            while let Some(done) = running.try_join_next() {
                count(&mut stats, done);
            }
            match leased {
                Ok(Some(scan)) => {
                    let (client, docker, config, stop) = (
                        self.client.clone(),
                        self.docker.clone(),
                        self.config.clone(),
                        stop.clone(),
                    );
                    let span = tracing::info_span!("scan", scan = scan.id, scanner = %scan.scanner);
                    running.spawn(
                        async move {
                            let ended = run_scan(&client, &docker, &config, scan, &stop).await;
                            drop(permit);
                            ended
                        }
                        .instrument(span),
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("leasing a scan failed: {e}");
                    tokio::select! {
                        () = stop.cancelled() => break,
                        () = tokio::time::sleep(BACKOFF) => {}
                    }
                }
            }
        }
        while let Some(done) = running.join_next().await {
            count(&mut stats, done);
        }
        sweeper.abort();
        stats
    }
}

/// Removes every container `config`'s host left in its stack, as a crash of the pool leaves them:
/// none of this host's scans can be running, since the pool has only just started.
pub async fn reap_own(docker: &Docker, config: &ScannerPoolConfig) -> Result<usize, DockerError> {
    let labels = [config.stack_label(), config.host_label()];
    let left = docker.list(&labels).await?;
    for container in &left {
        tracing::warn!(
            container = %container.id,
            scan = container.labels.get(LABEL_SCAN).map(String::as_str),
            "removing a scanner container this pool left when it stopped"
        );
        docker.remove(&container.id).await?;
    }
    Ok(left.len())
}

/// Removes the stack's containers whose deadline passed more than `SWEEP_GRACE` and their stop's
/// grace ago, whichever pool started them.
pub async fn sweep(docker: &Docker, config: &ScannerPoolConfig) -> Result<usize, DockerError> {
    let now = epoch_seconds(SystemTime::now());
    let mut removed = 0;
    for container in docker.list(&[config.stack_label()]).await? {
        let deadline = container
            .labels
            .get(LABEL_DEADLINE)
            .and_then(|d| d.parse::<u64>().ok());
        let grace = container
            .labels
            .get(LABEL_SCANNER)
            .and_then(|s| config.spec(s))
            .map_or(Duration::ZERO, |s| s.stop_grace);
        // a container with no deadline label carries the stack's label but isn't a scan's
        let Some(deadline) = deadline else { continue };
        if now > deadline + SWEEP_GRACE.as_secs() + grace.as_secs() {
            tracing::warn!(container = %container.id, "removing a scanner container past its deadline");
            docker.remove(&container.id).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn count(stats: &mut ScannerStats, done: Result<Result<(), ClientError>, tokio::task::JoinError>) {
    stats.scans += 1;
    match done {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            stats.errors += 1;
            tracing::error!("ending a scan failed: {e}");
        }
        Err(e) => {
            stats.errors += 1;
            tracing::error!("a scan panicked: {e}");
        }
    }
}

fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Why a scan's container stopped running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stopped {
    Exited(i64),
    Deadline(Option<i64>),
    Cancelled,
    /// The pool is stopping.
    Shutdown,
}

/// Renews the scan's lease every third of its length until dropped. Its token fires when the
/// renewal says the root was cancelled, or the lease is lost.
struct ScanLease {
    handle: tokio::task::JoinHandle<()>,
    token: CancellationToken,
}

impl ScanLease {
    fn start(client: &LeaseClient, scan: &LeasedScan) -> ScanLease {
        let token = CancellationToken::new();
        let (client, fired, id) = (client.clone(), token.clone(), scan.id);
        let every = Duration::from_secs_f64((scan.lease_seconds / 3.0).max(0.1));
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                match client.renew_scan(id).await {
                    Ok(renewal) if renewal.cancel_requested => {
                        tracing::info!(scan = id, "the scan was cancelled");
                        fired.cancel();
                        return;
                    }
                    Ok(_) => {}
                    Err(ClientError::LeaseLost(_)) => {
                        tracing::warn!(scan = id, "lost the scan's lease");
                        fired.cancel();
                        return;
                    }
                    Err(e) => tracing::warn!(scan = id, "renewal failed: {e}"),
                }
            }
        });
        ScanLease { handle, token }
    }
}

impl Drop for ScanLease {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Runs one leased scan and ends it, removing its container whatever happens.
async fn run_scan(
    client: &LeaseClient,
    docker: &Docker,
    config: &ScannerPoolConfig,
    scan: LeasedScan,
    stop: &CancellationToken,
) -> Result<(), ClientError> {
    let lease = ScanLease::start(client, &scan);
    let Some(spec) = config.spec(&scan.scanner).copied() else {
        let end = failed(format!("this pool has no scanner {:?}", scan.scanner));
        return client.end_scan(scan.id, &end).await;
    };
    let work = tempfile::Builder::new().prefix("ace-rs-scan-").tempdir()?;
    let mut container: Option<String> = None;
    let ended = run_container(
        client,
        docker,
        config,
        &spec,
        &scan,
        work.path(),
        &lease.token,
        stop,
        &mut container,
    )
    .await;
    if let Some(id) = &container
        && let Err(e) = docker.remove(id).await
    {
        tracing::error!(container = %id, "removing the scan's container failed: {e}");
    }
    let end = match ended {
        Ok(end) => end,
        Err(e) => failed(e),
    };
    if let ScanOutcome::Failed { error } = &end.outcome {
        tracing::warn!(scan = scan.id, "the scan failed: {error}");
    }
    drop(lease);
    match client.end_scan(scan.id, &end).await {
        // its lease ran out, or its root was cancelled and the reaper ended it; nothing waits now
        Err(ClientError::LeaseLost(_)) => {
            tracing::warn!(scan = scan.id, "the scan's lease was lost before its end");
            Ok(())
        }
        other => other,
    }
}

fn failed(error: impl std::fmt::Display) -> ScanEnd {
    ScanEnd {
        outcome: ScanOutcome::Failed {
            error: error.to_string(),
        },
        output: None,
        image_id: None,
        // a scan that failed before its container ran went nowhere
        proxied: None,
    }
}

/// Why a scan couldn't run or come back.
#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error(transparent)]
    Docker(#[from] DockerError),
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Refused(String),
}

/// Creates, fills, starts and waits for the scan's container, and brings back its output. The
/// container's id goes in `container` as soon as there is one, for the caller to remove.
#[allow(clippy::too_many_arguments)]
async fn run_container(
    client: &LeaseClient,
    docker: &Docker,
    config: &ScannerPoolConfig,
    spec: &ScannerSpec,
    scan: &LeasedScan,
    work: &Path,
    cancelled: &CancellationToken,
    stop: &CancellationToken,
    container: &mut Option<String>,
) -> Result<ScanEnd, RunError> {
    let total: u64 = scan.inputs.iter().map(|i| i.size).sum();
    if total > MAX_INPUT_BYTES {
        return Err(RunError::Refused(format!(
            "its inputs hold {total} bytes, past {MAX_INPUT_BYTES}"
        )));
    }
    let inputs = work.join("inputs");
    std::fs::create_dir(&inputs)?;
    let mut fetched = Vec::new();
    for (i, input) in scan.inputs.iter().enumerate() {
        let path = inputs.join(i.to_string());
        client.download(&input.download, &path).await?;
        fetched.push((input.name.as_str(), path));
    }
    let archive = input_archive(spec, &fetched)?;

    let deadline_at = SystemTime::now() + Duration::from_secs_f64(scan.deadline_seconds.max(0.0));
    let body = create_body(config, spec, scan, epoch_seconds(deadline_at));
    let name = format!(
        "{}-scan-{}-{:08x}",
        config.stack,
        scan.id,
        rand_suffix(scan.id)
    );
    let id = docker.create(&name, &body).await?;
    *container = Some(id.clone());
    // what the analysis cache keys a scanning module's result on (`ace_sdk::cache::Cache::scanners`)
    let image_id = docker.container_image(&id).await?;
    docker.put_archive(&id, archive).await?;
    docker.start(&id).await?;
    tracing::info!(container = %id, "started the scanner");

    let until_deadline = Duration::from_secs_f64(scan.deadline_seconds.max(0.0));
    let stopped = tokio::select! {
        waited = docker.wait(&id) => Stopped::Exited(waited?),
        () = tokio::time::sleep(until_deadline) => {
            tracing::warn!(container = %id, "the scan reached its deadline; stopping it");
            docker.stop(&id, spec.stop_grace).await?;
            let waited = tokio::time::timeout(spec.stop_grace + Duration::from_secs(30), docker.wait(&id)).await;
            Stopped::Deadline(match waited {
                Ok(Ok(code)) => Some(code),
                _ => None,
            })
        }
        () = cancelled.cancelled() => Stopped::Cancelled,
        () = stop.cancelled() => Stopped::Shutdown,
    };
    let exit_code = |code: i64| i32::try_from(code).unwrap_or(i32::MIN);
    let outcome = match stopped {
        Stopped::Cancelled => {
            docker.kill(&id).await?;
            return Ok(ScanEnd {
                outcome: ScanOutcome::Cancelled,
                output: None,
                image_id,
                proxied: config.proxied(spec, scan),
            });
        }
        Stopped::Shutdown => {
            docker.kill(&id).await?;
            return Err(RunError::Refused(
                "the scanner pool stopped while it ran".to_owned(),
            ));
        }
        Stopped::Exited(code) => ScanOutcome::Completed {
            exit_code: exit_code(code),
        },
        Stopped::Deadline(code) => ScanOutcome::TimedOut {
            exit_code: code.map(exit_code),
        },
    };

    // what it wrote, unread: Docker's tar of its output directory and its two log streams
    let limit = spec.max_output_bytes;
    let output = work.join(OUTPUT_ARCHIVE);
    let stdout = work.join(STDOUT);
    let stderr = work.join(STDERR);
    let mut used = docker
        .get_archive(&id, spec.output_dir, &output, limit)
        .await?;
    used += docker
        .logs(&id, "stdout", &stdout, limit.saturating_sub(used))
        .await?;
    used += docker
        .logs(&id, "stderr", &stderr, limit.saturating_sub(used))
        .await?;
    tracing::info!(bytes = used, "copied the scan's output out");
    let packed = work.join("scan.tar");
    let record = pack(
        &packed,
        &[
            (OUTPUT_ARCHIVE, &output),
            (STDOUT, &stdout),
            (STDERR, &stderr),
        ],
    )?;
    let url = client
        .scan_upload_url(scan.id, &record.sha256, record.size)
        .await?;
    client.upload(&url, &packed).await?;
    Ok(ScanEnd {
        outcome,
        output: Some(record),
        image_id,
        proxied: config.proxied(spec, scan),
    })
}

/// A number for the container's name that two pools of one stack won't both pick for one scan.
fn rand_suffix(scan: i64) -> u32 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    nanos ^ (std::process::id() << 8) ^ (scan as u32)
}

/// The container's definition: the spec's image, command and limits, the request's arguments, and
/// the labels a reaper selects by. Nothing in it comes from a file: the arguments are the module's,
/// which the core checked, and go to the scanner as argv, not through a shell.
fn create_body(
    config: &ScannerPoolConfig,
    spec: &ScannerSpec,
    scan: &LeasedScan,
    deadline: u64,
) -> serde_json::Value {
    let mut cmd: Vec<&str> = spec.command.to_vec();
    cmd.extend(scan.args.iter().map(String::as_str));
    // the pool's proxy, which the request asked for and the core never saw: ace3's manager adds
    // `--proxy` the same way
    if scan.proxy
        && let Some((arg, url)) = config.proxy(spec)
    {
        cmd.extend([arg, url]);
    }
    let mut host = json!({
        "NetworkMode": config.network(spec.name),
        "Init": spec.init,
        // the logs come back through the API, so they're kept, bounded, until the container goes
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "64m", "max-file": "1"}},
    });
    if let Some(memory) = spec.memory_bytes {
        host["Memory"] = json!(memory);
        host["MemorySwap"] = json!(memory);
    }
    if let Some(nano_cpus) = spec.nano_cpus {
        host["NanoCpus"] = json!(nano_cpus);
    }
    json!({
        "Image": config.image(spec.name),
        "Cmd": cmd,
        "Labels": {
            LABEL_STACK: config.stack,
            LABEL_HOST: config.host,
            LABEL_SCANNER: spec.name,
            LABEL_SCAN: scan.id.to_string(),
            LABEL_DEADLINE: deadline.to_string(),
        },
        "StopTimeout": spec.stop_grace.as_secs(),
        "AttachStdin": false,
        "AttachStdout": false,
        "AttachStderr": false,
        "Tty": false,
        "HostConfig": host,
    })
}

/// The tar copied in at `/`: the spec's input and output directories, each input under the input
/// directory at its checked name, and the output directory empty and writable by any user.
fn input_archive(spec: &ScannerSpec, inputs: &[(&str, PathBuf)]) -> Result<Vec<u8>, RunError> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut dirs: Vec<String> = Vec::new();
    let mut add_dir =
        |builder: &mut tar::Builder<Vec<u8>>, dir: &str, mode: u32| -> std::io::Result<()> {
            let mut path = String::new();
            for part in dir.trim_matches('/').split('/') {
                if !path.is_empty() {
                    path.push('/');
                }
                path.push_str(part);
                if dirs.contains(&path) {
                    continue;
                }
                dirs.push(path.clone());
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(mode);
                header.set_size(0);
                header.set_mtime(0);
                builder.append_data(&mut header, format!("{path}/"), std::io::empty())?;
            }
            Ok(())
        };
    add_dir(&mut builder, spec.input_dir, 0o755)?;
    add_dir(&mut builder, spec.output_dir, 0o777)?;
    for (name, path) in inputs {
        if !ace_sdk::scanners::is_input_name(name) {
            return Err(RunError::Refused(format!("the input name {name:?}")));
        }
        let full = format!("{}/{name}", spec.input_dir.trim_matches('/'));
        if let Some((parent, _)) = full.rsplit_once('/') {
            add_dir(&mut builder, parent, 0o755)?;
        }
        let file = std::fs::File::open(path)?;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(file.metadata()?.len());
        header.set_mtime(0);
        builder.append_data(&mut header, &full, file)?;
    }
    Ok(builder.into_inner()?)
}

/// Packs `files`, under their names, into the tar at `dest` without reading them, and returns its
/// sha256 and size.
fn pack(dest: &Path, files: &[(&str, &PathBuf)]) -> std::io::Result<ScanOutputRecord> {
    let mut builder = tar::Builder::new(std::fs::File::create(dest)?);
    for (name, path) in files {
        let file = std::fs::File::open(path)?;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(file.metadata()?.len());
        header.set_mtime(0);
        builder.append_data(&mut header, name, file)?;
    }
    builder.into_inner()?.flush()?;
    let mut hasher = sha2::Sha256::new();
    let mut file = std::fs::File::open(dest)?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok(ScanOutputRecord {
        sha256: ace_results::Sha256(hasher.finalize().into()),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ace_sdk::scanners::{JS_DEOBFUSCATOR, LeasedScanInput, PHISHKIT};
    use ace_sdk::wire::Presigned;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }

    fn scan(scanner: &str, args: &[&str]) -> LeasedScan {
        LeasedScan {
            id: 7,
            scanner: scanner.to_owned(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            inputs: vec![LeasedScanInput {
                name: "job/page.html".to_owned(),
                sha256: ace_results::Sha256([0; 32]),
                size: 3,
                download: Presigned {
                    url: String::new(),
                    headers: Vec::new(),
                },
            }],
            timeout_seconds: 30,
            deadline_seconds: 30.0,
            lease_seconds: 60.0,
            proxy: false,
        }
    }

    /// PLAN.md decision 64: the pool adds its proxy as phishkit's `--proxy` only for a scan that asks
    /// for it, and reports it without its credentials; a scanner with no proxy setting never gets one.
    #[test]
    fn a_scan_that_asks_goes_through_the_pool_s_proxy() {
        let config = ScannerPoolConfig::new(
            "s",
            "h",
            ace_sdk::scanners::SCANNERS,
            &env(&[(
                "ACE_RS_PHISHKIT_PROXY",
                "http://user:secret@proxy.example.com:3128",
            )]),
        );
        let phishkit = config.spec("phishkit").expect("a spec");
        let cmd = |scan: &LeasedScan| -> Vec<String> {
            serde_json::from_value(create_body(&config, phishkit, scan, 0)["Cmd"].clone())
                .expect("a command")
        };
        let mut asked = scan("phishkit", &["https://lure.example.net/"]);
        asked.proxy = true;
        let with = cmd(&asked);
        assert_eq!(
            with[with.len() - 2..],
            ["--proxy", "http://user:secret@proxy.example.com:3128"]
        );
        assert_eq!(
            config.proxied(phishkit, &asked).as_deref(),
            Some("http://proxy.example.com:3128"),
            "no credentials in what it reports"
        );
        let direct = scan("phishkit", &["https://lure.example.net/"]);
        assert!(!cmd(&direct).iter().any(|a| a == "--proxy"));
        assert_eq!(config.proxied(phishkit, &direct), None);
        let js = config.spec("js-deobfuscator").expect("a spec");
        let mut js_scan = scan("js-deobfuscator", &[]);
        js_scan.proxy = true;
        assert_eq!(config.proxied(js, &js_scan), None, "it takes no proxy");
        // a pool without the variable sends it direct
        let none = ScannerPoolConfig::new("s", "h", ace_sdk::scanners::SCANNERS, &env(&[]));
        assert_eq!(none.proxied(phishkit, &asked), None);
    }

    /// PLAN.md 7.7: js-deobfuscator's container has no network, phishkit's has the memory and CPU
    /// limits ace3 gives it and the default network, and each is labelled as this stack's and host's.
    #[test]
    fn containers_get_their_specs_limits_and_labels() {
        let specs = [JS_DEOBFUSCATOR, PHISHKIT];
        let config = ScannerPoolConfig::new("ace-rs", "host1", &specs, &env(&[]));
        let js = create_body(
            &config,
            &JS_DEOBFUSCATOR,
            &scan("js-deobfuscator", &["/a"]),
            99,
        );
        assert_eq!(js["HostConfig"]["NetworkMode"], "none");
        assert!(js["HostConfig"].get("Memory").is_none());
        assert_eq!(js["Image"], "ace-rs-js-deobfuscator:latest");
        assert_eq!(js["Cmd"], json!(["node", "/opt/app/harness.js", "/a"]));
        assert_eq!(js["Labels"][LABEL_STACK], "ace-rs");
        assert_eq!(js["Labels"][LABEL_HOST], "host1");
        assert_eq!(js["Labels"][LABEL_SCAN], "7");
        assert_eq!(js["Labels"][LABEL_DEADLINE], "99");
        let pk = create_body(
            &config,
            &PHISHKIT,
            &scan("phishkit", &["https://x.example/"]),
            1,
        );
        assert_eq!(pk["HostConfig"]["NetworkMode"], "bridge");
        assert_eq!(pk["HostConfig"]["Memory"], json!(2u64 << 30));
        assert_eq!(pk["HostConfig"]["MemorySwap"], json!(2u64 << 30));
        assert_eq!(pk["HostConfig"]["NanoCpus"], json!(2_000_000_000));
        assert_eq!(pk["HostConfig"]["Init"], true);
        assert_eq!(pk["StopTimeout"], 5);
        // nothing ace3's reaper selects by
        assert!(
            pk["Labels"]
                .as_object()
                .expect("labels")
                .keys()
                .all(|k| !k.starts_with("phishkit."))
        );
        let e2e = ScannerPoolConfig::new(
            "ace-rs-e2e",
            "h",
            &specs,
            &env(&[
                ("ACE_RS_PHISHKIT_NETWORK", "ace-rs-e2e_default"),
                ("ACE_RS_PHISHKIT_IMAGE", "x:1"),
            ]),
        );
        let pk = create_body(&e2e, &PHISHKIT, &scan("phishkit", &[]), 1);
        assert_eq!(pk["HostConfig"]["NetworkMode"], "ace-rs-e2e_default");
        assert_eq!(pk["Image"], "x:1");
        // a scanner with no network gets none whatever the environment says
        let js = create_body(&e2e, &JS_DEOBFUSCATOR, &scan("js-deobfuscator", &[]), 1);
        assert_eq!(js["HostConfig"]["NetworkMode"], "none");
    }

    #[test]
    fn inputs_go_under_the_input_directory_and_the_output_directory_is_made() {
        let dir = tempfile::tempdir().expect("a directory");
        let file = dir.path().join("0");
        std::fs::write(&file, b"abc").expect("written");
        let archive = input_archive(&PHISHKIT, &[("job/page.html", file.clone())]).expect("packed");
        let mut entries: Vec<(String, u32)> = tar::Archive::new(&archive[..])
            .entries()
            .expect("entries")
            .map(|e| {
                let e = e.expect("an entry");
                (
                    e.path().expect("a path").display().to_string(),
                    e.header().mode().expect("a mode"),
                )
            })
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            [
                ("phishkit/".to_owned(), 0o755),
                ("phishkit/input/".to_owned(), 0o755),
                ("phishkit/input/job/".to_owned(), 0o755),
                ("phishkit/input/job/page.html".to_owned(), 0o644),
                ("phishkit/output/".to_owned(), 0o777),
            ]
        );
        assert!(input_archive(&PHISHKIT, &[("../x", file)]).is_err());
    }

    #[test]
    fn the_output_is_packed_unread() {
        let dir = tempfile::tempdir().expect("a directory");
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::write(&a, b"not a tar at all").expect("written");
        std::fs::write(&b, b"\x01\x00\x00\x00\x00\x00\x00\x02hi").expect("written");
        let packed = dir.path().join("p.tar");
        let record = pack(&packed, &[(OUTPUT_ARCHIVE, &a), (STDOUT, &b)]).expect("packed");
        assert_eq!(
            record.size,
            std::fs::metadata(&packed).expect("a size").len()
        );
        let mut names = Vec::new();
        for entry in tar::Archive::new(std::fs::File::open(&packed).expect("open"))
            .entries()
            .expect("entries")
        {
            let mut entry = entry.expect("an entry");
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).expect("read");
            names.push((entry.path().expect("a path").display().to_string(), bytes));
        }
        assert_eq!(
            names[0],
            (OUTPUT_ARCHIVE.to_owned(), b"not a tar at all".to_vec())
        );
        assert_eq!(names[1].0, STDOUT);
    }
}
