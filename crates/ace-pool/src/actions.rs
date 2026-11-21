//! Running actions (PLAN.md 7.9): the remediators, remediation probes and file collectors a network pool
//! hosts, which lease remediations, remediation checks and file collections from the lease API
//! (`ace_core::actions`) beside the pool's lookups.
//!
//! ace3 runs each kind as a service of its own, whose manager gives each handler a worker with
//! `thread_count` threads. Here one loop leases an action of any of the pool's handlers whenever one of
//! `concurrency` slots is free, and runs its handler as a task of its own on the pool's runtime, contained
//! with the pool. While it runs, its lease is renewed every third of its length; a renewal that says it was
//! cancelled, or a lost lease, stops it, and no end is sent. A handler that panics, fails or runs past
//! `try_limit` ends its try `ERROR` (a check's as a transient error, tried again), as ace3's workers record
//! an exception. A collector writes its file into a directory of the try's own; the pool checks that the
//! file is a regular file in that directory, hashes it, uploads it and names it in the end.
//!
//! At shutdown the loop leases no more and stops the tries still running after `grace`; their leases lapse
//! and the reaper gives them to the next pool, as ace3's lock timeout does.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ace_results::Sha256;
use ace_sdk::actions::{
    ActionEnd, ActionKind, ActionSpec, CollectedFile, CollectorStatus, FileCollector, LeasedAction,
    RemediationAction, RemediationProbe, Remediator,
};
use sha2::Digest;
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::client::{ClientError, LeaseClient};

/// A handler the pool runs.
#[derive(Clone)]
pub enum Handler {
    Remediator(Arc<dyn Remediator>),
    Probe(Arc<dyn RemediationProbe>),
    Collector(Arc<dyn FileCollector>),
}

impl Handler {
    pub fn spec(&self) -> &'static ActionSpec {
        match self {
            Handler::Remediator(h) => h.spec(),
            Handler::Probe(h) => h.spec(),
            Handler::Collector(h) => h.spec(),
        }
    }
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.spec().pool_entry())
    }
}

/// A pool's handlers, by kind and name.
#[derive(Debug, Clone, Default)]
pub struct Handlers(Vec<Handler>);

impl Handlers {
    pub fn new() -> Handlers {
        Handlers::default()
    }

    /// Adds `handler`, refusing one whose spec its own rules refuse or whose kind and name another has.
    pub fn with(mut self, handler: Handler) -> Result<Handlers, String> {
        let spec = handler.spec();
        if let Some(why) = spec.refusal() {
            return Err(why);
        }
        if self.get(spec.kind, spec.name).is_some() {
            return Err(format!("{} is added twice", spec.pool_entry()));
        }
        self.0.push(handler);
        Ok(self)
    }

    pub fn get(&self, kind: ActionKind, name: &str) -> Option<&Handler> {
        self.0
            .iter()
            .find(|h| h.spec().kind == kind && h.spec().name == name)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn specs(&self) -> Vec<&'static ActionSpec> {
        self.0.iter().map(Handler::spec).collect()
    }

    /// Whether one of them is a file collector, which uploads the file it fetched, so its pool
    /// needs the bucket's port (`PoolDefinition::lookup_sandbox`, PLAN.md decision 28).
    pub fn collects_files(&self) -> bool {
        self.0.iter().any(|h| matches!(h, Handler::Collector(_)))
    }
}

/// How an action pool's run went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActionStats {
    /// Tries whose end was sent.
    pub ended: u64,
    /// Tries stopped by a cancellation, a lost lease or the shutdown, which send no end.
    pub stopped: u64,
    pub errors: u64,
}

/// The longest one try may run, by default. ace3 bounds none; its lock timeout hands a hung row to another
/// worker after 5 minutes and leaves the thread hung.
pub const DEFAULT_TRY_LIMIT: Duration = Duration::from_secs(15 * 60);

/// Leases and runs a pool's actions.
pub struct ActionPool {
    client: LeaseClient,
    handlers: Arc<Handlers>,
    concurrency: usize,
    lease_wait: Duration,
    grace: Duration,
    try_limit: Duration,
}

impl ActionPool {
    pub fn new(client: LeaseClient, handlers: Arc<Handlers>, concurrency: usize) -> ActionPool {
        ActionPool {
            client,
            handlers,
            concurrency: concurrency.max(1),
            lease_wait: Duration::from_secs(10),
            grace: crate::pool::SHUTDOWN_GRACE,
            try_limit: DEFAULT_TRY_LIMIT,
        }
    }

    pub fn lease_wait(mut self, wait: Duration) -> Self {
        self.lease_wait = wait;
        self
    }

    pub fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    pub fn try_limit(mut self, limit: Duration) -> Self {
        self.try_limit = limit;
        self
    }

    /// Leases and runs actions until `stop` fires, then waits up to `grace` for the tries still running.
    pub async fn run(&self, stop: CancellationToken) -> ActionStats {
        let slots = Arc::new(Semaphore::new(self.concurrency));
        let tries = CancellationToken::new();
        let mut running: JoinSet<Ran> = JoinSet::new();
        let mut stats = ActionStats::default();
        loop {
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
                leased = self.client.lease_action(self.lease_wait) => leased,
            };
            match leased {
                Ok(Some(action)) => {
                    let (client, handlers, token, limit) = (
                        self.client.clone(),
                        self.handlers.clone(),
                        tries.child_token(),
                        self.try_limit,
                    );
                    running.spawn(async move {
                        let _slot = slot;
                        run_one(&client, &handlers, action, token, limit).await
                    });
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("leasing an action failed: {e}");
                    stats.errors += 1;
                    tokio::select! {
                        () = stop.cancelled() => break,
                        () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            }
        }
        tries.cancel();
        let deadline = tokio::time::Instant::now() + self.grace;
        loop {
            match tokio::time::timeout_at(deadline, running.join_next()).await {
                Ok(Some(finished)) => count(&mut stats, finished),
                Ok(None) => break,
                Err(_) => {
                    tracing::warn!(
                        tries = running.len(),
                        "actions still running at the shutdown deadline; their leases will lapse"
                    );
                    running.abort_all();
                    break;
                }
            }
        }
        stats
    }
}

/// How one try went, for the stats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ran {
    Ended,
    Stopped,
    Failed,
}

fn count(stats: &mut ActionStats, finished: Result<Ran, tokio::task::JoinError>) {
    match finished {
        Ok(Ran::Ended) => stats.ended += 1,
        Ok(Ran::Stopped) => stats.stopped += 1,
        Ok(Ran::Failed) | Err(_) => stats.errors += 1,
    }
}

/// Runs one try of a leased action and sends its end, unless it was cancelled, lost its lease or the pool
/// is stopping.
pub async fn run_one(
    client: &LeaseClient,
    handlers: &Handlers,
    action: LeasedAction,
    shutdown: CancellationToken,
    limit: Duration,
) -> Ran {
    let span = tracing::info_span!(
        "pool.action",
        action = action.id,
        kind = %action.kind,
        handler = %action.handler
    );
    run_traced(client, handlers, action, shutdown, limit)
        .instrument(span)
        .await
}

async fn run_traced(
    client: &LeaseClient,
    handlers: &Handlers,
    action: LeasedAction,
    shutdown: CancellationToken,
    limit: Duration,
) -> Ran {
    let id = action.id;
    let stop = shutdown.child_token();
    let keeper = keep_lease(client, &action, stop.clone());
    let dir = match tempfile::Builder::new().prefix("ace4-action-").tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            keeper.abort();
            return send(
                client,
                id,
                &ActionEnd::error(action.kind, &format!("no directory: {e}")),
            )
            .await;
        }
    };
    let ended = match handlers.get(action.kind, &action.handler) {
        None => Some(ActionEnd::error(
            action.kind,
            &format!(
                "this pool doesn't run {}",
                ace_sdk::actions::pool_entry(action.kind, &action.handler)
            ),
        )),
        Some(handler) => {
            let tried = tokio::spawn(try_handler(
                handler.clone(),
                action.clone(),
                dir.path().to_owned(),
                client.clone(),
            ));
            tokio::select! {
                () = stop.cancelled() => None,
                joined = tokio::time::timeout(limit, tried) => Some(match joined {
                    Ok(Ok(end)) => end,
                    Ok(Err(e)) => ActionEnd::error(
                        action.kind,
                        &format!("the handler panicked: {}", crate::run::panic_message(e)),
                    ),
                    Err(_) => ActionEnd::error(
                        action.kind,
                        &format!("the handler ran past its limit of {} seconds", limit.as_secs()),
                    ),
                }),
            }
        }
    };
    keeper.abort();
    let Some(end) = ended else {
        tracing::info!(
            action = id,
            "stopped: cancelled, its lease lost, or the pool stopping"
        );
        return Ran::Stopped;
    };
    let end = match upload_file(client, &action, dir.path(), end).await {
        Ok(end) => end,
        Err(e) => {
            tracing::warn!(action = id, "uploading the collected file failed: {e}");
            ActionEnd::error(
                action.kind,
                &format!("uploading the collected file failed: {e}"),
            )
        }
    };
    send(client, id, &end).await
}

async fn send(client: &LeaseClient, id: i64, end: &ActionEnd) -> Ran {
    match client.end_action(id, end).await {
        Ok(()) => Ran::Ended,
        Err(ClientError::LeaseLost(_)) => {
            tracing::info!(
                action = id,
                "the action was cancelled or taken back before its end"
            );
            Ran::Stopped
        }
        Err(e) => {
            tracing::error!(action = id, "the action's end wasn't sent: {e}");
            Ran::Failed
        }
    }
}

/// Renews the action's lease every third of its length, firing `stop` when it was cancelled or the lease
/// is lost.
fn keep_lease(
    client: &LeaseClient,
    action: &LeasedAction,
    stop: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    let (client, id) = (client.clone(), action.id);
    let every = Duration::from_secs_f64((action.lease_seconds / 3.0).max(0.1));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            match client.renew_action(id).await {
                Ok(renewal) if renewal.cancelled => {
                    tracing::info!(action = id, "the action was cancelled");
                    stop.cancel();
                    return;
                }
                Ok(_) => {}
                Err(ClientError::LeaseLost(_)) => {
                    tracing::warn!(action = id, "lost the action's lease");
                    stop.cancel();
                    return;
                }
                Err(e) => tracing::warn!(action = id, "renewing the action failed: {e}"),
            }
        }
    })
}

/// What a remediator asks the core during one try, through the pool's lease client.
struct ClientCore {
    client: LeaseClient,
    action: i64,
}

impl ace_sdk::actions::ActionCore for ClientCore {
    fn removal_covers<'a>(
        &'a self,
        observable_value: &'a str,
    ) -> ace_sdk::actions::ActionFuture<'a, Result<bool, String>> {
        Box::pin(async move {
            self.client
                .removal_covers(self.action, observable_value)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// One try of the handler, as its end.
async fn try_handler(
    handler: Handler,
    action: LeasedAction,
    dir: std::path::PathBuf,
    client: LeaseClient,
) -> ActionEnd {
    match handler {
        Handler::Remediator(remediator) => {
            let core = ClientCore {
                client,
                action: action.id,
            };
            let result = match action.action {
                Some(RemediationAction::Restore) => remediator.restore(&action).await,
                // a remediation always has its action; a row without one is a remove, as ace3's default
                Some(RemediationAction::Remove) | None => {
                    remediator.remove_with(&action, &core).await
                }
            };
            ActionEnd::Remediation { result }
        }
        Handler::Probe(probe) => ActionEnd::RemediationCheck {
            outcome: probe.probe(&action).await,
        },
        Handler::Collector(collector) => {
            let result = collector.collect(&action, &dir).await;
            match (result.status, result.file) {
                (CollectorStatus::Success, Some(path)) => ActionEnd::FileCollection {
                    status: result.status,
                    message: result.message,
                    // named for now; `upload_file` hashes and uploads it
                    file: Some(CollectedFile {
                        sha256: Sha256([0; 32]),
                        size: 0,
                        name: path.to_string_lossy().into_owned(),
                    }),
                },
                (status, _) => ActionEnd::FileCollection {
                    status,
                    message: result.message,
                    file: None,
                },
            }
        }
    }
}

/// Uploads a collection's file, which `try_handler` named by its path, and names it by its hash and its
/// file name instead. Any other end passes through.
async fn upload_file(
    client: &LeaseClient,
    action: &LeasedAction,
    dir: &Path,
    end: ActionEnd,
) -> Result<ActionEnd, ClientError> {
    let ActionEnd::FileCollection {
        status,
        message,
        file: Some(named),
    } = end
    else {
        return Ok(end);
    };
    let path = std::path::PathBuf::from(&named.name);
    let path = if path.is_absolute() {
        path
    } else {
        dir.join(path)
    };
    let (path, name) = collected_file(dir, &path)?;
    let (sha256, size) = hash(&path).await?;
    let url = client.action_upload_url(action.id, &sha256, size).await?;
    client.upload(&url, &path).await?;
    Ok(ActionEnd::FileCollection {
        status,
        message,
        file: Some(CollectedFile { sha256, size, name }),
    })
}

/// The file a collector named, if it's a regular file inside `dir`, with its name.
fn collected_file(dir: &Path, path: &Path) -> Result<(std::path::PathBuf, String), ClientError> {
    let refuse = |why: &str| {
        ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("the collector's file {}: {why}", path.display()),
        ))
    };
    let dir = dir.canonicalize()?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(refuse("not a regular file"));
    }
    let resolved = path.canonicalize()?;
    if !resolved.starts_with(&dir) {
        return Err(refuse("outside the try's directory"));
    }
    let name = resolved
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| ace_core_file_name(n))
        .ok_or_else(|| refuse("no plain name of at most 255 bytes"))?;
    Ok((resolved, name))
}

/// The core's rule for a collected file's name (`ace_core::actions::is_file_name`).
fn ace_core_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\', '\0'])
}

async fn hash(path: &Path) -> Result<(Sha256, u64), ClientError> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((Sha256(hasher.finalize().into()), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_collected_file_must_be_a_plain_file_in_the_tries_directory() {
        let dir = tempfile::tempdir().expect("a directory");
        let inside = dir.path().join("report.pdf");
        std::fs::write(&inside, b"%PDF").expect("writes");
        let (_, name) = collected_file(dir.path(), &inside).expect("inside");
        assert_eq!(name, "report.pdf");
        let outside = tempfile::NamedTempFile::new().expect("a file");
        assert!(collected_file(dir.path(), outside.path()).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(outside.path(), &link).expect("links");
        assert!(collected_file(dir.path(), &link).is_err());
        assert!(collected_file(dir.path(), dir.path()).is_err());
    }

    struct TestCollector;

    static TEST_COLLECTOR: ActionSpec = ActionSpec::new(
        ActionKind::FileCollection,
        "test",
        "Test Collector",
        "Collects nothing.",
        "test",
    );

    impl FileCollector for TestCollector {
        fn spec(&self) -> &'static ActionSpec {
            &TEST_COLLECTOR
        }

        fn collect<'a>(
            &'a self,
            _: &'a LeasedAction,
            _: &'a Path,
        ) -> ace_sdk::actions::ActionFuture<'a, ace_sdk::actions::CollectorResult> {
            unreachable!("never run")
        }
    }

    /// PLAN.md decision 28: only a file collector uploads, so only a pool hosting one needs the
    /// bucket's port.
    #[test]
    fn only_a_file_collector_collects_files() {
        let remediator = Handlers::new()
            .with(Handler::Remediator(Arc::new(
                ace_sdk::actions::TestRemediator,
            )))
            .expect("added");
        assert!(!remediator.collects_files());
        assert!(!Handlers::new().collects_files());
        let both = remediator
            .with(Handler::Collector(Arc::new(TestCollector)))
            .expect("added");
        assert!(both.collects_files());
    }

    #[test]
    fn a_handler_is_added_once() {
        let handlers = Handlers::new()
            .with(Handler::Remediator(Arc::new(
                ace_sdk::actions::TestRemediator,
            )))
            .expect("added");
        assert!(handlers.get(ActionKind::Remediation, "test").is_some());
        assert!(
            handlers
                .with(Handler::Remediator(Arc::new(
                    ace_sdk::actions::TestRemediator
                )))
                .is_err()
        );
    }
}
