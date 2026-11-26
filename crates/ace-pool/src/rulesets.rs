//! A YARA pool's rulesets (PLAN.md 2.26): the pool loads the ruleset the core names by its
//! hash, and switches to a new one only after it has loaded.
//!
//! The watcher asks the lease API which ruleset is current. When it isn't the one on disk, it
//! downloads the bytes from the bucket into the pool's ruleset directory, checks that their
//! sha256 is the key, and has the binary load them (`Check`). Only then does it publish them as
//! the directory's current generation (`ace_sdk::generation`). A task process loads the current
//! generation when it starts, so a task that started before the switch finishes on the old
//! ruleset and every task after it runs on the new one. A download or a load that fails keeps
//! the old ruleset and is tried again on the next look.
//!
//! Each look also has the module prepare what it keeps beside the current generation (`Prepare`),
//! such as the YARA module's native copy of the ruleset, built on this host: after a switch, and on
//! the first look after the pool starts, when a new binary may need a copy of its own. A copy that
//! doesn't build is a warning, since tasks still load the core's file, and is tried again on the
//! next look. A generation's directory holds what was prepared for it, so it goes with it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ace_sdk::generation::{self, Generation, GenerationInfo};
use sha2::Digest;
use tokio_util::sync::CancellationToken;

use crate::client::{ClientError, LeaseClient};

/// Loads the ruleset at a path the way the pool's task processes will, and says why it didn't.
pub type Check = Arc<dyn Fn(&Path) -> Result<(), String> + Send + Sync>;

/// Prepares what the module keeps beside a generation, in its directory: the path of what it built,
/// None when there was nothing to build, or why it couldn't.
pub type Prepare = Arc<dyn Fn(&Generation) -> Result<Option<PathBuf>, String> + Send + Sync>;

/// How often the watcher asks for the current ruleset by default.
pub const DEFAULT_EVERY: Duration = Duration::from_secs(30);

/// How long a pool waits for the core's first ruleset before each look says so at ERROR (PLAN.md
/// 7.20): until there is one the pool leases nothing, so an alert's files go unanalyzed.
pub const FIRST_RULESET_PATIENCE: Duration = Duration::from_secs(300);

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("the ruleset downloaded as {key} has sha256 {actual}")]
    Integrity { key: String, actual: String },
    #[error("ruleset {key} didn't load: {error}")]
    Load { key: String, error: String },
    #[error("the ruleset directory: {0}")]
    Io(#[from] std::io::Error),
    #[error("the ruleset's check stopped: {0}")]
    Join(String),
}

/// Keeps a pool's ruleset directory on the core's current ruleset.
pub struct RulesetWatcher {
    client: LeaseClient,
    dir: PathBuf,
    check: Check,
    prepare: Option<Prepare>,
    every: Duration,
    patience: Duration,
}

impl RulesetWatcher {
    pub fn new(client: LeaseClient, dir: impl Into<PathBuf>, check: Check) -> Self {
        RulesetWatcher {
            client,
            dir: dir.into(),
            check,
            prepare: None,
            every: DEFAULT_EVERY,
            patience: FIRST_RULESET_PATIENCE,
        }
    }

    /// Prepares each current generation with `prepare` (`Prepare`).
    pub fn prepare(mut self, prepare: Prepare) -> Self {
        self.prepare = Some(prepare);
        self
    }

    pub fn every(mut self, every: Duration) -> Self {
        self.every = every;
        self
    }

    /// Waits this long for the first ruleset before saying so at ERROR, rather than
    /// `FIRST_RULESET_PATIENCE`.
    pub fn patience(mut self, patience: Duration) -> Self {
        self.patience = patience;
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Looks once: switches to the core's current ruleset if it isn't the one on disk. Returns
    /// the generation that is current afterwards, if any.
    pub async fn refresh(&self) -> Result<Option<Generation>, WatchError> {
        let current = self.switch().await?;
        if let Some(generation) = &current {
            self.prepared(generation).await;
        }
        Ok(current)
    }

    /// Prepares the generation, and says at WARN when it couldn't.
    async fn prepared(&self, generation: &Generation) {
        let Some(prepare) = self.prepare.clone() else {
            return;
        };
        let (target, started) = (generation.clone(), std::time::Instant::now());
        // a look waits for it: it reads and writes local files of one ruleset's size
        let prepared = tokio::task::spawn_blocking(move || prepare(&target)).await;
        match prepared {
            Ok(Ok(Some(path))) => tracing::info!(
                key = %generation.info.key,
                path = %path.display(),
                seconds = started.elapsed().as_secs_f64(),
                "prepared the ruleset for this pool's tasks"
            ),
            Ok(Ok(None)) => {}
            Ok(Err(error)) => tracing::warn!(
                key = %generation.info.key,
                dir = %generation.dir.display(),
                error,
                "preparing the ruleset for this pool's tasks failed; they load the core's file, \
                 more slowly, until a later look prepares it"
            ),
            Err(e) => tracing::warn!(
                key = %generation.info.key,
                dir = %generation.dir.display(),
                "preparing the ruleset stopped: {e}"
            ),
        }
    }

    /// Switches to the core's current ruleset if it isn't the one on disk.
    async fn switch(&self) -> Result<Option<Generation>, WatchError> {
        let on_disk = generation::current(&self.dir)?;
        let Some(current) = self.client.current_ruleset().await? else {
            return Ok(on_disk);
        };
        let info = GenerationInfo {
            key: current.key.to_hex(),
            commit: current.commit,
        };
        if on_disk.as_ref().is_some_and(|g| g.info == info) {
            return Ok(on_disk);
        }
        let download = self.dir.join(format!(".download-{}", info.key));
        self.client.download(&current.download, &download).await?;
        let (check, dir, key) = (self.check.clone(), self.dir.clone(), info.key.clone());
        let published = tokio::task::spawn_blocking(move || {
            let checked = verify(&download, &key).and_then(|()| {
                check(&download).map_err(|error| WatchError::Load {
                    key: key.clone(),
                    error,
                })
            });
            match checked {
                Ok(()) => Ok(generation::publish(&dir, &info, &download)?),
                Err(e) => {
                    if let Err(removing) = std::fs::remove_file(&download) {
                        tracing::warn!("removing a ruleset that didn't load: {removing}");
                    }
                    Err(e)
                }
            }
        })
        .await
        .map_err(|e| WatchError::Join(e.to_string()))??;
        tracing::info!(
            key = %published.info.key,
            commit = %published.info.commit,
            previous = ?on_disk.map(|g| g.info.key),
            "switched to a new ruleset"
        );
        Ok(Some(published))
    }

    /// Looks until a ruleset is current, as a pool does before it leases its first YARA task.
    /// None when `stop` fired first. Each look without one logs at INFO, and at ERROR once it has
    /// waited `patience`, since the pool leases nothing until then.
    pub async fn first(&self, stop: &CancellationToken) -> Option<Generation> {
        let started = tokio::time::Instant::now();
        loop {
            match self.refresh().await {
                Ok(Some(generation)) => return Some(generation),
                Ok(None) if started.elapsed() >= self.patience => tracing::error!(
                    waited_seconds = started.elapsed().as_secs(),
                    "the core has built no YARA ruleset, so this pool leases no task until it does: \
                     the core builds one from the signatures checkout ACE_RS_SIGNATURES_REPO names"
                ),
                Ok(None) => tracing::info!("waiting for the core's first ruleset"),
                Err(e) => tracing::error!("loading the current ruleset failed: {e}"),
            }
            tokio::select! {
                () = stop.cancelled() => return None,
                () = tokio::time::sleep(self.every) => {}
            }
        }
    }

    /// Looks every `every` until `stop` fires.
    pub async fn run(&self, stop: CancellationToken) {
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                () = tokio::time::sleep(self.every) => {}
            }
            if let Err(e) = self.refresh().await {
                tracing::error!("switching rulesets failed; the pool keeps its ruleset: {e}");
            }
        }
    }
}

/// Checks that the file's sha256 is `key`.
fn verify(path: &Path, key: &str) -> Result<(), WatchError> {
    let mut hasher = sha2::Sha256::new();
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let read = std::io::Read::read(&mut file, &mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if actual != key {
        return Err(WatchError::Integrity {
            key: key.to_owned(),
            actual,
        });
    }
    Ok(())
}
