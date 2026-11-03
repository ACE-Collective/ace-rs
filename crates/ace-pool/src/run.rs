//! Running one leased task: keeping its lease, fetching its input, running the module, sending
//! back what it wrote, and ending the task.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ace_sdk::LocalFileStore;
use ace_sdk::wire::{LeasedTask, TaskEnd};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::client::{ClientError, LeaseClient};
use crate::modules::{Modules, Run};

/// Renews a task's lease every third of its length until dropped. Its token fires when the
/// task is cancelled or the lease is lost, so the module stops.
pub struct LeaseKeeper {
    handle: JoinHandle<()>,
    token: CancellationToken,
}

impl LeaseKeeper {
    pub fn start(client: &LeaseClient, task: &LeasedTask) -> LeaseKeeper {
        let token = CancellationToken::new();
        let (client, fired, id) = (client.clone(), token.clone(), task.id);
        let every = Duration::from_secs_f64(task.lease_seconds / 3.0);
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                match client.renew(id).await {
                    Ok(renewal) if renewal.cancel_requested => {
                        tracing::info!(task = id, "the task was cancelled");
                        fired.cancel();
                    }
                    Ok(_) => {}
                    Err(ClientError::LeaseLost(_)) => {
                        tracing::warn!(task = id, "lost the lease");
                        fired.cancel();
                        return;
                    }
                    // a later renewal may still get through before the lease runs out
                    Err(e) => tracing::warn!(task = id, "renewal failed: {e}"),
                }
            }
        });
        LeaseKeeper { handle, token }
    }

    pub fn token(&self) -> &CancellationToken {
        &self.token
    }
}

impl Drop for LeaseKeeper {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// A task's own directory on this machine: its input and the files its module writes.
pub struct TaskDir {
    dir: tempfile::TempDir,
}

impl TaskDir {
    pub fn new() -> std::io::Result<TaskDir> {
        let dir = tempfile::Builder::new().prefix("ace4-task-").tempdir()?;
        std::fs::create_dir(dir.path().join("outputs"))?;
        Ok(TaskDir { dir })
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn input(&self) -> PathBuf {
        self.dir.path().join("input")
    }

    pub fn outputs(&self) -> PathBuf {
        self.dir.path().join("outputs")
    }
}

/// Downloads a file task's input into the task's directory and returns where it is.
pub async fn fetch_input(
    client: &LeaseClient,
    task: &LeasedTask,
    dir: &TaskDir,
) -> Result<Option<PathBuf>, ClientError> {
    let Some(file) = &task.observable.file else {
        return Ok(None);
    };
    let path = dir.input();
    client.download(&file.download, &path).await?;
    Ok(Some(path))
}

/// Uploads each file a result adds from the task's output directory, then ends the task.
pub async fn send_end(
    client: &LeaseClient,
    task: &LeasedTask,
    outputs: &LocalFileStore,
    end: &TaskEnd,
) -> Result<(), ClientError> {
    if let TaskEnd::Done { result } = end {
        for file in &result.files {
            let url = client.upload_url(task.id, &file.sha256, file.size).await?;
            client.upload(&url, &outputs.path_of(&file.sha256)).await?;
        }
    }
    client.end(task.id, end).await
}

/// Runs a leased task in this process, uncontained: a parser on a blocking thread, a lookup on
/// the runtime. Returns how it ended.
pub async fn run_in_process(
    client: &LeaseClient,
    modules: &Arc<Modules>,
    task: LeasedTask,
) -> Result<TaskEnd, ClientError> {
    let keeper = LeaseKeeper::start(client, &task);
    let dir = TaskDir::new()?;
    let input = fetch_input(client, &task, &dir).await?;
    let outputs = Arc::new(LocalFileStore::new(dir.outputs())?);
    let cancel = keeper.token().clone();
    let end = if modules.parser(&task.module).is_some() {
        let (modules, task, outputs) = (modules.clone(), task.clone(), outputs.clone());
        tokio::task::spawn_blocking(move || {
            let parser = modules.parser(&task.module).expect("checked above");
            parser.run(Run {
                task: &task,
                input: input.as_deref(),
                outputs,
                cancel,
                contained: false,
            })
        })
        .await
        .unwrap_or_else(|e| TaskEnd::Failed {
            error: format!("the module panicked: {}", panic_message(e)),
        })
    } else if let Some(lookup) = modules.lookup(&task.module) {
        lookup
            .run(Run {
                task: &task,
                input: input.as_deref(),
                outputs: outputs.clone(),
                cancel,
                contained: false,
            })
            .await
    } else {
        TaskEnd::Failed {
            error: format!("this pool doesn't run {}", task.module),
        }
    };
    send_end(client, &task, &outputs, &end).await?;
    Ok(end)
}

/// What a panicked task's join error says.
pub fn panic_message(error: tokio::task::JoinError) -> String {
    match error.try_into_panic() {
        Ok(payload) => payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a panic with no message".to_owned()),
        Err(e) => e.to_string(),
    }
}
