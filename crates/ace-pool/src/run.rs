//! Running one leased task: keeping its lease, fetching its input, running the module, sending
//! back what it wrote, and ending the task.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ace_sdk::LocalFileStore;
use ace_sdk::wire::{LeasedTask, TaskEnd};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument;

use crate::client::{ClientError, LeaseClient};
use crate::modules::{Modules, Run};

/// Renews a task's lease every third of its length until dropped. Its token fires when the
/// task is cancelled or the lease is lost, so the module stops.
pub struct LeaseKeeper {
    handle: JoinHandle<()>,
    token: CancellationToken,
}

impl LeaseKeeper {
    /// Starts renewing. Its token is a child of `shutdown`, so the pool's shutdown stops the
    /// module too.
    pub fn start(
        client: &LeaseClient,
        task: &LeasedTask,
        shutdown: &CancellationToken,
    ) -> LeaseKeeper {
        let token = shutdown.child_token();
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

/// Ends the task as the module did, or, when the module stopped because the pool is shutting
/// down, gives the task back to the queue (PLAN.md 2.21).
pub async fn finish(
    client: &LeaseClient,
    task: &LeasedTask,
    outputs: &LocalFileStore,
    end: &TaskEnd,
    shutdown: &CancellationToken,
) -> Result<(), ClientError> {
    if shutdown.is_cancelled() && matches!(end, TaskEnd::Cancelled) {
        tracing::info!(task = task.id, "shutting down; giving the task back");
        return client.release(task.id).await;
    }
    send_end(client, task, outputs, end).await
}

/// Runs a leased task in this process, uncontained: a parser on a blocking thread, a lookup on
/// the runtime. `shutdown` stops it, and the task then goes back to the queue. Returns how it
/// ended.
pub async fn run_in_process(
    client: &LeaseClient,
    modules: &Arc<Modules>,
    task: LeasedTask,
    shutdown: &CancellationToken,
) -> Result<TaskEnd, ClientError> {
    let keeper = LeaseKeeper::start(client, &task, shutdown);
    let dir = TaskDir::new()?;
    let input = fetch_input(client, &task, &dir)
        .instrument(tracing::info_span!("fetch_input"))
        .await?;
    let outputs = Arc::new(LocalFileStore::new(dir.outputs())?);
    // the module's own span (ace_sdk::module::task_span) is a child of this task's
    let span = tracing::Span::current();
    let cancel = keeper.token().clone();
    // each module runs in a task of its own, so a panic ends that task and fails it
    let (owned_modules, owned_task, owned_outputs) =
        (modules.clone(), task.clone(), outputs.clone());
    let joined = if modules.parser(&task.module).is_some() {
        tokio::task::spawn_blocking(move || match owned_modules.parser(&owned_task.module) {
            Some(parser) => span.in_scope(|| {
                parser.run(Run {
                    task: &owned_task,
                    input: input.as_deref(),
                    outputs: owned_outputs,
                    cancel,
                    contained: false,
                })
            }),
            None => unknown_module(&owned_task),
        })
        .await
    } else {
        tokio::spawn(
            async move {
                match owned_modules.lookup(&owned_task.module) {
                    Some(lookup) => {
                        lookup
                            .run(Run {
                                task: &owned_task,
                                input: input.as_deref(),
                                outputs: owned_outputs,
                                cancel,
                                contained: false,
                            })
                            .await
                    }
                    None => unknown_module(&owned_task),
                }
            }
            .instrument(span),
        )
        .await
    };
    let end = joined.unwrap_or_else(|e| TaskEnd::Failed {
        error: format!("the module panicked: {}", panic_message(e)),
    });
    finish(client, &task, &outputs, &end, shutdown)
        .instrument(tracing::info_span!("send_end"))
        .await?;
    Ok(end)
}

fn unknown_module(task: &LeasedTask) -> TaskEnd {
    TaskEnd::Failed {
        error: format!("this pool doesn't run {}", task.module),
    }
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
