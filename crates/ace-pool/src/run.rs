//! Running one leased task: keeping its lease, fetching its input, running the module, sending
//! back what it wrote, and ending the task.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ace_sdk::wire::{LeasedTask, TaskEnd};
use ace_sdk::{EmailBodyPart, LocalFileStore};
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

    /// A task's directory inside `parent`.
    pub fn new_in(parent: &Path) -> std::io::Result<TaskDir> {
        let dir = tempfile::Builder::new()
            .prefix("task-")
            .tempdir_in(parent)?;
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

/// Downloads the body parts of the email that carried the task's file, for the task's user to read,
/// each to a file of its own in `dir`, in the email's order.
pub async fn fetch_email_parts(
    client: &LeaseClient,
    task: &LeasedTask,
    dir: &Path,
) -> Result<Vec<EmailBodyPart>, ClientError> {
    let Some(email) = &task.carrying_email else {
        return Ok(Vec::new());
    };
    let mut parts = Vec::with_capacity(email.parts.len());
    for (index, part) in email.parts.iter().enumerate() {
        let path = dir.join(format!("email_body.{index}"));
        client.download(&part.download, &path).await?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        parts.push(EmailBodyPart {
            path,
            html: part.html,
        });
    }
    Ok(parts)
}

/// Downloads the files of the task's tree its module reads (`Module::READS_TREE_FILES`) into a
/// directory of their own in `dir`, each named by its sha256, for the task's user to read.
pub async fn fetch_tree_files(
    client: &LeaseClient,
    task: &LeasedTask,
    dir: &Path,
) -> Result<Option<PathBuf>, ClientError> {
    let Some(tree) = &task.tree else {
        return Ok(None);
    };
    let files = dir.join("tree_files");
    std::fs::create_dir_all(&files)?;
    std::fs::set_permissions(&files, std::fs::Permissions::from_mode(0o755))?;
    for observable in &tree.observables {
        let Some(download) = &observable.download else {
            continue;
        };
        // the core sends a file's sha256 as its value; anything else isn't a name to write
        if observable.value.len() != 64 || !observable.value.bytes().all(|b| b.is_ascii_hexdigit())
        {
            continue;
        }
        let path = files.join(&observable.value);
        client.download(download, &path).await?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    }
    Ok(Some(files))
}

/// Downloads the output archive of the task's latest scan (PLAN.md 7.7) into `dir`, for the task's
/// user to read.
pub async fn fetch_scan_output(
    client: &LeaseClient,
    task: &LeasedTask,
    dir: &Path,
) -> Result<Option<PathBuf>, ClientError> {
    let Some(output) = task.scan.as_ref().and_then(|scan| scan.output.as_ref()) else {
        return Ok(None);
    };
    let path = dir.join("scan_output");
    client.download(&output.download, &path).await?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    Ok(Some(path))
}

/// Uploads each file a result adds from the task's output directory, then ends the task. A 422 is
/// an end too, to the end or to an upload's URL: the core rejected the result, or the upload, and
/// failed the task, and its row says why.
pub async fn send_end(
    client: &LeaseClient,
    task: &LeasedTask,
    outputs: &LocalFileStore,
    end: &TaskEnd,
) -> Result<(), ClientError> {
    let uploads: Vec<(&ace_results::Sha256, u64)> = match end {
        TaskEnd::Done { result, .. } | TaskEnd::Incomplete { result, .. } => result
            .files
            .iter()
            .map(|f| (&f.sha256, f.size))
            .chain(result.stored.iter().map(|f| (&f.sha256, f.size)))
            .collect(),
        // a scan's inputs the module wrote (`TaskContext::write_scan_input`); its own file is
        // already in the bucket
        TaskEnd::Delay {
            scan: Some(scan), ..
        } => scan.inputs.iter().map(|i| (&i.sha256, i.size)).collect(),
        _ => Vec::new(),
    };
    {
        let mut sent = Vec::new();
        for (sha256, size) in uploads {
            let path = outputs.path_of(sha256);
            // a file a read put in the root, or another result stored there, is already in the
            // bucket, and the core checks that it is, and that the module may add one (`reads.md`,
            // `Module::ADDS_STORED_FILES`)
            if !path.exists() || sent.contains(&sha256) {
                continue;
            }
            sent.push(sha256);
            let url = match client.upload_url(task.id, sha256, size).await {
                // the core refused the upload and failed the task, saying why: a lookup that
                // doesn't declare fetched files (`Module::ADDS_FETCHED_FILES`, PLAN.md decision 28)
                Err(ClientError::Api { status: 422, error }) => {
                    tracing::error!(
                        task = task.id,
                        "the core refused the upload: {}",
                        error.error
                    );
                    return Ok(());
                }
                url => url?,
            };
            client.upload(&url, &path).await?;
        }
    }
    match client.end(task.id, end).await {
        Err(ClientError::Api { status: 422, error }) => {
            tracing::error!(
                task = task.id,
                "the core rejected the result: {}",
                error.error
            );
            Ok(())
        }
        sent => sent,
    }
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
    // a lookup parses nothing hostile, so it gets a file's record and not its bytes: its pool
    // can't reach the bucket (`pool::lookup_sandbox`), unless a module of it adds files it fetched,
    // which it uploads and never downloads (PLAN.md decision 28)
    let parser = modules.parser(&task.module).is_some();
    let input = async {
        if parser {
            fetch_input(client, &task, &dir).await
        } else {
            Ok(None)
        }
    }
    .instrument(tracing::info_span!("fetch_input"))
    .await?;
    let email_parts = fetch_email_parts(client, &task, dir.path()).await?;
    let tree_files = fetch_tree_files(client, &task, dir.path()).await?;
    let scan_output = fetch_scan_output(client, &task, dir.path()).await?;
    let outputs = Arc::new(LocalFileStore::new(dir.outputs())?);
    // the module's own span (ace_sdk::module::task_span) is a child of this task's
    let span = tracing::Span::current();
    let cancel = keeper.token().clone();
    // each module runs in a task of its own, so a panic ends that task and fails it
    let (owned_modules, owned_task, owned_outputs, reads) = (
        modules.clone(),
        task.clone(),
        outputs.clone(),
        client.reads(),
    );
    let tools = modules.local_tools(&task.module)?;
    let joined = if modules.parser(&task.module).is_some() {
        tokio::task::spawn_blocking(move || match owned_modules.parser(&owned_task.module) {
            Some(parser) => span.in_scope(|| {
                parser.run(Run {
                    task: &owned_task,
                    input: input.as_deref(),
                    email_parts: &email_parts,
                    tree_files: tree_files.as_deref(),
                    outputs: owned_outputs,
                    cancel,
                    contained: false,
                    reader: None,
                    tools,
                    scan_output: scan_output.as_deref(),
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
                                email_parts: &email_parts,
                                tree_files: tree_files.as_deref(),
                                outputs: owned_outputs,
                                cancel,
                                contained: false,
                                reader: Some(Arc::new(reads)),
                                tools: None,
                                scan_output: None,
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
