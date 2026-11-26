//! Replaying a task (PLAN.md 2.20), as `ace task replay <id>` does: its input fetched from the
//! bucket by hash, through the lease API, and its module run in this process, outside
//! containment, so a debugger can attach. The replay takes no lease and ends nothing: the task's
//! row stays as it was.

use std::path::Path;
use std::sync::Arc;

use ace_sdk::LocalFileStore;
use ace_sdk::wire::TaskEnd;
use tokio_util::sync::CancellationToken;

use crate::client::{ClientError, LeaseClient};
use crate::modules::{Modules, Run};

/// Replays task `id` with `modules`, keeping its input and outputs in `dir`, and returns how it
/// ended. A parser runs on this thread, so a hung module hangs here, where a debugger can see
/// it.
pub async fn replay(
    client: &LeaseClient,
    modules: &Modules,
    id: i64,
    dir: &Path,
) -> Result<TaskEnd, ClientError> {
    let task = client.replay_task(id).await?;
    replay_task(client, modules, &task, dir).await
}

/// `replay` for a task already fetched with `LeaseClient::replay_task`, as when the caller
/// builds only the module the task needs.
pub async fn replay_task(
    client: &LeaseClient,
    modules: &Modules,
    task: &ace_sdk::wire::LeasedTask,
    dir: &Path,
) -> Result<TaskEnd, ClientError> {
    // as a pool runs it: a lookup gets no file bytes unless it reads them
    // (`Module::READS_INPUT_FILE`), and the core sends a download only then
    let reads_input = modules.parser(&task.module).is_some()
        || modules
            .lookup(&task.module)
            .is_some_and(|lookup| lookup.manifest().reads_input_file);
    let input = match task
        .observable
        .file
        .as_ref()
        .and_then(|file| file.download.as_ref())
    {
        Some(download) if reads_input => {
            let path = dir.join("input");
            client.download(download, &path).await?;
            Some(path)
        }
        _ => None,
    };
    let email_parts = crate::run::fetch_email_parts(client, task, dir).await?;
    let tree_files = crate::run::fetch_tree_files(client, task, dir).await?;
    let outputs = Arc::new(LocalFileStore::new(dir.join("outputs"))?);
    // a lookup's directory for its temporary files (PLAN.md decision 61), kept in `dir` with its
    // input and outputs for whoever replays it to look at
    let lookup_dir = match modules.lookup(&task.module) {
        Some(_) => {
            let lookup_dir = dir.join("lookup");
            std::fs::create_dir_all(&lookup_dir)?;
            Some(lookup_dir)
        }
        None => None,
    };
    eprintln!(
        "replaying task {} ({} on {} {}) uncontained, in process {}, from {}",
        task.id,
        task.module,
        task.observable.kind,
        task.observable.value,
        std::process::id(),
        dir.display()
    );
    let run = Run {
        task,
        input: input.as_deref(),
        email_parts: &email_parts,
        tree_files: tree_files.as_deref(),
        outputs,
        cancel: CancellationToken::new(),
        contained: false,
        // a replay holds no lease, so its reads go to the admin route
        reader: Some(Arc::new(client.replay_reads())),
        // and runs its tools as plain processes, as it runs the module
        tools: modules.local_tools(&task.module)?,
        scan_output: None,
        task_dir: lookup_dir.as_deref(),
    };
    if let Some(parser) = modules.parser(&task.module) {
        Ok(tokio::task::block_in_place(|| parser.run(run)).end)
    } else if let Some(lookup) = modules.lookup(&task.module) {
        Ok(lookup.run(run).await.end)
    } else {
        Ok(TaskEnd::Failed {
            error: format!("no module {} to replay with", task.module),
        })
    }
}
