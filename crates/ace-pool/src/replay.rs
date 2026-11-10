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
    // as a pool runs it: a lookup gets no file bytes
    let input = match &task.observable.file {
        Some(file) if modules.parser(&task.module).is_some() => {
            let path = dir.join("input");
            client.download(&file.download, &path).await?;
            Some(path)
        }
        _ => None,
    };
    let email_body = crate::run::fetch_email_body(client, task, dir).await?;
    let tree_files = crate::run::fetch_tree_files(client, task, dir).await?;
    let outputs = Arc::new(LocalFileStore::new(dir.join("outputs"))?);
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
        email_body: email_body.as_deref(),
        tree_files: tree_files.as_deref(),
        outputs,
        cancel: CancellationToken::new(),
        contained: false,
        // a replay holds no lease, so its reads go to the admin route
        reader: Some(Arc::new(client.replay_reads())),
    };
    if let Some(parser) = modules.parser(&task.module) {
        Ok(tokio::task::block_in_place(|| parser.run(run)))
    } else if let Some(lookup) = modules.lookup(&task.module) {
        Ok(lookup.run(run).await)
    } else {
        Ok(TaskEnd::Failed {
            error: format!("no module {} to replay with", task.module),
        })
    }
}
