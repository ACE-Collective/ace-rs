//! The task process's side of the supervisor (PLAN.md 2.17): what a parser pool's binary runs
//! in its `task` mode.
//!
//! It reads a `TaskRequest` from stdin, builds the one module the request names, contains itself,
//! runs the module on one thread and writes the task's end as JSON to stdout. Its exit code is
//! one of the supervisor's (`EXIT_DONE`, `EXIT_SETUP`, `EXIT_MODULE`).
//!
//! The module is built before containment, so its setup, such as loading a ruleset or reading
//! libmagic's database, can read files the contained process can't. It is built from the request's
//! settings block, which the supervisor loaded and built the same module from when the pool
//! started, and from nothing else in the request: `Module::init` takes its settings only. No
//! other module of the pool is built, so a task pays for its own module's setup and holds only
//! what its own module read.
//!
//! The request is read before the module is built, because it names the module. It was always
//! read and parsed before containment; what the module does with the task's input still comes
//! after.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use ace_sdk::wire::TaskEnd;
use ace_sdk::{Component, LocalFileStore, Manifest, Secrets};
use tokio_util::sync::CancellationToken;

use crate::containment::contain;
use crate::modules::{Registry, Run};
use crate::supervisor::{EXIT_MODULE, EXIT_SETUP, TaskRequest};
use crate::tools::SocketRunner;
use ace_sdk::tools::ToolRunner;

fn setup_failed(why: impl std::fmt::Display) -> ExitCode {
    eprintln!("setup failed: {why}");
    exit(EXIT_SETUP)
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX))
}

/// The secrets a task process gives its module: those `manifest` declares and no others
/// (PLAN.md 2.24), or why they can't be read. It is asked once, for the task's own module.
pub type TaskSecrets<'a> = &'a dyn Fn(&Manifest) -> Result<Secrets, String>;

/// Runs one task in this process, contained, and returns the process's exit code. Of
/// `registry`'s modules it builds the one the request on stdin names, with the request's
/// settings and what `secrets` gives for it.
pub fn main(registry: &Registry, secrets: TaskSecrets<'_>) -> ExitCode {
    let mut bytes = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut bytes) {
        return setup_failed(format!("reading the request: {e}"));
    }
    let request: TaskRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(e) => return setup_failed(format!("the request doesn't read: {e}")),
    };
    let unknown = || setup_failed(format!("this pool doesn't run {}", request.task.module));
    let Some(manifest) = registry.manifest(&request.module) else {
        return unknown();
    };
    let component = Component {
        key: request.task.module.clone(),
        settings: request.settings.clone(),
        ..Component::of(manifest)
    };
    let secrets = match secrets(&manifest) {
        Ok(secrets) => secrets,
        Err(e) => return setup_failed(e),
    };
    let modules = match registry.build(std::slice::from_ref(&component), &secrets) {
        Ok(modules) => modules,
        Err(e) => return setup_failed(e),
    };
    // a lookup isn't run in a task process
    let Some(parser) = modules.parser(&request.task.module) else {
        return unknown();
    };
    let outputs = match LocalFileStore::new(&request.outputs) {
        Ok(outputs) => Arc::new(outputs),
        Err(e) => return setup_failed(format!("the output directory: {e}")),
    };
    // the supervisor's socket for the module's tools, taken before containment
    let tools: Option<Arc<dyn ToolRunner>> = match &request.tools {
        Some(scratch) => match SocketRunner::from_fd(scratch.clone()) {
            Ok(runner) => Some(Arc::new(runner)),
            Err(e) => return setup_failed(format!("the tool socket: {e}")),
        },
        None => None,
    };
    match contain(&request.profile) {
        Ok(contained) => eprintln!("contained: {contained:?}"),
        Err(e) => return setup_failed(format!("containment: {e}")),
    }
    let end = parser.run(Run {
        task: &request.task,
        input: request.input.as_deref(),
        email_parts: &request.email_parts,
        tree_files: request.tree_files.as_deref(),
        outputs,
        // the supervisor kills the process instead
        cancel: CancellationToken::new(),
        contained: true,
        // a parser declares no reads
        reader: None,
        tools,
        scan_output: request.scan_output.as_deref(),
        // a parser's tools have its scratch directory
        task_dir: None,
    });
    let reply = match serde_json::to_vec(&end) {
        Ok(reply) => reply,
        Err(e) => return setup_failed(format!("the reply doesn't serialize: {e}")),
    };
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = stdout.write_all(&reply).and_then(|()| stdout.flush()) {
        eprintln!("writing the reply: {e}");
        return exit(EXIT_SETUP);
    }
    match end {
        TaskEnd::Failed { .. } => exit(EXIT_MODULE),
        _ => ExitCode::SUCCESS,
    }
}
