//! The task process's side of the supervisor (PLAN.md 2.17): what a parser pool's binary runs
//! in its `task` mode.
//!
//! It reads a `TaskRequest` from stdin, contains itself, runs the module on one thread and
//! writes the task's end as JSON to stdout. Its exit code is one of the supervisor's
//! (`EXIT_DONE`, `EXIT_SETUP`, `EXIT_MODULE`). The pool's modules are built before `main` is
//! called, so a module's setup, such as loading a ruleset, happens before containment.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::Arc;

use ace_sdk::LocalFileStore;
use ace_sdk::wire::TaskEnd;
use tokio_util::sync::CancellationToken;

use crate::containment::contain;
use crate::modules::{Modules, Run};
use crate::supervisor::{EXIT_MODULE, EXIT_SETUP, TaskRequest};

fn setup_failed(why: impl std::fmt::Display) -> ExitCode {
    eprintln!("setup failed: {why}");
    exit(EXIT_SETUP)
}

fn exit(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX))
}

/// Runs one task in this process, contained, and returns the process's exit code.
pub fn main(modules: &Modules) -> ExitCode {
    let mut bytes = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut bytes) {
        return setup_failed(format!("reading the request: {e}"));
    }
    let request: TaskRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(e) => return setup_failed(format!("the request doesn't read: {e}")),
    };
    let Some(parser) = modules.parser(&request.task.module) else {
        return setup_failed(format!("this pool doesn't run {}", request.task.module));
    };
    let outputs = match LocalFileStore::new(&request.outputs) {
        Ok(outputs) => Arc::new(outputs),
        Err(e) => return setup_failed(format!("the output directory: {e}")),
    };
    match contain(&request.profile) {
        Ok(contained) => eprintln!("contained: {contained:?}"),
        Err(e) => return setup_failed(format!("containment: {e}")),
    }
    let end = parser.run(Run {
        task: &request.task,
        input: request.input.as_deref(),
        outputs,
        // the supervisor kills the process instead
        cancel: CancellationToken::new(),
        contained: true,
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
