//! `ace task`: tools for one task. `ace task replay <id>` (PLAN.md 2.20) fetches a task's input
//! from the bucket by hash, through the lease API, and runs its module here, outside
//! containment, so a debugger can attach. It needs `ACE_RS_API_URL` and `ACE_RS_ADMIN_TOKEN`, and
//! the site overlay at `ACE_RS_OVERLAY` when the task's component needs settings, such as the
//! YARA module's signature directory or a Splunk instance's query, and for the secrets the
//! module declares.

use std::path::PathBuf;
use std::process::ExitCode;

use ace_pool::client::LeaseClient;
use anyhow::{Context, Result, bail};
use clap::Subcommand;

use crate::App;

#[derive(Subcommand)]
pub enum TaskCommand {
    /// Run a task's module again on its inputs, here and uncontained. The task's row stays as it
    /// was.
    Replay {
        /// The task's id.
        id: i64,
        /// Keep the input and the module's outputs in this directory.
        #[arg(long)]
        keep: Option<PathBuf>,
    },
}

pub fn run(app: &App, command: TaskCommand) -> Result<ExitCode> {
    let TaskCommand::Replay { id, keep } = command;
    let registry = app.registry();
    let overlay = crate::cli::overlay(app)?;
    let components = crate::cli::components(&registry, &overlay)?;
    let base = std::env::var("ACE_RS_API_URL").context("ACE_RS_API_URL isn't set")?;
    let token = std::env::var("ACE_RS_ADMIN_TOKEN").context("ACE_RS_ADMIN_TOKEN isn't set")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let client = LeaseClient::new(&base, &token, "replay")?;
        let task = client.replay_task(id).await?;
        // only the task's component, so the others need no settings
        let Some(component) = components.iter().find(|c| c.key == task.module) else {
            bail!("this binary has no module {}", task.module);
        };
        // and only the secrets its module declares and its connections name
        let secrets = ace_pool::secrets::resolve_components(
            "replay",
            std::slice::from_ref(component),
            &overlay,
            &ace_pool::secrets::process_env,
        );
        // with every pool's tools, which a replay runs as plain processes
        let modules = registry
            .build(std::slice::from_ref(component), &secrets)?
            .with_tools(&app.tools());
        let temp;
        let dir = match keep {
            Some(dir) => {
                std::fs::create_dir_all(&dir)?;
                dir
            }
            None => {
                temp = tempfile::tempdir()?;
                temp.path().to_owned()
            }
        };
        let end = ace_pool::replay::replay_task(&client, &modules, &task, &dir).await?;
        println!("{}", serde_json::to_string_pretty(&end)?);
        Ok(ExitCode::SUCCESS)
    })
}
