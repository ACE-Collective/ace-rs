//! `ace task`: tools for one task. `ace task replay <id>` (PLAN.md 2.20) fetches a task's input
//! from the bucket by hash, through the lease API, and runs its module here, outside
//! containment, so a debugger can attach. It needs `ACE4_API_URL` and `ACE4_ADMIN_TOKEN`, and
//! the module's settings block when the module needs one, such as the YARA module's
//! signature directory.

use std::path::PathBuf;
use std::process::ExitCode;

use ace_pool::client::LeaseClient;
use ace_pool::modules::{Entry, Modules};
use ace_sdk::Secrets;
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde_json::Value;

#[derive(Subcommand)]
pub enum TaskCommand {
    /// Run a task's module again on its inputs, here and uncontained. The task's row stays as it
    /// was.
    Replay {
        /// The task's id.
        id: i64,
        /// The module's settings block, as JSON.
        #[arg(long)]
        settings: Option<String>,
        /// Keep the input and the module's outputs in this directory.
        #[arg(long)]
        keep: Option<PathBuf>,
    },
}

pub fn run(command: TaskCommand) -> Result<ExitCode> {
    let TaskCommand::Replay { id, settings, keep } = command;
    let settings: Option<Value> = settings
        .map(|text| serde_json::from_str(&text))
        .transpose()
        .context("--settings isn't JSON")?;
    let base = std::env::var("ACE4_API_URL").context("ACE4_API_URL isn't set")?;
    let token = std::env::var("ACE4_ADMIN_TOKEN").context("ACE4_ADMIN_TOKEN isn't set")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let client = LeaseClient::new(&base, &token, "replay")?;
        let task = client.replay_task(id).await?;
        let modules = module(&task.module, settings.as_ref())?;
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

/// Only the module the task needs, so the others need no settings.
fn module(name: &str, settings: Option<&Value>) -> Result<Modules> {
    let secrets = Secrets::new();
    Ok(match name {
        "email_analyzer" => Modules::new().with_parser(
            Entry::<ace_mod_email::EmailAnalyzer>::parser(settings, &secrets)?,
        ),
        "archive" => Modules::new().with_parser(Entry::<ace_mod_archive::ArchiveAnalyzer>::parser(
            settings, &secrets,
        )?),
        "yara_scanner_v3_4" => Modules::new().with_parser(
            Entry::<ace_mod_yara::YaraScanner>::parser(settings, &secrets)?,
        ),
        "rdap_analyzer" => Modules::new().with_lookup(Entry::<ace_mod_rdap::RdapAnalyzer>::lookup(
            settings, &secrets,
        )?),
        "splunk_api" => Modules::new().with_lookup(
            Entry::<ace_mod_splunk::SplunkAnalyzer>::lookup(settings, &secrets)?,
        ),
        other => bail!("this binary has no module {other}"),
    })
}
