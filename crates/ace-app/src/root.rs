//! `ace root`: tools for one root. `ace root normal-form <uuid>` (PLAN.md 3.1) prints the root's
//! tree in the form ace3's can be compared with. It reads Postgres directly, so it runs where
//! `ace serve` does, with `ACE4_DATABASE_URL`.

use std::process::ExitCode;

use ace_core::db::{Db, DbConfig};
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use uuid::Uuid;

#[derive(Subcommand)]
pub enum RootCommand {
    /// Print a root's tree as JSON, with a fixed order and nothing that says when or where it
    /// ran.
    NormalForm {
        /// The root's uuid.
        root: Uuid,
    },
}

pub fn run(command: RootCommand) -> Result<ExitCode> {
    let RootCommand::NormalForm { root } = command;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let db = Db::connect(&DbConfig::from_env("ace")?)
            .await
            .context("connecting to Postgres")?;
        let Some(form) = ace_core::normal::normal_form(db.pool(), root).await? else {
            bail!("no root {root}");
        };
        print!("{}", ace_core::normal::to_text(&form)?);
        Ok(ExitCode::SUCCESS)
    })
}
