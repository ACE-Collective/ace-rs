//! `ace schema`: the JSON Schema of each analysis type the binary's modules write (PLAN.md 1.16).

use std::path::PathBuf;
use std::process::ExitCode;

use ace_results::Registry;
use anyhow::{Context, Result};
use clap::Subcommand;

use crate::App;

#[derive(Subcommand)]
pub enum SchemaCommand {
    /// Write each analysis type's JSON Schema to a directory, one file per type.
    Export {
        /// The directory to write to. It's created if it doesn't exist.
        dir: PathBuf,
    },
}

pub fn run(app: &App, command: SchemaCommand) -> Result<ExitCode> {
    match command {
        SchemaCommand::Export { dir } => {
            let outputs: Vec<_> = app
                .registry()
                .manifests()
                .iter()
                .map(|m| m.output)
                .collect();
            let written = Registry::new(&outputs)
                .context("the modules' analysis types")?
                .export_schemas(&dir)
                .with_context(|| format!("writing schemas to {}", dir.display()))?;
            for path in &written {
                println!("{}", path.display());
            }
            eprintln!("ace: wrote {} schemas to {}", written.len(), dir.display());
            Ok(ExitCode::SUCCESS)
        }
    }
}
