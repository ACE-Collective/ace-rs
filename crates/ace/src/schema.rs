//! `ace schema`: the JSON Schema of each analysis type (PLAN.md 1.16).

use std::path::PathBuf;
use std::process::ExitCode;

use ace_results::Registry;
use anyhow::{Context, Result};
use clap::Subcommand;

#[derive(Subcommand)]
pub enum SchemaCommand {
    /// Write each analysis type's JSON Schema to a directory, one file per type.
    Export {
        /// The directory to write to. It's created if it doesn't exist.
        dir: PathBuf,
    },
}

pub fn run(command: SchemaCommand) -> Result<ExitCode> {
    match command {
        SchemaCommand::Export { dir } => {
            let written = Registry::builtin()
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
