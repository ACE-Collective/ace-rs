//! `ace schema`: the JSON Schema of each analysis type the binary's modules write (PLAN.md 1.16),
//! and the core's check of a result against it, for whoever writes a module without Rust's types
//! to catch a wrong field (PLAN.md 4.2).

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
    /// Check a result in a JSON file, the `result` a module returns, as the core does. It prints
    /// each field that fails and exits 1.
    Check {
        /// The file. The type it names in `analysis_type` and `schema_version` says the schema.
        result: PathBuf,
    },
}

fn registry(app: &App) -> Result<Registry> {
    let outputs: Vec<_> = app
        .registry()
        .manifests()
        .iter()
        .map(|m| m.output)
        .collect();
    Registry::new(&outputs).context("the modules' analysis types")
}

pub fn run(app: &App, command: SchemaCommand) -> Result<ExitCode> {
    match command {
        SchemaCommand::Export { dir } => {
            let written = registry(app)?
                .export_schemas(&dir)
                .with_context(|| format!("writing schemas to {}", dir.display()))?;
            for path in &written {
                println!("{}", path.display());
            }
            eprintln!("ace: wrote {} schemas to {}", written.len(), dir.display());
            Ok(ExitCode::SUCCESS)
        }
        SchemaCommand::Check { result } => {
            let text = std::fs::read_to_string(&result)
                .with_context(|| format!("reading {}", result.display()))?;
            let value = serde_json::from_str(&text)
                .with_context(|| format!("{} isn't JSON", result.display()))?;
            match registry(app)?.validate(&value) {
                Ok(()) => {
                    println!("{}: valid", result.display());
                    Ok(ExitCode::SUCCESS)
                }
                Err(invalid) => {
                    if invalid.fields().is_empty() {
                        println!("{}: {invalid}", result.display());
                    }
                    for field in invalid.fields() {
                        println!("{}: {field}", result.display());
                    }
                    Ok(ExitCode::FAILURE)
                }
            }
        }
    }
}
