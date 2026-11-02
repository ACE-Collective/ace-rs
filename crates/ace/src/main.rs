//! The `ace` command.

mod schema;
mod yara;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

/// ACE: the analysis correlation engine.
#[derive(Parser)]
#[command(name = "ace", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// JSON Schemas of the analysis types.
    #[command(subcommand)]
    Schema(schema::SchemaCommand),
    /// YARA rulesets and scans.
    #[command(subcommand)]
    Yara(yara::YaraCommand),
}

fn main() -> ExitCode {
    // Logs go to stderr, filtered by ACE4_LOG (tracing's EnvFilter syntax), WARN and up by
    // default.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_env("ACE4_LOG").unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Schema(command) => schema::run(command),
        Command::Yara(command) => yara::run(command),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ace: {e:#}");
            ExitCode::FAILURE
        }
    }
}
