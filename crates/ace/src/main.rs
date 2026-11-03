//! The `ace` command.

mod schema;
mod serve;
mod site;
mod task;
mod yara;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
    /// Serve the lease API to workers, and take back tasks whose lease expired.
    Serve,
    /// Tools for one task, such as replaying it.
    #[command(subcommand)]
    Task(task::TaskCommand),
}

fn main() -> ExitCode {
    // Logs go to stderr, filtered by ACE4_LOG (tracing's EnvFilter syntax), WARN and up by
    // default. `ace serve` also exports spans when ACE4_OTLP_ENDPOINT is set.
    let mut telemetry = ace_pool::telemetry::init("ace", "warn");

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Schema(command) => schema::run(command),
        Command::Yara(command) => yara::run(command),
        Command::Serve => serve::run(&mut telemetry),
        Command::Task(command) => task::run(command),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ace: {e:#}");
            ExitCode::FAILURE
        }
    }
}
