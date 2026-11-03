//! The `ace` command.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::App;

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
    Schema(crate::schema::SchemaCommand),
    /// YARA rulesets and scans.
    #[command(subcommand)]
    Yara(crate::yara::YaraCommand),
    /// Serve the lease API to workers, and take back tasks whose lease expired.
    Serve,
    /// Tools for one task, such as replaying it.
    #[command(subcommand)]
    Task(crate::task::TaskCommand),
}

pub fn main(app: &App) -> ExitCode {
    // Logs go to stderr, filtered by ACE4_LOG (tracing's EnvFilter syntax), WARN and up by
    // default. `ace serve` also exports spans when ACE4_OTLP_ENDPOINT is set.
    let mut telemetry = ace_pool::telemetry::init("ace", "warn");

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Schema(command) => crate::schema::run(app, command),
        Command::Yara(command) => crate::yara::run(command),
        Command::Serve => crate::serve::run(app, &mut telemetry),
        Command::Task(command) => crate::task::run(app, command),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ace: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// The overlay at `ACE4_OVERLAY`, or none. With none, every module runs as itself on its
/// defaults.
pub fn overlay() -> anyhow::Result<ace_sdk::Overlay> {
    match std::env::var_os("ACE4_OVERLAY").filter(|path| !path.is_empty()) {
        Some(path) => Ok(ace_sdk::Overlay::read(path.as_ref())?),
        None => Ok(ace_sdk::Overlay::default()),
    }
}

/// The components the overlay makes of the binary's modules.
pub fn components(
    registry: &ace_pool::modules::Registry,
    overlay: &ace_sdk::Overlay,
) -> anyhow::Result<Vec<ace_sdk::Component>> {
    use anyhow::Context;
    overlay
        .components(&registry.manifests())
        .context("loading the site overlay")
}
