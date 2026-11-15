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
    /// Checks of a signatures checkout, such as the one an author runs before a push.
    #[command(subcommand)]
    Signatures(crate::signatures::SignaturesCommand),
    /// The Signature Validation System: YARA validation, by hand.
    #[command(subcommand)]
    Svs(crate::svs::SvsCommand),
    /// Serve the lease API to workers and the JSON API to people, and take back tasks whose lease
    /// expired.
    Serve,
    /// Run the hunts in the signatures checkout on their schedules and submit what they find
    /// (`ACE4_HUNTER` names its configuration).
    Hunter,
    /// Tools for one task, such as replaying it.
    #[command(subcommand)]
    Task(crate::task::TaskCommand),
    /// Tools for one root, such as writing its tree in the normal form.
    #[command(subcommand)]
    Root(crate::root::RootCommand),
    /// Accounts and keys an operator makes, starting with the first admin.
    #[command(subcommand)]
    User(crate::user::UserCommand),
    Compare(crate::compare::CompareArgs),
}

/// Runs `ace` on `argv`, the words after it, in a GUI command's contained process (PLAN.md 5.12): with no
/// paths, no ports and no credentials, as `ace_pool::commands` runs it. It's this binary's own parser, so
/// what an analyst types gets the help and the usage errors a shell would, as in ace3. Every command
/// still needs something a contained process can't have, so each is refused with the reason, and only
/// `--help`, a command's `--help` and `--version` run. The process's stdout and stderr are the output.
///
/// ace3's GUI runs any `ace` command but global options and secrets (`ace3/docs/GUI_CLI.md`). Of
/// ace3's commands, ace4 has `yara scan` (here over a ruleset file, not ace3's scanner service) and
/// `user`, whose `create-first` and `create-key` are an operator's, not ace3's `user add`. ace4's
/// `svs yara` is ace3's (`validate`, `layout`, `prune`), as are `svs catalog` (`refresh`, `status`) and `svs coverage` (`refresh`, `status`, `snapshot`), and `svs
/// attack extract` is ace3's `bin/update-attack-catalog`; each is refused like the rest. ace4's `signatures check` is new; ace3's `signatures` lists what a node loads (`list`, `locations`) and
/// builds the Suricata lookup (`build-db`). ace3's other commands (`alert`, `cache`, `cas`,
/// `company`, `config`, `correlate`, `crash`, `cron`, `encryption`, `event`, `gui`, `hunt`,
/// `integration`, `js-deobfuscator`, `modules`, `node`, `nrd`, `observables`, `partitions`, `perm`,
/// `persistence`, `phishkit`, `remediation`, `search`, `service`, `storage`, `submit`, `test`
/// and `yara-qa`), and those `signatures` subcommands, wait for the steps that bring what they act
/// on.
pub(crate) fn run_contained(argv: &[String]) -> u8 {
    let words = std::iter::once("ace".to_owned()).chain(argv.iter().cloned());
    match Cli::try_parse_from(words) {
        // help and version are clap's "errors", written to stdout with exit code 0
        Err(e) => {
            if let Err(write) = e.print() {
                eprintln!("ace: writing the output: {write}");
            }
            u8::try_from(e.exit_code()).unwrap_or(2)
        }
        Ok(cli) => {
            let (name, why) = refusal(&cli.command);
            eprintln!("ace {name} doesn't run from the GUI: {why}");
            2
        }
    }
}

/// Why a command can't run as a GUI command: what it needs that a contained process has none of.
fn refusal(command: &Command) -> (&'static str, &'static str) {
    match command {
        Command::Schema(_) => (
            "schema",
            "it reads and writes files on the node, and a GUI command can open none",
        ),
        Command::Yara(_) => (
            "yara",
            "it reads signature directories and files on the node, and a GUI command can open none",
        ),
        Command::Signatures(_) => (
            "signatures",
            "it reads a signatures checkout on the node, and a GUI command can open none",
        ),
        Command::Svs(_) => (
            "svs",
            "it reads Postgres, the bucket and files on the node, and a GUI command holds no credentials \
             for the first two and can open none of the last",
        ),
        Command::Serve => ("serve", "it's the service itself, not a command"),
        Command::Hunter => ("hunter", "it's a service of its own, not a command"),
        Command::Task(_) => (
            "task",
            "a replay runs a module uncontained on purpose, so it runs from a shell",
        ),
        Command::Root(_) => (
            "root",
            "it reads Postgres, and a GUI command holds no database credentials",
        ),
        Command::User(_) => (
            "user",
            "it writes users and keys with the database's credentials, which only an operator's \
             shell holds; Administration's Users & Roles does the same through the service",
        ),
        Command::Compare(_) => (
            "compare",
            "it reads Postgres and ace3's API, and a GUI command can reach neither",
        ),
    }
}

pub fn main(app: &App) -> ExitCode {
    // Logs go to stderr, filtered by ACE4_LOG (tracing's EnvFilter syntax), WARN and up by
    // default. `ace serve` also exports spans when ACE4_OTLP_ENDPOINT is set.
    // `ace signatures check` reports each rule file that doesn't compile itself, so ace-yara's log of
    // the file it leaves out would say it twice.
    let cli = Cli::parse();
    let default_filter = match cli.command {
        Command::Signatures(_) => "warn,ace_yara::load=off",
        _ => "warn",
    };
    let mut telemetry = ace_pool::telemetry::init("ace", default_filter);

    let result = match cli.command {
        Command::Schema(command) => crate::schema::run(app, command),
        Command::Yara(command) => crate::yara::run(command),
        Command::Signatures(command) => crate::signatures::run(app, command),
        Command::Svs(command) => crate::svs::run(app, command),
        Command::Serve => crate::serve::run(app, &mut telemetry),
        Command::Hunter => crate::hunter::run(app, &mut telemetry),
        Command::Task(command) => crate::task::run(app, command),
        Command::Root(command) => crate::root::run(command),
        Command::User(command) => crate::user::run(app, command),
        Command::Compare(args) => crate::compare::run(app, args),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    /// A GUI command gets `ace`'s own help and usage errors, and every command is refused with why
    /// (PLAN.md 5.12).
    #[test]
    fn a_gui_command_runs_ace_s_own_parser() {
        assert_eq!(run_contained(&words("--help")), 0);
        assert_eq!(run_contained(&words("yara --help")), 0);
        assert_eq!(run_contained(&words("--version")), 0);
        assert_eq!(run_contained(&words("no-such-command")), 2);
        for line in [
            "serve",
            "schema export /tmp/x",
            "yara scan --rules /x f",
            "signatures check /x",
            "svs yara layout",
            "svs catalog status",
            "svs catalog refresh --force",
            "svs coverage status",
            "svs coverage refresh",
            "svs coverage snapshot",
            "svs attack extract v20.0 --input /x",
            "task replay 1",
            "root normal-form 00000000-0000-0000-0000-000000000000",
            "user create-key k --grant alert:read",
        ] {
            assert_eq!(run_contained(&words(line)), 2, "{line}");
        }
    }
}
