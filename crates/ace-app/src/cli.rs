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
    /// The Signature Validation System, by hand: YARA rule validation, the Atomic Red Team test
    /// catalog, ATT&CK coverage and the ATT&CK release it's computed against.
    #[command(subcommand)]
    Svs(crate::svs::SvsCommand),
    /// Serve the lease API to workers and the JSON API to people, and take back tasks whose lease
    /// expired.
    Serve,
    /// Serve the AI investigation API on a listener of its own, as a process that holds no key, token
    /// or database privilege the API doesn't need, and refuses to start if it is handed one.
    ServeAi,
    /// Run the hunts in the signatures checkout on their schedules and submit what they find
    /// (`ACE_RS_HUNTER` names its configuration).
    Hunter,
    /// Run the collector NAME, which the binary has, until a stop: it reads its source and submits
    /// what it finds, each item once (the overlay's `collectors.NAME`).
    Collect {
        /// The collector, as the binary names it.
        name: String,
    },
    /// Run the detection export NAME, which the binary has, until a stop: it publishes the observables
    /// enabled for detection to a system outside ACE when they change (the overlay's `exports.NAME`,
    /// which must say `enabled: true`).
    Export {
        /// The export, as the binary names it.
        name: String,
        /// Run one pass, then exit: 0 when it published or had nothing to, 1 when it failed.
        #[arg(long)]
        once: bool,
        /// With --once: publish everything, whatever the export last published.
        #[arg(long)]
        force: bool,
    },
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
/// ace3's commands, ace-rs has `yara scan` (here over a ruleset file, not ace3's scanner service) and
/// `user`, whose `create-first` and `create-key` are an operator's, not ace3's `user add`. ace-rs's
/// `svs yara` is ace3's (`validate`, `layout`, `prune`), as are `svs catalog` (`refresh`, `status`) and `svs coverage` (`refresh`, `status`, `snapshot`), and `svs
/// attack extract` is ace3's `bin/update-attack-catalog`; each is refused like the rest. ace-rs's `signatures check` is new; ace3's `signatures` lists what a node loads (`list`, `locations`) and
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
        Command::ServeAi => ("serve-ai", "it's a service of its own, not a command"),
        Command::Hunter => ("hunter", "it's a service of its own, not a command"),
        Command::Collect { .. } => (
            "collect",
            "a collector is a service of its own, not a command",
        ),
        Command::Export { .. } => (
            "export",
            "a detection export is a service of its own, and holds a credential a GUI command has none of",
        ),
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
    // Logs go to stderr, filtered by ACE_RS_LOG (tracing's EnvFilter syntax), WARN and up by
    // default. `ace serve` also exports spans when ACE_RS_OTLP_ENDPOINT is set.
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
        Command::ServeAi => crate::serve_ai::run(app, &mut telemetry),
        Command::Hunter => crate::hunter::run(app, &mut telemetry),
        Command::Collect { name } => crate::collector::run(app, &name, &mut telemetry),
        Command::Export { name, once, force } => {
            crate::export::run(app, &name, once, force, &mut telemetry)
        }
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

/// The overlay at `ACE_RS_OVERLAY`, or none, checked against the binary (`App::check_overlay`). With
/// none, every module runs as itself on its defaults.
pub fn overlay(app: &App) -> anyhow::Result<ace_sdk::Overlay> {
    let overlay = match std::env::var_os("ACE_RS_OVERLAY").filter(|path| !path.is_empty()) {
        Some(path) => ace_sdk::Overlay::read(path.as_ref())?,
        None => ace_sdk::Overlay::default(),
    };
    app.check_overlay(&overlay).map_err(anyhow::Error::msg)?;
    Ok(overlay)
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

/// The overlay's global observable exclusions over ace3's (`ace_sdk::exclusions`), which every
/// orchestrator that queues tasks keeps off what they name.
pub fn exclusions(overlay: &ace_sdk::Overlay) -> anyhow::Result<ace_sdk::exclusions::Exclusions> {
    ace_sdk::exclusions::Exclusions::from_section(&overlay.observable_exclusions)
        .map_err(|(path, message)| anyhow::anyhow!("the overlay's {path}: {message}"))
}

/// The overlay's analysis cache settings (`ace_core::cache`), checked against the components whose
/// results it keeps, as every orchestrator that queues tasks has them. Each component it keeps is
/// logged with its time to live.
pub fn analysis_cache(
    overlay: &ace_sdk::Overlay,
    components: &[ace_sdk::Component],
) -> anyhow::Result<ace_core::cache::CacheSettings> {
    let cache = ace_core::cache::CacheSettings::from_section(&overlay.analysis_cache);
    if let Some(why) = cache.check(components) {
        anyhow::bail!("the overlay's analysis_cache: {why}");
    }
    if !cache.enabled {
        tracing::info!("the analysis cache is off (analysis_cache.enabled)");
    }
    for component in components
        .iter()
        .filter(|c| ace_core::cache::caches(&cache, c))
    {
        tracing::info!(
            module = %component.key,
            ttl_seconds = component.cache_ttl.map_or(0, |ttl| ttl.as_secs()),
            "the module's results are kept in the analysis cache"
        );
    }
    Ok(cache)
}

/// The bucket a process that submits roots puts their files in, with its node cache in the temporary
/// directory `cache` (the hunter's and each collector's own).
pub(crate) async fn submitting_bucket(
    db: &ace_core::db::Db,
    cache: &str,
) -> anyhow::Result<ace_core::bucket::Bucket> {
    use ace_store::{BucketConfig, DEFAULT_CACHE_MAX_BYTES, NodeCache, Store};
    use anyhow::Context;
    let cache_dir = std::env::temp_dir().join(cache);
    let store = Store::new(
        &BucketConfig::from_env()?,
        NodeCache::new(&cache_dir, DEFAULT_CACHE_MAX_BYTES)
            .with_context(|| format!("the cache in {}", cache_dir.display()))?,
    )
    .await;
    Ok(ace_core::bucket::Bucket::new(
        db.clone(),
        store,
        ace_core::bucket::BucketSettings::default(),
    ))
}

/// The service a process outside `ace serve` submits roots through, `ace hunter` and `ace collect`:
/// its roots queue what `ace serve`'s would, in the same modes, with the same hooks, declarations,
/// exclusions and analysis cache, and SVS's and the dispositions' settings as `ace serve` has them.
pub(crate) fn submitting_service(
    app: &App,
    overlay: &ace_sdk::Overlay,
    db: ace_core::db::Db,
) -> anyhow::Result<ace_service::Service> {
    use ace_core::eligibility::Catalog;
    use ace_core::orchestrator::Orchestrator;
    use anyhow::Context;
    let components = components(&app.registry(), overlay)?;
    let modes = app.modes_with(&components, overlay);
    // SVS's settings, as `ace serve` has them: a hunt run's record asks the core who owns each match
    // (PLAN.md 7.10 batch 6)
    let runs = ace_core::svs::runs::RunsConfig::from_section(&overlay.svs.runs)
        .map_err(anyhow::Error::msg)
        .context("the overlay's svs.runs section")?;
    // a submitted root runs the pre rules as it's submitted; `ace serve` runs the rest, and the hooks a
    // pass ends with are marked due here as there, so the two have the same hooks
    let hooks = ace_core::hooks::Hooks::from_section(&overlay.hooks).with_svs(
        ace_core::svs::attribution::HookConfig {
            attribution_extra: runs.windows.attribution_extra,
        },
    );
    // as `ace serve` applies or audits the modules' declarations
    let takes = ace_core::takes::TakesMode::from_env().map_err(anyhow::Error::msg)?;
    // a submitted root looks results up and keeps them as `ace serve`'s roots do
    let cache = analysis_cache(overlay, &components)?;
    let orchestrator = Orchestrator::new(Catalog::of(components), modes)
        .with_hooks(hooks)
        .with_takes(takes)
        .with_exclusions(exclusions(overlay)?)
        .with_cache(cache);
    // the site's dispositions, as `ace serve` has them, for whatever the process reads through the
    // service
    let dispositions = ace_service::Dispositions::configured(overlay)
        .map_err(anyhow::Error::msg)
        .context("the overlay's disposition sections")?;
    Ok(ace_service::Service::new(db, orchestrator)
        .with_dispositions(dispositions)
        .with_runs(runs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    /// `ace --help` says what `ace svs` does now: it named YARA validation alone after the catalog,
    /// coverage and the ATT&CK extract joined it. Each of its subcommands has a word in the line.
    #[test]
    fn the_svs_command_s_help_names_what_it_holds() {
        use clap::CommandFactory;
        let cli = Cli::command();
        let svs = cli
            .get_subcommands()
            .find(|command| command.get_name() == "svs")
            .expect("ace svs");
        let about = svs.get_about().expect("its help").to_string();
        let mut subcommands: Vec<&str> = svs.get_subcommands().map(|c| c.get_name()).collect();
        subcommands.sort_unstable();
        assert_eq!(subcommands, ["attack", "catalog", "coverage", "yara"]);
        for word in ["YARA", "catalog", "coverage", "ATT&CK release"] {
            assert!(about.contains(word), "{about:?} doesn't say {word}");
        }
        assert!(!about.contains("YARA validation, by hand"), "{about:?}");
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
            "serve-ai",
            "collect example",
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
