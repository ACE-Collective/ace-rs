//! Builds the `ace` binary and each pool binary from a list of crates (PLAN.md 2.31), so a site
//! repository can build its own from this workspace's crates and its own (decision 9).
//!
//! An `App` is that list: the pools and the modules each one runs, the site's observable types,
//! the module groups its modules join, the analysis views that draw its modules' results, and the
//! observable actions its GUI offers. Each binary is a short `main` over one:
//!
//! ```text
//! // the core: `ace serve`, `ace task replay`, `ace schema export`, `ace yara ...`, `ace user ...`,
//! // `ace signatures check`
//! fn main() -> std::process::ExitCode {
//!     site::app().ace_main()
//! }
//!
//! // a pool
//! fn main() -> std::process::ExitCode {
//!     site::app().pool_main("lookups")
//! }
//! ```
//!
//! The `ace` binary links every pool's modules: the core's catalog needs their manifests, and
//! `ace task replay` runs a task's module in that process. Each pool binary runs only its own
//! pool's modules.
//!
//! Each kind of thing an ace3 integration can add (`ace3/docs/INTEGRATIONS.md`) becomes an entry
//! here once its feature exists in ace4: analysis modules and observable types (2.31), analysis
//! templates and observable actions (5.9, `analysis_view`, `observable_action`), hunt types (6.2,
//! `hunt_type`), correlation command types (6.6, `command_type`), the script command types that
//! stand in for hunt scripts (decision 16, `hunt_script`), scheduled tasks (6.7,
//! `scheduled_task`), remediators, remediation probes and file collectors (7.9, `LookupPool::action`),
//! collectors with the first collector (6.1), and the rest with the phases that build them.
//!
//! Everything here reads its configuration from the environment and the site overlay at run
//! time, and nothing from this workspace's checkout, so a binary built in another repository
//! runs the same way.

mod cli;
mod compare;
pub mod hunter;
pub mod nrd;
mod pools;
mod root;
pub mod scheduler;
mod schema;
mod serve;
mod signatures;
mod task;
mod user;
mod yara;

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use ace_core::modes::Modes;
use ace_pool::modules::Registry;
use ace_results::ObservableKind;
use ace_sdk::{Lookup, Manifest, Parser};

/// What a binary is built from: its pools with their modules, the site's observable types, and
/// the groups its modules join.
#[derive(Default)]
pub struct App {
    observable_types: Vec<ObservableKind>,
    parser_pools: Vec<ParserPool>,
    lookup_pools: Vec<LookupPool>,
    scanner_pools: Vec<ScannerPool>,
    groups: Vec<(String, String)>,
    views: ace_gui::Views,
    actions: ace_gui::ObservableActions,
    hunt_types: Vec<Arc<dyn ace_hunt::HuntType>>,
    command_types: Vec<(String, CommandTypeFactory)>,
    hunt_scripts: Vec<(String, String, HuntScriptFactory)>,
    scheduled_tasks: Vec<scheduler::Task>,
}

/// What builds a script command type from the hunter's network and the type's settings (its entry
/// in the hunter configuration's `scripts`, or null), or why it can't be built.
pub type HuntScriptFactory = Arc<
    dyn Fn(
            &ace_hunt::correlate::net::Net,
            &serde_json::Value,
        ) -> Result<Arc<dyn ace_hunt::correlate::script::Script>, String>
        + Send
        + Sync,
>;

/// What builds a correlation command type: the handler, or why it can't be built, in the words a
/// hunt that uses it is told.
pub type CommandTypeFactory = Arc<
    dyn Fn() -> Result<Arc<dyn ace_hunt::correlate::command::CommandType>, String> + Send + Sync,
>;

/// A parser pool: modules that read files, one contained process per task (PLAN.md 2.17).
pub struct ParserPool {
    name: String,
    registry: Registry,
    rulesets: Option<Rulesets>,
    /// It runs the commands analysts start from the GUI (PLAN.md 5.12).
    commands: bool,
    /// The programs its image carries, which its modules run in the sandbox runner (PLAN.md 7.3).
    tools: Vec<ace_sdk::tools::ToolSpec>,
}

/// A network pool: lookups, many at a time as async tasks in one contained process (2.16), and the
/// remediators, remediation probes and file collectors it hosts (PLAN.md 7.9).
pub struct LookupPool {
    name: String,
    registry: Registry,
    actions: Vec<(&'static ace_sdk::actions::ActionSpec, ActionFactory)>,
}

/// A built action handler: a remediator, a remediation probe or a file collector.
pub use ace_pool::actions::Handler as ActionHandler;

/// What a pool gives an action handler's builder: its overlay entry's settings and the secrets its
/// spec declares.
#[derive(Debug, Clone, Default)]
pub struct ActionSetup {
    pub settings: Option<serde_json::Value>,
    pub secrets: ace_sdk::Secrets,
}

/// What builds an action handler in its pool, or says why it can't.
pub type ActionFactory =
    Arc<dyn Fn(&ActionSetup) -> Result<ace_pool::actions::Handler, String> + Send + Sync>;

/// A scanner pool (PLAN.md 7.7): the process that holds the Docker socket and runs the scanner images
/// modules' scans ask for (`ace_pool::scanners`), as many at once as `ACE4_CONCURRENCY` says.
pub struct ScannerPool {
    name: String,
    scanners: Vec<ace_sdk::scanners::ScannerSpec>,
}

impl ScannerPool {
    pub fn new(name: &str) -> ScannerPool {
        ScannerPool {
            name: name.to_owned(),
            scanners: Vec::new(),
        }
    }

    /// A scanner the pool runs, such as `ace_sdk::scanners::PHISHKIT`. The core lists it as
    /// `@scan/<name>`.
    pub fn scanner(mut self, spec: ace_sdk::scanners::ScannerSpec) -> ScannerPool {
        self.scanners.push(spec);
        self
    }
}

/// A parser pool's YARA rulesets (2.26): the module whose `rulesets` setting the pool sets to its
/// ruleset directory, and the check that a downloaded ruleset loads.
#[derive(Clone, Copy)]
struct Rulesets {
    module: &'static str,
    check: fn(&Path) -> Result<(), String>,
}

impl App {
    pub fn new() -> App {
        App::default()
    }

    /// Adds a site's observable types to the binary's list, beside the open-source ones
    /// (`ObservableKind::BUILTIN`). Every binary a site builds should list the same types.
    pub fn observable_types(mut self, kinds: &[ObservableKind]) -> App {
        self.observable_types.extend_from_slice(kinds);
        self
    }

    pub fn parser_pool(mut self, pool: ParserPool) -> App {
        self.parser_pools.push(pool);
        self
    }

    pub fn scanner_pool(mut self, pool: ScannerPool) -> App {
        self.scanner_pools.push(pool);
        self
    }

    pub fn lookup_pool(mut self, pool: LookupPool) -> App {
        self.lookup_pools.push(pool);
        self
    }

    /// Puts `module`, or one of its overlay instances, in the module group `group` (ace3's
    /// `module_group_*`), so the analysis modes that run the group run it. ace3's groups name
    /// only ace3's own modules, so a site's module runs in no mode until it joins one.
    pub fn module_in_group(mut self, group: &str, module: &str) -> App {
        self.groups.push((group.to_owned(), module.to_owned()));
        self
    }

    /// Adds the view of a site's analysis type, ace3's analysis template (PLAN.md 5.9), beside the
    /// open-source ones (`ace_gui::Views::builtin`). A view for an open-source type takes the place of
    /// its own. A type with no view draws as its details in JSON.
    pub fn analysis_view<T: ace_gui::AnalysisView>(mut self) -> App {
        self.views = self.views.with(ace_gui::ViewEntry::of::<T>());
        self
    }

    /// Adds an observable action of the site's own (PLAN.md 5.9, #1032) after the open-source ones
    /// (`ace_gui::ObservableActions::builtin`). One with an open-source action's name takes its place.
    pub fn observable_action(mut self, action: ace_gui::ObservableAction) -> App {
        self.actions = self.actions.with(action);
        self
    }

    /// Adds a hunt type (PLAN.md 6.2), as an ace3 integration adds a `hunt_type_*` section with
    /// its class. One with a type's name already added takes its place.
    pub fn hunt_type(mut self, kind: impl ace_hunt::HuntType + 'static) -> App {
        self.hunt_types.retain(|k| k.name() != kind.name());
        self.hunt_types.push(Arc::new(kind));
        self
    }

    /// Adds a correlation command type (PLAN.md 6.6), ace3's `hunter.correlation.command_types`
    /// entry from an integration's `saq.integration.yaml`: a correlate command whose `type` is
    /// `name` runs the handler `build` makes. The registry is built when a process starts, the
    /// hunter's and `ace serve`'s for validation, each type once; one that fails to build is
    /// recorded with its error, which a hunt using it fails with, and the others still register.
    /// One with a name already added takes its place.
    pub fn command_type(
        mut self,
        name: &str,
        build: impl Fn() -> Result<Arc<dyn ace_hunt::correlate::command::CommandType>, String>
        + Send
        + Sync
        + 'static,
    ) -> App {
        self.command_types.retain(|(n, _)| n != name);
        self.command_types.push((name.to_owned(), Arc::new(build)));
        self
    }

    /// Adds a script command type (PLAN.md decision 16): an executable correlation command whose
    /// path ends with `suffix`, such as `hunts/scripts/dns_lookup.py`, runs the type `build` makes,
    /// named `name`, rather than the script. Only `ace hunter` builds them, with its network; `ace
    /// serve` validates a hunt that runs one but has none to run. One with a suffix already added
    /// takes its place.
    pub fn hunt_script(
        mut self,
        suffix: &str,
        name: &str,
        build: impl Fn(
            &ace_hunt::correlate::net::Net,
            &serde_json::Value,
        ) -> Result<Arc<dyn ace_hunt::correlate::script::Script>, String>
        + Send
        + Sync
        + 'static,
    ) -> App {
        self.hunt_scripts.retain(|(s, _, _)| s != suffix);
        self.hunt_scripts
            .push((suffix.to_owned(), name.to_owned(), Arc::new(build)));
        self
    }

    /// The script command types' names, each with the suffix it serves.
    pub fn hunt_script_names(&self) -> Vec<(&str, &str)> {
        self.hunt_scripts
            .iter()
            .map(|(suffix, name, _)| (suffix.as_str(), name.as_str()))
            .collect()
    }

    /// Builds the script command types into `types` over `net`, each with its entry of `settings`;
    /// one that fails to build is recorded with its error, which a hunt running it fails with. An
    /// entry of `settings` for no type is refused, as a mistake in the configuration.
    pub fn build_hunt_scripts(
        &self,
        types: &mut ace_hunt::correlate::command::CommandTypes,
        net: &ace_hunt::correlate::net::Net,
        settings: &std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Result<(), String> {
        if let Some(unknown) = settings
            .keys()
            .find(|k| !self.hunt_scripts.iter().any(|(_, n, _)| n == *k))
        {
            return Err(format!(
                "the hunter's configuration has settings for the script type {unknown}, which this binary hasn't"
            ));
        }
        for (suffix, name, build) in &self.hunt_scripts {
            let empty = serde_json::Value::Null;
            match build(net, settings.get(name).unwrap_or(&empty)) {
                Ok(handler) => types.register_script(suffix, name, handler),
                Err(e) => {
                    tracing::error!(name, "failed to load script command type {name}: {e}");
                    types.scripts_mut().failed(suffix, name, &e);
                }
            }
        }
        Ok(())
    }

    /// Adds a scheduled task to `ace serve`'s scheduler (PLAN.md 6.7), as an ace3 integration adds an
    /// executable to its `etc/cron/<cadence>/`. One with a core task's name takes its place. It acts as
    /// the component `scheduler:<name>`, which holds only what a grant gives it.
    pub fn scheduled_task(mut self, task: scheduler::Task) -> App {
        self.scheduled_tasks.retain(|t| t.name != task.name);
        self.scheduled_tasks.push(task);
        self
    }

    /// The scheduler's tasks: the core's (`scheduler::Task::builtin`) and the site's.
    pub fn scheduled_tasks(&self) -> Vec<scheduler::Task> {
        let mut tasks: Vec<scheduler::Task> = scheduler::Task::builtin()
            .into_iter()
            .filter(|t| !self.scheduled_tasks.iter().any(|s| s.name == t.name))
            .collect();
        tasks.extend(self.scheduled_tasks.iter().cloned());
        tasks
    }

    /// Every pool's action handlers' specs (PLAN.md 7.9), which `ace serve`'s core and API decide by. A
    /// handler two pools host is listed once.
    pub fn action_catalog(&self) -> Result<ace_core::actions::ActionCatalog, String> {
        let mut specs: Vec<&'static ace_sdk::actions::ActionSpec> = Vec::new();
        for (spec, _) in self.lookup_pools.iter().flat_map(|p| &p.actions) {
            if !specs
                .iter()
                .any(|s| s.kind == spec.kind && s.name == spec.name)
            {
                specs.push(spec);
            }
        }
        ace_core::actions::ActionCatalog::new(&specs)
    }

    /// The correlation command types, built: ace3's `load_command_types_from_config`.
    pub fn command_types(&self) -> ace_hunt::correlate::command::CommandTypes {
        let mut types = ace_hunt::correlate::command::CommandTypes::new();
        for (name, build) in &self.command_types {
            let built = build().and_then(|handler| types.register(name, handler).map(|_| ()));
            if let Err(e) = built {
                tracing::error!(name, "failed to load correlation command type {name}: {e}");
                types.failed(name, &e);
            }
        }
        types
    }

    /// The hunt types the binary loads hunts of: what 6.4's hunter runs and 6.8's `ace signatures
    /// check` loads.
    pub fn hunt_types(&self) -> &[Arc<dyn ace_hunt::HuntType>] {
        &self.hunt_types
    }

    /// The observable actions the GUI offers.
    pub fn actions(&self) -> &ace_gui::ObservableActions {
        &self.actions
    }

    /// The analysis views the GUI draws results with.
    pub fn views(&self) -> &ace_gui::Views {
        &self.views
    }

    /// Each module whose results have no view, as its name and its type's name and version.
    pub fn modules_without_a_view(&self) -> Vec<(&'static str, &'static str, u32)> {
        self.registry()
            .manifests()
            .iter()
            // a module that never stores a result has nothing to draw
            .filter(|m| m.stores_results && !self.views.has(m.output.name, m.output.version))
            .map(|m| (m.name, m.output.name, m.output.version))
            .collect()
    }

    /// Runs the `ace` command.
    pub fn ace_main(self) -> ExitCode {
        if let Err(code) = self.install_types() {
            return code;
        }
        cli::main(&self)
    }

    /// Runs the pool named `pool`: its supervisor or lease loop, or, for a parser pool, one task
    /// process when the first argument is `task`.
    pub fn pool_main(self, pool: &str) -> ExitCode {
        if let Err(code) = self.install_types() {
            return code;
        }
        if let Some(parsers) = self.parser_pools.iter().find(|p| p.name == pool) {
            return pools::parser_main(parsers);
        }
        if let Some(lookups) = self.lookup_pools.iter().find(|p| p.name == pool) {
            return pools::lookup_main(lookups);
        }
        if let Some(scanners) = self.scanner_pools.iter().find(|p| p.name == pool) {
            return pools::scanner_main(scanners);
        }
        eprintln!("this binary has no pool {pool}");
        ExitCode::from(2)
    }

    /// Makes this process's observable types the binary's list, before anything reads a type.
    fn install_types(&self) -> Result<(), ExitCode> {
        ace_results::install_types(&self.observable_types).map_err(|e| {
            eprintln!("the binary's observable types: {e}");
            ExitCode::from(2)
        })
    }

    /// Every parser pool's tools.
    fn tools(&self) -> Vec<ace_sdk::tools::ToolSpec> {
        let mut tools: Vec<ace_sdk::tools::ToolSpec> = Vec::new();
        for pool in &self.parser_pools {
            for tool in &pool.tools {
                if !tools.iter().any(|t| t.name == tool.name) {
                    tools.push(*tool);
                }
            }
        }
        tools
    }

    /// Every pool's modules.
    fn registry(&self) -> Registry {
        self.parser_pools
            .iter()
            .map(|p| &p.registry)
            .chain(self.lookup_pools.iter().map(|p| &p.registry))
            .fold(Registry::new(), Registry::merge)
    }

    /// ace3's modes and groups, with the site's modules in the groups they joined.
    fn modes(&self) -> Modes {
        self.groups
            .iter()
            .fold(Modes::ace3(), |modes, (group, module)| {
                modes.with_module_in_group(group, module)
            })
    }

    /// The modes with the overlay's instances in the groups they join (`InstanceSection::groups`).
    fn modes_with(&self, components: &[ace_sdk::Component]) -> Modes {
        components.iter().fold(self.modes(), |modes, component| {
            component.groups.iter().fold(modes, |modes, group| {
                modes.with_module_in_group(group, &component.key)
            })
        })
    }

    /// The pools and their modules, as `ACE4_POOLS` lists them: the core's default.
    fn pool_list(&self) -> String {
        let pool = |name: &str, registry: &Registry| {
            let modules: Vec<&str> = registry.manifests().iter().map(|m| m.name).collect();
            format!("{name}:{}", modules.join(","))
        };
        self.parser_pools
            .iter()
            .map(|p| {
                let listed = pool(&p.name, &p.registry);
                match (p.commands, listed.ends_with(':')) {
                    (false, _) => listed,
                    (true, true) => format!("{listed}{}", ace_sdk::wire::COMMANDS),
                    (true, false) => format!("{listed},{}", ace_sdk::wire::COMMANDS),
                }
            })
            .chain(self.lookup_pools.iter().map(|p| {
                let listed = pool(&p.name, &p.registry);
                let entries: Vec<String> = p
                    .actions
                    .iter()
                    .map(|(spec, _)| spec.pool_entry())
                    .collect();
                match (entries.is_empty(), listed.ends_with(':')) {
                    (true, _) => listed,
                    (false, true) => format!("{listed}{}", entries.join(",")),
                    (false, false) => format!("{listed},{}", entries.join(",")),
                }
            }))
            .chain(self.scanner_pools.iter().map(|p| {
                let scanners: Vec<String> = p
                    .scanners
                    .iter()
                    .map(|s| ace_sdk::scanners::pool_entry(s.name))
                    .collect();
                format!("{}:{}", p.name, scanners.join(","))
            }))
            .collect::<Vec<_>>()
            .join(";")
    }
}

impl ParserPool {
    /// An empty pool. Its name is what `ACE4_POOLS` and `pool_main` call it.
    pub fn new(name: &str) -> ParserPool {
        ParserPool {
            name: name.to_owned(),
            registry: Registry::new(),
            rulesets: None,
            commands: false,
            tools: Vec::new(),
        }
    }

    /// The programs the pool's image carries (PLAN.md 7.3), such as `ace_sdk::tools::SANDBOX_TOOLS`.
    /// Its modules may declare these and no others; the pool won't start with a module that
    /// declares a tool it hasn't, or a tool that isn't in its image.
    pub fn tools(mut self, tools: &[ace_sdk::tools::ToolSpec]) -> ParserPool {
        self.tools.extend_from_slice(tools);
        self
    }

    /// Runs the commands analysts start from the GUI's CLI page (PLAN.md 5.12), each in a contained
    /// process as a task's parser runs, beside the pool's tasks. The core lists it with `@commands`.
    pub fn commands(mut self) -> ParserPool {
        self.commands = true;
        self
    }

    pub fn module<M: Parser>(mut self) -> ParserPool {
        self.registry = self.registry.parser::<M>();
        self
    }

    /// Keeps the pool on the core's current YARA ruleset: the supervisor downloads each new
    /// ruleset into its ruleset directory (`ACE4_RULESET_DIR`), publishes it once `check` loads
    /// it, and leases nothing before the first one has. The module `M` gets the directory as its
    /// `rulesets` setting, whatever the overlay says.
    pub fn yara_rulesets<M: Parser>(
        mut self,
        check: fn(&Path) -> Result<(), String>,
    ) -> ParserPool {
        self.rulesets = Some(Rulesets {
            module: Manifest::parser::<M>().name,
            check,
        });
        self
    }
}

impl LookupPool {
    pub fn new(name: &str) -> LookupPool {
        LookupPool {
            name: name.to_owned(),
            registry: Registry::new(),
            actions: Vec::new(),
        }
    }

    /// Hosts an action handler (PLAN.md 7.9): a remediator, a remediation probe or a file collector, which
    /// `build` makes when the pool starts from its `ActionSetup`, as an ace3 integration's
    /// `remediator_*`, `external_remediation_probe_*` or `file_collector_*` section loads its class. The core
    /// lists it as `@<kind>/<name>`. One with a handler's kind and name already added takes its place.
    pub fn action(
        mut self,
        spec: &'static ace_sdk::actions::ActionSpec,
        build: impl Fn(&ActionSetup) -> Result<ace_pool::actions::Handler, String>
        + Send
        + Sync
        + 'static,
    ) -> LookupPool {
        self.actions
            .retain(|(s, _)| !(s.kind == spec.kind && s.name == spec.name));
        self.actions.push((spec, Arc::new(build)));
        self
    }

    pub fn module<M: Lookup>(mut self) -> LookupPool {
        self.registry = self.registry.lookup::<M>();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A script type is built with its settings; one that can't be is recorded and fails the
    /// steps that run it, and settings for a type the binary hasn't are refused (decision 16).
    #[test]
    fn hunt_scripts_are_built_with_their_settings() {
        let mut app = App::new();
        for (suffix, name) in ace_hunt::correlate::scripts::SCRIPTS {
            app = app.hunt_script(suffix, name, move |net, settings| {
                ace_hunt::correlate::scripts::build(name, net, settings)
            });
        }
        let net = hunter::net::net().expect("a network");
        let mut types = ace_hunt::correlate::command::CommandTypes::new();
        app.build_hunt_scripts(&mut types, &net, &std::collections::BTreeMap::new())
            .expect("built");
        let path = |name: &str| format!("/signatures/hunts/commands/../scripts/{name}.py");
        assert!(matches!(
            types.scripts().find(&path("removed_hunt_three")),
            Some(("removed_hunt_three", Err(e))) if e.contains("home_tenant")
        ));
        assert!(matches!(
            types.scripts().find(&path("dns_lookup")),
            Some(("dns_lookup", Ok(_)))
        ));
        let settings = std::collections::BTreeMap::from([(
            "removed_hunt_three".to_owned(),
            serde_json::json!({"home_tenant": "Example.onmicrosoft.com"}),
        )]);
        app.build_hunt_scripts(&mut types, &net, &settings)
            .expect("built");
        assert!(matches!(
            types.scripts().find(&path("removed_hunt_three")),
            Some((_, Ok(_)))
        ));
        let unknown =
            std::collections::BTreeMap::from([("nope".to_owned(), serde_json::json!({}))]);
        assert!(app.build_hunt_scripts(&mut types, &net, &unknown).is_err());
    }

    #[test]
    fn the_core_lists_each_pool_and_its_modules() {
        let app = App::new()
            .parser_pool(
                ParserPool::new("parsers")
                    .module::<ace_mod_email::EmailAnalyzer>()
                    .module::<ace_mod_yara::YaraScanner>()
                    .commands(),
            )
            .lookup_pool(LookupPool::new("lookups").action(
                &ace_sdk::actions::TEST_REMEDIATOR,
                |_| {
                    Ok(ActionHandler::Remediator(Arc::new(
                        ace_sdk::actions::TestRemediator,
                    )))
                },
            ));
        assert_eq!(
            app.pool_list(),
            "parsers:email_analyzer,yara_scanner_v3_4,@commands;lookups:@remediation/test"
        );
        let catalog = app.action_catalog().expect("a catalog");
        assert!(
            catalog
                .get(ace_sdk::actions::ActionKind::Remediation, "test")
                .is_some()
        );
        let names: Vec<&str> = app.registry().manifests().iter().map(|m| m.name).collect();
        assert_eq!(names, ["email_analyzer", "yara_scanner_v3_4"]);
    }
}
