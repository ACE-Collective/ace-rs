//! Builds the `ace` binary and each pool binary from a list of crates (PLAN.md 2.31), so a site
//! repository can build its own from this workspace's crates and its own (decision 9).
//!
//! An `App` is that list: the pools and the modules each one runs, the site's observable types,
//! the module groups and analysis modes its modules join, the analysis views that draw its modules' results, and the
//! observable actions its GUI offers. Each binary is a short `main` over one:
//!
//! ```text
//! // the core: `ace serve`, `ace serve-ai`, `ace task replay`, `ace schema export`, `ace yara ...`,
//! // `ace user ...`, `ace signatures check`
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
//! templates and observable actions (5.9, `analysis_view`, `observable_action`), the alert page's
//! summaries by alert type (ace3's `custom_alerts` templates, `alert_summary`), hunt types (6.2,
//! `hunt_type`), correlation command types (6.6, `command_type`), the script command types that
//! stand in for hunt scripts (decision 16, `hunt_script`), scheduled tasks (6.7,
//! `scheduled_task`), remediators, remediation probes and file collectors (7.9, `LookupPool::action`),
//! alert routers and their types (7.13, `alert_router`, `alert_router_type`),
//! collectors (6.1, `collector`, run by `ace collect <name>`), and the rest with the phases that
//! build them.
//!
//! A site builds on the open-source list rather than repeating it: `ace::app()` is an `App`, and
//! `add_to_parser_pool`, `add_to_lookup_pool` and `add_to_scanner_pool` add to one of its pools by
//! name. They only add: the closure is given an empty pool of that name, and what it holds joins the
//! pool already there, so a site can't drop one of the open-source modules, and a module the pool has
//! already, or a pool the list hasn't, is refused.
//!
//! Everything here reads its configuration from the environment and the site overlay at run
//! time, and nothing from this workspace's checkout, so a binary built in another repository
//! runs the same way.

pub mod ai;
mod cli;
pub mod collector;
mod compare;
pub mod hunter;
pub mod nrd;
mod pools;
mod root;
pub mod scheduler;
mod schema;
mod serve;
pub mod serve_ai;
mod signatures;
mod svs;
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
/// the groups and modes its modules join.
#[derive(Default)]
pub struct App {
    observable_types: Vec<ObservableKind>,
    file_roles: Vec<ace_results::FileRole>,
    directives: Vec<ace_sdk::directives::Directive>,
    parser_pools: Vec<ParserPool>,
    lookup_pools: Vec<LookupPool>,
    scanner_pools: Vec<ScannerPool>,
    groups: Vec<(String, String)>,
    mode_modules: Vec<(String, String)>,
    views: ace_gui::Views,
    actions: ace_gui::ObservableActions,
    summaries: ace_gui::AlertSummaries,
    icons: ace_gui::PivotIcons,
    hunt_types: Vec<Arc<dyn ace_hunt::HuntType>>,
    command_types: Vec<(
        String,
        &'static [ace_sdk::ConnectionSlot],
        CommandTypeFactory,
    )>,
    hunt_scripts: Vec<(String, String, HuntScriptFactory)>,
    scheduled_tasks: Vec<scheduler::Task>,
    alert_routers: Vec<(String, i32, Arc<dyn ace_service::routing::Router>)>,
    router_types: ace_service::routing::RouterTypes,
    ai_backend_types: Vec<(String, ai::AiBackendType)>,
    collectors: Vec<(collector::CollectorSpec, collector::CollectorFactory)>,
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

/// What builds a correlation command type from the shared connections the overlay's
/// `command_types.<name>.connections` binds to its slots: the handler, or why it can't be built, in
/// the words a hunt that uses it is told.
pub type CommandTypeFactory = Arc<
    dyn Fn(
            &ace_sdk::Connections,
        ) -> Result<Arc<dyn ace_hunt::correlate::command::CommandType>, String>
        + Send
        + Sync,
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

/// What a pool gives an action handler's builder: its overlay entry's settings, the secrets its
/// spec declares, and the shared connections its entry binds to the spec's slots, each with its own
/// secrets (`ace_sdk::connections`).
///
/// A test builds one with `ActionSetup::new` and the methods after it, so a field added here doesn't
/// break it.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ActionSetup {
    pub settings: Option<serde_json::Value>,
    pub secrets: ace_sdk::Secrets,
    pub connections: ace_sdk::Connections,
}

impl ActionSetup {
    /// A setup with `settings`, and no secrets or connections.
    pub fn new(settings: Option<serde_json::Value>) -> ActionSetup {
        ActionSetup {
            settings,
            ..ActionSetup::default()
        }
    }

    pub fn with_secrets(mut self, secrets: ace_sdk::Secrets) -> ActionSetup {
        self.secrets = secrets;
        self
    }

    pub fn with_connections(mut self, connections: ace_sdk::Connections) -> ActionSetup {
        self.connections = connections;
        self
    }
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

    /// Adds a site's file roles to the binary's list, beside the open-source ones
    /// (`FileRole::BUILTIN`): what a site's module may say a file it writes is, and so the `type=`
    /// tags its YARA rules may scan by (PLAN.md decision 25). Every binary a site builds should list
    /// the same roles; a result naming a role the binary doesn't list is refused.
    pub fn file_roles(mut self, roles: &[ace_results::FileRole]) -> App {
        self.file_roles.extend_from_slice(roles);
        self
    }

    /// The binary's file roles: the built-in ones and the site's, checked
    /// (`ace_results::role_list`).
    pub fn roles(&self) -> Result<Vec<ace_results::FileRole>, ace_results::RoleListError> {
        ace_results::role_list(&self.file_roles)
    }

    /// Adds a site's directives to those an analyst may add to an observable from the alert page's
    /// menu or the JSON API, beside the open-source ones (`ace_sdk::directives::BUILTIN`, ace3's
    /// `GUI_DIRECTIVES`), as an ace3 integration calls `register_directive(..., gui=True)` (PLAN.md
    /// decision 31). A module of the site's that requires one (`Module::REQUIRED_DIRECTIVES`) then runs
    /// on an observable an analyst gives it. `ace_main` refuses a list with a bad or repeated name.
    pub fn directives(mut self, directives: &[ace_sdk::directives::Directive]) -> App {
        self.directives.extend_from_slice(directives);
        self
    }

    /// The directives an analyst may add: the built-in ones and the site's, checked
    /// (`ace_sdk::directives::directive_list`).
    pub fn directive_list(
        &self,
    ) -> Result<ace_sdk::directives::DirectiveList, ace_sdk::directives::DirectiveListError> {
        ace_sdk::directives::directive_list(&self.directives)
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

    /// Puts `module` in the analysis mode `mode` alone (ace3's `analysis_mode_<mode>:
    /// enabled_modules:`), so it runs in that mode and not in the others that run its groups. A
    /// module both here and in a group runs in every mode either gives it, once, as ace3's mode is
    /// the union of its groups' modules and its enabled ones. `mode` must be one of ace3's modes and
    /// `module` a module one of the list's pools registers: `ace_main` refuses the list otherwise,
    /// naming each wrong pair, before it runs any command.
    pub fn module_in_mode(mut self, mode: &str, module: &str) -> App {
        self.mode_modules.push((mode.to_owned(), module.to_owned()));
        self
    }

    /// Adds the view of a site's analysis type, ace3's analysis template (PLAN.md 5.9), beside the
    /// open-source ones (`ace_gui::Views::builtin`). A view for an open-source type takes the place of
    /// its own. A type with no view draws as its details in JSON.
    pub fn analysis_view<T: ace_gui::AnalysisView>(mut self) -> App {
        self.views = self.views.with(ace_gui::ViewEntry::of::<T>());
        self
    }

    /// Adds the alert page's summary for an alert type, ace3's per-alert-type template
    /// (`analysis/custom/<alert_type>.html`), beside the open-source ones
    /// (`ace_gui::AlertSummaries::builtin`: mailbox and hunt alerts). It draws every alert whose type
    /// is `T::ALERT_TYPE` or starts with it and ` - `, unless a longer registered type matches. One
    /// for an open-source type takes its place. A type with none has the page's default summary.
    pub fn alert_summary<T: ace_gui::AlertSummary>(mut self) -> App {
        self.summaries = self.summaries.with(ace_gui::SummaryEntry::of::<T>());
        self
    }

    /// The ports the network pool `pool` allows for its components' connections beyond their own,
    /// such as a proxy's, with `overlay` (`ace_sdk::ConnectionType::tcp_ports`, PLAN.md decision
    /// 35), as the pool computes them when it starts. None for a pool this binary hasn't.
    pub fn lookup_connection_ports(
        &self,
        pool: &str,
        overlay: &ace_sdk::Overlay,
    ) -> Result<Option<Vec<u16>>, String> {
        match self.lookup_pools.iter().find(|p| p.name == pool) {
            Some(pool) => pools::connection_ports(pool, overlay).map(Some),
            None => Ok(None),
        }
    }

    /// Adds an icon a pivot link may name (PLAN.md decision 32 part (b)): `png`, a PNG of at most 64
    /// KiB the binary embeds, which the GUI serves itself, as an ace3 integration ships an image in its
    /// static directory for its pivot links. One with a registered icon's name takes its place. Panics
    /// on a name that isn't 1 to 64 of a-z, 0-9, `_` and `-`, or bytes that aren't such a PNG, as a
    /// binary that registers one is wrong when it starts.
    pub fn pivot_link_icon(mut self, name: &'static str, png: &'static [u8]) -> App {
        let icon = ace_gui::PivotIcon::new(name, png)
            .unwrap_or_else(|why| panic!("App::pivot_link_icon: {why}"));
        self.icons = std::mem::take(&mut self.icons).with(icon);
        self
    }

    /// The icons pivot links may name: ace4's own, none, and the site's.
    pub fn pivot_link_icons(&self) -> &ace_gui::PivotIcons {
        &self.icons
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
        self,
        name: &str,
        build: impl Fn() -> Result<Arc<dyn ace_hunt::correlate::command::CommandType>, String>
        + Send
        + Sync
        + 'static,
    ) -> App {
        self.command_type_with_connections(name, &[], move |_| build())
    }

    /// Adds a correlation command type that takes shared connections (`ace_sdk::connections`) in
    /// `slots`, as `command_type` does: the overlay's `command_types.<name>.connections` binds each
    /// slot, and `build` is given the connections. `ace hunter`, which runs the commands, holds their
    /// secrets; `ace serve`, which validates hunts, builds the type with the connections' settings
    /// and none of their secrets (PLAN.md 2.24).
    pub fn command_type_with_connections(
        mut self,
        name: &str,
        slots: &'static [ace_sdk::ConnectionSlot],
        build: impl Fn(
            &ace_sdk::Connections,
        ) -> Result<Arc<dyn ace_hunt::correlate::command::CommandType>, String>
        + Send
        + Sync
        + 'static,
    ) -> App {
        self.command_types.retain(|(n, _, _)| n != name);
        self.command_types
            .push((name.to_owned(), slots, Arc::new(build)));
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

    /// Adds an alert router (PLAN.md 7.13) that `ace serve` always runs, named `name`, at `priority` (lowest
    /// first; the built-in `detection_queue` is 500, and SVS's `svs_marker`, which every `App` runs, is
    /// 100). A name must be unique and neither a built-in's nor `svs_marker`, which `ace serve` checks when
    /// it starts.
    pub fn alert_router(
        mut self,
        name: &str,
        priority: i32,
        router: Arc<dyn ace_service::routing::Router>,
    ) -> App {
        self.alert_routers.push((name.to_owned(), priority, router));
        self
    }

    /// Adds an alert router type (PLAN.md 7.13), which the overlay's `alert_routers:` entries name with their
    /// own name, priority and settings, as an ace3 integration's entry names its class and `kwargs`. `build`
    /// makes a router from an entry's `settings` (null when left out), or says why it can't, which stops `ace
    /// serve`. One with a type's name already added takes its place.
    pub fn alert_router_type(
        mut self,
        kind: &str,
        build: impl Fn(&serde_json::Value) -> Result<Arc<dyn ace_service::routing::Router>, String>
        + Send
        + Sync
        + 'static,
    ) -> App {
        self.router_types = std::mem::take(&mut self.router_types).with(kind, Arc::new(build));
        self
    }

    /// Adds a backend type to the AI investigation API (PLAN.md 7.15), which the overlay's
    /// `ai_api.backends` entries name with their own name, limits, secrets and settings, as an ace3
    /// integration's `ai_query_backend_<name>` section names its class. `build` makes a backend from
    /// an entry's settings and the secrets it lists, or says why it can't, which stops `ace serve-ai`. One
    /// with a type's name already there, a built-in's included, takes its place.
    pub fn ai_backend_type(
        self,
        kind: &str,
        build: impl Fn(&ai::AiBackendSetup) -> Result<Arc<dyn ace_service::ai::AiQueryBackend>, String>
        + Send
        + Sync
        + 'static,
    ) -> App {
        self.ai_backend_type_with_connections(kind, &[], build)
    }

    /// Adds a backend type whose entries bind shared connections (`ace_sdk::connections`) to
    /// `slots` with `connections:`, as `ai_backend_type` does: the builder is given each bound
    /// connection with its secrets.
    pub fn ai_backend_type_with_connections(
        mut self,
        kind: &str,
        slots: &'static [ace_sdk::ConnectionSlot],
        build: impl Fn(&ai::AiBackendSetup) -> Result<Arc<dyn ace_service::ai::AiQueryBackend>, String>
        + Send
        + Sync
        + 'static,
    ) -> App {
        self.ai_backend_types.retain(|(name, _)| name != kind);
        self.ai_backend_types.push((
            kind.to_owned(),
            ai::AiBackendType {
                connections: slots,
                build: Arc::new(build),
            },
        ));
        self
    }

    /// The AI API's backend types: `splunk` and ace3's two testing backends, and the binary's own.
    pub fn ai_backend_types(&self) -> std::collections::BTreeMap<String, ai::AiBackendType> {
        let mut types = ai::builtin_types();
        for (kind, backend) in &self.ai_backend_types {
            types.insert(kind.clone(), backend.clone());
        }
        types
    }

    /// Adds a collector (PLAN.md 6.1), which `ace collect <name>` runs as its own process: a source
    /// outside ACE that submits roots, as an ace3 integration adds a collector service. `build` makes
    /// it from its overlay section's `settings` and the secrets `spec` names, or says why it can't,
    /// which stops `ace collect`. It acts as the component `collector:<name>` (`collector`'s module
    /// docs). One with a collector's name already added takes its place.
    ///
    /// # Panics
    ///
    /// When `spec.name` can't be a component's name: lowercase letters, digits and `- _ .`.
    pub fn collector(
        mut self,
        spec: collector::CollectorSpec,
        build: impl Fn(&collector::CollectorSetup) -> Result<Arc<dyn collector::Collector>, String>
        + Send
        + Sync
        + 'static,
    ) -> App {
        assert!(
            !spec.name.contains(':')
                && ace_service::Component::new(format!("collector:{}", spec.name)).is_ok(),
            "{:?} can't name a collector: use lowercase letters, digits and - _ .",
            spec.name
        );
        self.collectors.retain(|(s, _)| s.name != spec.name);
        self.collectors.push((spec, Arc::new(build)));
        self
    }

    /// The collectors' names, as `ace collect` takes them.
    pub fn collector_names(&self) -> Vec<&'static str> {
        self.collectors.iter().map(|(spec, _)| spec.name).collect()
    }

    /// Adds to the parser pool named `name` what `add` puts in an empty pool of that name: its
    /// modules, tools and rulesets, and its commands. Nothing of the pool's is dropped.
    ///
    /// # Panics
    ///
    /// When the list has no parser pool `name`, when `add` names a module the pool has, or when both
    /// keep YARA rulesets.
    pub fn add_to_parser_pool(
        mut self,
        name: &str,
        add: impl FnOnce(ParserPool) -> ParserPool,
    ) -> App {
        let added = add(ParserPool::new(name));
        let pool = self
            .parser_pools
            .iter_mut()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("the list has no parser pool {name}"));
        refuse_repeats(name, &pool.registry, &added.registry);
        pool.registry = std::mem::take(&mut pool.registry).merge(&added.registry);
        for tool in added.tools {
            if !pool.tools.iter().any(|t| t.name == tool.name) {
                pool.tools.push(tool);
            }
        }
        pool.commands |= added.commands;
        if let Some(rulesets) = added.rulesets {
            assert!(
                pool.rulesets.is_none(),
                "the parser pool {name} keeps YARA rulesets already"
            );
            pool.rulesets = Some(rulesets);
        }
        self
    }

    /// Adds to the network pool named `name` what `add` puts in an empty pool of that name: its
    /// modules and action handlers. Nothing of the pool's is dropped, though a handler with one of
    /// the pool's kinds and names takes its place, as `LookupPool::action` says.
    ///
    /// # Panics
    ///
    /// When the list has no network pool `name`, or when `add` names a module the pool has.
    pub fn add_to_lookup_pool(
        mut self,
        name: &str,
        add: impl FnOnce(LookupPool) -> LookupPool,
    ) -> App {
        let added = add(LookupPool::new(name));
        let pool = self
            .lookup_pools
            .iter_mut()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("the list has no network pool {name}"));
        refuse_repeats(name, &pool.registry, &added.registry);
        pool.registry = std::mem::take(&mut pool.registry).merge(&added.registry);
        for (spec, build) in added.actions {
            pool.actions
                .retain(|(s, _)| !(s.kind == spec.kind && s.name == spec.name));
            pool.actions.push((spec, build));
        }
        self
    }

    /// Adds to the scanner pool named `name` the scanners `add` puts in an empty pool of that name.
    ///
    /// # Panics
    ///
    /// When the list has no scanner pool `name`, or when `add` names a scanner the pool has.
    pub fn add_to_scanner_pool(
        mut self,
        name: &str,
        add: impl FnOnce(ScannerPool) -> ScannerPool,
    ) -> App {
        let added = add(ScannerPool::new(name));
        let pool = self
            .scanner_pools
            .iter_mut()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("the list has no scanner pool {name}"));
        for scanner in added.scanners {
            assert!(
                !pool.scanners.iter().any(|s| s.name == scanner.name),
                "the scanner pool {name} has the scanner {} already",
                scanner.name
            );
            pool.scanners.push(scanner);
        }
        self
    }

    /// The alert routers `ace serve` runs: the built-in one, SVS's marker router, the binary's and the
    /// overlay's, or why one of them can't be built.
    ///
    /// The marker router (PLAN.md 7.10 batches 7a and 8) is added here, for every `App`, and not by the
    /// binary's own list: without it a test run's alerts stay in the queue analysts triage, and a site
    /// binary built from `App::new()` rather than `ace::app()` would lack it and say nothing. This is the
    /// one place a binary's routers are put together, so it can't be left out. It belongs in this crate
    /// and not in `ace_service::routing::Routers::builtin`, which is 7.13's registry with ace3's one
    /// built-in router and is what a `Service` made for a test or a command has; ace3 names the marker
    /// router in the `alert_routers:` of the configuration every ace3 ships, which here is what every
    /// binary's `App` runs. It is first, so a router of the binary's or the overlay's that takes its
    /// name is refused as a duplicate.
    pub fn alert_routers(
        &self,
        overlay: &ace_sdk::Overlay,
    ) -> Result<ace_service::routing::Routers, String> {
        let mut routers = ace_service::routing::Routers::builtin().with(
            ace_service::svs_association::MARKER_ROUTER,
            ace_service::svs_association::MARKER_ROUTER_PRIORITY,
            Arc::new(ace_service::svs_association::MarkerRouter),
        )?;
        for (name, priority, router) in &self.alert_routers {
            routers = routers.with(name, *priority, router.clone())?;
        }
        routers.configured(&self.router_types, &overlay.alert_routers)
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

    /// Every pool's action handlers' specs (PLAN.md 7.9), whether or not an overlay turns them on. A
    /// handler two pools host is listed once.
    pub fn action_catalog(&self) -> Result<ace_core::actions::ActionCatalog, String> {
        self.catalog_of(|_| true)
    }

    /// The action handlers' specs `overlay` turns on, which `ace serve`'s core and API decide by: every
    /// handler but one off by default that the overlay has no `actions:` entry for (PLAN.md decision
    /// 28), so nobody is offered it or can queue it.
    pub fn action_catalog_for(
        &self,
        overlay: &ace_sdk::Overlay,
    ) -> Result<ace_core::actions::ActionCatalog, String> {
        self.catalog_of(|spec| spec.is_enabled(overlay))
    }

    fn catalog_of(
        &self,
        on: impl Fn(&ace_sdk::actions::ActionSpec) -> bool,
    ) -> Result<ace_core::actions::ActionCatalog, String> {
        let mut specs: Vec<&'static ace_sdk::actions::ActionSpec> = Vec::new();
        for (spec, _) in self.lookup_pools.iter().flat_map(|p| &p.actions) {
            if on(spec)
                && !specs
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
        self.command_types_for(&ace_sdk::Overlay::default(), &ace_sdk::Secrets::new())
    }

    /// The correlation command types, each built with the connections `overlay` binds to its slots
    /// and their secrets of `secrets`, the process's resolved ones. A binding the overlay can't make
    /// fails the type, as a failed build does; `ace` refuses such an overlay when it starts.
    pub fn command_types_for(
        &self,
        overlay: &ace_sdk::Overlay,
        secrets: &ace_sdk::Secrets,
    ) -> ace_hunt::correlate::command::CommandTypes {
        let mut types = ace_hunt::correlate::command::CommandTypes::new();
        for (name, slots, build) in &self.command_types {
            let built = self
                .command_type_bindings(overlay, name, slots)
                .and_then(|bindings| build(&ace_sdk::Connections::resolve(&bindings, secrets)))
                .and_then(|handler| types.register(name, handler).map(|_| ()));
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

    /// The summaries the GUI's alert page chooses from by an alert's type.
    pub fn alert_summaries(&self) -> &ace_gui::AlertSummaries {
        &self.summaries
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
            // a module that never stores a result has nothing to draw, and nor has a file's type
            // step, whose output is the file's type, not a result (PLAN.md decision 25)
            .filter(|m| m.name != ace_core::type_step::TYPE_STEP)
            .filter(|m| m.stores_results && !self.views.has(m.output.name, m.output.version))
            .map(|m| (m.name, m.output.name, m.output.version))
            .collect()
    }

    /// Each module whose declaration of what it takes, on its default settings, names a fact its
    /// lease wouldn't carry (`Manifest::declaration`), with why. A pool refuses such a module when
    /// it starts; a binary's own test keeps this empty.
    pub fn modules_with_unusable_declarations(&self) -> Vec<String> {
        self.registry()
            .manifests()
            .iter()
            .filter_map(|m| m.declaration(None).err().map(|e| e.to_string()))
            .collect()
    }

    /// Each module that opts into the analysis cache (`Module::CACHE`) whose task reads what its key
    /// doesn't hold (`Manifest::cache_refusal`), with why. Every binary refuses such a module when it
    /// reads its overlay; a binary's own test keeps this empty. Each cacheable module's pool must
    /// also carry the version of every tool it keys on (`ace_sdk::tools::ToolSpec::version_args`).
    pub fn modules_that_cannot_be_cached(&self) -> Vec<String> {
        let pools: Vec<(&[ace_sdk::tools::ToolSpec], Vec<Manifest>)> = self
            .parser_pools
            .iter()
            .map(|pool| (pool.tools.as_slice(), pool.registry.manifests()))
            .collect();
        let mut refused = Vec::new();
        for manifest in self.registry().manifests() {
            if let Some(why) = manifest.cache_refusal() {
                refused.push(why);
                continue;
            }
            let Some(cache) = manifest.cache else {
                continue;
            };
            for (tools, manifests) in &pools {
                if !manifests.iter().any(|m| m.name == manifest.name) {
                    continue;
                }
                for tool in cache.tools {
                    if !tools
                        .iter()
                        .any(|t| t.name == *tool && !t.version_args.is_empty())
                    {
                        refused.push(format!(
                            "{} keys on {tool}'s version, which its pool can't read",
                            manifest.name
                        ));
                    }
                }
            }
        }
        refused
    }

    /// The modules that opt into the analysis cache (`Module::CACHE`), by name.
    pub fn cacheable_modules(&self) -> Vec<&'static str> {
        self.registry()
            .manifests()
            .iter()
            .filter(|m| m.cache.is_some())
            .map(|m| m.name)
            .collect()
    }

    /// Runs the `ace` command.
    pub fn ace_main(self) -> ExitCode {
        if let Err(code) = self.install_types() {
            return code;
        }
        if let Err(wrong) = self.check_modes() {
            eprintln!("the binary's list: {wrong}");
            return ExitCode::from(2);
        }
        if let Err(wrong) = self.directive_list() {
            eprintln!("the binary's directives: {wrong}");
            return ExitCode::from(2);
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

    /// Makes this process's observable types and file roles the binary's lists, before anything
    /// reads a type or a role.
    fn install_types(&self) -> Result<(), ExitCode> {
        ace_results::install_types(&self.observable_types).map_err(|e| {
            eprintln!("the binary's observable types: {e}");
            ExitCode::from(2)
        })?;
        ace_results::install_roles(&self.file_roles).map_err(|e| {
            eprintln!("the binary's file roles: {e}");
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

    /// ace3's modes and groups, with the site's modules in the groups and the modes they joined
    /// (`module_in_group`, `module_in_mode`).
    pub fn modes(&self) -> Modes {
        let modes = self
            .groups
            .iter()
            .fold(Modes::ace3(), |modes, (group, module)| {
                modes.with_module_in_group(group, module)
            });
        self.mode_modules
            .iter()
            .fold(modes, |modes, (mode, module)| {
                modes.with_module_in_mode(mode, module)
            })
    }

    /// Every `module_in_group` pair whose group isn't one of ace3's, and every `module_in_mode` pair
    /// whose mode isn't one of ace3's or whose module no pool of the list registers, one line each,
    /// or Ok when there's none. A `module_in_group` module no pool registers may be an overlay
    /// instance's key, which only the overlay says: `check_overlay` checks it once it is read.
    fn check_modes(&self) -> Result<(), String> {
        let modes = Modes::ace3();
        let registry = self.registry();
        let manifests = registry.manifests();
        let groups = self
            .groups
            .iter()
            .filter(|(group, _)| modes.group(group).is_none())
            .map(|(group, module)| {
                let mut names: Vec<&str> = modes.group_names().collect();
                names.sort_unstable();
                format!(
                    "module_in_group({group}, {module}): there's no module group {group} (the groups are {})",
                    names.join(", ")
                )
            });
        let wrong: Vec<String> = groups
            .chain(self.mode_modules.iter().flat_map(|(mode, module)| {
                let no_mode = modes.mode(mode).is_none().then(|| {
                    let names: Vec<&str> = modes.mode_names().collect();
                    format!(
                        "module_in_mode({mode}, {module}): there's no analysis mode {mode} (the modes are {})",
                        names.join(", ")
                    )
                });
                let no_module = (!manifests.iter().any(|m| m.name == module)).then(|| {
                    format!(
                        "module_in_mode({mode}, {module}): no pool of the list registers a module {module}"
                    )
                });
                no_mode.into_iter().chain(no_module)
            }))
            .collect();
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(wrong.join("; "))
        }
    }

    /// Every `module_in_group` pair whose module is neither a module a pool of the list registers
    /// nor the key of one of `components`, the overlay's: an instance the overlay doesn't name. One
    /// line each, or Ok when there's none.
    fn check_group_instances(&self, components: &[ace_sdk::Component]) -> Result<(), String> {
        let manifests = self.registry().manifests();
        let wrong: Vec<String> = self
            .groups
            .iter()
            .filter(|(_, module)| {
                !manifests.iter().any(|m| m.name == module)
                    && !components.iter().any(|c| &c.key == module)
            })
            .map(|(group, module)| {
                format!(
                    "module_in_group({group}, {module}): no pool of the list registers a module {module}, \
                     and the overlay names no instance {module}"
                )
            })
            .collect();
        if wrong.is_empty() {
            Ok(())
        } else {
            Err(wrong.join("; "))
        }
    }

    /// Every connection type a component of the binary takes (`ace_sdk::connections`): its modules',
    /// action handlers', collectors', AI backend types' and command types' slots.
    pub fn connection_kinds(&self) -> Vec<ace_sdk::ConnectionKind> {
        let modules = self
            .registry()
            .manifests()
            .into_iter()
            .flat_map(|m| m.connections.iter().copied());
        let actions = self
            .lookup_pools
            .iter()
            .flat_map(|p| &p.actions)
            .flat_map(|(spec, _)| spec.connections.iter().copied());
        let collectors = self
            .collectors
            .iter()
            .flat_map(|(spec, _)| spec.connections.iter().copied());
        let backends = self
            .ai_backend_types
            .iter()
            .flat_map(|(_, kind)| kind.connections.iter().copied());
        let commands = self
            .command_types
            .iter()
            .flat_map(|(_, slots, _)| slots.iter().copied());
        let mut kinds: Vec<ace_sdk::ConnectionKind> = Vec::new();
        for slot in modules
            .chain(actions)
            .chain(collectors)
            .chain(backends)
            .chain(commands)
        {
            if !kinds.contains(&slot.kind) {
                kinds.push(slot.kind);
            }
        }
        kinds
    }

    /// The bindings `overlay` makes for the command type `name`'s `slots`.
    fn command_type_bindings(
        &self,
        overlay: &ace_sdk::Overlay,
        name: &str,
        slots: &[ace_sdk::ConnectionSlot],
    ) -> Result<Vec<ace_sdk::Binding>, String> {
        let uses = overlay
            .command_types
            .get(name)
            .map(|section| section.connections.clone())
            .unwrap_or_default();
        overlay
            .bind(&format!("command_types.{name}.connections"), slots, &uses)
            .map_err(|e| e.to_string())
    }

    /// The secrets of the connections `overlay` binds to the command types' slots: what `ace hunter`,
    /// which runs the commands, resolves for them.
    pub fn command_type_secret_names(&self, overlay: &ace_sdk::Overlay) -> Vec<String> {
        let bindings: Vec<ace_sdk::Binding> = self
            .command_types
            .iter()
            .filter_map(|(name, slots, _)| self.command_type_bindings(overlay, name, slots).ok())
            .flatten()
            .collect();
        ace_sdk::connections::secret_names(&bindings)
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    /// What an `ace` command checks of the overlay once it is read, before it uses it: every shared
    /// connection against its type (one no component of the binary takes is refused), every
    /// component's `connections:` against its slots (the modules', the action handlers', the
    /// collectors', the AI backends' and the command types'), a `command_types:` entry for a type the
    /// binary hasn't, and every `module_in_group` module that no pool registers against the
    /// overlay's instances. Each error names the path.
    pub fn check_overlay(&self, overlay: &ace_sdk::Overlay) -> Result<(), String> {
        overlay
            .check_connections(&self.connection_kinds())
            .map_err(|e| e.to_string())?;
        let components = overlay
            .components(&self.registry().manifests())
            .map_err(|e| e.to_string())?;
        for pool in &self.lookup_pools {
            for (spec, _) in &pool.actions {
                let entry = spec.overlay_entry();
                if let Some(section) = overlay.actions.get(&entry) {
                    overlay
                        .bind(
                            &format!("actions.{entry}.connections"),
                            spec.connections,
                            &section.connections,
                        )
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        for (spec, _) in &self.collectors {
            if let Some(section) = overlay.collectors.get(spec.name) {
                overlay
                    .bind(
                        &format!("collectors.{}.connections", spec.name),
                        spec.connections,
                        &section.connections,
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        let backend_types = self.ai_backend_types();
        for (name, backend) in &overlay.ai_api.backends {
            if let Some(kind) = backend_types.get(&backend.kind) {
                overlay
                    .bind(
                        &format!("ai_api.backends.{name}.connections"),
                        kind.connections,
                        &backend.connections,
                    )
                    .map_err(|e| e.to_string())?;
            }
        }
        if let Some(unknown) = overlay
            .command_types
            .keys()
            .find(|name| !self.command_types.iter().any(|(n, _, _)| n == *name))
        {
            return Err(format!(
                "the overlay's command_types.{unknown}: this binary has no command type {unknown}"
            ));
        }
        for (name, slots, _) in &self.command_types {
            self.command_type_bindings(overlay, name, slots)?;
        }
        self.check_group_instances(&components)
            .map_err(|wrong| format!("the binary's list and the overlay: {wrong}"))
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

/// Panics when `added` holds a module `pool` has, which would run twice.
fn refuse_repeats(name: &str, pool: &Registry, added: &Registry) {
    for manifest in added.manifests() {
        assert!(
            pool.manifest(manifest.name).is_none(),
            "the pool {name} has the module {} already",
            manifest.name
        );
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
    /// PLAN.md decision 32 part (b): a site registers a pivot link icon by name, a PNG, which the
    /// GUI then serves; ace4 registers none.
    #[test]
    fn a_site_registers_a_pivot_link_icon() {
        const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89";
        assert!(App::new().pivot_link_icons().names().is_empty());
        let app = App::new().pivot_link_icon("vendor_portal", PNG);
        assert_eq!(app.pivot_link_icons().names(), ["vendor_portal"]);
        let bad = std::panic::catch_unwind(|| App::new().pivot_link_icon("vendor", b"GIF89a"));
        assert!(bad.is_err(), "a GIF isn't taken");
        let bad = std::panic::catch_unwind(|| App::new().pivot_link_icon("Vendor Portal", PNG));
        assert!(bad.is_err(), "a name with a space isn't taken");
    }

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

    fn base() -> App {
        App::new()
            .parser_pool(
                ParserPool::new("parsers")
                    .module::<ace_mod_email::EmailAnalyzer>()
                    .commands(),
            )
            .lookup_pool(LookupPool::new("lookups").action(
                &ace_sdk::actions::TEST_REMEDIATOR,
                |_| {
                    Ok(ActionHandler::Remediator(Arc::new(
                        ace_sdk::actions::TestRemediator,
                    )))
                },
            ))
            .scanner_pool(ScannerPool::new("scanners").scanner(ace_sdk::scanners::PHISHKIT))
    }

    /// A site adds to a pool of a list it builds on (PLAN.md 6.1): what it adds joins the pool, and
    /// everything the pool held stays.
    #[test]
    fn a_site_adds_to_a_pool_and_drops_nothing() {
        let app = base()
            .add_to_parser_pool("parsers", |pool| pool.module::<ace_mod_yara::YaraScanner>())
            .add_to_lookup_pool("lookups", |pool| pool.module::<ace_mod_dns::FqdnAnalyzer>())
            .add_to_scanner_pool("scanners", |pool| {
                pool.scanner(ace_sdk::scanners::JS_DEOBFUSCATOR)
            });
        assert_eq!(
            app.pool_list(),
            "parsers:email_analyzer,yara_scanner_v3_4,@commands;\
             lookups:fqdn_analyzer,@remediation/test;\
             scanners:@scan/phishkit,@scan/js-deobfuscator"
        );
    }

    /// A module the pool has already would run twice, so it's refused, as is a pool the list hasn't.
    #[test]
    #[should_panic(expected = "the pool parsers has the module email_analyzer already")]
    fn a_site_can_t_add_a_module_twice() {
        let _ = base().add_to_parser_pool("parsers", |pool| {
            pool.module::<ace_mod_email::EmailAnalyzer>()
        });
    }

    #[test]
    #[should_panic(expected = "the list has no network pool network")]
    fn a_site_can_t_add_to_a_pool_the_list_hasn_t() {
        let _ =
            base().add_to_lookup_pool("network", |pool| pool.module::<ace_mod_dns::FqdnAnalyzer>());
    }

    /// A collector's name is its component's, so it can't hold a `:`.
    #[test]
    #[should_panic(expected = "can't name a collector")]
    fn a_collector_s_name_is_a_component_s() {
        struct Nothing;
        impl collector::Collector for Nothing {
            fn collect<'a>(&'a self, _: &'a collector::Submitter) -> collector::PassFuture<'a> {
                Box::pin(async { Ok(collector::Pass::Drained) })
            }
        }
        let app = App::new().collector(collector::CollectorSpec::new("journal"), |_| {
            Ok(Arc::new(Nothing))
        });
        assert_eq!(app.collector_names(), ["journal"]);
        let _ = app.collector(collector::CollectorSpec::new("a:b"), |_| {
            Ok(Arc::new(Nothing))
        });
    }

    /// A module put in one mode (ace3's `analysis_mode_<mode>: enabled_modules:`) runs in that mode
    /// and no other; one in a group as well runs wherever either puts it.
    #[test]
    fn a_module_in_a_mode_runs_in_that_mode_alone() {
        let app = base()
            .add_to_lookup_pool("lookups", |pool| pool.module::<ace_mod_dns::FqdnAnalyzer>())
            .module_in_mode("dispositioned", "email_analyzer")
            .module_in_mode("correlation", "fqdn_analyzer");
        assert_eq!(app.check_modes(), Ok(()));
        let modes = app.modes();
        let running = |module: &str| -> Vec<String> {
            modes
                .mode_names()
                .filter(|m| modes.modules_in(m).contains(module))
                .map(str::to_owned)
                .collect()
        };
        // fqdn_analyzer is in ace3's correlation group, so the mode adds nothing to where it runs
        assert_eq!(running("fqdn_analyzer"), ["analysis", "cli", "correlation"]);
        // email_analyzer's group, email, runs in four modes, and now dispositioned too
        assert_eq!(
            running("email_analyzer"),
            ["analysis", "cli", "correlation", "dispositioned", "email"]
        );
    }

    /// A mode that isn't one of ace3's, or a module no pool registers, stops the binary before any
    /// command runs, with each wrong pair named.
    #[test]
    fn a_module_in_a_mode_that_isn_t_or_a_module_the_list_hasn_t_is_refused() {
        let app = base()
            .module_in_mode("corelation", "email_analyzer")
            .module_in_mode("correlation", "email_analyzer")
            .module_in_mode("correlation", "mail_api_email_extraction");
        let wrong = app.check_modes().expect_err("refused");
        assert_eq!(
            wrong,
            "module_in_mode(corelation, email_analyzer): there's no analysis mode corelation \
             (the modes are analysis, binary, cli, correlation, dispositioned, email, event, file, \
             suricata_ids, yara); module_in_mode(correlation, mail_api_email_extraction): no pool of \
             the list registers a module mail_api_email_extraction"
        );
        assert_eq!(app.ace_main(), ExitCode::from(2));
    }

    /// A group that isn't one of ace3's stops the binary before any command runs, with the pair
    /// named. A module no pool registers may be an overlay instance's key: the binary starts, and
    /// the overlay, once read, must name that instance.
    #[test]
    fn a_module_in_a_group_that_isn_t_or_an_instance_the_overlay_hasn_t_is_refused() {
        let app = base()
            .module_in_group("corelation", "email_analyzer")
            .module_in_group("correlation", "email_analyzer");
        let wrong = app.check_modes().expect_err("refused");
        assert!(
            wrong.starts_with(
                "module_in_group(corelation, email_analyzer): there's no module group corelation \
                 (the groups are "
            ) && wrong.contains(" correlation, ")
                && !wrong.contains(';'),
            "{wrong}"
        );
        assert_eq!(app.ace_main(), ExitCode::from(2));

        let app = base().module_in_group("correlation", "email_copy");
        assert_eq!(
            app.check_modes(),
            Ok(()),
            "an instance is known only to the overlay"
        );
        let wrong = app
            .check_overlay(&ace_sdk::Overlay::default())
            .expect_err("the overlay names no instance email_copy");
        assert_eq!(
            wrong,
            "the binary's list and the overlay: module_in_group(correlation, email_copy): no pool of \
             the list registers a module email_copy, and the overlay names no instance email_copy"
        );
        let overlay =
            ace_sdk::Overlay::from_yaml("modules: {email_analyzer: {instances: {email_copy: {}}}}")
                .expect("loads");
        assert_eq!(app.check_overlay(&overlay), Ok(()));
        // a registered module needs no overlay
        let app = base().module_in_group("correlation", "email_analyzer");
        assert_eq!(app.check_modes(), Ok(()));
        assert_eq!(app.check_overlay(&ace_sdk::Overlay::default()), Ok(()));
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
