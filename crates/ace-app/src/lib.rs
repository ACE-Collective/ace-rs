//! Builds the `ace` binary and each pool binary from a list of crates (PLAN.md 2.31), so a site
//! repository can build its own from this workspace's crates and its own (decision 9).
//!
//! An `App` is that list: the pools and the modules each one runs, the site's observable types,
//! and the module groups its modules join. Each binary is a short `main` over one:
//!
//! ```text
//! // the core: `ace serve`, `ace task replay`, `ace schema export`, `ace yara ...`
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
//! here once its feature exists in ace4: analysis modules and observable types now, collectors
//! with the first collector (6.1), and the rest with the phases that build them.
//!
//! Everything here reads its configuration from the environment and the site overlay at run
//! time, and nothing from this workspace's checkout, so a binary built in another repository
//! runs the same way.

mod cli;
mod pools;
mod root;
mod schema;
mod serve;
mod task;
mod yara;

use std::path::Path;
use std::process::ExitCode;

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
    groups: Vec<(String, String)>,
}

/// A parser pool: modules that read files, one contained process per task (PLAN.md 2.17).
pub struct ParserPool {
    name: String,
    registry: Registry,
    rulesets: Option<Rulesets>,
}

/// A network pool: lookups, many at a time as async tasks in one contained process (2.16).
pub struct LookupPool {
    name: String,
    registry: Registry,
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

    /// The pools and their modules, as `ACE4_POOLS` lists them: the core's default.
    fn pool_list(&self) -> String {
        let pool = |name: &str, registry: &Registry| {
            let modules: Vec<&str> = registry.manifests().iter().map(|m| m.name).collect();
            format!("{name}:{}", modules.join(","))
        };
        self.parser_pools
            .iter()
            .map(|p| pool(&p.name, &p.registry))
            .chain(self.lookup_pools.iter().map(|p| pool(&p.name, &p.registry)))
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
        }
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
        }
    }

    pub fn module<M: Lookup>(mut self) -> LookupPool {
        self.registry = self.registry.lookup::<M>();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_core_lists_each_pool_and_its_modules() {
        let app = App::new()
            .parser_pool(
                ParserPool::new("parsers")
                    .module::<ace_mod_email::EmailAnalyzer>()
                    .module::<ace_mod_yara::YaraScanner>(),
            )
            .lookup_pool(LookupPool::new("lookups"));
        assert_eq!(
            app.pool_list(),
            "parsers:email_analyzer,yara_scanner_v3_4;lookups:"
        );
        let names: Vec<&str> = app.registry().manifests().iter().map(|m| m.name).collect();
        assert_eq!(names, ["email_analyzer", "yara_scanner_v3_4"]);
    }
}
