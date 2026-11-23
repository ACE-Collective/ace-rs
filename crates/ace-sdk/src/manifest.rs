//! Module manifests and settings loading.
//!
//! Each module crate exports its manifest as a constant, built from the module's type:
//!
//! ```text
//! pub const MANIFEST: Manifest = Manifest::parser::<EmailAnalyzer>();
//! ```
//!
//! A manifest says what the module takes and writes, what it depends on, the limits and sandbox
//! it runs under, the schema of its settings and the secrets it reads. The core and the pools
//! read it without building the module.

use std::fmt;
use std::time::Duration;

use ace_results::{AnalysisTypeInfo, ObservableKind};
use schemars::Schema;
use serde_json::{Value, json};

use crate::lists::ListSpec;
use crate::module::{EXCLUDE_ALL, Lookup, Module, OtherAdditionsAllowed, Parser, Settings};
use crate::reads::Read;
use crate::takes::Takes;
use crate::tree::TreeFiles;
use crate::writes::Write;

/// The limits a module's task runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    /// The task's deadline, which `TaskContext::time_left` counts down to.
    pub timeout: Duration,
    /// A parser process's address-space limit. A lookup shares its pool's memory limit.
    pub memory_mb: u64,
    /// A parser process's CPU-time limit.
    pub cpu_seconds: u64,
}

impl Resources {
    pub const DEFAULT: Resources = Resources {
        timeout: Duration::from_secs(300),
        memory_mb: 1024,
        cpu_seconds: 300,
    };
}

impl Default for Resources {
    fn default() -> Self {
        Resources::DEFAULT
    }
}

/// How a module's task is contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sandbox {
    /// A parser: one single-threaded process per task, with rlimits, Landlock rules and a seccomp
    /// filter that blocks fork, clone and exec (PLAN.md 2.18). No network.
    Contained,
    /// A lookup: a task in an async pool process that may connect to these TCP ports.
    Network { tcp_ports: &'static [u16] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Parser,
    Lookup,
}

/// What the core and the pools know about a module without building it.
#[derive(Clone, Copy)]
pub struct Manifest {
    pub name: &'static str,
    pub kind: ModuleKind,
    /// The observable types the module takes. A type that extends one of these is taken too.
    pub inputs: &'static [ObservableKind],
    /// The module takes every installed type (`Module::ANY_INPUT`).
    pub any_input: bool,
    pub output: AnalysisTypeInfo,
    /// Modules that run on the observable before this one (`Module::DEPENDS_ON`).
    pub depends_on: &'static [&'static str],
    /// `analyze` reads its dependencies' results, not only its declaration
    /// (`Module::READS_DEPENDENCIES`).
    pub reads_dependencies: bool,
    /// Directives that keep the module off an observable, besides `exclude_all`.
    pub skip_directives: &'static [&'static str],
    /// Directives an observable must have for the module to run on it.
    pub required_directives: &'static [&'static str],
    /// Directives an observable of one type must have (`Module::REQUIRED_DIRECTIVES_BY_KIND`).
    pub required_directives_by_kind: &'static [(ObservableKind, &'static [&'static str])],
    pub resources: Resources,
    pub sandbox: Sandbox,
    pub secrets: &'static [&'static str],
    /// The shared connections it takes (`Module::CONNECTIONS`).
    pub connections: &'static [crate::connections::ConnectionSlot],
    /// The module runs only as named instances (`Module::INSTANCES_ONLY`).
    pub instances_only: bool,
    /// The module runs without an overlay section (`Module::ENABLED_BY_DEFAULT`).
    pub enabled_by_default: bool,
    /// The module reads its carrying email (`Module::READS_CARRYING_EMAIL`).
    pub reads_carrying_email: bool,
    /// The module runs when the rest of its root is done (`Module::RUNS_LAST`).
    pub runs_last: bool,
    /// The observable types below its observable a module that runs last reads
    /// (`Module::READS_BELOW`).
    pub reads_below: &'static [ObservableKind],
    /// The module reads which modules' results added its observable (`Module::READS_ADDED_BY`).
    pub reads_added_by: bool,
    /// The module reads its related observables' tags (`Module::READS_RELATED_TAGS`).
    pub reads_related_tags: bool,
    /// The module reads its root's event time (`Module::READS_EVENT_TIME`).
    pub reads_event_time: bool,
    /// ace3's `automation_limit` on its defaults (`Module::AUTOMATION_LIMIT`).
    pub automation_limit: Option<u32>,
    /// The module reads its root's tree (`Module::READS_TREE`).
    pub reads_tree: bool,
    /// The files of the tree whose bytes it reads (`Module::READS_TREE_FILES`).
    pub reads_tree_files: Option<TreeFiles>,
    /// The modules whose results' details it reads in its tree (`Module::READS_TREE_DETAILS`).
    pub reads_tree_details: &'static [&'static str],
    /// What the module may add to other observables in its root (`Module::ADDS_TO_OTHERS`).
    pub adds_to_others: Option<OtherAdditionsAllowed>,
    /// The module changes its root's description and details (`Module::SETS_ROOT`).
    pub sets_root: bool,
    /// The module adds links to its root's (`Module::ADDS_ROOT_PIVOT_LINKS`).
    pub adds_root_pivot_links: bool,
    /// The module adds files a module it depends on stored for the root
    /// (`Module::ADDS_STORED_FILES`).
    pub adds_stored_files: bool,
    /// The lookup adds files it fetched (`Module::ADDS_FETCHED_FILES`).
    pub adds_fetched_files: bool,
    /// The lookup reads its input file's bytes (`Module::READS_INPUT_FILE`).
    pub reads_input_file: bool,
    /// The modules its results may limit what they add to (`Module::LIMITS_ANALYSIS_TO`).
    pub limits_analysis_to: &'static [&'static str],
    /// The analyst-edited lists the module reads (`Module::LISTS`).
    pub lists: &'static [ListSpec],
    /// The reads of ACE's own data the module makes (`Module::READS`).
    pub reads: &'static [Read],
    /// The writes to ACE's own data the module makes (`Module::WRITES`).
    pub writes: &'static [Write],
    /// The module's tasks end with a result when they find something (`Module::STORES_RESULTS`).
    pub stores_results: bool,
    /// The programs the module runs (`Module::TOOLS`).
    pub tools: &'static [&'static str],
    /// The scanners the module sends its observable through (`Module::SCANNERS`).
    pub scanners: &'static [&'static str],
    /// The module's opt-in to the analysis cache (`Module::CACHE`).
    pub cache: Option<crate::cache::Cache>,
    settings_schema: fn() -> Schema,
    check_settings: fn(Option<&Value>) -> Result<(), SettingsError>,
    takes: fn(Option<&Value>) -> Result<Takes, SettingsError>,
}

impl Manifest {
    /// A parser's manifest. A parser that declares a read or a write doesn't build: its task
    /// process has no network and no channel back while it runs, so it gets ACE's data on the
    /// lease, and its result is all it hands back.
    pub const fn parser<M: Parser>() -> Self {
        assert!(
            M::READS.is_empty(),
            "a parser can't declare reads (Module::READS)"
        );
        assert!(
            M::WRITES.is_empty(),
            "a parser can't declare writes (Module::WRITES)"
        );
        assert!(
            M::CONNECTIONS.is_empty(),
            "a parser can't take a connection (Module::CONNECTIONS)"
        );
        assert!(
            !M::ADDS_FETCHED_FILES,
            "a parser can't declare fetched files (Module::ADDS_FETCHED_FILES): its supervisor uploads its files"
        );
        assert!(
            !M::READS_INPUT_FILE,
            "a parser can't declare it reads its input file (Module::READS_INPUT_FILE): it always does"
        );
        Manifest::of::<M>(ModuleKind::Parser, Sandbox::Contained)
    }

    pub const fn lookup<M: Lookup>() -> Self {
        assert!(
            M::TOOLS.is_empty(),
            "a lookup can't declare tools (Module::TOOLS)"
        );
        assert!(
            M::SCANNERS.is_empty(),
            "a lookup can't declare scanners (Module::SCANNERS)"
        );
        Manifest::of::<M>(
            ModuleKind::Lookup,
            Sandbox::Network {
                tcp_ports: M::TCP_PORTS,
            },
        )
    }

    const fn of<M: Module>(kind: ModuleKind, sandbox: Sandbox) -> Self {
        assert!(
            M::READS_TREE || M::READS_TREE_FILES.is_none(),
            "a module reads its tree's files only with its tree (Module::READS_TREE)"
        );
        assert!(
            M::READS_TREE || M::READS_TREE_DETAILS.is_empty(),
            "a module reads results' details only with its tree (Module::READS_TREE)"
        );
        Manifest {
            name: M::NAME,
            kind,
            inputs: M::INPUTS,
            any_input: M::ANY_INPUT,
            output: AnalysisTypeInfo::of::<M::Output>(),
            depends_on: M::DEPENDS_ON,
            reads_dependencies: M::READS_DEPENDENCIES,
            skip_directives: M::SKIP_DIRECTIVES,
            required_directives: M::REQUIRED_DIRECTIVES,
            required_directives_by_kind: M::REQUIRED_DIRECTIVES_BY_KIND,
            resources: M::RESOURCES,
            sandbox,
            secrets: M::SECRETS,
            connections: M::CONNECTIONS,
            instances_only: M::INSTANCES_ONLY,
            enabled_by_default: M::ENABLED_BY_DEFAULT,
            reads_carrying_email: M::READS_CARRYING_EMAIL,
            runs_last: M::RUNS_LAST,
            reads_below: M::READS_BELOW,
            reads_added_by: M::READS_ADDED_BY,
            reads_related_tags: M::READS_RELATED_TAGS,
            reads_event_time: M::READS_EVENT_TIME,
            automation_limit: M::AUTOMATION_LIMIT,
            reads_tree: M::READS_TREE,
            reads_tree_files: M::READS_TREE_FILES,
            reads_tree_details: M::READS_TREE_DETAILS,
            adds_to_others: M::ADDS_TO_OTHERS,
            sets_root: M::SETS_ROOT,
            adds_root_pivot_links: M::ADDS_ROOT_PIVOT_LINKS,
            adds_stored_files: M::ADDS_STORED_FILES,
            adds_fetched_files: M::ADDS_FETCHED_FILES,
            reads_input_file: M::READS_INPUT_FILE,
            limits_analysis_to: M::LIMITS_ANALYSIS_TO,
            lists: M::LISTS,
            reads: M::READS,
            writes: M::WRITES,
            stores_results: M::STORES_RESULTS,
            tools: M::TOOLS,
            scanners: M::SCANNERS,
            cache: M::CACHE,
            settings_schema: settings_schema::<M::Settings>,
            check_settings: check_settings::<M::Settings>,
            takes: takes::<M>,
        }
    }

    /// The JSON Schema of the module's settings block.
    pub fn settings_schema(&self) -> Schema {
        (self.settings_schema)()
    }

    /// Checks a settings block without building the module, as a config overlay is loaded.
    pub fn check_settings(&self, block: Option<&Value>) -> Result<(), SettingsError> {
        (self.check_settings)(block)
    }

    /// What the module takes on a settings block (`Module::takes`, `crate::takes`), checked against
    /// what its lease carries: a rule on a dependency's result needs the dependency in
    /// `DEPENDS_ON`, and a lookup's rules can read a file's path but not its size, mime type or
    /// `yara_meta`, which only a parser's lease carries with the bytes, and a lookup's that reads its
    /// input file (`Module::READS_INPUT_FILE`, PLAN.md decision 45). Otherwise the pool would decline on a fact
    /// its task lacks where the core took it. Which modules added the observable, whether it came
    /// with the submission and the root's mode come in the lease's gate for the declaration alone
    /// (`wire::Gate`), whatever the module's `analyze` reads.
    pub fn declaration(&self, block: Option<&Value>) -> Result<Takes, DeclarationError> {
        let takes = (self.takes)(block).map_err(DeclarationError::Settings)?;
        let reads = takes.reads();
        let refuse = |what: String| Err(DeclarationError::Unread(self.name, what));
        if let Some(module) = reads
            .results
            .iter()
            .find(|m| !self.depends_on.contains(&m.as_str()))
        {
            return refuse(format!("{module}'s result, which isn't in DEPENDS_ON"));
        }
        if reads.file_record && self.kind == ModuleKind::Lookup && !self.reads_input_file {
            return refuse(
                "a file's size, type, role or yara_meta, which a lookup's lease lacks unless it reads its input file (READS_INPUT_FILE)".into(),
            );
        }
        Ok(takes)
    }

    /// Why the module can't be cached as it opts in (`Module::CACHE`), or None when it can, or
    /// doesn't opt in: what its task reads that its key doesn't hold (`crate::cache::refusal`).
    pub fn cache_refusal(&self) -> Option<String> {
        crate::cache::refusal(self)
    }

    /// True when the module takes observables of `kind`, directly or through a parent type, or
    /// takes every type (`Module::ANY_INPUT`).
    pub fn accepts(&self, kind: ObservableKind) -> bool {
        self.any_input || self.inputs.iter().any(|&input| kind.is_subtype_of(input))
    }

    /// The types it takes as itself: its `INPUTS`, or every type the binary installed
    /// (`ObservableKind::all`) for a module that takes any. Read once the binary installed its
    /// types, as `ace_app` does first.
    pub fn input_kinds(&self) -> Vec<ObservableKind> {
        if self.any_input {
            ObservableKind::all().to_vec()
        } else {
            self.inputs.to_vec()
        }
    }

    /// The first of `directives` that keeps the module off an observable: `exclude_all`, or one
    /// of the module's own skip directives.
    pub fn skipped_by<'d>(&self, directives: &'d [String]) -> Option<&'d str> {
        directives
            .iter()
            .map(String::as_str)
            .find(|d| *d == EXCLUDE_ALL || self.skip_directives.contains(d))
    }

    /// The first of the module's required directives that `directives` lacks.
    pub fn missing_directive(&self, directives: &[String]) -> Option<&'static str> {
        self.required_directives
            .iter()
            .copied()
            .find(|required| !directives.iter().any(|d| d == required))
    }

    /// The first directive an observable of type `kind` needs for the module and lacks: the
    /// module's own requirements first, then its type's (`Module::REQUIRED_DIRECTIVES_BY_KIND`).
    pub fn missing_directive_for(
        &self,
        kind: ObservableKind,
        directives: &[String],
    ) -> Option<&'static str> {
        self.missing_directive(directives).or_else(|| {
            self.required_directives_by_kind
                .iter()
                .filter(|(k, _)| *k == kind)
                .flat_map(|(_, required)| required.iter().copied())
                .find(|required| !directives.iter().any(|d| d == required))
        })
    }

    /// The manifest as JSON, for listing modules and for snapshots.
    pub fn describe(&self) -> Value {
        let sandbox = match self.sandbox {
            Sandbox::Contained => json!({"kind": "contained"}),
            Sandbox::Network { tcp_ports } => json!({"kind": "network", "tcp_ports": tcp_ports}),
        };
        json!({
            "name": self.name,
            "kind": match self.kind {
                ModuleKind::Parser => "parser",
                ModuleKind::Lookup => "lookup",
            },
            "inputs": self.input_kinds(),
            "output": {"analysis_type": self.output.name, "schema_version": self.output.version},
            "depends_on": self.depends_on,
            "skip_directives": self.skip_directives,
            "resources": {
                "timeout_seconds": self.resources.timeout.as_secs(),
                "memory_mb": self.resources.memory_mb,
                "cpu_seconds": self.resources.cpu_seconds,
            },
            "sandbox": sandbox,
            "secrets": self.secrets,
            "connections": self
                .connections
                .iter()
                .map(|slot| json!({"slot": slot.name, "type": slot.kind.name, "secrets": slot.kind.secrets}))
                .collect::<Vec<_>>(),
            "reads": self.reads.iter().map(|r| r.name).collect::<Vec<_>>(),
            "writes": self.writes.iter().map(|w| w.name).collect::<Vec<_>>(),
            "tools": self.tools,
            "scanners": self.scanners,
            "required_directives": self.required_directives,
            "required_directives_by_kind": self
                .required_directives_by_kind
                .iter()
                .map(|(kind, directives)| json!({"type": kind, "directives": directives}))
                .collect::<Vec<_>>(),
            "settings_schema": self.settings_schema(),
            // on its default settings; a site's settings can change it (`Component::takes`)
            "takes": self.declaration(None).map_or(Value::Null, |takes| takes.describe()),
            // ace3's `cache_ttl`, on its defaults; a site's overlay can change it (`cache_ttl`)
            "cache": self.cache.as_ref().map(|cache| json!({
                "version": cache.version,
                "ttl_seconds": cache.ttl.as_secs(),
                "lists": cache.lists.iter().map(|l| l.name).collect::<Vec<_>>(),
                "tools": cache.tools,
                "files": cache.files,
            })),
        })
    }
}

impl fmt::Debug for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manifest")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("inputs", &self.inputs)
            .field("output", &self.output)
            .field("depends_on", &self.depends_on)
            .field("skip_directives", &self.skip_directives)
            .field("resources", &self.resources)
            .field("sandbox", &self.sandbox)
            .field("secrets", &self.secrets)
            .field("connections", &self.connections)
            .finish_non_exhaustive()
    }
}

fn settings_schema<S: Settings>() -> Schema {
    schemars::schema_for!(S)
}

fn check_settings<S: Settings>(block: Option<&Value>) -> Result<(), SettingsError> {
    load_settings::<S>(block).map(drop)
}

fn takes<M: Module>(block: Option<&Value>) -> Result<Takes, SettingsError> {
    load_settings::<M::Settings>(block).map(|settings| M::takes(&settings))
}

/// A declaration of what a module takes that can't be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    #[error(transparent)]
    Settings(SettingsError),
    #[error("{0} declares what it takes from {1}")]
    Unread(&'static str, String),
}

/// A settings block that didn't load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    #[error("unknown settings key {path}")]
    UnknownKey { path: String },
    #[error("invalid setting {path}: {message}")]
    Invalid { path: String, message: String },
}

/// Loads a module's settings block. A missing or null block gives the defaults. A key the
/// settings type doesn't declare fails to load (ace3 #858), whether or not the type remembered
/// `#[serde(deny_unknown_fields)]`.
pub fn load_settings<S: Settings>(block: Option<&Value>) -> Result<S, SettingsError> {
    let block = match block {
        None | Some(Value::Null) => return Ok(S::default()),
        Some(block) => block,
    };
    let mut unknown = Vec::new();
    let mut note_unknown = |path: serde_ignored::Path<'_>| unknown.push(path.to_string());
    let deserializer = serde_ignored::Deserializer::new(block, &mut note_unknown);
    let settings: S = serde_path_to_error::deserialize(deserializer).map_err(|e| {
        let path = e.path().to_string();
        let message = e.into_inner().to_string();
        // a type with deny_unknown_fields fails on the key itself, and the path ends with it
        if message.starts_with("unknown field `") {
            SettingsError::UnknownKey { path }
        } else {
            SettingsError::Invalid { path, message }
        }
    })?;
    match unknown.into_iter().next() {
        Some(path) => Err(SettingsError::UnknownKey { path }),
        None => Ok(settings),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::example::{LineCounter, LineCounterSettings, Resolver, ResolverSettings};
    use schemars::JsonSchema;
    use serde::Deserialize;

    const LINE_COUNTER: Manifest = Manifest::parser::<LineCounter>();
    const RESOLVER: Manifest = Manifest::lookup::<Resolver>();

    #[test]
    fn a_settings_block_with_an_unknown_key_fails_to_load() {
        let block = json!({"max_bytes": 10, "max_byte": 20});
        let err = load_settings::<LineCounterSettings>(Some(&block)).unwrap_err();
        println!("{err}");
        assert_eq!(
            err,
            SettingsError::UnknownKey {
                path: "max_byte".to_owned()
            }
        );
        assert_eq!(LINE_COUNTER.check_settings(Some(&block)), Err(err));
    }

    #[test]
    fn known_keys_load_and_missing_ones_default() {
        let settings: LineCounterSettings =
            load_settings(Some(&json!({"max_bytes": 10}))).expect("loads");
        assert_eq!(settings.max_bytes, 10);
        assert_eq!(
            load_settings::<LineCounterSettings>(None).expect("defaults"),
            LineCounterSettings::default()
        );
        assert_eq!(
            load_settings::<LineCounterSettings>(Some(&Value::Null)).expect("defaults"),
            LineCounterSettings::default()
        );
        assert_eq!(
            load_settings::<ResolverSettings>(Some(&json!({"delays": 2})))
                .expect("loads")
                .delays,
            2
        );
    }

    #[test]
    fn a_wrong_type_names_its_key() {
        let err =
            load_settings::<LineCounterSettings>(Some(&json!({"max_bytes": "ten"}))).unwrap_err();
        assert!(
            matches!(&err, SettingsError::Invalid { path, .. } if path == "max_bytes"),
            "{err}"
        );
    }

    /// A settings type whose nested struct forgot deny_unknown_fields.
    #[derive(Debug, Default, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    struct Outer {
        inner: Inner,
    }

    #[derive(Debug, Default, Deserialize, JsonSchema)]
    #[serde(default)]
    struct Inner {
        port: u16,
    }

    #[test]
    fn unknown_keys_fail_even_without_deny_unknown_fields() {
        let err =
            load_settings::<Outer>(Some(&json!({"inner": {"port": 1, "host": "x"}}))).unwrap_err();
        assert_eq!(
            err,
            SettingsError::UnknownKey {
                path: "inner.host".to_owned()
            }
        );
        let err = load_settings::<Outer>(Some(&json!({"outer": 1}))).unwrap_err();
        assert_eq!(
            err,
            SettingsError::UnknownKey {
                path: "outer".to_owned()
            }
        );
    }

    /// A parser that declares a read, which it couldn't make.
    struct ReadingParser;

    impl Module for ReadingParser {
        const NAME: &'static str = "reading_parser";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const READS: &'static [crate::reads::Read] =
            &[<crate::reads::SnortSignature as crate::reads::ReadKind>::READ];
        type Output = crate::example::LineStats;
        type Settings = LineCounterSettings;
        fn init(_: &LineCounterSettings) -> Result<Self, crate::ModuleError> {
            Ok(ReadingParser)
        }
    }

    impl Parser for ReadingParser {
        fn analyze(
            &self,
            _: &crate::TaskContext<LineCounterSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(String::new()))
        }
    }

    #[test]
    fn a_parser_can_t_declare_a_read_but_a_lookup_can() {
        // in a constant, as a module crate's MANIFEST is, this fails the build
        let refused = std::panic::catch_unwind(Manifest::parser::<ReadingParser>);
        assert!(refused.is_err());
        assert!(RESOLVER.reads.is_empty());
        assert_eq!(RESOLVER.describe()["reads"], json!([]));
    }

    /// A parser that declares a write, which it couldn't hand back.
    struct WritingParser;

    impl Module for WritingParser {
        const NAME: &'static str = "writing_parser";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const WRITES: &'static [Write] =
            &[<crate::writes::SmtpLog as crate::writes::WriteKind>::WRITE];
        type Output = crate::example::LineStats;
        type Settings = LineCounterSettings;
        fn init(_: &LineCounterSettings) -> Result<Self, crate::ModuleError> {
            Ok(WritingParser)
        }
    }

    impl Parser for WritingParser {
        fn analyze(
            &self,
            _: &crate::TaskContext<LineCounterSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(String::new()))
        }
    }

    #[test]
    fn a_parser_can_t_declare_a_write() {
        let refused = std::panic::catch_unwind(Manifest::parser::<WritingParser>);
        assert!(refused.is_err());
        assert_eq!(RESOLVER.describe()["writes"], json!([]));
    }

    /// A parser and a lookup that declare what they take from facts named in their settings.
    struct Declaring;

    impl Module for Declaring {
        const NAME: &'static str = "declaring";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        type Output = crate::example::LineStats;
        type Settings = DeclaringSettings;
        fn init(_: &DeclaringSettings) -> Result<Self, crate::ModuleError> {
            Ok(Declaring)
        }
        fn takes(settings: &DeclaringSettings) -> Takes {
            use crate::takes::{Case, Condition, Text};
            let condition = match settings.fact.as_str() {
                "added_by" => Condition::added_by("archive"),
                "mode" => Condition::Mode("correlation".to_owned()),
                "at_root" => Condition::AtRoot,
                "result" => Condition::HasResult("file_type".to_owned()),
                "size" => Condition::not_empty(),
                "type" => Condition::type_fact(crate::takes::TypeFact::IsPdfFile),
                "role" => Condition::role(ace_results::FileRole::EMAIL_ATTACHMENT),
                _ => Condition::Path(Text::ends_with(".x", Case::Exact)),
            };
            Takes::everything().and(condition, "no")
        }
    }

    #[derive(Debug, Default, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields, default)]
    struct DeclaringSettings {
        fact: String,
    }

    impl Parser for Declaring {
        fn analyze(
            &self,
            _: &crate::TaskContext<DeclaringSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(String::new()))
        }
    }

    impl crate::Lookup for Declaring {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(
            &self,
            _: &crate::TaskContext<DeclaringSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(String::new()))
        }
    }

    #[test]
    fn a_declaration_may_read_only_what_its_lease_carries() {
        let parser = Manifest::parser::<Declaring>();
        let lookup = Manifest::lookup::<Declaring>();
        let fact = |fact: &str| json!({"fact": fact});
        // a path is in every file task's lease; a file's size only in a parser's
        assert!(parser.declaration(Some(&fact("path"))).is_ok());
        assert!(lookup.declaration(Some(&fact("path"))).is_ok());
        assert!(parser.declaration(Some(&fact("size"))).is_ok());
        let refused = |manifest: &Manifest, which: &str| {
            manifest
                .declaration(Some(&fact(which)))
                .expect_err("refused")
                .to_string()
        };
        for which in ["size", "type", "role"] {
            assert!(parser.declaration(Some(&fact(which))).is_ok(), "{which}");
            assert!(refused(&lookup, which).contains("a lookup's lease lacks"));
        }
        // which modules added the observable, whether it came with the submission and the mode are
        // in the lease's gate, whatever the module's analyze reads
        for which in ["added_by", "at_root", "mode"] {
            assert!(parser.declaration(Some(&fact(which))).is_ok(), "{which}");
            assert!(lookup.declaration(Some(&fact(which))).is_ok(), "{which}");
        }
        // a dependency's result needs the module to ask for it
        assert!(refused(&parser, "result").contains("DEPENDS_ON"));
        let mut asks = parser;
        asks.depends_on = &["file_type"];
        assert!(asks.declaration(Some(&fact("result"))).is_ok());
        // a block that doesn't load is the settings' error
        assert!(matches!(
            parser.declaration(Some(&json!({"facts": 1}))),
            Err(DeclarationError::Settings(_))
        ));
        assert_eq!(parser.describe()["takes"][0]["otherwise"], "no");
    }

    /// The pool checks the declaration on the task's own facts before `analyze`
    /// (`crate::module::run_parser`), so a task queued while it took the file, or under the core's
    /// audit, declines as the core would decline it now.
    #[test]
    fn a_parser_s_declaration_is_checked_again_before_analyze() {
        let run = |path: &str| {
            let file = crate::InputFile {
                path: ace_results::AlertPath::new(path).expect("a path"),
                sha256: ace_results::Sha256([0; 32]),
                size: 1,
                yara_meta: Vec::new(),
                mime_type: None,
                facts: None,
                role: None,
                local_path: Default::default(),
            };
            let ctx = crate::TaskContext::new::<Declaring>(
                uuid::Uuid::nil(),
                crate::Observable::file(file),
                std::sync::Arc::new(DeclaringSettings::default()),
            );
            crate::run_parser(&Declaring, &ctx).expect("runs")
        };
        assert_eq!(run("a.y"), crate::Outcome::Skipped("no".to_owned()));
        // analyze ran, and said nothing
        assert_eq!(run("a.x"), crate::Outcome::Skipped(String::new()));
    }

    /// A cacheable lookup whose declaration reads which modules added its observable and whether it
    /// came with the submission, and whose `analyze` says what it saw of them.
    struct Gated;

    impl Module for Gated {
        const NAME: &'static str = "gated";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const CACHE: Option<crate::cache::Cache> = Some(crate::cache::Cache::new(
            1,
            std::time::Duration::from_secs(60),
        ));
        type Output = crate::example::LineStats;
        type Settings = DeclaringSettings;
        fn init(_: &DeclaringSettings) -> Result<Self, crate::ModuleError> {
            Ok(Gated)
        }
        fn takes(_: &DeclaringSettings) -> Takes {
            use crate::takes::Condition;
            Takes::everything().and(
                Condition::Any(vec![
                    Condition::AtRoot,
                    Condition::added_by_other_than(&["gated"]),
                ]),
                "only gated added it",
            )
        }
    }

    impl crate::Lookup for Gated {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(
            &self,
            ctx: &crate::TaskContext<DeclaringSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(format!(
                "saw {:?} {} {:?} {}",
                ctx.added_by(),
                ctx.at_root(),
                ctx.tree().map(|t| t.analysis_mode.clone()),
                ctx.event_time().is_some()
            )))
        }
    }

    /// A fact only a declaration reads reaches the declaration and never `analyze`, whatever the
    /// lease sends, so a cacheable module can read it there and the cache doesn't refuse it.
    #[tokio::test]
    async fn a_fact_only_the_declaration_reads_reaches_it_and_never_analyze() {
        use crate::wire::{EventTimeSource, Gate, RootEventTime};
        assert_eq!(Manifest::lookup::<Gated>().cache_refusal(), None);
        let run = |gate: Gate| async move {
            // a lease that sends every fact to `analyze` as well, as no core does
            let ctx = crate::TaskContext::new::<Gated>(
                uuid::Uuid::nil(),
                crate::Observable::new(ObservableKind::Fqdn, "a.example"),
                std::sync::Arc::new(DeclaringSettings::default()),
            )
            .with_added_by(gate.added_by.clone())
            .with_at_root(gate.at_root)
            .with_tree(Some(crate::tree::TreeView {
                analysis_mode: gate.mode.clone(),
                ..crate::tree::TreeView::default()
            }))
            .with_event_time(Some(RootEventTime {
                time: Some(chrono::Utc::now()),
                source: EventTimeSource::Event,
            }))
            .with_gate(gate);
            crate::run_lookup(&Gated, &ctx).await.expect("runs")
        };
        let seen = crate::Outcome::Skipped("saw [] false None false".to_owned());
        let at_root = Gate {
            at_root: true,
            ..Gate::default()
        };
        assert_eq!(run(at_root).await, seen);
        let added = Gate {
            added_by: vec!["gated".to_owned(), "other".to_owned()],
            ..Gate::default()
        };
        assert_eq!(run(added).await, seen);
        let only_its_own = Gate {
            added_by: vec!["gated".to_owned()],
            mode: Some("correlation".to_owned()),
            ..Gate::default()
        };
        assert_eq!(
            run(only_its_own).await,
            crate::Outcome::Skipped("only gated added it".to_owned())
        );
    }

    /// A cacheable lookup that takes `upload_to_scanner` only from an analyst (PLAN.md decision 44) and
    /// reads its input file's bytes (decision 45), as a site's upload to a scanning service does.
    struct AnalystAsked;

    impl Module for AnalystAsked {
        const NAME: &'static str = "analyst_asked";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const REQUIRED_DIRECTIVES: &'static [&'static str] = &["upload_to_scanner"];
        const READS_INPUT_FILE: bool = true;
        const CACHE: Option<crate::cache::Cache> = Some(crate::cache::Cache::new(
            1,
            std::time::Duration::from_secs(60),
        ));
        type Output = crate::example::LineStats;
        type Settings = DeclaringSettings;
        fn init(_: &DeclaringSettings) -> Result<Self, crate::ModuleError> {
            Ok(AnalystAsked)
        }
        fn takes(_: &DeclaringSettings) -> Takes {
            Takes::everything().and(
                crate::takes::Condition::directive_from(
                    "upload_to_scanner",
                    &[crate::directives::DirectiveSource::Analyst],
                ),
                "no analyst asked for an upload",
            )
        }
    }

    impl crate::Lookup for AnalystAsked {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(
            &self,
            _: &crate::TaskContext<DeclaringSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped("ran".to_owned()))
        }
    }

    /// The pool checks where a directive came from on the lease's gate, as the core did: a hunt's
    /// or a module's doesn't run the module, an analyst's does. Neither the source, which only the
    /// declaration reads, nor the file's bytes, which its value names, keeps it from the cache.
    #[tokio::test]
    async fn a_directive_s_source_decides_on_the_gate_and_the_cache_takes_the_module() {
        use crate::directives::{DirectiveSource, SourcedDirective};
        use crate::wire::Gate;
        let manifest = Manifest::lookup::<AnalystAsked>();
        assert!(manifest.reads_input_file && manifest.kind == ModuleKind::Lookup);
        assert_eq!(manifest.cache_refusal(), None);
        assert!(!Manifest::lookup::<Gated>().reads_input_file);
        let run = |sources: Vec<SourcedDirective>| async move {
            let mut observable = crate::Observable::new(ObservableKind::File, "0".repeat(64));
            observable.directives = vec!["upload_to_scanner".to_owned()];
            let ctx = crate::TaskContext::new::<AnalystAsked>(
                uuid::Uuid::nil(),
                observable,
                std::sync::Arc::new(DeclaringSettings::default()),
            )
            .with_gate(Gate {
                directive_sources: sources,
                ..Gate::default()
            });
            crate::run_lookup(&AnalystAsked, &ctx).await.expect("runs")
        };
        let declined = crate::Outcome::Skipped("no analyst asked for an upload".to_owned());
        assert_eq!(run(Vec::new()).await, declined);
        let others = vec![
            SourcedDirective::new("upload_to_scanner", DirectiveSource::Hunt),
            SourcedDirective::new("upload_to_scanner", DirectiveSource::Submission),
            SourcedDirective::new("upload_to_scanner", DirectiveSource::Module),
            SourcedDirective::new("crawl", DirectiveSource::Analyst),
        ];
        assert_eq!(run(others).await, declined);
        assert_eq!(
            run(vec![SourcedDirective::new(
                "upload_to_scanner",
                DirectiveSource::Analyst
            )])
            .await,
            crate::Outcome::Skipped("ran".to_owned())
        );
    }

    /// A parser that declares it reads its input file, which it always does.
    struct ReadsItsInput;

    impl Module for ReadsItsInput {
        const NAME: &'static str = "reads_its_input";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const READS_INPUT_FILE: bool = true;
        type Output = crate::example::LineStats;
        type Settings = LineCounterSettings;
        fn init(_: &LineCounterSettings) -> Result<Self, crate::ModuleError> {
            Ok(ReadsItsInput)
        }
    }

    impl Parser for ReadsItsInput {
        fn analyze(
            &self,
            _: &crate::TaskContext<LineCounterSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(String::new()))
        }
    }

    #[test]
    fn only_a_lookup_declares_it_reads_its_input_file() {
        let refused = std::panic::catch_unwind(Manifest::parser::<ReadsItsInput>);
        assert!(refused.is_err());
    }

    /// A lookup that takes a file by its size and type, as a sandbox submission takes what its
    /// vendor runs (PLAN.md decision 45), and reads its bytes or doesn't, as its setting says.
    struct BySize;

    impl Module for BySize {
        const NAME: &'static str = "by_size";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        type Output = crate::example::LineStats;
        type Settings = DeclaringSettings;
        fn init(_: &DeclaringSettings) -> Result<Self, crate::ModuleError> {
            Ok(BySize)
        }
        fn takes(_: &DeclaringSettings) -> Takes {
            Takes::everything()
                .and(crate::takes::Condition::not_empty(), "an empty file")
                .and(
                    crate::takes::Condition::type_fact(crate::takes::TypeFact::IsPeFile),
                    "not a PE",
                )
        }
    }

    impl crate::Lookup for BySize {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(
            &self,
            _: &crate::TaskContext<DeclaringSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(String::new()))
        }
    }

    struct BySizeWithBytes;

    impl Module for BySizeWithBytes {
        const NAME: &'static str = "by_size_with_bytes";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const READS_INPUT_FILE: bool = true;
        type Output = crate::example::LineStats;
        type Settings = DeclaringSettings;
        fn init(_: &DeclaringSettings) -> Result<Self, crate::ModuleError> {
            Ok(BySizeWithBytes)
        }
        fn takes(settings: &DeclaringSettings) -> Takes {
            BySize::takes(settings)
        }
    }

    impl crate::Lookup for BySizeWithBytes {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(
            &self,
            _: &crate::TaskContext<DeclaringSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(String::new()))
        }
    }

    /// A lookup's lease carries a file's size and type only with its bytes, so only a lookup that
    /// reads them may declare on them.
    #[test]
    fn a_lookup_declares_on_a_file_s_record_only_when_it_reads_the_file() {
        assert!(matches!(
            Manifest::lookup::<BySize>().declaration(None),
            Err(DeclarationError::Unread("by_size", _))
        ));
        let takes = Manifest::lookup::<BySizeWithBytes>()
            .declaration(None)
            .expect("its lease carries the record");
        let reads = takes.reads();
        assert!(reads.file_record && reads.file_type);
    }

    /// A cacheable lookup that depends on a module whose result only its declaration reads, and
    /// whose `analyze` says what it saw of it.
    struct Deciding;

    impl Module for Deciding {
        const NAME: &'static str = "deciding";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const DEPENDS_ON: &'static [&'static str] = &["apex"];
        const READS_DEPENDENCIES: bool = false;
        const CACHE: Option<crate::cache::Cache> = Some(crate::cache::Cache::new(
            1,
            std::time::Duration::from_secs(60),
        ));
        type Output = crate::example::LineStats;
        type Settings = DeclaringSettings;
        fn init(_: &DeclaringSettings) -> Result<Self, crate::ModuleError> {
            Ok(Deciding)
        }
        fn takes(_: &DeclaringSettings) -> Takes {
            Takes::everything().and(
                crate::takes::Condition::result_text(
                    "apex",
                    "apex_domain",
                    crate::takes::Text::exact(crate::takes::Match::NotEmpty),
                )
                .negated(),
                "its apex is looked up",
            )
        }
    }

    impl crate::Lookup for Deciding {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(
            &self,
            ctx: &crate::TaskContext<DeclaringSettings>,
        ) -> Result<crate::Outcome<crate::example::LineStats>, crate::ModuleError> {
            Ok(crate::Outcome::Skipped(format!(
                "saw {:?} {:?}",
                ctx.dependency_details(),
                ctx.dependency_error::<ApexLike>()
            )))
        }
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
    struct ApexLike {}

    impl ace_results::AnalysisType for ApexLike {
        const NAME: &'static str = "apex_like";
        const VERSION: u32 = 1;
        const MODULE: &'static str = "apex";
    }

    /// A dependency's result that only the declaration reads reaches the declaration and never
    /// `analyze`, so the cache doesn't refuse the module for it (`Module::READS_DEPENDENCIES`).
    #[tokio::test]
    async fn a_dependency_only_the_declaration_reads_reaches_it_and_never_analyze() {
        assert_eq!(Manifest::lookup::<Deciding>().cache_refusal(), None);
        let run = |apex: &'static str| async move {
            let ctx = crate::TaskContext::new::<Deciding>(
                uuid::Uuid::nil(),
                crate::Observable::new(ObservableKind::Fqdn, "www.example.com"),
                std::sync::Arc::new(DeclaringSettings::default()),
            )
            .with_dependency_results([("apex".to_owned(), json!({ "apex_domain": apex }))])
            .with_dependency_errors([("apex".to_owned(), "a partial result".to_owned())]);
            crate::run_lookup(&Deciding, &ctx).await.expect("runs")
        };
        assert_eq!(
            run("example.com").await,
            crate::Outcome::Skipped("its apex is looked up".to_owned())
        );
        assert_eq!(
            run("").await,
            crate::Outcome::Skipped("saw {} None".to_owned())
        );
    }

    #[test]
    fn a_required_directive_is_named_when_missing() {
        assert_eq!(RESOLVER.missing_directive(&[]), None);
        let mut manifest = RESOLVER;
        manifest.required_directives = &["original_email", "archive"];
        assert_eq!(
            manifest.missing_directive(&["archive".to_owned()]),
            Some("original_email")
        );
        assert_eq!(
            manifest.missing_directive(&["archive".to_owned(), "original_email".to_owned()]),
            None
        );
    }

    #[test]
    fn manifests_describe_their_modules() {
        assert_eq!(LINE_COUNTER.name, "example_line_counter");
        assert_eq!(LINE_COUNTER.kind, ModuleKind::Parser);
        assert_eq!(LINE_COUNTER.sandbox, Sandbox::Contained);
        assert_eq!(LINE_COUNTER.output.name, "example_line_stats");
        assert!(LINE_COUNTER.accepts(ObservableKind::File));
        assert!(!LINE_COUNTER.accepts(ObservableKind::Fqdn));
        assert_eq!(
            LINE_COUNTER.skipped_by(&["sandbox".to_owned(), "exclude_all".to_owned()]),
            Some("exclude_all")
        );
        assert_eq!(LINE_COUNTER.skipped_by(&["no_scan".to_owned()]), None);

        assert_eq!(RESOLVER.kind, ModuleKind::Lookup);
        assert_eq!(RESOLVER.sandbox, Sandbox::Network { tcp_ports: &[] });
        assert_eq!(RESOLVER.secrets, ["resolver_token"]);
        // email_dkim_signing_domain extends fqdn
        assert!(RESOLVER.accepts(ObservableKind::EmailDkimSigningDomain));

        let schema = LINE_COUNTER.settings_schema();
        assert_eq!(
            schema.get("additionalProperties"),
            Some(&Value::Bool(false))
        );
        let described = RESOLVER.describe();
        assert_eq!(described["inputs"], json!(["fqdn"]));
        assert_eq!(
            described["sandbox"],
            json!({"kind": "network", "tcp_ports": []})
        );
    }
}
