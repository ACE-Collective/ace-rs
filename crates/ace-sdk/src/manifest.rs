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
    pub output: AnalysisTypeInfo,
    /// Modules whose results this one needs before it runs.
    pub depends_on: &'static [&'static str],
    /// Directives that keep the module off an observable, besides `exclude_all`.
    pub skip_directives: &'static [&'static str],
    /// Directives an observable must have for the module to run on it.
    pub required_directives: &'static [&'static str],
    /// Directives an observable of one type must have (`Module::REQUIRED_DIRECTIVES_BY_KIND`).
    pub required_directives_by_kind: &'static [(ObservableKind, &'static [&'static str])],
    pub resources: Resources,
    pub sandbox: Sandbox,
    pub secrets: &'static [&'static str],
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
    /// The module adds files a module it depends on stored for the root
    /// (`Module::ADDS_STORED_FILES`).
    pub adds_stored_files: bool,
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
            output: AnalysisTypeInfo::of::<M::Output>(),
            depends_on: M::DEPENDS_ON,
            skip_directives: M::SKIP_DIRECTIVES,
            required_directives: M::REQUIRED_DIRECTIVES,
            required_directives_by_kind: M::REQUIRED_DIRECTIVES_BY_KIND,
            resources: M::RESOURCES,
            sandbox,
            secrets: M::SECRETS,
            instances_only: M::INSTANCES_ONLY,
            enabled_by_default: M::ENABLED_BY_DEFAULT,
            reads_carrying_email: M::READS_CARRYING_EMAIL,
            runs_last: M::RUNS_LAST,
            reads_below: M::READS_BELOW,
            reads_added_by: M::READS_ADDED_BY,
            reads_related_tags: M::READS_RELATED_TAGS,
            reads_tree: M::READS_TREE,
            reads_tree_files: M::READS_TREE_FILES,
            reads_tree_details: M::READS_TREE_DETAILS,
            adds_to_others: M::ADDS_TO_OTHERS,
            sets_root: M::SETS_ROOT,
            adds_stored_files: M::ADDS_STORED_FILES,
            lists: M::LISTS,
            reads: M::READS,
            writes: M::WRITES,
            stores_results: M::STORES_RESULTS,
            tools: M::TOOLS,
            scanners: M::SCANNERS,
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
    /// what its lease carries: a rule that reads which modules added the observable needs
    /// `READS_ADDED_BY`, one on the root's mode needs `READS_TREE`, one on a dependency's result
    /// needs the dependency in `DEPENDS_ON`, and a lookup's rules can read a file's path but not its
    /// size, mime type or `yara_meta`, which only a parser's lease carries. Otherwise the pool would
    /// decline on a fact its task lacks where the core took it.
    pub fn declaration(&self, block: Option<&Value>) -> Result<Takes, DeclarationError> {
        let takes = (self.takes)(block).map_err(DeclarationError::Settings)?;
        let reads = takes.reads();
        let refuse = |what: String| Err(DeclarationError::Unread(self.name, what));
        if reads.added_by && !self.reads_added_by {
            return refuse("which modules added the observable, without READS_ADDED_BY".into());
        }
        if reads.mode && !self.reads_tree {
            return refuse("the root's mode, without READS_TREE".into());
        }
        if let Some(module) = reads
            .results
            .iter()
            .find(|m| !self.depends_on.contains(&m.as_str()))
        {
            return refuse(format!("{module}'s result, which isn't in DEPENDS_ON"));
        }
        if reads.file_record && self.kind == ModuleKind::Lookup {
            return refuse(
                "a file's size, mime type or yara_meta, which a lookup's lease lacks".into(),
            );
        }
        Ok(takes)
    }

    /// True when the module takes observables of `kind`, directly or through a parent type.
    pub fn accepts(&self, kind: ObservableKind) -> bool {
        self.inputs.iter().any(|&input| kind.is_subtype_of(input))
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
            "inputs": self.inputs,
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
                "result" => Condition::HasResult("file_type".to_owned()),
                "size" => Condition::not_empty(),
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
        assert!(refused(&lookup, "size").contains("a lookup's lease lacks"));
        // the rest need the module to ask for what it reads
        assert!(refused(&parser, "added_by").contains("READS_ADDED_BY"));
        assert!(refused(&parser, "mode").contains("READS_TREE"));
        assert!(refused(&parser, "result").contains("DEPENDS_ON"));
        let mut asks = parser;
        asks.reads_added_by = true;
        asks.reads_tree = true;
        asks.depends_on = &["file_type"];
        for which in ["added_by", "mode", "result"] {
            assert!(asks.declaration(Some(&fact(which))).is_ok(), "{which}");
        }
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
