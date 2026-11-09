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
use crate::module::{EXCLUDE_ALL, Lookup, Module, Parser, Settings};
use crate::reads::Read;
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
    /// The analyst-edited lists the module reads (`Module::LISTS`).
    pub lists: &'static [ListSpec],
    /// The reads of ACE's own data the module makes (`Module::READS`).
    pub reads: &'static [Read],
    /// The writes to ACE's own data the module makes (`Module::WRITES`).
    pub writes: &'static [Write],
    /// The module's tasks end with a result when they find something (`Module::STORES_RESULTS`).
    pub stores_results: bool,
    settings_schema: fn() -> Schema,
    check_settings: fn(Option<&Value>) -> Result<(), SettingsError>,
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
        Manifest::of::<M>(
            ModuleKind::Lookup,
            Sandbox::Network {
                tcp_ports: M::TCP_PORTS,
            },
        )
    }

    const fn of<M: Module>(kind: ModuleKind, sandbox: Sandbox) -> Self {
        Manifest {
            name: M::NAME,
            kind,
            inputs: M::INPUTS,
            output: AnalysisTypeInfo::of::<M::Output>(),
            depends_on: M::DEPENDS_ON,
            skip_directives: M::SKIP_DIRECTIVES,
            required_directives: M::REQUIRED_DIRECTIVES,
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
            lists: M::LISTS,
            reads: M::READS,
            writes: M::WRITES,
            stores_results: M::STORES_RESULTS,
            settings_schema: settings_schema::<M::Settings>,
            check_settings: check_settings::<M::Settings>,
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
            "required_directives": self.required_directives,
            "settings_schema": self.settings_schema(),
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
