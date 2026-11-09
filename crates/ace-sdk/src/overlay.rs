//! The site overlay: the small YAML file a site writes over its modules' manifests (PLAN.md
//! 2.23).
//!
//! ```yaml
//! modules:
//!   rdap_analyzer:
//!     settings:
//!       request_timeout_seconds: 10
//!   splunk_api:
//!     instances:
//!       proxy_domain_lookup:
//!         inputs: [fqdn]
//!         settings:
//!           query: index=proxy hostname="<O_VALUE>"
//! secrets:
//!   splunk_password: env:ACE4_SPLUNK_PASSWORD
//!   resolver_token: file:/run/secrets/resolver_token
//! ```
//!
//! Every level refuses keys it doesn't know, settings blocks included (ace3 #858). A module with
//! no section runs on its manifest's defaults (ace3 #1044). A section for a module this build
//! doesn't have logs a warning and is skipped, so removing a module never stops startup (ace3
//! #901, #916).
//!
//! `scheduler:` sets the schedule, timeout or `enabled` of the core's scheduled tasks (PLAN.md 6.7),
//! by task name, each key refused when unknown. A task this build doesn't have logs a warning and is
//! skipped, as a removed module is.
//!
//! `nrd:` lists the feeds of the newly registered domains list (PLAN.md 7.4), as ace3's `nrd:`
//! section does, for the scheduler's `nrd_refresh` task.
//!
//! `secrets:` says where each secret comes from, by the name modules declare in
//! `Module::SECRETS`: `env:<VARIABLE>` or `file:<path>`, as ace3's `env:` references. Nothing
//! is read when the overlay loads; a pool reads only the ones its modules declare (PLAN.md 2.24,
//! ace3 #1009).
//!
//! A module that ace3 ships disabled (`Module::ENABLED_BY_DEFAULT` false) runs only when the overlay
//! has a section for it, empty or not.
//!
//! A module with `instances` runs once per instance and not as itself, as each of ace3's
//! `analysis_module_*` sections is one run of its class. An instance's name is its key: the
//! name its tasks and results carry in the queue and the tree, and the name modes and groups
//! list. It may narrow the module's inputs, and join module groups with `groups`.

use std::collections::BTreeMap;

use ace_results::ObservableKind;
use serde::Deserialize;
use serde_json::Value;

use crate::manifest::{Manifest, SettingsError};

/// A site's overlay, as its YAML file says it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Overlay {
    /// Sections by module name.
    pub modules: BTreeMap<String, ModuleSection>,
    /// Where each secret comes from, by name.
    pub secrets: BTreeMap<String, SecretSource>,
    /// The core's scheduled tasks (PLAN.md 6.7), by task name. `ace serve` reads it; a pool doesn't.
    pub scheduler: BTreeMap<String, ScheduledTaskSection>,
    /// The feeds of the newly registered domains list (PLAN.md 7.4), ace3's `nrd:` section, which
    /// `ace serve`'s `nrd_refresh` task reads.
    pub nrd: NrdSection,
}

/// ace3's `nrd:` section: the feeds the `nrd_refresh` task builds the newly registered domains list
/// from. ace3's `enabled` kill switch is the task's own `scheduler.nrd_refresh.enabled`, and its
/// `database_path` is Postgres.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NrdSection {
    /// The fewest hours between two rebuilds. Once they've passed, each run asks each feed with
    /// HEAD whether it changed, and rebuilds only when one did.
    pub check_interval_hours: u64,
    /// The feeds, in order. None is no list.
    pub url_lists: Vec<NrdList>,
    /// A PEM file of CA certificates to trust besides the platform's. Certificates are always
    /// verified.
    pub ca_certificates: Option<std::path::PathBuf>,
}

impl Default for NrdSection {
    fn default() -> Self {
        NrdSection {
            check_interval_hours: 24,
            url_lists: Vec::new(),
            ca_certificates: None,
        }
    }
}

/// One feed: a text file of domains, one a line, and the URLs to try when its own fails.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NrdList {
    pub url: String,
    #[serde(default)]
    pub backups: Vec<String>,
}

/// What the overlay says about one of the core's scheduled tasks. Each field left out keeps the
/// task's default; `ace_app`'s scheduler lists the tasks and their defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScheduledTaskSection {
    /// A five-field cron expression, in UTC, as ace3's `etc/cron.yaml` schedules its cadences.
    pub schedule: Option<String>,
    /// How long a run may take before it's stopped.
    pub timeout_seconds: Option<u64>,
    /// False stops the task running.
    pub enabled: Option<bool>,
}

/// Where a secret's value comes from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum SecretSource {
    /// `env:<VARIABLE>`: an environment variable of the process.
    Env(String),
    /// `file:<path>`: a file's contents without its trailing newline, such as a Compose secret
    /// in `/run/secrets`.
    File(std::path::PathBuf),
}

impl TryFrom<String> for SecretSource {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        match text.split_once(':') {
            Some(("env", name)) if !name.is_empty() => Ok(SecretSource::Env(name.to_owned())),
            Some(("file", path)) if !path.is_empty() => Ok(SecretSource::File(path.into())),
            _ => Err(format!(
                "{text:?} is neither env:<VARIABLE> nor file:<path>"
            )),
        }
    }
}

impl std::fmt::Display for SecretSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretSource::Env(name) => write!(f, "env:{name}"),
            SecretSource::File(path) => write!(f, "file:{}", path.display()),
        }
    }
}

/// What the overlay says about one module.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ModuleSection {
    /// The module's settings block, when it runs as itself.
    pub settings: Option<Value>,
    /// Named instances, each a run of the module with its own inputs and settings.
    pub instances: BTreeMap<String, InstanceSection>,
}

/// One named instance of a module.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InstanceSection {
    /// The observable types the instance takes, each one the module takes. None takes the
    /// module's own.
    pub inputs: Option<Vec<ObservableKind>>,
    pub settings: Option<Value>,
    /// The module groups the instance joins, as a site's config adds a section to ace3's
    /// `module_group_*` lists, so the analysis modes that run a group run it. An instance named as
    /// one of ace3's modules is in that module's groups already.
    pub groups: Vec<String>,
}

/// An overlay that doesn't load.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OverlayError {
    #[error("the overlay doesn't parse at {path}: {message}")]
    Parse { path: String, message: String },
    #[error("the overlay's {path}: {source}")]
    Settings {
        path: String,
        #[source]
        source: SettingsError,
    },
    #[error("the overlay's instance {instance} of {module} takes {kind}, which {module} doesn't")]
    Input {
        module: String,
        instance: String,
        kind: ObservableKind,
    },
    #[error(
        "the overlay's instance {instance} of {module} has a module's or another instance's name"
    )]
    DuplicateKey { module: String, instance: String },
    #[error("the overlay names instance {0:?}; a name is lowercase letters, digits and _")]
    BadName(String),
    #[error("the overlay {path} can't be read: {message}")]
    Read { path: String, message: String },
}

/// What the core queues and a pool runs: a module as itself, or one named instance of it.
#[derive(Debug, Clone)]
pub struct Component {
    /// The name in the queue and the tree: the module's name, or the instance's.
    pub key: String,
    pub manifest: Manifest,
    /// The observable types it takes: the manifest's, or the instance's narrower list.
    pub inputs: Vec<ObservableKind>,
    /// Its settings block. None runs on the settings type's defaults.
    pub settings: Option<Value>,
    /// The module groups an instance joins (`InstanceSection::groups`).
    pub groups: Vec<String>,
}

impl Component {
    /// The module as itself, on its defaults.
    pub fn of(manifest: Manifest) -> Component {
        Component {
            key: manifest.name.to_owned(),
            manifest,
            inputs: manifest.inputs.to_vec(),
            settings: None,
            groups: Vec::new(),
        }
    }

    /// True when it takes observables of `kind`, directly or through a parent type.
    pub fn accepts(&self, kind: ObservableKind) -> bool {
        self.inputs.iter().any(|&input| kind.is_subtype_of(input))
    }

    /// The instance's name, when this is a named instance.
    pub fn instance(&self) -> Option<&str> {
        (self.key != self.manifest.name).then_some(self.key.as_str())
    }
}

impl Overlay {
    /// Parses an overlay. An empty file is an overlay with no sections.
    pub fn from_yaml(text: &str) -> Result<Overlay, OverlayError> {
        let parse_error = |path: String, message: String| OverlayError::Parse { path, message };
        let value: Value =
            serde_norway::from_str(text).map_err(|e| parse_error(String::new(), e.to_string()))?;
        if value.is_null() {
            return Ok(Overlay::default());
        }
        serde_path_to_error::deserialize(value).map_err(|e| {
            let path = e.path().to_string();
            parse_error(path, e.into_inner().to_string())
        })
    }

    /// Reads and parses the overlay at `path`.
    pub fn read(path: &std::path::Path) -> Result<Overlay, OverlayError> {
        let text = std::fs::read_to_string(path).map_err(|e| OverlayError::Read {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        Overlay::from_yaml(&text)
    }

    /// The overlay without the sections of modules not in `manifests`. A pool's binary links
    /// only its own modules, so it reads the site's overlay through this: the other pools'
    /// sections aren't removed modules, and the core, which knows every module, warns about the
    /// ones that are.
    pub fn for_pool(&self, manifests: &[Manifest]) -> Overlay {
        Overlay {
            modules: self
                .modules
                .iter()
                .filter(|(name, _)| manifests.iter().any(|m| m.name == name.as_str()))
                .map(|(name, section)| (name.clone(), section.clone()))
                .collect(),
            secrets: self.secrets.clone(),
            scheduler: BTreeMap::new(),
            nrd: NrdSection::default(),
        }
    }

    /// The components the overlay makes of `manifests`, the modules this build has, with each
    /// settings block checked against its module's settings type. A section for a module not in
    /// `manifests` logs a warning and is skipped.
    pub fn components(&self, manifests: &[Manifest]) -> Result<Vec<Component>, OverlayError> {
        for name in self.modules.keys() {
            if !manifests.iter().any(|m| m.name == name) {
                tracing::warn!(
                    module = %name,
                    "the overlay has a section for a module this build doesn't have; skipping it"
                );
            }
        }
        let mut components = Vec::new();
        for &manifest in manifests {
            let section = self.modules.get(manifest.name);
            if manifest.instances_only && section.is_none_or(|s| s.instances.is_empty()) {
                if section.is_some_and(|s| s.settings.is_some()) {
                    return Err(OverlayError::Parse {
                        path: format!("modules.{}.settings", manifest.name),
                        message: "this module runs only as named instances, each with its own \
                                  settings"
                            .into(),
                    });
                }
                tracing::info!(
                    module = manifest.name,
                    "the overlay names no instance of this module, so it doesn't run"
                );
                continue;
            }
            let Some(section) = section else {
                if manifest.enabled_by_default {
                    components.push(Component::of(manifest));
                } else {
                    tracing::info!(
                        module = manifest.name,
                        "this module is off unless the overlay has a section for it, and it has none"
                    );
                }
                continue;
            };
            let check = |path: String, block: Option<&Value>| {
                manifest
                    .check_settings(block)
                    .map_err(|source| OverlayError::Settings { path, source })
            };
            if section.instances.is_empty() {
                check(
                    format!("modules.{}.settings", manifest.name),
                    section.settings.as_ref(),
                )?;
                components.push(Component {
                    settings: section.settings.clone(),
                    ..Component::of(manifest)
                });
                continue;
            }
            if section.settings.is_some() {
                return Err(OverlayError::Parse {
                    path: format!("modules.{}.settings", manifest.name),
                    message: "a module with instances takes its settings in each instance".into(),
                });
            }
            for (name, instance) in &section.instances {
                if name.is_empty()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                {
                    return Err(OverlayError::BadName(name.clone()));
                }
                check(
                    format!("modules.{}.instances.{name}.settings", manifest.name),
                    instance.settings.as_ref(),
                )?;
                let inputs = match &instance.inputs {
                    None => manifest.inputs.to_vec(),
                    Some(inputs) => {
                        if let Some(&kind) = inputs.iter().find(|&&k| !manifest.accepts(k)) {
                            return Err(OverlayError::Input {
                                module: manifest.name.to_owned(),
                                instance: name.clone(),
                                kind,
                            });
                        }
                        inputs.clone()
                    }
                };
                components.push(Component {
                    key: name.clone(),
                    manifest,
                    inputs,
                    settings: instance.settings.clone(),
                    groups: instance.groups.clone(),
                });
            }
        }
        // an instance named like a module, or like another module's instance, would share its
        // tasks and results
        let mut seen = std::collections::BTreeSet::new();
        for component in &components {
            let clashes_with_module =
                component.instance().is_some() && manifests.iter().any(|m| m.name == component.key);
            if clashes_with_module || !seen.insert(component.key.as_str()) {
                return Err(OverlayError::DuplicateKey {
                    module: component.manifest.name.to_owned(),
                    instance: component.key.clone(),
                });
            }
        }
        Ok(components)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::example::{LineCounter, Resolver};
    use std::sync::{Arc, Mutex};

    const LINE_COUNTER: Manifest = Manifest::parser::<LineCounter>();
    const RESOLVER: Manifest = Manifest::lookup::<Resolver>();

    fn manifests() -> Vec<Manifest> {
        vec![LINE_COUNTER, RESOLVER]
    }

    fn components(yaml: &str) -> Result<Vec<Component>, OverlayError> {
        Overlay::from_yaml(yaml)?.components(&manifests())
    }

    fn keys(components: &[Component]) -> Vec<&str> {
        components.iter().map(|c| c.key.as_str()).collect()
    }

    #[test]
    fn an_unknown_key_fails_at_every_level() {
        let cases = [
            ("modul: {}", "modul", "unknown field `modul`"),
            (
                "modules: {example_resolver: {setings: {}}}",
                "modules.example_resolver.setings",
                "unknown field `setings`",
            ),
            (
                "modules: {example_resolver: {instances: {a: {input: [fqdn]}}}}",
                "modules.example_resolver.instances.a.input",
                "unknown field `input`",
            ),
        ];
        for (yaml, path, message) in cases {
            let err = components(yaml).unwrap_err();
            println!("{err}");
            match err {
                OverlayError::Parse {
                    path: got,
                    message: said,
                } => {
                    assert_eq!(got, path, "{yaml}");
                    assert!(said.starts_with(message), "{yaml}: {said}");
                }
                other => panic!("{yaml}: {other}"),
            }
        }
        // inside a settings block, the module's settings type refuses it
        let err =
            components("modules: {example_line_counter: {settings: {max_byte: 3}}}").unwrap_err();
        println!("{err}");
        assert_eq!(
            err,
            OverlayError::Settings {
                path: "modules.example_line_counter.settings".to_owned(),
                source: SettingsError::UnknownKey {
                    path: "max_byte".to_owned()
                },
            }
        );
        let err = components(
            "modules: {example_resolver: {instances: {a: {settings: {delays: 1, delay: 2}}}}}",
        )
        .unwrap_err();
        assert!(
            matches!(&err, OverlayError::Settings { path, source: SettingsError::UnknownKey { path: key } }
                if path == "modules.example_resolver.instances.a.settings" && key == "delay"),
            "{err}"
        );
    }

    #[test]
    fn a_module_with_no_section_runs_on_its_defaults() {
        for yaml in ["", "# nothing yet\n", "modules: {}"] {
            let components = components(yaml).expect("loads");
            assert_eq!(
                keys(&components),
                ["example_line_counter", "example_resolver"]
            );
            assert!(components.iter().all(|c| c.settings.is_none()));
            assert!(components.iter().all(|c| c.instance().is_none()));
            assert_eq!(components[1].inputs, RESOLVER.inputs);
        }
        // a section for one module leaves the other on its defaults
        let components = components("modules: {example_line_counter: {settings: {max_bytes: 5}}}")
            .expect("loads");
        assert_eq!(
            components[0].settings,
            Some(serde_json::json!({"max_bytes": 5}))
        );
        assert_eq!(components[1].settings, None);
    }

    /// Collects what tracing writes, for the warning tests.
    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_removed_module_logs_a_warning_and_the_rest_loads() {
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        let loaded = tracing::subscriber::with_default(subscriber, || {
            components(
                "modules:\n  pdf_parser_v1: {settings: {anything: 1}}\n  example_line_counter: {settings: {max_bytes: 5}}\n",
            )
        })
        .expect("startup continues");
        let logs = String::from_utf8(logs.0.lock().expect("lock").clone()).expect("text");
        println!("{logs}");
        assert_eq!(keys(&loaded), ["example_line_counter", "example_resolver"]);
        assert!(logs.contains("WARN"), "{logs}");
        assert!(logs.contains("module=pdf_parser_v1"), "{logs}");
        assert!(logs.contains("doesn't have"), "{logs}");
    }

    /// A module that needs a site's settings to do anything, as the Splunk module needs its
    /// query, runs only as named instances: with none, it isn't a component at all.
    #[test]
    fn an_instances_only_module_runs_only_as_its_instances() {
        let mut resolver = RESOLVER;
        resolver.instances_only = true;
        let manifests = [LINE_COUNTER, resolver];
        let of = |yaml: &str| Overlay::from_yaml(yaml).and_then(|o| o.components(&manifests));
        assert_eq!(keys(&of("").expect("loads")), ["example_line_counter"]);
        assert_eq!(
            keys(&of("modules: {example_resolver: {instances: {a: {}}}}").expect("loads")),
            ["example_line_counter", "a"]
        );
        let err = of("modules: {example_resolver: {settings: {delays: 1}}}").unwrap_err();
        assert!(err.to_string().contains("only as named instances"), "{err}");
    }

    /// A module ace3 ships disabled runs only when the overlay has a section for it, empty or not,
    /// as an ace3 site turns one on with `enabled: true`.
    #[test]
    fn a_module_off_by_default_runs_only_with_a_section() {
        let mut resolver = RESOLVER;
        resolver.enabled_by_default = false;
        let manifests = [LINE_COUNTER, resolver];
        let of = |yaml: &str| Overlay::from_yaml(yaml).and_then(|o| o.components(&manifests));
        assert_eq!(keys(&of("").expect("loads")), ["example_line_counter"]);
        assert_eq!(
            keys(&of("modules: {example_resolver: {}}").expect("loads")),
            ["example_line_counter", "example_resolver"]
        );
        let set = of("modules: {example_resolver: {settings: {delays: 1}}}").expect("loads");
        assert_eq!(set[1].settings, Some(serde_json::json!({"delays": 1})));
    }

    /// An instance can join module groups, as a site's config lists a section in ace3's groups.
    #[test]
    fn an_instance_carries_the_groups_it_joins() {
        let components = components(
            "modules:\n  example_resolver:\n    instances:\n      proxy:\n        groups: [correlation]\n      plain: {}\n",
        )
        .expect("loads");
        let groups: Vec<(&str, Vec<String>)> = components
            .iter()
            .map(|c| (c.key.as_str(), c.groups.clone()))
            .collect();
        assert_eq!(
            groups,
            [
                ("example_line_counter", vec![]),
                ("plain", vec![]),
                ("proxy", vec!["correlation".to_owned()])
            ]
        );
    }

    #[test]
    fn instances_are_components_with_their_own_inputs_and_settings() {
        let components = components(
            "modules:\n  example_resolver:\n    instances:\n      dkim_domains:\n        inputs: [email_dkim_signing_domain]\n        settings: {delays: 1}\n      all_domains: {}\n",
        )
        .expect("loads");
        assert_eq!(
            keys(&components),
            ["example_line_counter", "all_domains", "dkim_domains"]
        );
        let dkim = &components[2];
        assert_eq!(dkim.instance(), Some("dkim_domains"));
        assert_eq!(dkim.manifest.name, "example_resolver");
        assert!(dkim.accepts(ObservableKind::EmailDkimSigningDomain));
        assert!(!dkim.accepts(ObservableKind::Fqdn));
        assert_eq!(dkim.settings, Some(serde_json::json!({"delays": 1})));
        assert!(components[1].accepts(ObservableKind::Fqdn));

        // an instance can't take what its module doesn't, or reuse a key
        let err = super::tests::components(
            "modules: {example_resolver: {instances: {a: {inputs: [file]}}}}",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                OverlayError::Input { kind, .. } if kind == ObservableKind::File
            ),
            "{err}"
        );
        let err = super::tests::components(
            "modules: {example_resolver: {instances: {example_line_counter: {}}}}",
        )
        .unwrap_err();
        assert!(matches!(err, OverlayError::DuplicateKey { .. }), "{err}");
        let err =
            super::tests::components("modules: {example_resolver: {instances: {Bad-Name: {}}}}")
                .unwrap_err();
        assert!(matches!(err, OverlayError::BadName(_)), "{err}");
    }

    #[test]
    fn secrets_name_their_sources() {
        let overlay = Overlay::from_yaml(
            "secrets:\n  resolver_token: env:ACE4_RESOLVER_TOKEN\n  other: file:/run/secrets/other\n",
        )
        .expect("loads");
        assert_eq!(
            overlay.secrets["resolver_token"],
            SecretSource::Env("ACE4_RESOLVER_TOKEN".to_owned())
        );
        assert_eq!(
            overlay.secrets["other"],
            SecretSource::File("/run/secrets/other".into())
        );
        let err = Overlay::from_yaml("secrets: {resolver_token: ACE4_RESOLVER_TOKEN}").unwrap_err();
        println!("{err}");
        assert!(
            matches!(&err, OverlayError::Parse { path, .. } if path == "secrets.resolver_token"),
            "{err}"
        );
    }
}
