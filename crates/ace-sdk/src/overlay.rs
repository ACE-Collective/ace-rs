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
//! ```
//!
//! Every level refuses keys it doesn't know, settings blocks included (ace3 #858). A module with
//! no section runs on its manifest's defaults (ace3 #1044). A section for a module this build
//! doesn't have logs a warning and is skipped, so removing a module never stops startup (ace3
//! #901, #916).
//!
//! A module with `instances` runs once per instance and not as itself, as each of ace3's
//! `analysis_module_*` sections is one run of its class. An instance's name is its key: the
//! name its tasks and results carry in the queue and the tree, and the name modes and groups
//! list. It may narrow the module's inputs.

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
}

impl Component {
    /// The module as itself, on its defaults.
    pub fn of(manifest: Manifest) -> Component {
        Component {
            key: manifest.name.to_owned(),
            manifest,
            inputs: manifest.inputs.to_vec(),
            settings: None,
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
            let Some(section) = self.modules.get(manifest.name) else {
                components.push(Component::of(manifest));
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
                OverlayError::Input {
                    kind: ObservableKind::File,
                    ..
                }
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
}
