//! The analysis type registry and JSON Schema export.
//!
//! Each analysis type is listed by name and version, with the module that writes it and its
//! schema. The list is plain data, built from `AnalysisTypeInfo::of::<T>()`, so finding a type or
//! its module needs no instance (ace3 #827) and nothing registers at run time.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use schemars::Schema;
use schemars::generate::SchemaSettings;
use serde_json::{Value, json};

use crate::envelope::{AnalysisType, ResultEnvelope};
use crate::validate::{InvalidResult, ResultValidator};

/// Every analysis type ace4 knows, in the order `ace schema export` writes them. Each ported
/// module adds its types here.
pub const BUILTIN: &[AnalysisTypeInfo] = &[
    AnalysisTypeInfo::of::<crate::types::email::EmailAnalysis>(),
    AnalysisTypeInfo::of::<crate::types::rdap::RdapAnalysis>(),
];

/// One analysis type: its name, version, module and schema.
#[derive(Clone, Copy)]
pub struct AnalysisTypeInfo {
    pub name: &'static str,
    pub version: u32,
    pub module: &'static str,
    schema: fn() -> Schema,
}

impl AnalysisTypeInfo {
    pub const fn of<T: AnalysisType>() -> Self {
        AnalysisTypeInfo {
            name: T::NAME,
            version: T::VERSION,
            module: T::MODULE,
            schema: result_schema::<T>,
        }
    }

    /// The JSON Schema of a whole result of this type: the envelope, with the type's details.
    pub fn schema(&self) -> Schema {
        (self.schema)()
    }

    /// The file `export_schemas` writes this type's schema to.
    pub fn schema_file_name(&self) -> String {
        format!("{}.v{}.schema.json", self.name, self.version)
    }
}

impl std::fmt::Debug for AnalysisTypeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisTypeInfo")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("module", &self.module)
            .finish_non_exhaustive()
    }
}

/// The JSON Schema (draft 2020-12) of a result of type `T`. `analysis_type` and
/// `schema_version` are pinned to `T`'s name and version, so a result of another type fails it.
pub fn result_schema<T: AnalysisType>() -> Schema {
    let mut schema = SchemaSettings::draft2020_12()
        .for_deserialize()
        .into_generator()
        .into_root_schema_for::<ResultEnvelope<T>>();
    let object = schema.ensure_object();
    object.insert(
        "title".to_owned(),
        json!(format!("{} version {}", T::NAME, T::VERSION)),
    );
    if let Some(Value::Object(properties)) = object.get_mut("properties") {
        properties.insert(
            "analysis_type".to_owned(),
            json!({"type": "string", "const": T::NAME}),
        );
        properties.insert(
            "schema_version".to_owned(),
            json!({"type": "integer", "const": T::VERSION}),
        );
    }
    schema
}

/// A set of analysis types, at most one per (name, version).
#[derive(Debug)]
pub struct Registry {
    types: BTreeMap<(&'static str, u32), Entry>,
}

#[derive(Debug)]
struct Entry {
    info: AnalysisTypeInfo,
    /// Compiled the first time a result of this type is checked.
    validator: OnceLock<Result<ResultValidator, String>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("analysis type {name} version {version} is listed twice")]
    Duplicate { name: &'static str, version: u32 },
    #[error("analysis type {name} is written by both {first} and {second}")]
    TwoModules {
        name: &'static str,
        first: &'static str,
        second: &'static str,
    },
}

impl Registry {
    pub fn new(types: &[AnalysisTypeInfo]) -> Result<Self, RegistryError> {
        let mut by_key = BTreeMap::new();
        for info in types {
            if let Some(other) = types
                .iter()
                .find(|other| other.name == info.name && other.module != info.module)
            {
                return Err(RegistryError::TwoModules {
                    name: info.name,
                    first: info.module,
                    second: other.module,
                });
            }
            let entry = Entry {
                info: *info,
                validator: OnceLock::new(),
            };
            if by_key.insert((info.name, info.version), entry).is_some() {
                return Err(RegistryError::Duplicate {
                    name: info.name,
                    version: info.version,
                });
            }
        }
        Ok(Registry { types: by_key })
    }

    /// The registry of `BUILTIN`.
    pub fn builtin() -> &'static Registry {
        static BUILTIN_REGISTRY: OnceLock<Registry> = OnceLock::new();
        BUILTIN_REGISTRY.get_or_init(|| {
            // a duplicate in BUILTIN is a bug that the builtin_registry_loads test catches
            Registry::new(BUILTIN).unwrap_or_else(|e| panic!("BUILTIN is invalid: {e}"))
        })
    }

    pub fn get(&self, name: &str, version: u32) -> Option<&AnalysisTypeInfo> {
        self.entry(name, version).map(|entry| &entry.info)
    }

    fn entry(&self, name: &str, version: u32) -> Option<&Entry> {
        self.types
            .iter()
            .find(|((n, v), _)| *n == name && *v == version)
            .map(|(_, entry)| entry)
    }

    /// The module that writes `name`.
    pub fn module_of(&self, name: &str) -> Option<&'static str> {
        self.types()
            .find(|info| info.name == name)
            .map(|info| info.module)
    }

    /// Every type, by name and then version.
    pub fn types(&self) -> impl Iterator<Item = &AnalysisTypeInfo> {
        self.types.values().map(|entry| &entry.info)
    }

    /// Checks a result in JSON against the schema of the type it names in `analysis_type` and
    /// `schema_version`.
    pub fn validate(&self, result: &Value) -> Result<(), InvalidResult> {
        let name = result.get("analysis_type").and_then(Value::as_str);
        let version = result.get("schema_version").and_then(Value::as_u64);
        let (Some(name), Some(version)) = (name, version) else {
            return Err(InvalidResult::Untyped);
        };
        let entry = u32::try_from(version)
            .ok()
            .and_then(|version| self.entry(name, version))
            .ok_or_else(|| InvalidResult::UnknownType {
                name: name.to_owned(),
                version,
            })?;
        let validator = entry
            .validator
            .get_or_init(|| ResultValidator::new(&entry.info.schema()).map_err(|e| e.to_string()))
            .as_ref()
            .map_err(|e| InvalidResult::BadSchema {
                name: entry.info.name,
                version: entry.info.version,
                error: e.clone(),
            })?;
        validator.validate(result)
    }

    /// Writes each type's schema to `<dir>/<name>.v<version>.schema.json`, creating `dir` if it
    /// is missing, and returns the paths written. Keys are sorted, so the output doesn't depend
    /// on how serde_json was built.
    pub fn export_schemas(&self, dir: &Path) -> io::Result<Vec<PathBuf>> {
        fs::create_dir_all(dir)?;
        let mut written = Vec::new();
        for info in self.types() {
            let path = dir.join(info.schema_file_name());
            let mut text = serde_json::to_string_pretty(&sort_json_keys(info.schema().to_value()))
                .map_err(io::Error::other)?;
            text.push('\n');
            fs::write(&path, text)?;
            written.push(path);
        }
        Ok(written)
    }
}

/// `value` with every object's keys in sorted order, whether or not serde_json was built with
/// `preserve_order`, for output that is compared byte for byte, such as snapshots.
pub fn sort_json_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let entries: BTreeMap<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_json_keys(v)))
                .collect();
            Value::Object(entries.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sort_json_keys).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct A1 {}
    impl AnalysisType for A1 {
        const NAME: &'static str = "a";
        const VERSION: u32 = 1;
        const MODULE: &'static str = "module_a";
    }

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct A2 {}
    impl AnalysisType for A2 {
        const NAME: &'static str = "a";
        const VERSION: u32 = 2;
        const MODULE: &'static str = "module_a";
    }

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct AFromB {}
    impl AnalysisType for AFromB {
        const NAME: &'static str = "a";
        const VERSION: u32 = 3;
        const MODULE: &'static str = "module_b";
    }

    #[test]
    fn builtin_registry_loads() {
        assert_eq!(Registry::builtin().types().count(), BUILTIN.len());
    }

    #[test]
    fn finds_types_and_modules_by_name() {
        let registry = Registry::new(&[AnalysisTypeInfo::of::<A2>(), AnalysisTypeInfo::of::<A1>()])
            .expect("valid");
        assert_eq!(registry.module_of("a"), Some("module_a"));
        assert_eq!(registry.module_of("b"), None);
        assert_eq!(registry.get("a", 2).map(|t| t.version), Some(2));
        assert!(registry.get("a", 3).is_none());
        let versions: Vec<u32> = registry.types().map(|t| t.version).collect();
        assert_eq!(versions, [1, 2]);
    }

    #[test]
    fn refuses_duplicates() {
        let err = Registry::new(&[AnalysisTypeInfo::of::<A1>(), AnalysisTypeInfo::of::<A1>()])
            .unwrap_err();
        assert!(matches!(err, RegistryError::Duplicate { .. }), "{err}");
        let err = Registry::new(&[
            AnalysisTypeInfo::of::<A1>(),
            AnalysisTypeInfo::of::<AFromB>(),
        ])
        .unwrap_err();
        assert!(matches!(err, RegistryError::TwoModules { .. }), "{err}");
    }
}
