//! PLAN.md 1.16: the schema export of a sample type, snapshot-tested.
//!
//! `ace schema export <dir>` calls `Registry::builtin().export_schemas(dir)`. The builtin list is
//! empty until track C's modules add their types, so this test exports a registry holding one
//! sample type that uses each kind of field a real type would.

use std::collections::BTreeMap;

use ace_results::{AnalysisType, AnalysisTypeInfo, Bytes, Registry};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A sample analysis type.
#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleAnalysis {
    /// A required string.
    pub subject: String,
    /// Bytes stay bytes.
    pub raw_subject: Bytes,
    pub attachment_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default)]
    pub headers: Vec<SampleHeader>,
    pub verdict: SampleVerdict,
    #[serde(default)]
    pub counts: BTreeMap<String, u64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleHeader {
    pub name: String,
    pub value: Bytes,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SampleVerdict {
    Clean,
    Suspicious,
}

impl AnalysisType for SampleAnalysis {
    const NAME: &'static str = "sample_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "sample_module";
}

#[test]
fn sample_type_schema_export() {
    let registry =
        Registry::new(&[AnalysisTypeInfo::of::<SampleAnalysis>()]).expect("one type is valid");
    let dir = tempfile::tempdir().expect("temp dir");
    let out = dir.path().join("schemas");

    let written = registry.export_schemas(&out).expect("export works");

    let names: Vec<String> = written
        .iter()
        .map(|p| {
            p.file_name()
                .expect("a file")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, ["sample_analysis.v1.schema.json"]);
    let text = std::fs::read_to_string(&written[0]).expect("the file reads");
    insta::assert_snapshot!(text);
}

#[test]
fn builtin_export_writes_one_file_per_type() {
    let dir = tempfile::tempdir().expect("temp dir");
    let written = Registry::builtin()
        .export_schemas(dir.path())
        .expect("export works");
    assert_eq!(written.len(), ace_results::BUILTIN.len());
}
