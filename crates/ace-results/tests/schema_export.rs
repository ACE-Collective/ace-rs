//! PLAN.md 1.16: the schema export of a sample type, snapshot-tested.
//!
//! `ace schema export <dir>` calls `Registry::builtin().export_schemas(dir)`. The builtin list is
//! empty until track C's modules add their types, so this test exports a registry holding the
//! sample type from `common`.

mod common;

use ace_results::{AnalysisTypeInfo, Registry};
use common::SampleAnalysis;

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
