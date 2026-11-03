//! PLAN.md 1.16: the schema export of a sample type, snapshot-tested.
//!
//! `ace schema export <dir>` exports the registry of its binary's modules' types. This test exports a
//! registry holding the sample type from `common`, so its snapshot changes only with the envelope,
//! not with each module's details.

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
