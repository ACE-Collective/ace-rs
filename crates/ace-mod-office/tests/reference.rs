//! PLAN.md 7.5 batch 5: the Office container modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps office` from `tools/ace3/dumps/fixtures/office`, which
//! `tools/samples/make-office-containers` writes, and the samples the modules take. Every
//! difference is listed and explained in differences.md, next to this file.

use std::path::{Path, PathBuf};

use ace_mod_office::{
    ActiveMimeAnalyzer, ExtractedOleAnalyzer, HiddenMimeAnalyzer, OfficeParserAnalyzer,
    OfficeXmlRelAnalyzer, OneNoteAnalyzer, XmlBinaryAnalyzer, XmlPlainTextAnalyzer,
};
use ace_results::{ObservableKind, ObservableRef, Relationship, RelationshipKind};
use ace_sdk::{Observable, Parser};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff, normal_form};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/office")
}

/// The file a dump analyzed: a fixture, labelled `fixtures/office/<folder>/<name>...`, or a sample.
fn local_file(dump: &Dump) -> PathBuf {
    let label = dump.value["input"]["label"].as_str().expect("a label");
    match label.strip_prefix("fixtures/office/") {
        Some(rest) => fixtures().join(rest.split(' ').next().expect("a name")),
        None => ace_testkit::samples_dir().join(label),
    }
}

/// The dump's file, with its directives, `yara_meta` types and what it was extracted from.
fn input<M: Parser>(harness: &Harness<M>, dump: &Dump) -> Observable {
    let input = &dump.value["input"];
    let tags: Vec<&str> = input["meta_tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut observable = harness
        .file(
            input["observable"]["file_path"].as_str().expect("a path"),
            local_file(dump),
            &tags,
        )
        .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
    for directive in input["directives"].as_array().into_iter().flatten() {
        observable = observable.with_directive(directive.as_str().expect("a directive"));
    }
    if let Some(source) = source(dump) {
        observable = observable
            .with_relationship(Relationship::new(RelationshipKind::ExtractedFrom, source));
    }
    observable
}

fn source(dump: &Dump) -> Option<ObservableRef> {
    let from = dump.value["input"].get("extracted_from")?;
    Some(ObservableRef::new(
        ObservableKind::File,
        from["value"].as_str().expect("a value"),
    ))
}

fn compare<M: Parser>(
    module: &str,
    class: &str,
    settings: impl Fn(&Dump) -> Value,
    view: Option<(&str, &str)>,
) -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all(module).expect("the dumps read") {
        let settings = settings(&dump);
        let mut harness = if settings.is_null() {
            Harness::<M>::new().map(|h| h.with_typer(ace_mod_files::file_type::type_of))
        } else {
            Harness::<M>::with_settings(settings)
                .map(|h| h.with_typer(ace_mod_files::file_type::type_of))
        }
        .expect("harness");
        if let Some(file_type) = dump.file_type() {
            harness = harness.dependency_result("file_type", file_type.clone());
        }
        if let (Some(source), Some(from)) =
            (source(&dump), dump.value["input"].get("extracted_from"))
        {
            let tags: Vec<&str> = from["tags"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            harness = harness.related_tags(source, &tags);
            if from.get("added_by").is_some() {
                harness = harness.added_by(&["officeparser3"]);
            }
        }
        let observable = input(&harness, &dump);
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if let Some((name, fixture)) = view
            && dump.short_name() == name
        {
            ace_testkit::check_view_fixture(fixture, &outcome);
        }
        let differences = diff(&dump.normal_form(class), &normal_form(&outcome));
        compared.push((format!("{module}/{}", dump.short_name()), differences));
    }
    compared
}

#[test]
fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = compare::<OneNoteAnalyzer>(
        "onenote_extraction",
        "OneNoteFileAnalysis",
        |dump| {
            if dump.short_name().ends_with(".small") {
                json!({"max_bytes": 1100})
            } else {
                Value::Null
            }
        },
        Some(("onenote/two_files.one", "onenote_two_files")),
    );
    compared.extend(compare::<ActiveMimeAnalyzer>(
        "active_mime",
        "ActiveMimeAnalysis",
        |_| Value::Null,
        Some(("activemime/ole.mso", "active_mime_ole")),
    ));
    compared.extend(compare::<HiddenMimeAnalyzer>(
        "hidden_mime",
        "HiddenMIMEAnalysis",
        |_| Value::Null,
        Some(("mime/hidden.bin", "hidden_mime_bin")),
    ));
    compared.extend(compare::<XmlBinaryAnalyzer>(
        "xml_binary_analyzer",
        "XMLBinaryDataAnalysis",
        |_| Value::Null,
        Some(("flat/flat.xml", "xml_binary_flat")),
    ));
    compared.extend(compare::<XmlPlainTextAnalyzer>(
        "xml_plain_text_analyzer",
        "XMLPlainTextAnalysis",
        |_| Value::Null,
        Some(("plain/document.xml", "xml_plain_text_document")),
    ));
    compared.extend(compare::<OfficeXmlRelAnalyzer>(
        "office_xml_rel",
        "OfficeXMLRelationshipExternalURLAnalysis",
        |_| Value::Null,
        Some(("rels/external/document.xml.rels", "office_xml_rel_external")),
    ));
    compared.extend(compare::<OfficeParserAnalyzer>(
        "officeparser3",
        "OfficeParserAnalysis3",
        |_| Value::Null,
        Some(("ole/native.doc", "officeparser_native")),
    ));
    compared.extend(compare::<ExtractedOleAnalyzer>(
        "extracted_ole_analyzer",
        "ExtractedOLEAnalysis",
        |_| Value::Null,
        Some(("extracted/payload.vbs", "extracted_ole_payload")),
    ));
    assert!(
        compared.len() >= 180,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

/// What the officeparser3 port leaves for each file in `ACE_RS_OFFICEPARSER_DIR`, one JSON line each:
/// how it ended, whether it made a manifest, and each file's sha256, for a comparison with
/// officeparser3 itself in ace3's container (`docs/measurements/office-containers.md`).
#[test]
#[ignore = "a comparison, with files a script mutates"]
fn officeparser3_outputs() {
    use sha2::{Digest, Sha256};
    let dir = std::env::var("ACE_RS_OFFICEPARSER_DIR").expect("ACE_RS_OFFICEPARSER_DIR");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .expect("the directory")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    names.sort();
    for name in names {
        let data = std::fs::read(format!("{dir}/{name}")).expect("the file");
        let run = ace_mod_office::officeparser::tool::run(&data);
        let end = match &run.end {
            ace_mod_office::officeparser::tool::End::Finished => "finished",
            ace_mod_office::officeparser::tool::End::Raised(_) => "raised",
            ace_mod_office::officeparser::tool::End::Exited => "exited",
            ace_mod_office::officeparser::tool::End::Killed => "killed",
        };
        let files: serde_json::Map<String, Value> = run
            .files
            .iter()
            .map(|(k, v)| {
                let hex: String = Sha256::digest(v.as_slice())
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                (k.clone(), Value::String(hex))
            })
            .collect();
        println!(
            "{}",
            json!({"name": name, "end": end, "manifest": run.manifest, "files": files})
        );
    }
}
