//! PLAN.md 7.5 batch 4: the HTML modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps html` from `tools/ace3/dumps/fixtures/html`, hand-made, and the
//! samples the modules take. Every difference is listed and explained in differences.md, next to
//! this file.
//!
//! ace3 writes a DOM snapshot beside each script, `<script>.dom.json`, which isn't an observable;
//! the dumps keep those files' text (`run_module.py --sidecars`). ace-rs keeps the snapshots in the
//! result's `dom_snapshots`, so each is checked against ace3's file, and then left out of the
//! normal form.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ace_mod_html::{HarExtractor, HtmlDataUrlAnalyzer, HtmlJavaScriptExtractor, MhtmlAnalyzer};
use ace_results::types::html::DomSnapshotFile;
use ace_results::{ObservableKind, ObservableRef, Relationship, RelationshipKind};
use ace_sdk::{Observable, Outcome, Parser};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff, normal_form};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/html")
}

/// The file a dump analyzed: a fixture, labelled `fixtures/html/<name>...`, or a sample.
fn local_file(dump: &Dump) -> PathBuf {
    let label = dump.value["input"]["label"].as_str().expect("a label");
    match label.strip_prefix("fixtures/html/") {
        Some(rest) => fixtures().join(rest.split(' ').next().expect("a name")),
        None => ace_testkit::samples_dir().join(label),
    }
}

/// The dump's file, with its directives and relationships, and the `yara_meta` types it had
/// when the module ran: its own, and those of file_type when the module waits for it.
fn input<M: Parser>(harness: &Harness<M>, dump: &Dump, after_file_type: bool) -> Observable {
    let input = &dump.value["input"];
    let tags_from = if after_file_type {
        &dump.value["observable_after"]["yara_meta"]
    } else {
        &input["meta_tags"]
    };
    let tags: Vec<&str> = tags_from
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
    for r in input["relationships"].as_array().into_iter().flatten() {
        let kind: RelationshipKind =
            serde_json::from_value(r["type"].clone()).expect("a relationship kind");
        let target_kind: ObservableKind = r["target"]["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a kind");
        let target =
            ObservableRef::new(target_kind, r["target"]["value"].as_str().expect("a value"));
        observable = observable.with_relationship(Relationship::new(kind, target));
    }
    observable
}

/// Checks ace-rs's snapshots against the sidecars ace3 wrote, and takes them out of the form.
fn check_sidecars(dump: &Dump, form: &mut Value) -> Vec<Difference> {
    let snapshots: Vec<DomSnapshotFile> = form["details"]
        .as_object_mut()
        .and_then(|details| details.remove("dom_snapshots"))
        .map(|v| serde_json::from_value(v).expect("snapshots"))
        .unwrap_or_default();
    let mut ace_rs = BTreeMap::new();
    for snapshot in snapshots {
        for file in &snapshot.files {
            ace_rs.insert(
                format!("{file}.dom.json"),
                serde_json::to_value(&snapshot.snapshot).expect("serializes"),
            );
        }
    }
    let ace3: BTreeMap<String, Value> = dump.value["sidecars"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(path, text)| {
            (
                path.clone(),
                serde_json::from_str(text.as_str().expect("text")).expect("a sidecar's JSON"),
            )
        })
        .collect();
    let mut differences = Vec::new();
    for path in ace3
        .keys()
        .chain(ace_rs.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if ace3.get(path) != ace_rs.get(path) {
            differences.push(Difference {
                path: format!("/sidecars/{}", path.replace('/', "~1")),
                ace3: ace3.get(path).cloned(),
                ace_rs: ace_rs.get(path).cloned(),
            });
        }
    }
    differences
}

fn compare<M: Parser>(
    module: &str,
    class: &str,
    settings: impl Fn(&Dump) -> Value,
    after_file_type: bool,
    view: Option<(&str, &str)>,
) -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all(module).expect("the dumps read") {
        let settings = settings(&dump);
        let mut harness = if settings.is_null() {
            Harness::<M>::new()
        } else {
            Harness::<M>::with_settings(settings)
        }
        .expect("harness")
        .with_typer(ace_mod_files::file_type::type_of);
        if let Some(file_type) = dump.file_type() {
            harness = harness.dependency_result("file_type", file_type.clone());
        }
        let observable = input(&harness, &dump, after_file_type);
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if let Some((name, fixture)) = view
            && dump.short_name() == name
        {
            ace_testkit::check_view_fixture(fixture, &outcome);
        }
        let mut form = normal_form(&outcome);
        let mut differences = if matches!(outcome, Outcome::Done(_)) {
            check_sidecars(&dump, &mut form)
        } else {
            Vec::new()
        };
        differences.extend(diff(&dump.normal_form(class), &form));
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
    let mut compared = compare::<HtmlDataUrlAnalyzer>(
        "html_data_url_extraction",
        "HTMLDataURLAnalysis",
        |_| json!({}),
        false,
        Some(("data_urls.html", "html_data_url_page")),
    );
    compared.extend(compare::<MhtmlAnalyzer>(
        "mhtml",
        "MHTMLAnalysis",
        |_| Value::Null,
        false,
        Some(("page.mht", "mhtml_page")),
    ));
    compared.extend(compare::<HtmlJavaScriptExtractor>(
        "html_js_extraction",
        "HTMLJavaScriptExtractionAnalysis",
        |_| json!({}),
        true,
        Some(("scripts.html", "html_js_scripts")),
    ));
    compared.extend(compare::<HarExtractor>(
        "har_extraction",
        "HARAnalysis",
        |dump| {
            if dump.short_name().ends_with(".small") {
                json!({"max_file_size": 1000})
            } else {
                json!({})
            }
        },
        false,
        Some(("session.har", "har_session")),
    ));
    assert!(
        compared.len() >= 90,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
