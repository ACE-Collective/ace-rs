//! PLAN.md 7.5 batch 13: the packet capture modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps pcap_analyzer pcap_dns pcap_tls pcap_http pcap_files
//! pcap_tls_decryption tls_keylog` from samples/ace3/pcap and the samples
//! `tools/samples/make-pcaps` writes. tshark and capinfos run as plain processes
//! (`ace_sdk::tools::LocalRunner`), the dev image's, which are the sandbox image's at ace3's version.
//! A unit test rather than a test binary of its own (the brief's 2.33). Every difference is listed
//! and explained in `tests/differences.md`.
//!
//! A module that follows pcap_analyzer gets its result as the core would send it, from ace4's own
//! pcap_analyzer on the same sample, and the files it adds with no upload get the size of what
//! pcap_analyzer stored, as the core gives them.

use std::collections::BTreeMap;
use std::path::Path;

use ace_results::types::pcap::PcapAnalysis;
use ace_results::{AnalysisType, ObservableKind};
use ace_sdk::tree::{TreePath, TreeView};
use ace_sdk::{Outcome, Parser};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff, normal_form};
use serde_json::Value;

use crate::{
    PcapAnalyzer, PcapDns, PcapFiles, PcapHttp, PcapTls, PcapTlsDecryptor, TlsKeylogAnalyzer,
};

/// A dump's capture: its label's first word, a sample path.
fn sample(dump: &Dump) -> String {
    let label = dump.value["input"]["label"].as_str().expect("a label");
    label.split(' ').next().expect("a path").to_owned()
}

/// ace4's pcap_analyzer on a sample: its details, as a JSON value, and the size of each file it
/// stored.
fn analyzer(path: &str) -> (Option<Value>, BTreeMap<String, u64>) {
    let harness = Harness::<PcapAnalyzer>::new()
        .expect("harness")
        .with_typer(ace_mod_files::file_type::type_of);
    let observable = harness.sample(path).expect("the sample");
    match harness.run_parser(observable).expect("pcap_analyzer runs") {
        Outcome::Done(result) => {
            let sizes = result
                .stored
                .iter()
                .map(|s| (s.sha256.to_hex(), s.size))
                .collect();
            (
                Some(serde_json::to_value(&result.details).expect("details")),
                sizes,
            )
        }
        _ => (None, BTreeMap::new()),
    }
}

/// The tags pcap_analyzer gave the capture, which a category's dump also shows, as the form doesn't
/// say which module added a tag.
fn without_analyzer_tags(mut form: Value, analyzer: &Value) -> Value {
    if form.is_null() {
        return form;
    }
    let embedded = !analyzer["index"]["embedded_secrets"].is_null();
    if embedded && let Some(tags) = form["analyzed"]["tags"].as_object_mut() {
        tags.retain(|tag, _| !tag.starts_with("pcap_embedded_"));
    }
    form
}

fn compare_analyzer() -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all("pcap_analyzer").expect("the dumps read") {
        let harness = Harness::<PcapAnalyzer>::new()
            .expect("harness")
            .with_typer(ace_mod_files::file_type::type_of);
        let observable = harness.sample(&sample(&dump)).expect("the sample");
        let outcome = harness.run_parser(observable).expect("pcap_analyzer runs");
        if dump.short_name() == "ace3/pcap/network.pcap" {
            ace_testkit::check_view_fixture("pcap_analyzer_network", &outcome);
        }
        let differences = diff(&dump.normal_form("PcapAnalysis"), &normal_form(&outcome));
        compared.push((format!("pcap_analyzer/{}", dump.short_name()), differences));
    }
    compared
}

fn compare_category<M: Parser>(view: Option<(&str, &str)>) -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    let instance = M::NAME.strip_prefix("pcap_").expect("a pcap category");
    for dump in Dump::all(M::NAME).expect("the dumps read") {
        let path = sample(&dump);
        let (details, sizes) = analyzer(&path);
        // the dumps ran the category alone after pcap_analyzer
        let mut harness =
            Harness::<M>::with_settings(serde_json::json!({"categories": [instance]}))
                .expect("harness")
                .with_typer(ace_mod_files::file_type::type_of);
        if let Some(details) = &details {
            harness = harness.dependency_result(PcapAnalysis::MODULE, details.clone());
        }
        let observable = harness.sample(&path).expect("the sample");
        let mut outcome = harness.run_parser(observable).expect("the category runs");
        if let Outcome::Done(result) = &mut outcome {
            for file in &mut result.files {
                file.size = sizes[&file.sha256.to_hex()];
            }
        }
        if let Some((name, fixture)) = view
            && dump.short_name() == name
        {
            ace_testkit::check_view_fixture(fixture, &outcome);
        }
        let ace3 = dump.normal_form_instance("PcapCategoryAnalysis", instance);
        let ace3 = without_analyzer_tags(ace3, details.as_ref().unwrap_or(&Value::Null));
        compared.push((
            format!("{}/{}", M::NAME, dump.short_name()),
            diff(&ace3, &normal_form(&outcome)),
        ));
    }
    compared
}

/// The decryption's dumps: the capture, with the key log the root also held, which tls_keylog
/// tags, as the core sends them in the tree.
fn compare_decryption() -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all("pcap_tls_decryption").expect("the dumps read") {
        let path = sample(&dump);
        let (details, _) = analyzer(&path);
        // the dumps ran pcap_analyzer and the decryption alone
        let mut harness =
            Harness::<PcapTlsDecryptor>::with_settings(serde_json::json!({"categories": []}))
                .expect("harness")
                .with_typer(ace_mod_files::file_type::type_of);
        if let Some(details) = &details {
            harness = harness.dependency_result(PcapAnalysis::MODULE, details.clone());
        }
        let observable = harness.sample(&path).expect("the sample");
        let mut observables = vec![ace_sdk::tree::TreeObservable {
            kind: ObservableKind::File,
            value: observable.value.clone(),
            tags: Vec::new(),
            directives: Vec::new(),
            detections: 0,
            paths: vec![TreePath {
                path: observable
                    .path
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
                yara_meta: Vec::new(),
            }],
            size: None,
            pending: Vec::new(),
            download: None,
            relationships: Vec::new(),
        }];
        let label = dump.value["input"]["label"].as_str().expect("a label");
        if let Some(keylog) = label.split(" with ").nth(1) {
            let bytes =
                std::fs::read(ace_testkit::samples_dir().join(keylog)).expect("the key log");
            let sha256 = crate::sha256_hex(&bytes);
            // tls_keylog's tag, which the core sends the file for
            let keylog_harness = Harness::<TlsKeylogAnalyzer>::new()
                .expect("harness")
                .with_typer(ace_mod_files::file_type::type_of);
            let keylog_observable = keylog_harness.sample(keylog).expect("the key log sample");
            let tagged = matches!(
                keylog_harness
                    .run_parser(keylog_observable)
                    .expect("tls_keylog runs"),
                Outcome::Done(_)
            );
            observables.push(ace_sdk::tree::TreeObservable {
                kind: ObservableKind::File,
                value: sha256.clone(),
                tags: if tagged {
                    vec![crate::keylog::TAG_TLS_KEYLOG.to_owned()]
                } else {
                    Vec::new()
                },
                directives: Vec::new(),
                detections: 0,
                paths: vec![TreePath {
                    path: keylog.rsplit('/').next().expect("a name").to_owned(),
                    yara_meta: Vec::new(),
                }],
                size: Some(bytes.len() as u64),
                pending: Vec::new(),
                download: None,
                relationships: Vec::new(),
            });
            if tagged {
                harness = harness.tree_file(&sha256, &bytes).expect("the tree file");
            }
        }
        harness = harness.tree(TreeView {
            this: 0,
            observables,
            ..TreeView::default()
        });
        let outcome = harness.run_parser(observable).expect("the decryption runs");
        if dump.short_name() == "ace3/pcap/http_tls.pcapng.with_sslkeylog.txt" {
            ace_testkit::check_view_fixture("pcap_tls_decryption_http_tls", &outcome);
        }
        let ace3 = dump.normal_form("PcapTlsDecryptionAnalysis");
        let ace3 = without_analyzer_tags(ace3, details.as_ref().unwrap_or(&Value::Null));
        compared.push((
            format!("pcap_tls_decryption/{}", dump.short_name()),
            diff(&ace3, &normal_form(&outcome)),
        ));
    }
    compared
}

fn compare_keylog() -> Vec<(String, Vec<Difference>)> {
    let mut compared = Vec::new();
    for dump in Dump::all("tls_keylog").expect("the dumps read") {
        let harness = Harness::<TlsKeylogAnalyzer>::new()
            .expect("harness")
            .with_typer(ace_mod_files::file_type::type_of);
        let observable = harness.sample(&sample(&dump)).expect("the sample");
        let outcome = harness.run_parser(observable).expect("tls_keylog runs");
        if dump.short_name() == "ace3/pcap/sslkeylog.txt" {
            ace_testkit::check_view_fixture("tls_keylog_sslkeylog", &outcome);
        }
        compared.push((
            format!("tls_keylog/{}", dump.short_name()),
            diff(
                &dump.normal_form("TlsKeylogAnalysis"),
                &normal_form(&outcome),
            ),
        ));
    }
    compared
}

#[test]
fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = compare_analyzer();
    compared.extend(compare_category::<PcapDns>(Some((
        "ace3/pcap/network.pcap",
        "pcap_dns_network",
    ))));
    compared.extend(compare_category::<PcapTls>(Some((
        "ace3/pcap/http_tls.pcapng",
        "pcap_tls_http_tls",
    ))));
    compared.extend(compare_category::<PcapHttp>(Some((
        "ace3/pcap/http_tls.pcapng",
        "pcap_http_http_tls",
    ))));
    compared.extend(compare_category::<PcapFiles>(Some((
        "ace4/pcap/many_files.pcap",
        "pcap_files_many_files",
    ))));
    compared.extend(compare_decryption());
    compared.extend(compare_keylog());
    assert!(
        compared.len() >= 9 * 5 + 9 + 4,
        "only {} dumps compared",
        compared.len()
    );
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}
