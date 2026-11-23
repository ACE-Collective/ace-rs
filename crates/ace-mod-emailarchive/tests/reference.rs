//! PLAN.md 7.5 batch 9: the email archive modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps email_archive`. ace3's archive was run_module.py's in-memory
//! `archived_messages` and CAS pool, under the test-only key in
//! `tools/ace3/dumps/fixtures/email_archive/key`. Each read is answered here with what the core
//! answers for that archive, the file `fixtures/email_archive/store.json` names; ace-pool's lease_api
//! test runs the core's read and the archiver's write over the same fixtures in Postgres and the
//! bucket, and checks them against the same dumps. Every difference is listed in differences.md,
//! next to this file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ace_mod_email::EmailAnalyzer;
use ace_mod_emailarchive::{EmailArchiver, MessageIdAnalyzer};
use ace_results::types::email::EmailAnalysis;
use ace_results::{AnalysisType, ObservableKind};
use ace_sdk::tree::{TreeObservable, TreeView};
use ace_sdk::{Observable, Outcome};
use ace_testkit::Harness;
use ace_testkit::reads::FakeReads;
use ace_testkit::reference::{Dump, ListedDifferences, diff, normal_form};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn listed_for(module: &str) -> ListedDifferences {
    let mut listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    listed
        .rows
        .retain(|row| row.section.as_deref() == Some(module));
    listed
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ace3/dumps/fixtures/email_archive")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn store() -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixtures().join("store.json")).expect("reads"))
        .expect("JSON")
}

fn normalize_message_id(id: &str) -> String {
    ace_sdk::email_threads::normalize_message_id(id)
}

/// What the core's `archived-email` read answers for `message_id` over store.json's archive: the
/// newest email archived with it whose object is still there, by its plaintext's hash, or nothing.
fn archived_email_answer(message_id: &str) -> Value {
    let store = store();
    let wanted = normalize_message_id(message_id);
    let newest = store["emails"]
        .as_array()
        .expect("emails")
        .iter()
        .filter(|e| normalize_message_id(e["message_id"].as_str().expect("an id")) == wanted)
        .filter(|e| e["delete_file"] != true)
        .max_by_key(|e| e["insert_date"].as_str().expect("a date").to_owned());
    let Some(email) = newest else {
        return json!({"email": null, "error": null});
    };
    let bytes =
        std::fs::read(fixtures().join(email["file"].as_str().expect("a file"))).expect("reads");
    json!({"email": {"sha256": sha256_hex(&bytes), "size": bytes.len()}, "error": null})
}

#[tokio::test]
async fn the_message_id_analyzer_matches_the_reference_dumps() {
    let listed = listed_for("message_id_analyzer_v2");
    let mut compared = Vec::new();
    let dumps = Dump::all("message_id_analyzer_v2").expect("the dumps read");
    assert_eq!(dumps.len(), 6);
    for dump in dumps {
        let value = dump.value["input"]["observable"]["value"]
            .as_str()
            .expect("a value")
            .to_owned();
        let reads =
            Arc::new(FakeReads::new().answer("archived-email", archived_email_answer(&value)));
        let harness = Harness::<MessageIdAnalyzer>::new()
            .expect("harness")
            .reader(reads.clone());
        let outcome = harness
            .run_lookup(harness.observable(ObservableKind::MessageId, &value))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        assert_eq!(
            reads.requests(),
            [("archived-email", json!({"subject": null}))],
            "{value}"
        );
        if value == "<archived-2@example.com>" {
            ace_testkit::check_view_fixture("message_id_archived_2", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &dump.normal_form("MessageIDAnalysisV2"),
                &normal_form(&outcome),
            ),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

#[tokio::test]
async fn a_message_id_its_email_added_isn_t_looked_up() {
    let reads = Arc::new(FakeReads::new());
    let harness = Harness::<MessageIdAnalyzer>::new()
        .expect("harness")
        .reader(reads.clone())
        .added_by(&[EmailAnalysis::MODULE]);
    let outcome = harness
        .run_lookup(harness.observable(ObservableKind::MessageId, "<a@b>"))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
    assert!(reads.requests().is_empty());
}

/// The email's file, and ace-rs's email module's result for it.
fn email(dump: &Dump) -> (Observable, Value) {
    let harness = Harness::<EmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
        );
    let mut observable = harness
        .sample(dump.short_name())
        .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
    if let Some(file) = observable.file.as_mut() {
        file.mime_type = dump.mime_type().map(str::to_owned);
    }
    let details = match harness
        .run_parser(observable.clone())
        .unwrap_or_else(|e| panic!("{}: {e}", dump.name))
    {
        Outcome::Done(result) => serde_json::to_value(&result.details).expect("JSON"),
        other => panic!("{}: the email module gave {other:?}", dump.name),
    };
    (observable, details)
}

/// The tree a task on the email gets: the email, untagged, as run_module.py's root has it.
fn tree_of(observable: &Observable) -> TreeView {
    TreeView {
        this: 0,
        observables: vec![TreeObservable {
            kind: ObservableKind::File,
            value: observable.value.clone(),
            tags: Vec::new(),
            directives: vec!["archive".to_owned()],
            detections: 0,
            paths: Vec::new(),
            size: None,
            pending: Vec::new(),
            download: None,
            relationships: Vec::new(),
        }],
        ..Default::default()
    }
}

#[tokio::test]
async fn the_archiver_matches_the_reference_dumps_and_writes_ace3_s_rows() {
    let listed = listed_for("email_archiver");
    let mut compared = Vec::new();
    let dumps: Vec<Dump> = Dump::all("email_archiver")
        .expect("the dumps read")
        .into_iter()
        .filter(|d| !d.short_name().starts_with("local/"))
        .collect();
    assert!(dumps.len() >= 50, "{}", dumps.len());
    let mut archived = 0;
    for dump in dumps {
        let (observable, details) = email(&dump);
        let harness = Harness::<EmailArchiver>::new()
            .expect("harness")
            .dependency_result(EmailAnalysis::MODULE, details)
            .tree(tree_of(&observable));
        let (outcome, writes) = harness
            .run_lookup_writing(observable.with_directive("archive"))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        // what ace3 wrote to its archive: the Message-ID to the email
        let rows = dump.value["email_archive_after"]["archived_messages"]
            .as_array()
            .expect("rows");
        match writes.as_slice() {
            [] => assert!(rows.is_empty(), "{}: ace3 archived it", dump.name),
            [write] => {
                archived += 1;
                assert_eq!(write.write, "email-archive");
                assert_eq!(rows.len(), 1, "{}", dump.name);
                let message_id = write.body["message_id"].as_str().expect("an id");
                assert_eq!(
                    Some(sha256_hex(normalize_message_id(message_id).as_bytes()).to_uppercase()),
                    rows[0]["message_id_hash"].as_str().map(str::to_owned),
                    "{}",
                    dump.name
                );
                assert_eq!(write.body.as_object().map(|b| b.len()), Some(1));
                assert_eq!(
                    rows[0]["digest"].as_str().map(str::to_owned),
                    Some(harness_value(&outcome)),
                    "{}",
                    dump.name
                );
            }
            more => panic!("{}: {more:?}", dump.name),
        }
        if dump.short_name() == "ace3/email/o365_journaled.email.rfc822" {
            ace_testkit::check_view_fixture("email_archive_o365_journaled", &outcome);
        }
        // the email and file type modules tag the email too, so only the analysis is compared
        compared.push((
            dump.short_name().to_owned(),
            diff(
                &analysis_only(dump.normal_form("EmailArchiveResults")),
                &analysis_only(normal_form(&outcome)),
            ),
        ));
    }
    assert!(archived >= 10, "{archived}");
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

/// A normal form's summary and details.
fn analysis_only(form: Value) -> Value {
    if form.is_null() {
        return form;
    }
    json!({"summary": form["summary"], "details": form["details"]})
}

/// The hash an archiver's result names.
fn harness_value<D: AnalysisType>(outcome: &Outcome<D>) -> String {
    match outcome {
        Outcome::Done(result) => serde_json::to_value(&result.details).expect("JSON")["hash"]
            .as_str()
            .expect("a hash")
            .to_owned(),
        _ => panic!("no result"),
    }
}

#[tokio::test]
async fn a_decrypted_email_isn_t_archived() {
    let harness = Harness::<EmailArchiver>::new().expect("harness");
    let observable = harness
        .file_bytes("email.rfc822", b"Message-ID: <a@b>\r\n\r\n", &[])
        .expect("a file");
    let mut tree = tree_of(&observable);
    tree.observables[0].tags.push("decrypted_email".to_owned());
    let (outcome, writes) = harness
        .tree(tree)
        .run_lookup_writing(observable.with_directive("archive"))
        .await
        .expect("runs");
    assert!(matches!(outcome, Outcome::Skipped(_)), "{outcome:?}");
    assert!(writes.is_empty());
}
