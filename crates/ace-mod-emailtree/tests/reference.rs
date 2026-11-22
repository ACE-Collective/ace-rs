//! PLAN.md 7.5 batch 8: the lure and mailbox modules against ace3's reference dumps, made by
//! `tools/ace3/dumps/make-dumps emailtree`, which kept each run's whole root (`run_module.py
//! --tree-view`). Each module gets that root as the core's tree, and the email module's result for
//! the email, which ace4's email module makes from the same file, as the core sends a module that
//! depends on it. Every difference is listed and explained in differences.md, next to this file.

use std::path::Path;

use ace_mod_email::EmailAnalyzer;
use ace_mod_emailtree::{LureUrlAnalyzer, MailboxEmailAnalyzer};
use ace_results::AnalysisType;
use ace_results::types::email::EmailAnalysis;
use ace_sdk::{Observable, Outcome};
use ace_testkit::Harness;
use ace_testkit::reference::{Difference, Dump, ListedDifferences, diff};
use serde_json::{Value, json};

fn listed() -> ListedDifferences {
    ListedDifferences::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"))
        .expect("differences.md reads")
}

/// The sample a dump ran on, named before its variant's suffix.
fn sample(dump: &Dump) -> String {
    let name = dump.short_name();
    match name.find(".email.rfc822") {
        Some(at) => name[..at + ".email.rfc822".len()].to_owned(),
        None => name.to_owned(),
    }
}

/// The email's file, and ace4's email module's result for it.
fn email(dump: &Dump) -> (Observable, Value) {
    let harness = Harness::<EmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            "file_type",
            ace_testkit::file_type_details("RFC 822 mail, ASCII text", "message/rfc822"),
        );
    let mut observable = harness
        .sample(&sample(dump))
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

fn this(dump: &Dump, observable: &Observable) -> usize {
    dump.tree_index("file", &observable.value)
        .unwrap_or_else(|| panic!("{}: the email isn't in its root", dump.name))
}

/// The email's primary lure URL, when it has `crawl` in ace3's root after the run. Other URLs there
/// can have it too, from an attached email's own lure.
fn crawled(dump: &Dump, primary: &Value) -> Value {
    let crawled = dump.value["tree_view"]["observables"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|o| {
            o["type"] == "url"
                && o["value"] == *primary
                && o["directives"]
                    .as_array()
                    .is_some_and(|d| d.contains(&json!("crawl")))
        });
    if crawled { json!([primary]) } else { json!([]) }
}

/// ace3's lure analysis without the uuids it gives observables, which ace4's don't have.
fn ace3_lure(dump: &Dump) -> Value {
    let Some(analysis) = dump.analysis("LureURLAnalysis") else {
        return json!({"analysis": null, "crawl": []});
    };
    let mut details = analysis["details"].clone();
    if let Some(primary) = details["primary"].as_object_mut() {
        primary.remove("observable_uuid");
    }
    for candidate in details["candidates"].as_array_mut().into_iter().flatten() {
        if let Some(candidate) = candidate.as_object_mut() {
            candidate.remove("observable_uuid");
        }
    }
    json!({
        "crawl": crawled(dump, &details["primary"]["url"]),
        "analysis": {"summary": analysis["summary"], "details": details},
    })
}

/// The settings file `make-dumps` gave a run named for one, as the overlay's block.
fn lure_settings(dump: &Dump) -> Value {
    let name = dump.short_name();
    if name.ends_with(".settings") {
        json!({"max_candidates": 2, "crawl_primary": false, "noise_keywords": null, "weights": {"body": 0}})
    } else if name.ends_with(".context") {
        json!({
            "sign_off_phrases": ["cheers", "best regards"],
            "attachment_reference_keywords": ["bid documents"],
            "sentence_words": 3,
            "sentence_end_words": 2,
            "weights": {"quoted_message": -10, "signature_block": -5, "attachment_reference": 7, "only_link": 3},
        })
    } else if name.ends_with(".no_reference") {
        json!({"attachment_reference_keywords": null, "sign_off_phrases": null})
    } else {
        Value::Null
    }
}

#[test]
fn the_lure_module_matches_the_reference_dumps_or_lists_each_difference() {
    let mut compared: Vec<(String, Vec<Difference>)> = Vec::new();
    let dumps = Dump::all("lure_url_analyzer").expect("the dumps read");
    assert!(dumps.len() >= 50, "only {} dumps", dumps.len());
    let mut found = 0;
    for dump in dumps {
        let (observable, email) = email(&dump);
        let mut tree = dump.tree_view_with_details(
            this(&dump, &observable),
            &["LureURLAnalysis"],
            &["pdf_link_text"],
        );
        // the crawl the module adds is what's compared
        for o in tree.observables.iter_mut() {
            o.directives.retain(|d| d != "crawl");
        }
        let mut harness = Harness::<LureUrlAnalyzer>::with_settings(lure_settings(&dump))
            .expect("harness")
            .dependency_result(EmailAnalysis::MODULE, email)
            .tree(tree.clone());
        for (sha256, body) in dump.tree_bodies() {
            harness = harness.tree_file(&sha256, &body).expect("the body");
        }
        let outcome = harness
            .run_parser(observable)
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let ace4 = match &outcome {
            Outcome::Done(result) => {
                found += 1;
                if dump.short_name() == "ace4/email/lure_button.email.rfc822" {
                    ace_testkit::check_view_fixture("lure_url_button", &outcome);
                }
                let crawl: Vec<&String> = result
                    .others
                    .iter()
                    .filter(|o| o.additions.directives.iter().any(|d| d == "crawl"))
                    .map(|o| &o.observable.value)
                    .collect();
                json!({
                    "analysis": {
                        "summary": result.summary,
                        "details": serde_json::to_value(&result.details).expect("JSON"),
                    },
                    "crawl": crawl,
                })
            }
            Outcome::Skipped(_) => json!({"analysis": null, "crawl": []}),
            Outcome::Delay(_) => panic!("{}: the module delayed", dump.name),
            Outcome::Incomplete(_) => panic!("{}: the module was incomplete", dump.name),
            Outcome::DoneNotKept(_) => panic!("{}: the module's result was not kept", dump.name),
        };
        compared.push((
            format!("lure_url_analyzer/{}", dump.short_name()),
            diff(&ace3_lure(&dump), &ace4),
        ));
    }
    assert!(found >= 15, "only {found} lure results");
    if let Err(report) = listed().check(&compared, &[]) {
        panic!("{report}");
    }
}

/// What ace3's mailbox module did: its analysis, the root's description and the keys of its
/// details, and the Message-IDs it tracked.
fn ace3_mailbox(dump: &Dump) -> Value {
    let root = &dump.value["root_after"];
    let analysis = dump.analysis("MailboxEmailAnalysis");
    let mut keys: Vec<&String> = root["details"]
        .as_object()
        .into_iter()
        .flat_map(|d| d.keys())
        .filter(|k| *k != "comment")
        .collect();
    keys.sort();
    let tracked: Vec<&Value> = dump.value["tree_view"]["observables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|o| {
            o["type"] == "message_id"
                && o["directives"]
                    .as_array()
                    .is_some_and(|d| d.contains(&json!("tracked")))
        })
        .map(|o| &o["value"])
        .collect();
    json!({
        "analysis": analysis.map(|a| json!({"summary": a["summary"], "details": a["details"]})),
        "description": root["description"],
        "details": keys,
        "tracked": tracked,
    })
}

#[test]
fn the_mailbox_module_matches_the_reference_dumps_or_lists_each_difference() {
    let mut compared: Vec<(String, Vec<Difference>)> = Vec::new();
    let dumps = Dump::all("mailbox_email_analyzer").expect("the dumps read");
    assert!(dumps.len() >= 50, "only {} dumps", dumps.len());
    for dump in dumps {
        let (observable, email) = email(&dump);
        let tree = dump.tree_view(this(&dump, &observable), &["MailboxEmailAnalysis"]);
        let harness = Harness::<MailboxEmailAnalyzer>::new()
            .expect("harness")
            .dependency_result(EmailAnalysis::MODULE, email.clone())
            .tree(tree);
        let outcome = harness
            .run_parser(observable.with_directive("original_email"))
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        if dump.short_name() == "ace4/email/lure_button.email.rfc822" {
            ace_testkit::check_view_fixture("mailbox_lure_button", &outcome);
        }
        let ace4 = match &outcome {
            Outcome::Done(result) => {
                let root = result.root.as_ref().expect("the root's changes");
                let merged = root.details.clone().map(Value::Object);
                assert_eq!(
                    merged.as_ref(),
                    Some(&email),
                    "{}: the merged details",
                    dump.name
                );
                let mut keys: Vec<&String> = root.details.iter().flat_map(|d| d.keys()).collect();
                keys.sort();
                let tracked: Vec<&String> = result
                    .others
                    .iter()
                    .filter(|o| o.additions.directives.iter().any(|d| d == "tracked"))
                    .map(|o| &o.observable.value)
                    .collect();
                json!({
                    "analysis": {
                        "summary": result.summary,
                        "details": serde_json::to_value(&result.details).expect("JSON"),
                    },
                    "description": root.description,
                    "details": keys,
                    "tracked": tracked,
                })
            }
            Outcome::Skipped(_) => json!({
                "analysis": null,
                "description": "ace4 reference dump",
                "details": [],
                "tracked": [],
            }),
            Outcome::Delay(_) => panic!("{}: the module delayed", dump.name),
            Outcome::Incomplete(_) => panic!("{}: the module was incomplete", dump.name),
            Outcome::DoneNotKept(_) => panic!("{}: the module's result was not kept", dump.name),
        };
        compared.push((
            format!("mailbox_email_analyzer/{}", dump.short_name()),
            diff(&ace3_mailbox(&dump), &ace4),
        ));
    }
    if let Err(report) = listed().check(&compared, &[]) {
        panic!("{report}");
    }
}

/// ace3 8617ba8e: an outbound journaled email whose analysis `scan_inbound_only` skipped has no
/// `EmailAnalysis` in ace3, so a mailbox root's description calls it unparsable. Here its result only
/// carries the file's tag (`EmailAnalysis::is_tag_only`), and reads the same.
#[test]
fn a_mailbox_email_with_only_its_outbound_tag_is_unparsable() {
    let dumps = Dump::all("mailbox_email_analyzer").expect("the dumps read");
    let dump = dumps
        .iter()
        .find(|d| d.short_name() == "ace4/email/lure_button.email.rfc822")
        .expect("the dump");
    let (observable, _) = email(dump);
    let mut tree = dump.tree_view(this(dump, &observable), &["MailboxEmailAnalysis"]);
    tree.alert_type = Some("mailbox".to_owned());
    let outcome = Harness::<MailboxEmailAnalyzer>::new()
        .expect("harness")
        .dependency_result(
            EmailAnalysis::MODULE,
            json!({"parsing_error": null, "extraction_errors": [], "email": null}),
        )
        .tree(tree)
        .run_parser(observable.with_directive("original_email"))
        .expect("runs");
    let Outcome::Done(result) = outcome else {
        panic!("{outcome:?}");
    };
    let description = result.root.and_then(|root| root.description);
    assert!(
        description
            .as_deref()
            .is_some_and(|d| d.ends_with(" unparsable email")),
        "{description:?}"
    );
}
