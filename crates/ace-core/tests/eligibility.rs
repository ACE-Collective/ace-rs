//! PLAN.md 2.10: eligibility. A table covers each rule; landing results queues what became
//! eligible; a detection mid-analysis turns the root into an alert in correlation mode and
//! queues the correlation group's modules for the observables already in the tree; and a
//! cancelled dependency leaves its dependents waiting, not failed (ace3 #846).

use crate::common;

use std::collections::BTreeSet;
use std::time::Duration;

use ace_core::eligibility::{Catalog, Facts, Ineligible, check};
use ace_core::modes::{AnalysisMode, Modes};
use ace_core::orchestrator::{Orchestrator, Scope};
use ace_core::testing::TestDb;
use ace_core::tree;
use ace_results::{ObservableKind, ObservableRef};
use serde_json::json;

use common::{file_type_says_email, manifests, result, root_with, tasks_of, worker};

const EMAIL_SHA256: &str = "5d2569cdbe088294e456effabcfd8362108468f12deaf6464f95bc5400f85874";

/// ace3's modes, with two alike for these tests: the file group without the YARA module, plus
/// a module that depends on `archive`.
fn modes() -> Modes {
    let test = |name: &str| AnalysisMode {
        name: name.to_owned(),
        module_groups: vec!["file".to_owned()],
        enabled_modules: vec!["test_depends_on_archive".to_owned()],
        disabled_modules: vec!["yara_scanner_v3_4".to_owned()],
    };
    Modes::ace3()
        .with_mode(test("test"))
        .with_mode(test("test_again"))
        .with_mode(AnalysisMode {
            name: "test_without_archive".to_owned(),
            module_groups: Vec::new(),
            enabled_modules: vec!["test_depends_on_archive".to_owned()],
            disabled_modules: Vec::new(),
        })
}

fn orchestrator() -> Orchestrator {
    Orchestrator::new(Catalog::new(manifests()), modes())
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn each_rule() {
    const FILE: ObservableKind = ObservableKind::File;
    const FQDN: ObservableKind = ObservableKind::Fqdn;
    const DKIM_DOMAIN: ObservableKind = ObservableKind::EmailDkimSigningDomain;
    struct Case {
        what: &'static str,
        module: &'static str,
        kind: ObservableKind,
        directives: &'static [&'static str],
        exclude: &'static [&'static str],
        mode: &'static str,
        results: &'static [&'static str],
        expected: Result<(), Ineligible>,
    }
    let case = |what, module, kind, mode, expected| Case {
        what,
        module,
        kind,
        directives: &[],
        exclude: &[],
        mode,
        results: &[],
        expected,
    };
    let cases = [
        case(
            "takes its input type",
            "email_analyzer",
            FILE,
            "email",
            Ok(()),
        ),
        case(
            "takes a type that extends its input",
            "rdap_analyzer",
            DKIM_DOMAIN,
            "correlation",
            Ok(()),
        ),
        case(
            "doesn't take the type",
            "email_analyzer",
            FQDN,
            "email",
            Err(Ineligible::NotAnInput),
        ),
        case(
            "the mode doesn't run its group",
            "rdap_analyzer",
            FQDN,
            "email",
            Err(Ineligible::NotInMode),
        ),
        case(
            "no group names it",
            "splunk_api",
            FQDN,
            "analysis",
            Err(Ineligible::NotInMode),
        ),
        case(
            "the mode enables it by name",
            "alert_added_to_event",
            FQDN,
            "dispositioned",
            Ok(()),
        ),
        case(
            "the mode disables it",
            "yara_scanner_v3_4",
            FILE,
            "test",
            Err(Ineligible::NotInMode),
        ),
        case(
            "an unknown mode runs nothing",
            "email_analyzer",
            FILE,
            "no_such_mode",
            Err(Ineligible::NotInMode),
        ),
        Case {
            directives: &["no_scan"],
            ..case(
                "no_scan keeps the YARA module off",
                "yara_scanner_v3_4",
                FILE,
                "email",
                Err(Ineligible::Directive("no_scan".to_owned())),
            )
        },
        Case {
            directives: &["no_scan"],
            ..case(
                "no_scan leaves other modules alone",
                "archive",
                FILE,
                "email",
                Ok(()),
            )
        },
        Case {
            directives: &["whitelisted"],
            ..case(
                "a whitelisted directive keeps nothing off, since ace3 removed whitelisting (8617ba8e)",
                "archive",
                FILE,
                "email",
                Ok(()),
            )
        },
        Case {
            directives: &["original_email", "exclude_all"],
            ..case(
                "exclude_all keeps every module off",
                "archive",
                FILE,
                "email",
                Err(Ineligible::Directive("exclude_all".to_owned())),
            )
        },
        Case {
            exclude: &["archive"],
            ..case(
                "the observable excludes it",
                "archive",
                FILE,
                "email",
                Err(Ineligible::Excluded),
            )
        },
        case(
            "a dependency has no result yet",
            "test_depends_on_archive",
            FILE,
            "test",
            Err(Ineligible::WaitingFor("archive".to_owned())),
        ),
        case(
            "a dependency the mode doesn't run doesn't hold it back",
            "test_depends_on_archive",
            FILE,
            "test_without_archive",
            Ok(()),
        ),
        Case {
            results: &["archive"],
            ..case(
                "a dependency has a result",
                "test_depends_on_archive",
                FILE,
                "test",
                Ok(()),
            )
        },
        Case {
            results: &["email_analyzer"],
            ..case(
                "a file without the directive the email logger requires",
                "email_logger",
                FILE,
                "email",
                Err(Ineligible::MissingDirective("original_email".to_owned())),
            )
        },
        Case {
            directives: &["original_email"],
            ..case(
                "the original email, before the email module's result",
                "email_logger",
                FILE,
                "email",
                Err(Ineligible::WaitingFor("email_analyzer".to_owned())),
            )
        },
        Case {
            directives: &["original_email"],
            results: &["email_analyzer"],
            ..case(
                "the original email, once the email module parsed it",
                "email_logger",
                FILE,
                "email",
                Ok(()),
            )
        },
        Case {
            directives: &["original_email", "exclude_all"],
            results: &["email_analyzer"],
            ..case(
                "a directive that keeps it off wins over one it requires",
                "email_logger",
                FILE,
                "email",
                Err(Ineligible::Directive("exclude_all".to_owned())),
            )
        },
    ];

    let catalog = Catalog::new(manifests());
    let modes = modes();
    for case in cases {
        let component = catalog.component(case.module).expect("a known module");
        let directives = strings(case.directives);
        let exclude = strings(case.exclude);
        let results: BTreeSet<&str> = case.results.iter().copied().collect();
        // as the orchestrator passes them: what the mode runs and the catalog has
        let mut mode_modules = modes.modules_in(case.mode);
        mode_modules.retain(|m| catalog.keys().contains(m));
        let got = check(
            component,
            Facts {
                kind: case.kind,
                directives: &directives,
                exclude_modules: &exclude,
                limit_modules: &[],
            },
            &mode_modules,
            &results,
        );
        assert_eq!(got, case.expected, "{}", case.what);
    }
}

/// PLAN.md decision 33: a module the overlay turns off (`enabled: false`) isn't in the catalog, so a
/// module that depends on it doesn't wait for it, as ace3's engine treats a dependency on a module it
/// didn't load, and decision 30 one the binary hasn't.
#[test]
fn a_dependency_turned_off_in_the_overlay_is_met() {
    let overlay =
        ace_sdk::Overlay::from_yaml("modules: {archive: {enabled: false}}").expect("parses");
    let catalog = Catalog::of(overlay.components(&manifests()).expect("components"));
    assert!(catalog.component("archive").is_none(), "no component of it");
    let component = catalog
        .component("test_depends_on_archive")
        .expect("the dependent");
    let modes = modes();
    let mut mode_modules = modes.modules_in("test");
    mode_modules.retain(|m| catalog.keys().contains(m));
    let got = check(
        component,
        Facts {
            kind: ObservableKind::File,
            directives: &[],
            exclude_modules: &[],
            limit_modules: &[],
        },
        &mode_modules,
        &BTreeSet::new(),
    );
    assert_eq!(got, Ok(()));
}

#[tokio::test]
async fn a_detection_mid_analysis_queues_the_correlation_group_for_the_tree() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = orchestrator();
    let (root, ids) = root_with(
        db,
        "email",
        &[
            (ObservableKind::File, EMAIL_SHA256),
            (ObservableKind::Fqdn, "evil.example.com"),
        ],
    )
    .await;
    file_type_says_email(db, root, ids[0]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .queue_eligible(&mut tx, root, Scope::All, false)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    // email mode runs the common, file and email groups: nothing for the fqdn yet
    let queued =
        |module: &str, value: &str| (module.to_owned(), value.to_owned(), "queued".to_owned());
    assert_eq!(
        tasks_of(db, root).await,
        [
            queued("archive", EMAIL_SHA256),
            queued("email_analyzer", EMAIL_SHA256),
            queued("yara_scanner_v3_4", EMAIL_SHA256),
        ]
    );

    // the YARA task lands a match, with a detection and a new fqdn, while the others wait
    let scanner = worker(
        &test_db,
        "yara",
        &["yara_scanner_v3_4"],
        Duration::from_secs(60),
    )
    .await;
    let task = scanner.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    let landed = orchestrator
        .land_result(
            &mut tx,
            &scanner,
            &task,
            &result(json!({
                "analysis_type": "yara_scan_results",
                "schema_version": 1,
                "details": {"matches": ["evil_macro"]},
                "detections": [{"description": "matched rule evil_macro"}],
                "observables": [{"type": "fqdn", "value": "c2.example.com"}],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    assert_eq!(landed.mode_changed_to.as_deref(), Some("correlation"));

    let stored = tree::root(db.pool(), root)
        .await
        .expect("reads")
        .expect("exists");
    assert_eq!(stored.analysis_mode, "correlation");
    // RDAP for the fqdn that was already there and for the one the result added; the email
    // and archive tasks are still waiting
    let tasks = tasks_of(db, root).await;
    assert_eq!(
        tasks,
        [
            queued("archive", EMAIL_SHA256),
            queued("email_analyzer", EMAIL_SHA256),
            queued("rdap_analyzer", "c2.example.com"),
            queued("rdap_analyzer", "evil.example.com"),
            (
                "yara_scanner_v3_4".to_owned(),
                EMAIL_SHA256.to_owned(),
                "done".to_owned()
            ),
        ]
    );
    assert_eq!(landed.queued.len(), 2);
    let alerted: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT alerted_at FROM analysis.roots WHERE id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert!(alerted.is_some());
    let detections: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis.detections WHERE root_id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("counts");
    assert_eq!(detections, 1);
}

/// ace3 removed whitelisting (8617ba8e): a `whitelisted` tag or directive is an ordinary one. A result
/// that adds them to the observable it analyzed stops nothing, and a detection in a root holding them
/// makes it an alert.
#[tokio::test]
async fn a_whitelisted_tag_stops_nothing_and_a_root_holding_one_alerts() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = orchestrator();
    let (root, ids) = root_with(db, "email", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    file_type_says_email(db, root, ids[0]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .queue_eligible(&mut tx, root, Scope::All, false)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");

    // a result tags the email whitelisted, as ace3's email module did for a whitelisted sender
    let parser = worker(
        &test_db,
        "parsers",
        &["email_analyzer"],
        Duration::from_secs(60),
    )
    .await;
    let task = parser.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    let landed = orchestrator
        .land_result(
            &mut tx,
            &parser,
            &task,
            &result(json!({
                "analysis_type": "email_analysis",
                "schema_version": 1,
                "details": {"parsing_error": null, "extraction_errors": [], "email": null},
                "analyzed": {"tags": ["whitelisted"], "directives": ["whitelisted"]},
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    assert_eq!(landed.mode_changed_to, None);
    let state =
        |module: &str, state: &str| (module.to_owned(), EMAIL_SHA256.to_owned(), state.to_owned());
    assert_eq!(
        tasks_of(db, root).await,
        [
            state("archive", "queued"),
            state("email_analyzer", "done"),
            state("yara_scanner_v3_4", "queued"),
        ],
        "the rest of the root's analysis goes on"
    );

    // a detection on the tagged file makes the root an alert
    let scanner = worker(
        &test_db,
        "yara",
        &["yara_scanner_v3_4"],
        Duration::from_secs(60),
    )
    .await;
    let task = scanner.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    let landed = orchestrator
        .land_result(
            &mut tx,
            &scanner,
            &task,
            &result(json!({
                "analysis_type": "yara_scan_results",
                "schema_version": 1,
                "details": {"matches": ["evil"]},
                "detections": [{"description": "matched rule evil"}],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    assert_eq!(landed.mode_changed_to.as_deref(), Some("correlation"));
    let alerted: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT alerted_at FROM analysis.roots WHERE id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert!(alerted.is_some(), "a root holding a whitelisted tag alerts");
}

#[tokio::test]
async fn a_result_makes_its_dependents_eligible_and_a_cancelled_dependency_fails_none() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = orchestrator();
    let (root, _) = root_with(db, "test", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .queue_eligible(&mut tx, root, Scope::All, false)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    let state_of = |tasks: &[(String, String, String)], module: &str| {
        tasks
            .iter()
            .find(|(m, _, _)| m == module)
            .map(|(_, _, state)| state.clone())
    };
    let tasks = tasks_of(db, root).await;
    assert_eq!(state_of(&tasks, "archive").as_deref(), Some("queued"));
    // the dependent waits for archive's result: no task, and nothing failed
    assert_eq!(state_of(&tasks, "test_depends_on_archive"), None);

    // the dependency is cancelled, as when its root's analysis is stopped
    sqlx::query(
        "UPDATE queue.tasks SET state = 'cancelled' WHERE root_id = $1 AND module = 'archive'",
    )
    .bind(root)
    .execute(db.pool())
    .await
    .expect("cancels");
    let mut tx = db.begin().await.expect("begins");
    assert!(
        orchestrator
            .queue_eligible(&mut tx, root, Scope::All, false)
            .await
            .expect("queues")
            .is_empty(),
        "another pass in the same mode leaves the cancelled task alone"
    );
    tx.commit().await.expect("commits");
    assert_eq!(
        state_of(&tasks_of(db, root).await, "test_depends_on_archive"),
        None
    );

    // a mode change runs the cancelled dependency again, and its result lets the dependent run
    let mut tx = db.begin().await.expect("begins");
    let requeued = orchestrator
        .set_mode(&mut tx, root, "test_again")
        .await
        .expect("changes the mode");
    tx.commit().await.expect("commits");
    assert_eq!(requeued.len(), 1);
    assert_eq!(
        state_of(&tasks_of(db, root).await, "archive").as_deref(),
        Some("queued")
    );
    let archiver = worker(&test_db, "archiver", &["archive"], Duration::from_secs(60)).await;
    let task = archiver.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    let landed = orchestrator
        .land_result(
            &mut tx,
            &archiver,
            &task,
            &result(json!({
                "analysis_type": "archive_analysis",
                "schema_version": 1,
                "details": {"file_count": 0},
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    assert_eq!(landed.queued.len(), 1);
    let tasks = tasks_of(db, root).await;
    assert_eq!(state_of(&tasks, "archive").as_deref(), Some("done"));
    assert_eq!(
        state_of(&tasks, "test_depends_on_archive").as_deref(),
        Some("queued")
    );
}

/// A macro found in a document and in a part of it arrives with two redirections, and in either
/// order the tree keeps the same one.
#[tokio::test]
async fn an_observables_redirection_doesnt_depend_on_which_result_landed_first() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (low, high) = ("aa".repeat(32), "bb".repeat(32));
    for (first, second) in [(&low, &high), (&high, &low)] {
        let (root, _) = root_with(db, "test", &[(ObservableKind::Fqdn, "example.com")]).await;
        let mut tx = db.begin().await.expect("begins");
        for target in [first, second] {
            let mut macro_file =
                ace_results::NewObservable::new(ObservableKind::File, "cc".repeat(32));
            macro_file.redirection =
                Some(ObservableRef::new(ObservableKind::File, target.as_str()));
            tree::upsert_observable(&mut tx, root, &macro_file)
                .await
                .expect("upserts");
        }
        let mut plain = ace_results::NewObservable::new(ObservableKind::File, "cc".repeat(32));
        plain.redirection = None;
        tree::upsert_observable(&mut tx, root, &plain)
            .await
            .expect("upserts");
        tx.commit().await.expect("commits");
        let macro_ref = ObservableRef::new(ObservableKind::File, "cc".repeat(32));
        let id = tree::find_observable(db.pool(), root, &macro_ref)
            .await
            .expect("finds")
            .expect("is there");
        let target = tree::redirection(db.pool(), root, id).await.expect("reads");
        assert_eq!(
            target,
            Some(ObservableRef::new(ObservableKind::File, low.as_str()))
        );
    }
}

/// A result of `analysis_type` on `on`, which added `added` under these paths.
async fn add_result(
    db: &ace_core::db::Db,
    root: uuid::Uuid,
    on: tree::ObservableId,
    analysis_type: &str,
    details: serde_json::Value,
    added: &[(tree::ObservableId, Option<&str>)],
) {
    let mut tx = db.begin().await.expect("begins");
    let envelope = result(json!({
        "analysis_type": analysis_type, "schema_version": 1, "details": details,
    }));
    let id = tree::insert_result(&mut tx, root, on, analysis_type, &envelope)
        .await
        .expect("inserts");
    for (observable, path) in added {
        tree::add_result_addition(&mut tx, root, id, *observable, *path)
            .await
            .expect("adds");
    }
    tx.commit().await.expect("commits");
}

/// The walk ace3's `search_down` does: past an archive to the nearest email, by any route, to the
/// email's body parts. A cycle ends, an email with no body part is one, and nothing above a root is
/// none.
#[tokio::test]
async fn a_file_finds_the_body_of_the_email_that_carried_it() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (outer, nested, zip, doc, body, inner_body, outer_html) = (
        hash("a"),
        hash("b"),
        hash("c"),
        hash("d"),
        hash("e"),
        hash("f"),
        hash("0"),
    );
    let values = [&outer, &nested, &zip, &doc, &body, &inner_body, &outer_html];
    let files: Vec<(ObservableKind, &str)> = values
        .iter()
        .map(|value| (ObservableKind::File, value.as_str()))
        .collect();
    let (root, ids) = root_with(db, "test", &files).await;
    let (outer_id, nested_id, zip_id, doc_id, body_id, inner_id, html_id) =
        (ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6]);
    let message = json!({"email": {}});

    // the outer email adds the nested one, its two body parts, and the nested one's zip, as ace3's
    // does; every part counts, in the order the email added them (ace3's `body_parts`)
    add_result(
        db,
        root,
        outer_id,
        "email_analysis",
        message.clone(),
        &[
            (body_id, Some("email.rfc822.unknown_text_plain_000.txt")),
            (nested_id, Some("email.rfc822.email_000.rfc822")),
            (html_id, Some("email.rfc822.unknown_text_html_001.html")),
            (zip_id, Some("a_000.zip")),
        ],
    )
    .await;
    let outer_body = vec![
        tree::EmailBodyFile {
            path: "email.rfc822.unknown_text_plain_000.txt".to_owned(),
            sha256: body.clone(),
            html: false,
        },
        tree::EmailBodyFile {
            path: "email.rfc822.unknown_text_html_001.html".to_owned(),
            sha256: outer_html.clone(),
            html: true,
        },
    ];
    assert_eq!(
        tree::carrying_email(db.pool(), root, zip_id)
            .await
            .expect("reads"),
        Some(outer_body)
    );

    // the nested email is nearer than the outer one, by the route through its own zip
    add_result(
        db,
        root,
        nested_id,
        "email_analysis",
        message.clone(),
        &[
            (inner_id, Some("x/email.rfc822.unknown_text_html_000.html")),
            (zip_id, Some("a.zip")),
        ],
    )
    .await;
    add_result(
        db,
        root,
        zip_id,
        "archive_analysis",
        json!({}),
        &[(doc_id, Some("a.zip.extracted/a.docx"))],
    )
    .await;
    let inner = vec![tree::EmailBodyFile {
        path: "x/email.rfc822.unknown_text_html_000.html".to_owned(),
        sha256: inner_body.clone(),
        html: true,
    }];
    assert_eq!(
        tree::carrying_email(db.pool(), root, doc_id)
            .await
            .expect("reads"),
        Some(inner.clone())
    );

    // a file that contains its own ancestor ends the walk
    add_result(
        db,
        root,
        doc_id,
        "archive_analysis",
        json!({}),
        &[(zip_id, Some("a.docx.extracted/a.zip"))],
    )
    .await;
    assert_eq!(
        tree::carrying_email(db.pool(), root, doc_id)
            .await
            .expect("reads"),
        Some(inner)
    );

    // no route to an email, and an email that couldn't be parsed isn't one
    assert_eq!(
        tree::carrying_email(db.pool(), root, outer_id)
            .await
            .expect("reads"),
        None
    );
    let (other_root, other) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, outer.as_str()),
            (ObservableKind::File, doc.as_str()),
        ],
    )
    .await;
    add_result(
        db,
        other_root,
        other[0],
        "email_analysis",
        json!({"email": null}),
        &[(other[1], Some("c.docx"))],
    )
    .await;
    assert_eq!(
        tree::carrying_email(db.pool(), other_root, other[1])
            .await
            .expect("reads"),
        None
    );

    // an email with no text part is still an email, with no body parts
    let (third_root, third) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, outer.as_str()),
            (ObservableKind::File, doc.as_str()),
        ],
    )
    .await;
    add_result(
        db,
        third_root,
        third[0],
        "email_analysis",
        message,
        &[(third[1], Some("c.docx"))],
    )
    .await;
    assert_eq!(
        tree::carrying_email(db.pool(), third_root, third[1])
            .await
            .expect("reads"),
        Some(Vec::new())
    );
}

/// An email still to be parsed holds back what reads its carrying email.
#[tokio::test]
async fn an_unfinished_email_is_pending_and_a_failed_one_isnt() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = "a".repeat(64);
    let (root, ids) = root_with(db, "test", &[(ObservableKind::File, hash.as_str())]).await;
    assert!(!tree::emails_pending(db.pool(), root).await.expect("reads"));
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(&mut tx, root, ids[0], "email_analyzer")
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    assert!(tree::emails_pending(db.pool(), root).await.expect("reads"));
    let worker = worker(&test_db, "w", &["email_analyzer"], Duration::from_secs(30)).await;
    let task = worker.claim().await.expect("claims").expect("the task");
    assert!(tree::emails_pending(db.pool(), root).await.expect("reads"));
    worker.fail(task.id, "broke").await.expect("fails");
    assert!(!tree::emails_pending(db.pool(), root).await.expect("reads"));
}

/// What a module that runs last waits for: anything in the root but modules that run last.
#[tokio::test]
async fn a_module_that_runs_last_waits_for_every_other_module() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = "a".repeat(64);
    let (root, ids) = root_with(db, "test", &[(ObservableKind::File, hash.as_str())]).await;
    let last = ["xlmdeobfuscator".to_owned()];
    assert!(
        !tree::others_pending(db.pool(), root, &last)
            .await
            .expect("reads")
    );
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(&mut tx, root, ids[0], "xlmdeobfuscator")
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    assert!(
        !tree::others_pending(db.pool(), root, &last)
            .await
            .expect("reads")
    );

    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(&mut tx, root, ids[0], "archive")
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    assert!(
        tree::others_pending(db.pool(), root, &last)
            .await
            .expect("reads")
    );
    let worker = worker(&test_db, "w", &["archive"], Duration::from_secs(30)).await;
    let task = worker.claim().await.expect("claims").expect("the task");
    assert!(
        tree::others_pending(db.pool(), root, &last)
            .await
            .expect("reads")
    );
    worker.fail(task.id, "broke").await.expect("fails");
    assert!(
        !tree::others_pending(db.pool(), root, &last)
            .await
            .expect("reads")
    );
}

/// What a module that runs last waits for among those that run last: a task on a file below its
/// observable, as the email's lure_url_analyzer waits for xlmdeobfuscator on its attachment's decrypted
/// workbook, whose output has the URLs it reads. Not one on the same observable, above it, beside it, in
/// a cycle with it, or on another type, as email_thread_analyzer on the email's message_id, which waits
/// itself for the email logger on the email, so no two wait on each other.
#[tokio::test]
async fn a_module_that_runs_last_waits_for_one_below_it() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (email, xls, decrypted, sibling) = (hash("a"), hash("b"), hash("c"), hash("d"));
    let mut observables: Vec<(ObservableKind, &str)> = [&email, &xls, &decrypted, &sibling]
        .iter()
        .map(|value| (ObservableKind::File, value.as_str()))
        .collect();
    observables.push((ObservableKind::MessageId, "<a@example.com>"));
    let (root, ids) = root_with(db, "test", &observables).await;
    let (email_id, xls_id, decrypted_id, sibling_id, message_id) =
        (ids[0], ids[1], ids[2], ids[3], ids[4]);
    add_result(
        db,
        root,
        email_id,
        "email_analysis",
        json!({}),
        &[(xls_id, Some("invoice.xls")), (message_id, None)],
    )
    .await;
    add_result(
        db,
        root,
        xls_id,
        "msoffice_encryption_analysis",
        json!({}),
        &[(decrypted_id, Some("invoice.xls.decrypted"))],
    )
    .await;
    let last = [
        "lure_url_analyzer".to_owned(),
        "xlmdeobfuscator".to_owned(),
        "email_logger".to_owned(),
        "email_thread_analyzer".to_owned(),
    ];
    let pending = |id| {
        let last = &last;
        async move {
            tree::held_back(db.pool(), root, id, last)
                .await
                .expect("reads")
                .is_some()
        }
    };
    let queue = |id, module: &'static str| async move {
        let mut tx = db.begin().await.expect("begins");
        ace_core::queue::enqueue(&mut tx, root, id, module)
            .await
            .expect("queues");
        tx.commit().await.expect("commits");
    };
    queue(email_id, "lure_url_analyzer").await;
    queue(email_id, "email_logger").await;
    queue(sibling_id, "xlmdeobfuscator").await;
    queue(message_id, "email_thread_analyzer").await;
    // the same observable's, one beside it and one below that isn't on a file don't hold it back
    assert!(!pending(email_id).await);
    assert!(!pending(message_id).await, "nor does one above");
    queue(decrypted_id, "xlmdeobfuscator").await;
    assert!(pending(email_id).await, "one below holds it back");
    let held = |id| {
        let last = &last;
        async move {
            tree::held_back(db.pool(), root, id, last)
                .await
                .expect("reads")
        }
    };
    assert_eq!(held(email_id).await, Some(tree::HeldBack::ByLastBelow));
    // anything that doesn't run last holds back every one, which is read first
    queue(sibling_id, "archive").await;
    assert_eq!(held(email_id).await, Some(tree::HeldBack::ByOthers));
    assert_eq!(held(decrypted_id).await, Some(tree::HeldBack::ByOthers));
    let archive = worker(&test_db, "a", &["archive"], Duration::from_secs(30)).await;
    let task = archive.claim().await.expect("claims").expect("the task");
    archive.fail(task.id, "broke").await.expect("fails");
    assert!(pending(xls_id).await, "however far below");
    assert!(!pending(decrypted_id).await, "one above doesn't");
    // until it's finished
    let worker = worker(&test_db, "w", &["xlmdeobfuscator"], Duration::from_secs(30)).await;
    while let Some(task) = worker.claim().await.expect("claims") {
        assert!(pending(email_id).await, "running, it still holds it back");
        worker.fail(task.id, "broke").await.expect("fails");
    }
    assert!(!pending(email_id).await);
    // in a cycle, each is above the other, so neither waits
    add_result(
        db,
        root,
        decrypted_id,
        "archive_analysis",
        json!({}),
        &[(email_id, Some("again.eml"))],
    )
    .await;
    queue(xls_id, "xlmdeobfuscator").await;
    assert!(!pending(email_id).await && !pending(xls_id).await);
}

/// A task that runs last and waits for every other module is due as soon as the last of them ends,
/// however long its wait had grown, with its wait's record as it was, the step its next wait doubles
/// from, and no delay of its module's. Nothing else moves: not while another module's task is left, a module's own delay
/// among them, which keeps its time, and not a task that waits for one below it.
#[tokio::test]
async fn a_task_held_back_for_the_others_is_due_when_the_last_of_them_ends() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (file, below) = (hash("a"), hash("b"));
    let (root, ids) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, file.as_str()),
            (ObservableKind::File, below.as_str()),
            (ObservableKind::Fqdn, "example.com"),
        ],
    )
    .await;
    let queue = |id, module: &'static str| async move {
        let mut tx = db.begin().await.expect("begins");
        ace_core::queue::enqueue(&mut tx, root, id, module)
            .await
            .expect("queues");
        tx.commit().await.expect("commits");
    };
    for (id, module) in [
        (ids[0], "xlmdeobfuscator"),
        (ids[1], "xlmdeobfuscator"),
        (ids[0], "lure_url_analyzer"),
        (ids[0], "archive"),
        (ids[1], "archive"),
        (ids[2], "proxy_domain_splunk"),
    ] {
        queue(id, module).await;
    }
    let lease = Duration::from_secs(30);
    let minute = Duration::from_secs(60);
    // as the lease holds them back: two for the others, for a minute, as after many asks, and one
    // for a task below it
    let last = worker(
        &test_db,
        "last",
        &["xlmdeobfuscator", "lure_url_analyzer"],
        lease,
    )
    .await;
    let mut held = Vec::new();
    while let Some(task) = last.claim().await.expect("claims") {
        let by = if task.module == "lure_url_analyzer" {
            tree::HeldBack::ByLastBelow
        } else {
            tree::HeldBack::ByOthers
        };
        let wait = ace_core::queue::HeldBackWait { by, step: 6 };
        last.hold(task.id, minute, Some(wait)).await.expect("holds");
        held.push(task.id);
    }
    assert_eq!(held.len(), 3);
    let record = || async {
        sqlx::query_as::<_, (i64, Option<String>, Option<i32>, i32, bool)>(
            "SELECT id, held_back_by, held_back_step, delays, first_delayed_at IS NULL
             FROM queue.tasks
             WHERE root_id = $1 AND module = 'xlmdeobfuscator' ORDER BY id",
        )
        .bind(root)
        .fetch_all(db.pool())
        .await
        .expect("reads")
    };
    let before = record().await;
    // a module's own delay, which is another module's task still to run
    let splunk = worker(&test_db, "splunk", &["proxy_domain_splunk"], lease).await;
    let task = splunk.claim().await.expect("claims").expect("the task");
    let own = Duration::from_millis(1500);
    let due = splunk
        .delay(task.id, own, &json!({"sid": "1"}))
        .await
        .expect("delays");

    let archive = worker(&test_db, "archive", &["archive"], lease).await;
    let task = archive.claim().await.expect("claims").expect("the task");
    archive.complete(task.id).await.expect("completes");
    assert!(
        last.claim().await.expect("claims").is_none(),
        "an archive task is left"
    );
    let task = archive.claim().await.expect("claims").expect("the task");
    archive.fail(task.id, "broke").await.expect("fails");
    assert!(
        last.claim().await.expect("claims").is_none(),
        "the Splunk task is left, delayed"
    );
    assert!(
        splunk.claim().await.expect("claims").is_none(),
        "and its own delay is as long as it was"
    );
    assert_eq!(splunk.next_due().await.expect("reads"), Some(due));

    tokio::time::sleep(own).await;
    let task = splunk.claim().await.expect("claims").expect("the task");
    splunk.complete(task.id).await.expect("completes");
    // the last of the others ended: both are due, 58 seconds early
    let mut woken = Vec::new();
    while let Some(task) = last.claim().await.expect("claims") {
        assert_eq!(task.module, "xlmdeobfuscator");
        assert_eq!(
            task.held_back,
            Some(ace_core::queue::HeldBackWait {
                by: tree::HeldBack::ByOthers,
                step: 6
            }),
            "the wait the lease doubles its next from"
        );
        assert!(task.delayed.is_none(), "its module never delayed it");
        woken.push(task.id);
    }
    assert_eq!(
        woken.len(),
        2,
        "the one waiting for a task below keeps its wait"
    );
    assert_eq!(record().await, before, "nothing of the waits' record moved");
    let lure: String = sqlx::query_scalar(
        "SELECT state::text FROM queue.tasks WHERE root_id = $1 AND module = 'lure_url_analyzer'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(lure, "delayed");
}

/// A task of a module that runs last that hasn't asked yet isn't marked as held back, so it counts as
/// another module's and the others' wait stands; a task's end, or its hold when the lease holds that
/// one back for a task below it (`Worker::hold`), wakes them then. A cancelled root's tasks
/// stay cancelled.
#[tokio::test]
async fn a_task_that_has_not_asked_yet_puts_the_wake_off_until_it_has() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (file, below) = (hash("a"), hash("b"));
    let (root, ids) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, file.as_str()),
            (ObservableKind::File, below.as_str()),
        ],
    )
    .await;
    let queue = |id, module: &'static str| async move {
        let mut tx = db.begin().await.expect("begins");
        ace_core::queue::enqueue(&mut tx, root, id, module)
            .await
            .expect("queues");
        tx.commit().await.expect("commits");
    };
    let lease = Duration::from_secs(30);
    let minute = Duration::from_secs(60);
    let held_back = |by| Some(ace_core::queue::HeldBackWait { by, step: 0 });
    let last = worker(&test_db, "last", &["xlmdeobfuscator"], lease).await;
    // held back for the last other task
    queue(ids[1], "xlmdeobfuscator").await;
    queue(ids[0], "archive").await;
    let first = last.claim().await.expect("claims").expect("the task");
    last.hold(first.id, minute, held_back(tree::HeldBack::ByOthers))
        .await
        .expect("holds");
    // and one that hasn't asked
    queue(ids[0], "xlmdeobfuscator").await;
    let archive = worker(&test_db, "archive", &["archive"], lease).await;
    let task = archive.claim().await.expect("claims").expect("the task");
    archive.complete(task.id).await.expect("completes");
    let fresh = last
        .claim()
        .await
        .expect("claims")
        .expect("the one not asked");
    assert_eq!(fresh.observable.id, ids[0]);
    assert!(
        last.claim().await.expect("claims").is_none(),
        "the first one's wait stands"
    );
    // the lease holds the fresh one back for the one below it, and says so
    last.hold(fresh.id, minute, held_back(tree::HeldBack::ByLastBelow))
        .await
        .expect("holds");
    let woken = last.claim().await.expect("claims").expect("the first");
    assert_eq!(woken.id, first.id);
    assert!(
        last.claim().await.expect("claims").is_none(),
        "the one held back for a task below keeps its wait"
    );

    // a cancelled root: its held tasks are cancelled, and an end wakes none of them
    let (root, ids) = root_with(db, "test", &[(ObservableKind::File, file.as_str())]).await;
    for module in ["xlmdeobfuscator", "archive"] {
        let mut tx = db.begin().await.expect("begins");
        ace_core::queue::enqueue(&mut tx, root, ids[0], module)
            .await
            .expect("queues");
        tx.commit().await.expect("commits");
    }
    let task = last.claim().await.expect("claims").expect("the task");
    last.hold(task.id, minute, held_back(tree::HeldBack::ByOthers))
        .await
        .expect("holds");
    let running = archive.claim().await.expect("claims").expect("the task");
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::cancel_root(&mut tx, root)
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");
    archive.cancelled(running.id).await.expect("ends");
    assert!(last.claim().await.expect("claims").is_none());
    assert_eq!(
        tasks_of(db, root).await,
        [
            ("archive".to_owned(), file.clone(), "cancelled".to_owned()),
            ("xlmdeobfuscator".to_owned(), file, "cancelled".to_owned()),
        ]
    );
}

/// The core's wait for a task that runs last. One held back by the others waits the whole 32 s at
/// once, since their last end wakes it (`queue::check_completion`); asking again sooner only asks
/// what the wake answers. One held back by a task below it, which nothing wakes, starts at 250 ms
/// and doubles to 32 s while that holds it back, and starts low again when the reason changes.
#[test]
fn a_task_held_back_by_the_others_waits_for_their_wake() {
    use ace_core::queue::HeldBackWait;
    use tree::HeldBack::{ByLastBelow, ByOthers};
    let ms = Duration::from_millis;
    let mut before = None;
    for _ in 0..3 {
        let (wait, after) = HeldBackWait::next(before, ByOthers);
        assert_eq!(
            after,
            ms(32_000),
            "held back by the others, {before:?} before"
        );
        before = Some(wait);
    }
    let mut waits = Vec::new();
    for _ in 0..9 {
        let (wait, after) = HeldBackWait::next(before, ByLastBelow);
        waits.push(after);
        before = Some(wait);
    }
    assert_eq!(
        waits,
        [250, 500, 1000, 2000, 4000, 8000, 16_000, 32_000, 32_000].map(ms),
        "below it: from 250 ms, as the others' wait ended"
    );
    assert_eq!(
        HeldBackWait::next(before, ByOthers).1,
        ms(32_000),
        "the others again, after a long wait below"
    );
}

/// The others' last task can end between the lease's read that they're pending and its hold, while
/// the task held back is still running and unmarked, so that end wakes nothing. The hold then wakes
/// it itself, under the root's lock both take, so it doesn't sit out its 32 s.
#[tokio::test]
async fn a_hold_after_the_others_last_end_is_due_at_once() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let file = "a".repeat(64);
    let (root, ids) = root_with(db, "test", &[(ObservableKind::File, file.as_str())]).await;
    for module in ["xlmdeobfuscator", "archive"] {
        let mut tx = db.begin().await.expect("begins");
        ace_core::queue::enqueue(&mut tx, root, ids[0], module)
            .await
            .expect("queues");
        tx.commit().await.expect("commits");
    }
    let lease = Duration::from_secs(30);
    let last = worker(&test_db, "last", &["xlmdeobfuscator"], lease).await;
    let archive = worker(&test_db, "archive", &["archive"], lease).await;
    let task = last.claim().await.expect("claims").expect("the task");
    // the lease read the archive task as pending; it ends before the hold
    let other = archive.claim().await.expect("claims").expect("the task");
    archive.complete(other.id).await.expect("completes");
    let (wait, after) = ace_core::queue::HeldBackWait::next(None, tree::HeldBack::ByOthers);
    last.hold(task.id, after, Some(wait)).await.expect("holds");
    let again = last.claim().await.expect("claims");
    assert_eq!(again.map(|t| t.id), Some(task.id), "due at once");
}

/// A task that runs last whose module delays it after the core held it back waits for its module's
/// delay, not the core's: the end of the last other task doesn't wake it, and it no longer counts as
/// held back, so it puts off the wake of those that are until it ends.
#[tokio::test]
async fn a_module_delay_after_a_hold_is_not_woken_as_held_back() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (one, two) = (hash("a"), hash("b"));
    let (root, ids) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, one.as_str()),
            (ObservableKind::File, two.as_str()),
        ],
    )
    .await;
    for (id, module) in [
        (ids[0], "xlmdeobfuscator"),
        (ids[1], "xlmdeobfuscator"),
        (ids[0], "archive"),
    ] {
        let mut tx = db.begin().await.expect("begins");
        ace_core::queue::enqueue(&mut tx, root, id, module)
            .await
            .expect("queues");
        tx.commit().await.expect("commits");
    }
    let lease = Duration::from_secs(30);
    let minute = Duration::from_secs(60);
    let others = Some(ace_core::queue::HeldBackWait {
        by: tree::HeldBack::ByOthers,
        step: 0,
    });
    let last = worker(&test_db, "last", &["xlmdeobfuscator"], lease).await;
    // one held back and then run, which delays itself; the other held back
    let own = last.claim().await.expect("claims").expect("a task");
    last.hold(own.id, Duration::ZERO, others)
        .await
        .expect("holds");
    let held = last.claim().await.expect("claims").expect("the other");
    last.hold(held.id, minute, others).await.expect("holds");
    let own = last
        .claim()
        .await
        .expect("claims")
        .expect("the first again");
    assert_eq!(own.held_back, others);
    let due = last
        .delay(own.id, minute, &json!({"asked": 1}))
        .await
        .expect("delays");
    let archive = worker(&test_db, "archive", &["archive"], lease).await;
    let task = archive.claim().await.expect("claims").expect("the task");
    archive.complete(task.id).await.expect("completes");
    assert!(
        last.claim().await.expect("claims").is_none(),
        "the module's delay stands, and puts the held one's wake off"
    );
    let run_after: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT run_after FROM queue.tasks WHERE id = $1")
            .bind(own.id.0)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(run_after, due, "its own delay's time");
}

/// Migration 0089 moves a hold the lease wrote as a delay before it to the hold's own columns, and
/// takes the delay record that was the hold's off the task. Its UPDATE runs here on rows as they were
/// before it: a held task, a module's own delay, and a task that ended after a hold, which it leaves.
#[tokio::test]
async fn migration_0089_moves_a_hold_written_as_a_delay() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let migration = include_str!("../migrations/0089_held_back.sql");
    let start = migration
        .find("UPDATE queue.tasks")
        .expect("the migration's move");
    let hash = |c: &str| c.repeat(64);
    let (one, two, three) = (hash("a"), hash("b"), hash("c"));
    let (root, ids) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, one.as_str()),
            (ObservableKind::File, two.as_str()),
            (ObservableKind::File, three.as_str()),
        ],
    )
    .await;
    let mut tasks = Vec::new();
    for (id, state, delay_state) in [
        (
            ids[0],
            "delayed",
            json!({"held_back_by": "last_below", "step": 3}),
        ),
        (ids[1], "delayed", json!({"asked": 1})),
        (ids[2], "done", json!({"held_back_by": "others", "step": 0})),
    ] {
        let mut tx = db.begin().await.expect("begins");
        let task = ace_core::queue::enqueue(&mut tx, root, id, "xlmdeobfuscator")
            .await
            .expect("queues")
            .expect("a new task");
        tx.commit().await.expect("commits");
        sqlx::query(
            "UPDATE queue.tasks SET state = $2::queue.task_state, delay_state = $3,
                    first_delayed_at = now(), delays = 2, held_back_by = NULL,
                    held_back_step = NULL
             WHERE id = $1",
        )
        .bind(task.0)
        .bind(state)
        .bind(delay_state)
        .execute(db.pool())
        .await
        .expect("writes the old shape");
        tasks.push(task.0);
    }
    sqlx::raw_sql(&migration[start..])
        .execute(db.pool())
        .await
        .expect("moves them");
    // its mark, its step, its delay state, whether it has a first delay, and its delays
    type Moved = (
        Option<String>,
        Option<i32>,
        Option<serde_json::Value>,
        bool,
        i32,
    );
    let rows: Vec<Moved> = sqlx::query_as(
        "SELECT held_back_by, held_back_step, delay_state, first_delayed_at IS NOT NULL, delays
         FROM queue.tasks WHERE id = ANY($1) ORDER BY id",
    )
    .bind(&tasks)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(
        rows,
        [
            (Some("last_below".to_owned()), Some(3), None, false, 0),
            (None, None, Some(json!({"asked": 1})), true, 2),
            (
                None,
                None,
                Some(json!({"held_back_by": "others", "step": 0})),
                true,
                2
            ),
        ]
    );
}

/// The walk ace3's `recurse_tree` does: the file, what was added below it by any module, and no
/// further than that. A cycle ends, and a result with no rules has none.
#[tokio::test]
async fn a_file_finds_the_yara_rules_of_what_is_below_it() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (outer, zip, doc, sibling) = (hash("a"), hash("b"), hash("c"), hash("d"));
    let files: Vec<(ObservableKind, &str)> = [&outer, &zip, &doc, &sibling]
        .iter()
        .map(|value| (ObservableKind::File, value.as_str()))
        .collect();
    let (root, ids) = root_with(db, "test", &files).await;
    let (outer_id, zip_id, doc_id, sibling_id) = (ids[0], ids[1], ids[2], ids[3]);
    let yara = |rules: &[&str]| json!({"scan_results": rules.iter().map(|rule| json!({"rule": rule})).collect::<Vec<_>>()});

    add_result(
        db,
        root,
        outer_id,
        "email_analysis",
        json!({}),
        &[(zip_id, Some("a.zip")), (sibling_id, Some("b.txt"))],
    )
    .await;
    add_result(
        db,
        root,
        zip_id,
        "archive_analysis",
        json!({}),
        &[(doc_id, Some("a.zip.extracted/a.xlsm"))],
    )
    .await;
    add_result(
        db,
        root,
        outer_id,
        "yara_scan_results",
        yara(&["on_outer"]),
        &[],
    )
    .await;
    add_result(db, root, zip_id, "yara_scan_results", yara(&[]), &[]).await;
    add_result(
        db,
        root,
        doc_id,
        "yara_scan_results",
        yara(&["z_on_doc", "a_on_doc", "a_on_doc"]),
        &[],
    )
    .await;
    add_result(
        db,
        root,
        sibling_id,
        "yara_scan_results",
        yara(&["on_sibling"]),
        &[],
    )
    .await;

    let rules = |id| async move {
        tree::yara_rules_below(db.pool(), root, id)
            .await
            .expect("reads")
    };
    assert_eq!(rules(doc_id).await, ["a_on_doc", "z_on_doc"]);
    assert_eq!(rules(zip_id).await, ["a_on_doc", "z_on_doc"]);
    assert_eq!(rules(sibling_id).await, ["on_sibling"]);
    assert_eq!(
        rules(outer_id).await,
        ["a_on_doc", "on_outer", "on_sibling", "z_on_doc"]
    );

    // a file that contains its own ancestor ends the walk
    add_result(
        db,
        root,
        doc_id,
        "archive_analysis",
        json!({}),
        &[(zip_id, Some("a.xlsm.extracted/a.zip"))],
    )
    .await;
    assert_eq!(rules(doc_id).await, ["a_on_doc", "z_on_doc"]);
}

/// What a module that runs last reads of the tree on its lease: the observables of the types it
/// reads below its own, in the order they were added and each once, and its own observable's
/// results from the modules it depends on.
#[tokio::test]
async fn a_task_reads_what_is_below_its_observable_and_what_it_depends_on() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (email, zip, doc) = (hash("a"), hash("b"), hash("c"));
    let (root, ids) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, email.as_str()),
            (ObservableKind::File, zip.as_str()),
            (ObservableKind::File, doc.as_str()),
            (ObservableKind::Url, "https://a.example/"),
            (ObservableKind::Url, "https://b.example/"),
            (ObservableKind::Fqdn, "a.example"),
            (ObservableKind::Url, "https://elsewhere.example/"),
        ],
    )
    .await;
    let (email_id, zip_id, doc_id) = (ids[0], ids[1], ids[2]);
    let (url_a, url_b, fqdn) = (ids[3], ids[4], ids[5]);
    add_result(
        db,
        root,
        email_id,
        "email_analyzer",
        json!({"first": true}),
        &[(zip_id, Some("a.zip")), (url_b, None)],
    )
    .await;
    add_result(
        db,
        root,
        zip_id,
        "archive",
        json!({}),
        &[(doc_id, Some("a.zip.extracted/a.doc"))],
    )
    .await;
    add_result(
        db,
        root,
        doc_id,
        "xlm",
        json!({}),
        &[(url_a, None), (fqdn, None), (url_b, None)],
    )
    .await;
    add_result(db, root, email_id, "yara", json!({}), &[]).await;

    let below = tree::observables_below(db.pool(), root, email_id, &[ObservableKind::Url])
        .await
        .expect("reads");
    let values: Vec<&str> = below.iter().map(|o| o.value.as_str()).collect();
    assert_eq!(values, ["https://a.example/", "https://b.example/"]);
    assert!(
        tree::observables_below(db.pool(), root, doc_id, &[ObservableKind::Fqdn])
            .await
            .expect("reads")
            .iter()
            .all(|o| o.value == "a.example")
    );
    let results = tree::results_of(db.pool(), root, email_id, &["email_analyzer", "archive"])
        .await
        .expect("reads");
    assert_eq!(
        results,
        [tree::DependencyResult {
            module: "email_analyzer".to_owned(),
            details: json!({"first": true}),
            error: None,
        }]
    );
}

/// What a module reads of where its observable came from (PLAN.md 7.5 batch 5): the modules
/// whose results added it, each once in the order of its first, and the tags of the observables
/// it's related to, none for a target the root doesn't hold.
#[tokio::test]
async fn a_task_reads_who_added_its_observable_and_its_relatives_tags() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (doc, stream, other, copy) = (hash("a"), hash("b"), hash("c"), hash("d"));
    let (root, ids) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, doc.as_str()),
            (ObservableKind::File, stream.as_str()),
            (ObservableKind::File, copy.as_str()),
        ],
    )
    .await;
    let (doc_id, stream_id, copy_id) = (ids[0], ids[1], ids[2]);
    add_result(
        db,
        root,
        doc_id,
        "olevba_v1_2",
        json!({}),
        &[(stream_id, Some("a.doc.olevba/x"))],
    )
    .await;
    add_result(
        db,
        root,
        doc_id,
        "officeparser3",
        json!({}),
        &[(stream_id, Some("a.doc.officeparser/x"))],
    )
    .await;
    add_result(
        db,
        root,
        copy_id,
        "olevba_v1_2",
        json!({}),
        &[(stream_id, None)],
    )
    .await;
    assert_eq!(
        tree::added_by(db.pool(), root, stream_id)
            .await
            .expect("reads"),
        ["olevba_v1_2", "officeparser3"]
    );
    assert!(
        tree::added_by(db.pool(), root, doc_id)
            .await
            .expect("reads")
            .is_empty()
    );

    let mut tx = db.begin().await.expect("begins");
    tree::add_to_observable(
        &mut tx,
        root,
        doc_id,
        &serde_json::from_value(json!({"tags": ["microsoft_office", "ole"]})).expect("additions"),
    )
    .await
    .expect("tags");
    let mut related = ace_results::NewObservable::new(ObservableKind::File, stream.as_str());
    for target in [doc.as_str(), other.as_str()] {
        related.relationships.push(ace_results::Relationship::new(
            ace_results::RelationshipKind::ExtractedFrom,
            ace_results::ObservableRef::new(ObservableKind::File, target),
        ));
    }
    tree::upsert_observable(&mut tx, root, &related)
        .await
        .expect("relates");
    tx.commit().await.expect("commits");
    let tags = tree::related_tags(db.pool(), root, stream_id)
        .await
        .expect("reads");
    let tags: Vec<(&str, Vec<&str>)> = tags
        .iter()
        .map(|r| {
            (
                r.observable.value.as_str(),
                r.tags.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    assert_eq!(
        tags,
        [
            (doc.as_str(), vec!["microsoft_office", "ole"]),
            (other.as_str(), vec![])
        ]
    );
}

/// A file's relationships and redirection reach the tree, and what a module adds to the
/// redirection lands on the file it redirects to, with its `yara_meta` tags on that file's path.
#[tokio::test]
async fn a_result_links_observables_and_adds_to_what_one_redirects_to() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let document = "aa".repeat(32);
    let part = "bb".repeat(32);
    let (root, ids) = root_with(db, "test", &[(ObservableKind::File, &document)]).await;
    let orchestrator = Orchestrator::new(Catalog::new(manifests()), modes());
    let mut tx = db.begin().await.expect("begins");
    tree::add_file(&mut tx, root, ids[0], "a.docx", &[])
        .await
        .expect("adds");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");

    // the archive module decomposes the document into a part that redirects to it
    let archiver = worker(&test_db, "archiver", &["archive"], Duration::from_secs(60)).await;
    let task = archiver.claim().await.expect("claims").expect("a task");
    let reference = json!({"type": "file", "value": document});
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result(
            &mut tx,
            &archiver,
            &task,
            &result(json!({
                "analysis_type": "archive_analysis",
                "schema_version": 1,
                "details": {},
                "files": [{
                    "path": "a.docx.extracted/word/document.xml",
                    "sha256": part,
                    "size": 1,
                    "relationships": [{"type": "extracted_from", "target": reference}],
                    "redirection": reference,
                }],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");

    let part_ref = ObservableRef::new(ObservableKind::File, part.as_str());
    let part_id = tree::find_observable(db.pool(), root, &part_ref)
        .await
        .expect("finds")
        .expect("is there");
    let document_ref = ObservableRef::new(ObservableKind::File, document.as_str());
    assert_eq!(
        tree::redirection(db.pool(), root, part_id)
            .await
            .expect("reads"),
        Some(document_ref)
    );

    // a module on the part sandboxes the document, as YARA does; the part stays as it was
    let task = archiver.claim().await.expect("claims").expect("a task");
    assert_eq!(task.observable.id, part_id);
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result(
            &mut tx,
            &archiver,
            &task,
            &result(json!({
                "analysis_type": "archive_analysis",
                "schema_version": 1,
                "details": {},
                "analyzed": {"yara_meta": ["seen=part"]},
                "redirected": {"directives": ["sandbox"], "yara_meta": ["seen=document"]},
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");

    let form = ace_core::normal::normal_form(db.pool(), root)
        .await
        .expect("reads")
        .expect("exists");
    let on_document = &form["observables"][format!("file:{document}")];
    let on_part = &form["observables"][format!("file:{part}")];
    assert_eq!(on_document["directives"], json!({"sandbox": true}));
    assert_eq!(
        on_document["paths"]["a.docx"],
        json!({"seen=document": true})
    );
    assert_eq!(on_part["directives"], json!({}));
    assert_eq!(
        on_part["paths"]["a.docx.extracted/word/document.xml"],
        json!({"seen=part": true})
    );
    assert_eq!(
        on_part["relationships"],
        json!({format!("extracted_from file:{document}"): true})
    );
    assert_eq!(on_part["redirection"], json!(format!("file:{document}")));
}

/// PLAN.md 7.5 batch 8: a module that walks the tree reads it as it is, with the root's alert type,
/// what each result added under which path, the tasks still to finish and the files it reads; a
/// result adds to other observables in the root and drops what's for one the root doesn't hold; and
/// only a module that declares it changes its root's description and details.
#[tokio::test]
async fn a_task_walks_its_roots_tree_and_a_result_changes_others_and_its_root() {
    use ace_sdk::tree::TreeFiles;

    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (email, body, big) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
    let (root, ids) = root_with(
        db,
        "test",
        &[
            (ObservableKind::File, email.as_str()),
            (ObservableKind::File, body.as_str()),
            (ObservableKind::File, big.as_str()),
            (ObservableKind::Url, "https://lure.example/x"),
            (ObservableKind::EmailConversation, "a@x|b@y"),
        ],
    )
    .await;
    let (email_id, body_id, big_id, url_id, conversation_id) =
        (ids[0], ids[1], ids[2], ids[3], ids[4]);
    add_result(
        db,
        root,
        email_id,
        "email_analysis",
        json!({}),
        &[
            (body_id, Some("email.rfc822.unknown_text_html_000")),
            (big_id, Some("email.rfc822.unknown_text_html_001")),
            (conversation_id, None),
        ],
    )
    .await;
    add_result(
        db,
        root,
        body_id,
        "url_extraction_analysis",
        json!({}),
        &[(url_id, None)],
    )
    .await;
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(
        &mut tx,
        root,
        conversation_id,
        "email_conversation_frequency_analyzer",
    )
    .await
    .expect("queues");
    tx.commit().await.expect("commits");
    sqlx::query(
        "UPDATE analysis.roots SET origin = '{\"alert_type\": \"mailbox\", \"details\": {\"query\": \"q\"}}'
         WHERE id = $1",
    )
    .bind(root)
    .execute(db.pool())
    .await
    .expect("sets the origin");
    for (sha256, size) in [(&body, 10i64), (&big, 11)] {
        sqlx::query(
            "INSERT INTO store.objects (pool, sha256, size) VALUES ('alert_files', $1, $2)",
        )
        .bind(sha256)
        .bind(size)
        .execute(db.pool())
        .await
        .expect("records the object");
    }

    let files = TreeFiles {
        names_containing: &[".unknown_text_html"],
        max_size: 10,
        tagged: None,
    };
    let (view, wanted) = tree::tree_view(db.pool(), root, email_id, Some(files), &[])
        .await
        .expect("reads");
    assert_eq!(view.alert_type.as_deref(), Some("mailbox"));
    assert!(!view.truncated);
    assert_eq!(view.this().value, email);
    assert_eq!(view.observables.len(), 5);
    assert_eq!(
        wanted,
        [(1, body.clone())],
        "the body no larger than the limit"
    );
    assert_eq!(view.observables[1].size, Some(10));
    assert_eq!(
        view.observables[4].pending,
        ["email_conversation_frequency_analyzer"]
    );
    let email_result = view
        .result_of(0, "email_analysis")
        .expect("the email's result");
    assert_eq!(
        email_result
            .added
            .iter()
            .map(|a| (a.observable, a.path.as_deref()))
            .collect::<Vec<_>>(),
        [
            (1, Some("email.rfc822.unknown_text_html_000")),
            (2, Some("email.rfc822.unknown_text_html_001")),
            (4, None)
        ]
    );
    assert_eq!(
        view.search_up(3, |i| i == 0),
        Some(0),
        "the url came from the email"
    );

    // a result of the module that changes its root: crawl on the url, nothing for a url the root
    // doesn't hold, and the root's description and details
    // manifests()' two stubs share a type, which check_result's registry refuses
    let orchestrator = Orchestrator::new(
        Catalog::new([common::stubs::SETS_ROOT, ace_mod_archive::MANIFEST]),
        modes(),
    );
    let changes = json!({
        "analysis_type": "test_sets_root", "schema_version": 1, "details": {},
        "others": [
            {"observable": {"type": "url", "value": "https://lure.example/x"}, "additions": {"directives": ["crawl"]}},
            {"observable": {"type": "url", "value": "https://elsewhere.example/"}, "additions": {"tags": ["x"]}},
        ],
        "root": {"description": "ACE Mailbox Scanner Detection - hello", "details": {"email": {"subject": "hello"}}},
    });
    if let Err(e) = orchestrator.check_result("test_sets_root", &changes) {
        panic!("{} {:?}", e.error, e.fields);
    }
    // what a module adds to other observables is only what it declares
    let other = |additions: serde_json::Value| {
        json!({
            "analysis_type": "test_sets_root", "schema_version": 1, "details": {},
            "others": [{"observable": {"type": "url", "value": "https://lure.example/x"}, "additions": additions}],
        })
    };
    for (additions, why) in [
        (json!({"tags": ["y"]}), "the tag \"y\""),
        (
            json!({"directives": ["sandbox"]}),
            "the directive \"sandbox\"",
        ),
        (json!({"detections": [{"description": "d"}]}), "a detection"),
        (json!({"yara_meta": ["type=x"]}), "a yara_meta tag"),
        (
            json!({"relationships": [{"type": "related_to",
                                      "target": {"type": "url", "value": "https://lure.example/x"}}]}),
            "a relationship",
        ),
    ] {
        let refused = orchestrator
            .check_result("test_sets_root", &other(additions))
            .expect_err("refused");
        assert!(
            refused.error.contains(why) && refused.error.contains("ADDS_TO_OTHERS"),
            "{}",
            refused.error
        );
    }
    let refused = orchestrator
        .check_result(
            "archive",
            &json!({"analysis_type": "archive_analysis", "schema_version": 1, "details": {},
                    "others": [{"observable": {"type": "url", "value": "https://lure.example/x"},
                                "additions": {"directives": ["crawl"]}}]}),
        )
        .expect_err("refused");
    assert!(
        refused
            .error
            .contains("doesn't declare what it adds to other observables"),
        "{}",
        refused.error
    );
    let refused = orchestrator
        .check_result(
            "archive",
            &json!({"analysis_type": "archive_analysis", "schema_version": 1, "details": {},
                    "root": {"description": "no"}}),
        )
        .expect_err("refused");
    assert!(refused.error.contains("SETS_ROOT"), "{}", refused.error);

    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(&mut tx, root, email_id, "test_sets_root")
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    let changer = worker(
        &test_db,
        "changer",
        &["test_sets_root"],
        Duration::from_secs(60),
    )
    .await;
    let task = changer.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result(&mut tx, &changer, &task, &result(changes))
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    let (description, origin): (String, serde_json::Value) =
        sqlx::query_as("SELECT description, origin FROM analysis.roots WHERE id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("reads the root");
    assert_eq!(description, "ACE Mailbox Scanner Detection - hello");
    assert_eq!(
        origin,
        json!({"alert_type": "mailbox", "details": {"query": "q", "email": {"subject": "hello"}}})
    );
    let (view, _) = tree::tree_view(db.pool(), root, email_id, None, &[])
        .await
        .expect("reads");
    assert_eq!(view.observables[3].directives, ["crawl"]);
    assert_eq!(
        view.observables.len(),
        5,
        "nothing added for the url the root doesn't hold"
    );
}

/// PLAN.md decision 48: a result limits what analyzes an observable or a file it adds to modules it
/// declares, which then run on it whether the root's mode runs them or not, and nothing else does; a
/// second result adding the file without a limit doesn't lift it.
#[tokio::test]
async fn a_result_limits_what_analyzes_what_it_adds() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let email = "a".repeat(64);
    let (root, ids) = root_with(db, "test", &[(ObservableKind::File, email.as_str())]).await;
    let orchestrator = Orchestrator::new(
        // two stubs that share a type would fail check_result's registry
        Catalog::new([
            common::stubs::SETS_ROOT,
            ace_mod_archive::MANIFEST,
            common::stubs::ALERT_ADDED_TO_EVENT,
        ]),
        modes(),
    );
    let container = "b".repeat(64);
    let limited = |limit: serde_json::Value| {
        json!({
            "analysis_type": "test_sets_root", "schema_version": 1, "details": {},
            "files": [{"path": "container.7z", "sha256": container, "size": 3,
                       "limit_modules": limit}],
            "observables": [{"type": "fqdn", "value": "limited.example",
                             "limit_modules": ["alert_added_to_event"]}],
        })
    };
    let changes = limited(json!(["alert_added_to_event"]));
    if let Err(e) = orchestrator.check_result("test_sets_root", &changes) {
        panic!("{} {:?}", e.error, e.fields);
    }
    // a name the module doesn't declare, and a module that declares none, are refused
    let refused = orchestrator
        .check_result("test_sets_root", &limited(json!(["archive"])))
        .expect_err("refused");
    assert!(
        refused.error.contains("\"archive\"") && refused.error.contains("LIMITS_ANALYSIS_TO"),
        "{}",
        refused.error
    );
    let refused = orchestrator
        .check_result(
            "archive",
            &json!({"analysis_type": "archive_analysis", "schema_version": 1, "details": {},
                    "observables": [{"type": "fqdn", "value": "x.example",
                                     "limit_modules": ["archive"]}]}),
        )
        .expect_err("refused");
    assert!(
        refused.error.contains("LIMITS_ANALYSIS_TO"),
        "{}",
        refused.error
    );

    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(&mut tx, root, ids[0], "test_sets_root")
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    let limiter = worker(
        &test_db,
        "limiter",
        &["test_sets_root"],
        Duration::from_secs(60),
    )
    .await;
    let task = limiter.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result(&mut tx, &limiter, &task, &result(changes))
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    let limits: Vec<(String, Vec<String>)> = sqlx::query_as(
        "SELECT value, limit_modules FROM analysis.observables
         WHERE root_id = $1 AND limit_modules <> '{}' ORDER BY value",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .expect("reads the limits");
    assert_eq!(
        limits,
        [
            (container.clone(), strings(&["alert_added_to_event"])),
            (
                "limited.example".to_owned(),
                strings(&["alert_added_to_event"])
            ),
        ]
    );
    // the mode runs archive on a file, and not alert_added_to_event; on these two only
    // alert_added_to_event runs
    let tasks = tasks_of(db, root).await;
    let modules_on = |value: &str| {
        tasks
            .iter()
            .filter(|(_, v, _)| v == value)
            .map(|(module, _, _)| module.as_str())
            .collect::<Vec<_>>()
    };
    assert_eq!(modules_on(&container), ["alert_added_to_event"]);
    assert_eq!(modules_on("limited.example"), ["alert_added_to_event"]);

    // another result adding the same file without a limit keeps it
    let mut tx = db.begin().await.expect("begins");
    let mut again = ace_results::NewObservable::new(ObservableKind::File, container.clone());
    again.tags = strings(&["again"]);
    tree::upsert_observable(&mut tx, root, &again)
        .await
        .expect("adds it again");
    tx.commit().await.expect("commits");
    let kept: Vec<String> = sqlx::query_scalar(
        "SELECT unnest(limit_modules) FROM analysis.observables WHERE root_id = $1 AND value = $2",
    )
    .bind(root)
    .bind(&container)
    .fetch_all(db.pool())
    .await
    .expect("reads the limit");
    assert_eq!(kept, ["alert_added_to_event"]);
}

/// PLAN.md decision 53: a result adds links to its root's own, each once, when its module declares
/// it may; another module's root links, and root links that change the description from a module
/// that may only add links, are refused.
#[tokio::test]
async fn a_result_adds_links_to_its_root_once_each() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let (root, ids) = root_with(db, "test", &[(ObservableKind::File, &"a".repeat(64))]).await;
    let orchestrator = Orchestrator::new(
        Catalog::new([common::stubs::SETS_ROOT, ace_mod_archive::MANIFEST]),
        modes(),
    );
    let link = |n: u32| {
        json!({"url": format!("https://tickets.example/{n}"), "text": format!("Ticket {n}"),
                              "icon": "servicenow"})
    };
    let with_links = |links: Vec<serde_json::Value>| {
        json!({"analysis_type": "test_sets_root", "schema_version": 1, "details": {},
               "root": {"pivot_links": links}})
    };
    let refused = orchestrator
        .check_result(
            "archive",
            &json!({"analysis_type": "archive_analysis", "schema_version": 1, "details": {},
                    "root": {"pivot_links": [link(1)]}}),
        )
        .expect_err("refused");
    assert!(
        refused.error.contains("ADDS_ROOT_PIVOT_LINKS"),
        "{}",
        refused.error
    );
    sqlx::query(
        "UPDATE analysis.roots SET pivot_links = $2, description = 'as submitted' WHERE id = $1",
    )
    .bind(root)
    .bind(json!([link(1)]))
    .execute(db.pool())
    .await
    .expect("the submission's link");
    let land = |links: Vec<serde_json::Value>| {
        let orchestrator = &orchestrator;
        let test_db = &test_db;
        let changes = with_links(links);
        let on = ids[0];
        async move {
            if let Err(e) = orchestrator.check_result("test_sets_root", &changes) {
                panic!("{} {:?}", e.error, e.fields);
            }
            let db = test_db.db();
            let mut tx = db.begin().await.expect("begins");
            ace_core::queue::enqueue(&mut tx, root, on, "test_sets_root")
                .await
                .expect("queues");
            tx.commit().await.expect("commits");
            let linker = worker(
                test_db,
                "linker",
                &["test_sets_root"],
                Duration::from_secs(60),
            )
            .await;
            let task = linker.claim().await.expect("claims").expect("a task");
            let mut tx = db.begin().await.expect("begins");
            orchestrator
                .land_result(&mut tx, &linker, &task, &result(changes))
                .await
                .expect("lands");
            tx.commit().await.expect("commits");
        }
    };
    land(vec![link(1), link(2), link(2), link(3)]).await;
    let links = || async {
        let links: serde_json::Value =
            sqlx::query_scalar("SELECT pivot_links FROM analysis.roots WHERE id = $1")
                .bind(root)
                .fetch_one(db.pool())
                .await
                .expect("reads the root");
        links
            .as_array()
            .expect("a list")
            .iter()
            .map(|l| l["text"].as_str().unwrap_or_default().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(links().await, ["Ticket 1", "Ticket 2", "Ticket 3"]);
    // a later result's links join them once each, up to the root's bound
    // 100 more, 2 of them the root's already: the root keeps its bound
    let many: Vec<serde_json::Value> = (2..102).map(link).collect();
    sqlx::query("DELETE FROM queue.tasks WHERE root_id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("clears the first task");
    sqlx::query("DELETE FROM analysis.results WHERE root_id = $1")
        .bind(root)
        .execute(db.pool())
        .await
        .expect("clears the first result");
    land(many).await;
    let kept = links().await;
    assert_eq!(kept.len(), ace_results::MAX_PIVOT_LINKS);
    assert_eq!(kept[..4], ["Ticket 1", "Ticket 2", "Ticket 3", "Ticket 4"]);
    let description: Option<String> =
        sqlx::query_scalar("SELECT description FROM analysis.roots WHERE id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("reads the root");
    assert_eq!(
        description.as_deref(),
        Some("as submitted"),
        "links alone leave the description"
    );
}

/// PLAN.md 7.6: the core's hooks, `observable_modifier` and `configuration_defined_tagging`
/// (`ace_core::hooks`), from an overlay's `hooks:` section.
fn hooked(yaml: &str) -> Orchestrator {
    let modes = modes().with_mode(AnalysisMode {
        name: "hooks_test".to_owned(),
        module_groups: vec!["common".to_owned(), "yara".to_owned()],
        enabled_modules: Vec::new(),
        disabled_modules: Vec::new(),
    });
    let overlay = ace_sdk::Overlay::from_yaml(yaml).expect("an overlay");
    let hooks = ace_core::hooks::Hooks::from_section(&overlay.hooks);
    Orchestrator::new(Catalog::new(manifests()), modes).with_hooks(hooks)
}

async fn idle(db: &ace_core::db::Db, root: uuid::Uuid) -> bool {
    ace_core::queue::root_is_idle(db, root)
        .await
        .expect("reads")
}

/// Runs the hooks task the root has queued, as `ace serve`'s hooks worker does.
async fn run_hooks(test_db: &TestDb, orchestrator: &Orchestrator) -> ace_core::hooks::Ran {
    let hooks = worker(
        test_db,
        "core/hooks",
        &[ace_core::hooks::HOOKS_MODULE],
        Duration::from_secs(60),
    )
    .await;
    let task = hooks.claim().await.expect("claims").expect("a hooks task");
    orchestrator.run_hooks(&hooks, &task).await.expect("runs")
}

#[tokio::test]
async fn the_hooks_run_when_a_pass_ends_and_what_they_do_is_in_the_tree() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = hooked(
        r#"
hooks:
  configuration_defined_tagging:
    tags: {evil_fqdn: alert, boring: fp}
  observable_modifier:
    rules:
      - name: evil below a yara match
        uuid: 0b4c3f86-2b1e-4d0e-9a51-6f0c1a6d1c11
        conditions:
          observable_types: [fqdn]
          value_pattern: '^evil\.'
          tree_conditions:
            - analysis_type: yara_scanner_v3_4
              details_match: {matches: '^evil_'}
        actions:
          add_tags: [evil_fqdn]
          set_display_value: the bad one
          limit_analysis: [rdap_analyzer]
"#,
    );
    let (root, _) = root_with(db, "hooks_test", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");

    let scanner = worker(
        &test_db,
        "yara",
        &["yara_scanner_v3_4"],
        Duration::from_secs(60),
    )
    .await;
    let task = scanner.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result(
            &mut tx,
            &scanner,
            &task,
            &result(json!({
                "analysis_type": "yara_scan_results",
                "schema_version": 1,
                "details": {"matches": ["evil_macro"]},
                "observables": [
                    {"type": "fqdn", "value": "evil.example.com"},
                    {"type": "fqdn", "value": "fine.example.com", "tags": ["boring"]},
                ],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    // nothing is left to run, so the hooks are, and the pass waits for them
    assert!(!idle(db, root).await);
    assert!(tasks_of(db, root).await.contains(&(
        ace_core::hooks::HOOKS_MODULE.to_owned(),
        EMAIL_SHA256.to_owned(),
        "queued".to_owned()
    )));

    // the rule matched, so the hooks run again once what it made eligible is done: RDAP, which the
    // mode doesn't run, since a limit takes the place of the mode's modules, as in ace3
    let first = run_hooks(&test_db, &orchestrator).await;
    assert!(first.effects.matched);
    assert!(!first.effects.detected);
    let rdap = worker(
        &test_db,
        "rdap",
        &["rdap_analyzer"],
        Duration::from_secs(60),
    )
    .await;
    let task = rdap
        .claim()
        .await
        .expect("claims")
        .expect("RDAP, by the limit");
    assert_eq!(task.observable.value, "evil.example.com");
    rdap.complete(task.id).await.expect("completes");
    assert!(!idle(db, root).await, "the hooks are queued again");

    // nothing more matches, so the tag's level makes a detection on the root, which makes it an alert
    let second = run_hooks(&test_db, &orchestrator).await;
    assert!(!second.effects.matched);
    assert!(second.effects.detected);
    assert_eq!(second.mode_changed_to.as_deref(), Some("correlation"));

    let form = ace_core::normal::normal_form(db.pool(), root)
        .await
        .expect("reads")
        .expect("a root");
    assert_eq!(
        form["root"]["detections"],
        json!({"tag evil_fqdn is configured to be alertable": [null]})
    );
    let evil = &form["observables"]["fqdn:evil.example.com"];
    assert_eq!(evil["tags"], json!({"evil_fqdn": true}));
    assert_eq!(
        evil["results"]["observable_modifier"],
        json!({
            "summary": "Applied 1 rule(s): evil below a yara match",
            "tags": {},
            "details": {"matched_rules": [{
                "name": "evil below a yara match",
                "uuid": "0b4c3f86-2b1e-4d0e-9a51-6f0c1a6d1c11",
                "actions_applied": {
                    "add_tags": ["evil_fqdn"],
                    "limit_analysis": ["rdap_analyzer"],
                    "set_display_value": "the bad one",
                },
            }]},
        })
    );
    assert!(
        form["observables"]["signature_id:0b4c3f86-2b1e-4d0e-9a51-6f0c1a6d1c11"].is_object(),
        "the rule's signature_id"
    );
    assert!(
        form["observables"]["fqdn:fine.example.com"]["results"]["observable_modifier"].is_null()
    );
    let (display_value, limit): (Option<String>, Vec<String>) = sqlx::query_as(
        "SELECT display_value, limit_modules FROM analysis.observables
         WHERE root_id = $1 AND value = 'evil.example.com'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(display_value.as_deref(), Some("the bad one"));
    assert_eq!(limit, ["rdap_analyzer"]);
    // the correlation mode runs RDAP on the other fqdn, and the hooks again at the end of that pass
    let tasks = tasks_of(db, root).await;
    assert!(
        tasks.contains(&(
            "rdap_analyzer".to_owned(),
            "fine.example.com".to_owned(),
            "queued".to_owned()
        )),
        "{tasks:?}"
    );
    let due: bool = sqlx::query_scalar("SELECT hooks_due FROM analysis.roots WHERE id = $1")
        .bind(root)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert!(due);
}

/// ace3's global `observable_exclusions` (its executor's `_process_observable_exclusions`): an
/// observable they name gets no task, and the observable modifier's rules don't evaluate it, while a
/// subdomain of it is analyzed as any other. ace3's defaults hold unless the overlay drops them.
#[tokio::test]
async fn a_globally_excluded_observable_gets_no_task_and_no_rule() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hooked = hooked(
        r#"
hooks:
  observable_modifier:
    rules:
      - name: tag youtube
        uuid: 6a1e5a54-0d7f-4a77-8c3b-37d3c4fcbc09
        phase: pre
        conditions: {observable_types: [fqdn], value_pattern: 'youtube\.com$'}
        actions: {add_tags: [seen_by_a_rule]}
"#,
    );
    let rdap_mode = AnalysisMode {
        name: "hooks_rdap".to_owned(),
        module_groups: vec![
            "common".to_owned(),
            "yara".to_owned(),
            "correlation".to_owned(),
        ],
        enabled_modules: Vec::new(),
        disabled_modules: Vec::new(),
    };
    let orchestrator = Orchestrator::new(
        hooked.catalog().as_ref().clone(),
        hooked.modes().clone().with_mode(rdap_mode),
    )
    .with_hooks(hooked.hooks().clone());
    assert!(
        orchestrator.exclusions().excludes("fqdn", "youtube.com"),
        "ace3's defaults"
    );
    let rdap_and_tags = |root| async move {
        let rdap: Vec<String> = tasks_of(db, root)
            .await
            .into_iter()
            .filter(|(module, _, _)| module == "rdap_analyzer")
            .map(|(_, value, _)| value)
            .collect();
        let tagged: Vec<String> = sqlx::query_scalar(
            "SELECT value FROM analysis.observables
             WHERE root_id = $1 AND 'seen_by_a_rule' = ANY(tags) ORDER BY value",
        )
        .bind(root)
        .fetch_all(db.pool())
        .await
        .expect("reads");
        (rdap, tagged)
    };
    let observables = [
        (ObservableKind::Fqdn, "youtube.com"),
        (ObservableKind::Fqdn, "www.youtube.com"),
    ];
    let (root, _) = root_with(db, "hooks_rdap", &observables).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    assert_eq!(
        rdap_and_tags(root).await,
        (
            vec!["www.youtube.com".to_owned()],
            vec!["www.youtube.com".to_owned()]
        ),
        "the excluded apex gets no task and no rule; its subdomain gets both"
    );

    // an overlay that drops ace3's entry analyzes it again
    let overlay = ace_sdk::Overlay::from_yaml("observable_exclusions: {exclude_youtube: null}")
        .expect("an overlay");
    let exclusions = ace_sdk::exclusions::Exclusions::from_section(&overlay.observable_exclusions)
        .expect("reads");
    let orchestrator = orchestrator.with_exclusions(exclusions);
    let (root, _) = root_with(db, "hooks_rdap", &observables).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let both = vec!["www.youtube.com".to_owned(), "youtube.com".to_owned()];
    let (mut rdap, tagged) = rdap_and_tags(root).await;
    rdap.sort();
    assert_eq!((rdap, tagged), (both.clone(), both));
}

#[tokio::test]
async fn a_pre_rule_acts_before_anything_is_queued_for_an_observable() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = hooked(
        r#"
hooks:
  observable_modifier:
    rules:
      - name: no rdap for the quiet one
        uuid: 6a1e5a54-0d7f-4a77-8c3b-37d3c4fcbc01
        phase: pre
        conditions: {observable_types: [fqdn], value_pattern: '^quiet\.'}
        actions: {exclude_analysis: [rdap_analyzer]}
      - name: drop what yara adds
        uuid: 6a1e5a54-0d7f-4a77-8c3b-37d3c4fcbc02
        phase: pre
        conditions:
          value_pattern: '^gone\.'
          tree_conditions: [{analysis_type: yara_scanner_v3_4, scope: parent}]
        actions: {ignore: true}
      - name: a detection
        uuid: 6a1e5a54-0d7f-4a77-8c3b-37d3c4fcbc03
        phase: pre
        conditions: {value_pattern: '^loud\.'}
        actions: {add_detection_points: [a loud fqdn]}
"#,
    );
    // correlation's group runs RDAP; the mode's a detectable one
    let modes_with_rdap = AnalysisMode {
        name: "hooks_rdap".to_owned(),
        module_groups: vec![
            "common".to_owned(),
            "yara".to_owned(),
            "correlation".to_owned(),
        ],
        enabled_modules: Vec::new(),
        disabled_modules: Vec::new(),
    };
    let orchestrator = Orchestrator::new(
        orchestrator.catalog().as_ref().clone(),
        orchestrator.modes().clone().with_mode(modes_with_rdap),
    )
    .with_hooks(orchestrator.hooks().clone());
    let (root, _) = root_with(db, "hooks_rdap", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let scanner = worker(
        &test_db,
        "yara",
        &["yara_scanner_v3_4"],
        Duration::from_secs(60),
    )
    .await;
    let task = scanner.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    let landed = orchestrator
        .land_result(
            &mut tx,
            &scanner,
            &task,
            &result(json!({
                "analysis_type": "yara_scan_results",
                "schema_version": 1,
                "details": {"matches": []},
                "observables": [
                    {"type": "fqdn", "value": "quiet.example.com"},
                    {"type": "fqdn", "value": "gone.example.com"},
                    {"type": "fqdn", "value": "plain.example.com"},
                ],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    assert_eq!(landed.mode_changed_to, None, "no pre rule detected yet");
    let rdap: Vec<String> = tasks_of(db, root)
        .await
        .into_iter()
        .filter(|(module, _, _)| module == "rdap_analyzer")
        .map(|(_, value, _)| value)
        .collect();
    assert_eq!(
        rdap,
        ["plain.example.com"],
        "excluded, and ignored with exclude_all"
    );
    let (ignored, directives): (bool, Vec<String>) = sqlx::query_as(
        "SELECT ignored, directives FROM analysis.observables
         WHERE root_id = $1 AND value = 'gone.example.com'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert!(ignored, "its only parent was the yara result");
    assert_eq!(directives, ["exclude_all"]);
    let held: bool = sqlx::query_scalar(
        "SELECT a.ignored FROM analysis.result_additions a
         JOIN analysis.observables o ON o.id = a.observable_id
         WHERE a.root_id = $1 AND o.value = 'gone.example.com'",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert!(held, "the yara result no longer holds it");

    // a pre rule's detection on a later landing makes the root an alert at once
    let rdap_worker = worker(
        &test_db,
        "rdap",
        &["rdap_analyzer"],
        Duration::from_secs(60),
    )
    .await;
    let task = rdap_worker.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    let landed = orchestrator
        .land_result(
            &mut tx,
            &rdap_worker,
            &task,
            &result(json!({
                "analysis_type": "rdap_analysis",
                "schema_version": 1,
                "details": {},
                "observables": [{"type": "fqdn", "value": "loud.example.com"}],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    assert_eq!(landed.mode_changed_to.as_deref(), Some("correlation"));
    let (description, signature, family): (String, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT d.description, d.signature_uuid, d.signature_family
             FROM analysis.detections d JOIN analysis.observables o ON o.id = d.observable_id
             WHERE d.root_id = $1 AND o.value = 'loud.example.com'",
        )
        .bind(root)
        .fetch_one(db.pool())
        .await
        .expect("reads");
    assert_eq!(description, "a loud fqdn");
    assert_eq!(
        signature.as_deref(),
        Some("6a1e5a54-0d7f-4a77-8c3b-37d3c4fcbc03")
    );
    assert_eq!(family.as_deref(), Some("observable_modifier"));
}

#[tokio::test]
async fn a_reset_reruns_a_module_and_the_hooks_end_once_nothing_new_matches() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = hooked(
        r#"
hooks:
  observable_modifier:
    rules:
      - name: rdap again
        uuid: 1c7b5d0e-6b55-4a42-b0e5-2f6e3c0d9a10
        conditions: {observable_types: [fqdn]}
        actions: {reset_analysis: [rdap_analyzer, archive], add_directives: [again]}
"#,
    );
    let orchestrator = Orchestrator::new(
        orchestrator.catalog().as_ref().clone(),
        orchestrator.modes().clone().with_mode(AnalysisMode {
            name: "hooks_rdap".to_owned(),
            module_groups: vec!["common".to_owned(), "correlation".to_owned()],
            enabled_modules: Vec::new(),
            disabled_modules: Vec::new(),
        }),
    )
    .with_hooks(orchestrator.hooks().clone());
    let (root, _) = root_with(db, "hooks_rdap", &[(ObservableKind::Fqdn, "x.example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let rdap = worker(
        &test_db,
        "rdap",
        &["rdap_analyzer"],
        Duration::from_secs(60),
    )
    .await;
    // RDAP ends with no result, ace3's "no analysis"
    let task = rdap.claim().await.expect("claims").expect("a task");
    rdap.complete(task.id).await.expect("completes");
    assert!(!idle(db, root).await);

    let ran = run_hooks(&test_db, &orchestrator).await;
    assert_eq!(
        ran.effects.requeued,
        [task.id],
        "only a module that ran is reset"
    );
    let form = ace_core::normal::normal_form(db.pool(), root)
        .await
        .expect("reads")
        .expect("a root");
    assert_eq!(
        form["observables"]["fqdn:x.example.com"]["results"]["observable_modifier"]["details"]["matched_rules"]
            [0]["actions_applied"],
        json!({"reset_analysis": ["rdap_analyzer"], "add_directives": ["again"]})
    );
    let task = rdap.claim().await.expect("claims").expect("RDAP again");
    rdap.complete(task.id).await.expect("completes");
    // the hooks run once more, match nothing new, and the pass ends
    let ran = run_hooks(&test_db, &orchestrator).await;
    assert!(!ran.effects.matched);
    assert!(idle(db, root).await);
}

#[tokio::test]
async fn a_failed_hooks_task_ends_the_pass_and_doesnt_run_again() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = hooked("hooks:\n  configuration_defined_tagging:\n    tags: {x: alert}\n");
    let (root, _) = root_with(db, "hooks_test", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let scanner = worker(
        &test_db,
        "yara",
        &["yara_scanner_v3_4"],
        Duration::from_secs(60),
    )
    .await;
    let task = scanner.claim().await.expect("claims").expect("a task");
    scanner.fail(task.id, "boom").await.expect("fails");
    let hooks = worker(
        &test_db,
        "core/hooks",
        &[ace_core::hooks::HOOKS_MODULE],
        Duration::from_secs(60),
    )
    .await;
    let task = hooks.claim().await.expect("claims").expect("a hooks task");
    hooks
        .fail(task.id, "the hooks failed")
        .await
        .expect("fails");
    assert!(idle(db, root).await, "the pass ends without them");
    assert!(hooks.claim().await.expect("claims").is_none());
}

/// A rule ace3 would log and skip is skipped, and the rules around it run (the owner's decision of
/// 2026-11-24): the overlay still parses, and the core still starts.
#[test]
fn the_hooks_skip_rules_ace3_would_skip() {
    let kept = |rule: &str| -> Vec<String> {
        let yaml = format!(
            "hooks:\n  observable_modifier:\n    rules:\n      - {rule}\n      - {{name: fine, uuid: fine}}\n"
        );
        let overlay = ace_sdk::Overlay::from_yaml(&yaml).expect("the overlay parses");
        let hooks = ace_core::hooks::Hooks::from_section(&overlay.hooks);
        let rules = hooks.rules().expect("the modifier is on");
        rules.rules().iter().map(|r| r.name.clone()).collect()
    };
    for bad in [
        "{name: a}",
        "{uuid: u, phase: later}",
        "{uuid: u, conditions: {value_pattern: '('}}",
        "{uuid: u, conditions: {observable_types: [nope]}}",
        "{uuid: u, conditions: {tree_conditions: [{observable_match: {size: x}}]}}",
        "{uuid: u, actions: {explode: true}}",
    ] {
        assert_eq!(kept(bad), ["fine"], "{bad}");
    }
    let long = format!(
        "{{uuid: u, conditions: {{value_pattern: '{}'}}}}",
        "a".repeat(1025)
    );
    assert_eq!(kept(&long), ["fine"]);
    // Python's patterns compile, look-around included
    assert_eq!(
        kept("{name: ahead, uuid: u, conditions: {value_pattern: '(?=x)'}}"),
        ["ahead", "fine"]
    );
    let many: String = (0..1001)
        .map(|i| format!("      - {{uuid: u{i}}}\n"))
        .collect();
    let overlay = ace_sdk::Overlay::from_yaml(&format!(
        "hooks:\n  observable_modifier:\n    rules:\n{many}"
    ))
    .expect("parses");
    let hooks = ace_core::hooks::Hooks::from_section(&overlay.hooks);
    assert_eq!(
        hooks.rules().expect("on").rules().len(),
        1000,
        "the first 1000"
    );
    // no section, and a section of disabled rules and no file, run nothing
    let none = ace_core::hooks::Hooks::from_section(&ace_sdk::hooks::HooksSection::default());
    assert!(none.names().is_empty());
    let off = ace_sdk::Overlay::from_yaml(
        "hooks:\n  observable_modifier:\n    rules:\n      - {uuid: u, enabled: false}\n",
    )
    .expect("parses");
    assert!(
        ace_core::hooks::Hooks::from_section(&off.hooks)
            .names()
            .is_empty()
    );
}

/// ace3's `rules_config_path`: the file's rules follow the overlay's, and a change to the file is taken
/// when it's read again, as ace3 watches it. A file that can't be read, or doesn't read as rules,
/// keeps the rules running.
#[tokio::test]
async fn the_rules_file_is_read_again_when_it_changes() {
    let errors = Errors::default();
    // this thread's alone: the test runs on a current-thread runtime
    let _logging =
        tracing::subscriber::set_default(tracing_subscriber::layer::SubscriberExt::with(
            tracing_subscriber::registry(),
            errors.clone(),
        ));
    let dir = tempfile::tempdir().expect("a directory");
    let file = dir.path().join("rules.yaml");
    let names = |hooks: &ace_core::hooks::Hooks| -> Vec<String> {
        let rules = hooks.rules().expect("on");
        rules.rules().iter().map(|r| r.name.clone()).collect()
    };
    let overlay = ace_sdk::Overlay::from_yaml(&format!(
        "hooks:\n  observable_modifier:\n    rules_file: {}\n    rules:\n      - {{name: inline, uuid: i}}\n",
        file.display()
    ))
    .expect("parses");
    // no file yet: the modifier is on, with the overlay's rules, and logs that it can't read it
    let hooks = ace_core::hooks::Hooks::from_section(&overlay.hooks);
    assert_eq!(names(&hooks), ["inline"]);
    let modifier = hooks.modifier().expect("on").clone();
    assert!(!modifier.reload().await, "still no file");

    assert!(errors.any("rules file can't be read"));
    std::fs::write(&file, "rules:\n  - {name: one, uuid: a}\n  - {name: bad}\n").expect("written");
    assert!(modifier.reload().await, "the file's rules are taken");
    assert!(
        errors.any("doesn't compile, so it is skipped"),
        "a skipped rule is logged at ERROR"
    );
    assert_eq!(names(&hooks), ["inline", "one"], "a clone sees the reload");
    assert!(
        !modifier.reload().await,
        "an unchanged file isn't compiled again"
    );

    std::fs::write(
        &file,
        "rules:\n  - {name: two, uuid: b}\n  - {name: dup, uuid: i}\n",
    )
    .expect("written");
    assert!(modifier.reload().await);
    assert_eq!(
        names(&hooks),
        ["inline", "two"],
        "a uuid the overlay has is skipped"
    );

    std::fs::write(&file, "rules: [not: yaml").expect("written");
    assert!(!modifier.reload().await);
    assert_eq!(names(&hooks), ["inline", "two"], "the rules running stay");
    assert!(errors.any("doesn't read, so the rules running stay"));
    std::fs::remove_file(&file).expect("removed");
    assert!(!modifier.reload().await);
    assert_eq!(names(&hooks), ["inline", "two"]);
}

/// A value ace3's observable class refuses isn't added, as ace3's `add_observable_by_spec` returns
/// None for it: a certificate's common name a module adds as an fqdn lands nowhere, nor do the
/// relationships to it, no module runs on it, and the rest of the result lands.
#[tokio::test]
async fn a_value_its_type_refuses_isnt_added_and_nothing_refers_to_it() {
    let records = common::Records::default();
    // this thread's alone: the test runs on a current-thread runtime
    let _logging = records.on_this_thread();
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = orchestrator();
    let (root, ids) = root_with(
        db,
        "correlation",
        &[(ObservableKind::Fqdn, "evil.example.com")],
    )
    .await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let rdap = worker(
        &test_db,
        "rdap",
        &["rdap_analyzer"],
        Duration::from_secs(60),
    )
    .await;
    let task = rdap.claim().await.expect("claims").expect("a task");
    let refused = json!({"type": "fqdn", "value": "GTS Root R1"});
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result(
            &mut tx,
            &rdap,
            &task,
            &result(json!({
                "analysis_type": "test_stub",
                "schema_version": 1,
                "details": {"note": "x"},
                "analyzed": {"relationships": [{"type": "related_to", "target": refused}]},
                "observables": [
                    refused,
                    {"type": "fqdn", "value": "c2.example.com",
                     "relationships": [{"type": "related_to", "target": refused}]},
                    {"type": "hostname", "value": " HOST "},
                ],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");

    let stored: BTreeSet<(String, String)> = tree::observables(db.pool(), root)
        .await
        .expect("reads")
        .into_iter()
        .map(|o| (o.kind.to_string(), o.value))
        .collect();
    let pair = |k: &str, v: &str| (k.to_owned(), v.to_owned());
    assert_eq!(
        stored,
        BTreeSet::from([
            pair("fqdn", "c2.example.com"),
            pair("fqdn", "evil.example.com"),
            pair("hostname", "HOST"),
        ]),
        "the refused fqdn isn't there and the hostname is stripped"
    );
    let relationships: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis.relationships WHERE root_id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("counts");
    assert_eq!(relationships, 0);
    assert!(
        !tasks_of(db, root)
            .await
            .iter()
            .any(|(_, value, _)| value == "GTS Root R1")
    );
    assert!(
        tree::relationships(db.pool(), root, ids[0])
            .await
            .expect("reads")
            .is_empty()
    );
    let logged = records.find("the observable isn't added: not a valid fqdn");
    let logged = logged.expect("the refusal is logged");
    assert_eq!(logged.level, tracing::Level::DEBUG);
    for (field, value) in [
        ("root", root.to_string()),
        ("module", "rdap_analyzer".to_owned()),
        ("observable_type", "fqdn".to_owned()),
        ("observable_value", "GTS Root R1".to_owned()),
    ] {
        assert_eq!(logged.fields.get(field), Some(&value), "{field}");
    }
}

/// The messages of the ERROR records a test's thread logs.
#[derive(Clone, Default)]
struct Errors(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl Errors {
    fn any(&self, text: &str) -> bool {
        self.0
            .lock()
            .expect("the records")
            .iter()
            .any(|m| m.contains(text))
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Errors {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        if *event.metadata().level() == tracing::Level::ERROR {
            let mut message = Message(String::new());
            event.record(&mut message);
            self.0.lock().expect("the records").push(message.0);
        }
    }
}

/// PLAN.md 7.10 batch 6: SVS's hook, ace3's `svs_alert_tagger`, is one of the core's hooks, in the modes
/// that list its module, whatever the overlay's `hooks:` section says. What it judges and writes is
/// `ace-service`'s `svs_attribution_tests`, which run it through `Orchestrator::run_hooks`.
#[test]
fn the_svs_hook_runs_in_the_modes_that_list_its_module() {
    let hooks = ace_core::hooks::Hooks::none();
    assert!(hooks.names().is_empty());
    let modes = Modes::ace3();
    assert!(!hooks.run_in(&modes, "correlation"));
    let hooks = hooks.with_svs(ace_core::svs::attribution::HookConfig::default());
    assert_eq!(hooks.names(), ["svs_alert_tagger"]);
    assert!(hooks.run_in(&modes, "correlation"));
    for mode in ["analysis", "cli", "dispositioned", "email", "event"] {
        assert!(!hooks.run_in(&modes, mode), "{mode}");
    }
}

/// Modules that declare what they take (`ace_sdk::takes`, PLAN.md decision 23), one fact each, for
/// the tests below, and two that add files and one whose result the last reads.
mod declaring {
    use ace_results::{ObservableKind, RelationshipKind};
    use ace_sdk::takes::{Case, Condition, Takes, Text};
    use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

    use crate::common::stubs::StubOutput;

    macro_rules! declaring {
        ($ty:ident, $name:literal, $kind:ident, { $($extra:tt)* }, $takes:expr) => {
            pub struct $ty;

            impl Module for $ty {
                const NAME: &'static str = $name;
                const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
                $($extra)*
                type Output = StubOutput;
                type Settings = ();

                fn init(_: &()) -> Result<Self, ModuleError> {
                    Ok($ty)
                }

                fn takes(_: &()) -> Takes {
                    $takes
                }
            }

            declaring!(@run $kind $ty);
        };
        (@run parser $ty:ident) => {
            impl Parser for $ty {
                fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<StubOutput>, ModuleError> {
                    Ok(Outcome::Skipped("a stub".to_owned()))
                }
            }
        };
        (@run lookup $ty:ident) => {
            impl Lookup for $ty {
                const TCP_PORTS: &'static [u16] = &[];

                async fn analyze(
                    &self,
                    _: &TaskContext<()>,
                ) -> Result<Outcome<StubOutput>, ModuleError> {
                    Ok(Outcome::Skipped("a stub".to_owned()))
                }
            }
        };
    }

    declaring!(Carrier, "test_carrier", lookup, {}, Takes::everything());
    declaring!(Carrier2, "test_carrier2", lookup, {}, Takes::everything());
    declaring!(Typer, "test_typer", lookup, {}, Takes::everything());
    declaring!(
        ByName,
        "test_takes_name",
        parser,
        {},
        Takes::everything().and(
            Condition::Name(Text::ends_with(".dmg", Case::Lower)),
            "not named .dmg"
        )
    );
    declaring!(
        ByDirective,
        "test_takes_directive",
        parser,
        {},
        Takes::everything().and(Condition::directive("render"), "no render directive")
    );
    declaring!(
        ByAdder,
        "test_takes_added_by",
        parser,
        {},
        Takes::everything().and(Condition::added_by("test_carrier2"), "not test_carrier2's")
    );
    declaring!(
        ByMode,
        "test_takes_mode",
        parser,
        {},
        Takes::everything().and(Condition::Mode("correlation".to_owned()), "not correlation")
    );
    declaring!(
        ByResult,
        "test_takes_result",
        parser,
        {
            const DEPENDS_ON: &'static [&'static str] = &["test_typer"];
        },
        Takes::everything().and(Condition::result_true("test_typer", "flag"), "no flag")
    );
    declaring!(
        ByRelationship,
        "test_takes_relationship",
        parser,
        {},
        Takes::everything().and(
            Condition::Relationship(RelationshipKind::ExtractedFrom),
            "not extracted"
        )
    );
    declaring!(
        ByYaraMeta,
        "test_takes_yara_meta",
        parser,
        {},
        Takes::everything().and(Condition::yara_meta("type", "x"), "not type=x")
    );

    pub const DECLARING: [&str; 7] = [
        "test_takes_name",
        "test_takes_directive",
        "test_takes_added_by",
        "test_takes_mode",
        "test_takes_result",
        "test_takes_relationship",
        "test_takes_yara_meta",
    ];

    pub fn manifests() -> Vec<Manifest> {
        vec![
            Manifest::lookup::<Carrier>(),
            Manifest::lookup::<Carrier2>(),
            Manifest::lookup::<Typer>(),
            Manifest::parser::<ByName>(),
            Manifest::parser::<ByDirective>(),
            Manifest::parser::<ByAdder>(),
            Manifest::parser::<ByMode>(),
            Manifest::parser::<ByResult>(),
            Manifest::parser::<ByRelationship>(),
            Manifest::parser::<ByYaraMeta>(),
        ]
    }
}

/// A mode that runs every module of `declaring`, and a correlation mode that does too.
fn declaring_orchestrator(takes: ace_core::takes::TakesMode) -> Orchestrator {
    let mode = |name: &str| AnalysisMode {
        name: name.to_owned(),
        module_groups: Vec::new(),
        enabled_modules: declaring::manifests()
            .iter()
            .map(|m| m.name.to_owned())
            .collect(),
        disabled_modules: Vec::new(),
    };
    let modes = Modes::ace3()
        .with_mode(mode("takes"))
        .with_mode(mode("correlation"));
    Orchestrator::new(Catalog::new(declaring::manifests()), modes).with_takes(takes)
}

/// Lands a result of `module` on the task a worker of it claims.
async fn land(
    test_db: &TestDb,
    orchestrator: &Orchestrator,
    module: &str,
    envelope: serde_json::Value,
) -> ace_core::orchestrator::Landed {
    let db = test_db.db();
    let worker = worker(test_db, module, &[module], Duration::from_secs(60)).await;
    let task = worker.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    let landed = orchestrator
        .land_result(&mut tx, &worker, &task, &result(envelope))
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    landed
}

/// The declaring modules with a task on `file`, and whether each is marked declined.
async fn declaring_tasks(
    db: &ace_core::db::Db,
    root: uuid::Uuid,
    file: &str,
) -> Vec<(String, bool)> {
    sqlx::query_as(
        "SELECT t.module, t.declined IS NOT NULL FROM queue.tasks t
         JOIN analysis.observables o ON o.root_id = t.root_id AND o.id = t.observable_id
         WHERE t.root_id = $1 AND o.value = $2 AND t.module LIKE 'test_takes_%'
         ORDER BY t.module",
    )
    .bind(root)
    .bind(file)
    .fetch_all(db.pool())
    .await
    .expect("lists tasks")
}

/// The steps both tests take: a root with a file C, a result on C that adds a file F under a name
/// none of the declarations takes, then a second result on C that adds F again with each fact the
/// declarations wait for (a nearer name, a directive, the module that adds it, a relationship, a
/// `yara_meta` tag), then file_type's stand-in's result on F, then the mode's change. Each step's
/// tasks are returned.
async fn late_facts(
    test_db: &TestDb,
    orchestrator: &Orchestrator,
) -> (uuid::Uuid, Vec<Vec<(String, bool)>>) {
    let db = test_db.db();
    let (c, f) = ("c1".repeat(32), "f1".repeat(32));
    let (root, ids) = root_with(db, "takes", &[(ObservableKind::File, c.as_str())]).await;
    let mut tx = db.begin().await.expect("begins");
    tree::add_file(&mut tx, root, ids[0], "c.bin", &[])
        .await
        .expect("adds");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let mut steps = vec![declaring_tasks(db, root, &c).await];

    let added = |path: &str, extra: serde_json::Value| {
        let mut file = json!({"path": path, "sha256": f, "size": 1});
        if let (Some(file), Some(extra)) = (file.as_object_mut(), extra.as_object()) {
            file.extend(extra.clone());
        }
        json!({"analysis_type": "test_stub", "schema_version": 1, "details": {"note": ""},
               "files": [file]})
    };
    land(
        test_db,
        orchestrator,
        "test_carrier",
        added("z.bin", json!({})),
    )
    .await;
    steps.push(declaring_tasks(db, root, &f).await);
    let reference = json!({"type": "file", "value": c});
    land(
        test_db,
        orchestrator,
        "test_carrier2",
        added(
            "a.dmg",
            json!({
                "directives": ["render"],
                "yara_meta": ["type=x"],
                "relationships": [{"type": "extracted_from", "target": reference}],
            }),
        ),
    )
    .await;
    steps.push(declaring_tasks(db, root, &f).await);
    // the stand-in for file_type: a worker of it takes C's task first, then F's
    for _ in 0..2 {
        land(
            test_db,
            orchestrator,
            "test_typer",
            json!({"analysis_type": "test_stub", "schema_version": 1,
                   "details": {"note": "", "flag": true}}),
        )
        .await;
    }
    steps.push(declaring_tasks(db, root, &f).await);
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .set_mode(&mut tx, root, "correlation")
        .await
        .expect("changes the mode");
    tx.commit().await.expect("commits");
    steps.push(declaring_tasks(db, root, &f).await);
    (root, steps)
}

/// PLAN.md decision 23: the core doesn't queue a task a module's declaration declines, and a fact
/// that arrives later queues it then: a nearer path, a directive, the module that adds the file, a
/// relationship and a `yara_meta` tag when a result adds the file again, a dependency's result when
/// it lands, and the mode when it changes.
#[tokio::test]
async fn a_fact_that_arrives_later_queues_the_task_a_declaration_declined() {
    let test_db = TestDb::new().await;
    let orchestrator = declaring_orchestrator(ace_core::takes::TakesMode::Applied);
    let (_, steps) = late_facts(&test_db, &orchestrator).await;
    let names = |step: &[(String, bool)]| -> Vec<String> {
        step.iter().map(|(module, _)| module.clone()).collect()
    };
    // C, named c.bin, with nothing any declaration waits for
    assert_eq!(names(&steps[0]), Vec::<String>::new());
    // F, added as z.bin by test_carrier
    assert_eq!(names(&steps[1]), Vec::<String>::new());
    // F, added again as a.dmg, which sorts first at the same depth, with the rest
    assert_eq!(
        names(&steps[2]),
        [
            "test_takes_added_by",
            "test_takes_directive",
            "test_takes_name",
            "test_takes_relationship",
            "test_takes_yara_meta",
        ]
    );
    // file_type's stand-in's result, which test_takes_result waits for and reads
    assert!(names(&steps[3]).contains(&"test_takes_result".to_owned()));
    assert!(!names(&steps[3]).contains(&"test_takes_mode".to_owned()));
    // the mode's change
    let mut all: Vec<String> = declaring::DECLARING
        .iter()
        .map(|m| (*m).to_owned())
        .collect();
    all.sort();
    assert_eq!(names(&steps[4]), all);
    assert!(steps.iter().flatten().all(|(_, marked)| !marked));
}

/// The audit setting queues every task as before and marks the ones a declaration declines; a
/// mark goes when the declaration takes the task, which is when the setting's absence would have
/// queued it; and a marked task that stores a result is in the audit's report.
#[tokio::test]
async fn the_audit_queues_every_task_and_reports_a_declined_one_that_stored_a_result() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = declaring_orchestrator(ace_core::takes::TakesMode::Audit);
    let (root, steps) = late_facts(&test_db, &orchestrator).await;
    let marked = |step: &[(String, bool)]| -> Vec<String> {
        step.iter()
            .filter(|(_, marked)| *marked)
            .map(|(module, _)| module.clone())
            .collect()
    };
    // on C every declaring module is queued, all but the result's marked, since that one waits for
    // its dependency
    assert_eq!(steps[0].len(), 6);
    assert_eq!(marked(&steps[0]).len(), 6);
    // on F after the second result: the facts arrived, so only the mode's is still marked
    assert_eq!(marked(&steps[2]), ["test_takes_mode"]);
    assert_eq!(marked(&steps[3]), ["test_takes_mode"]);
    assert_eq!(marked(&steps[4]), Vec::<String>::new());
    assert!(
        ace_core::takes::audit_report(db.pool())
            .await
            .expect("reads")
            .is_empty()
    );

    // C's task of the name's module is still marked: a result from it is what the report lists
    let worker = worker(
        &test_db,
        "namer",
        &["test_takes_name"],
        Duration::from_secs(60),
    )
    .await;
    let mut task = worker.claim().await.expect("claims").expect("a task");
    while task.observable.value != "c1".repeat(32) {
        worker.complete(task.id).await.expect("ends");
        task = worker.claim().await.expect("claims").expect("a task");
    }
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result(
            &mut tx,
            &worker,
            &task,
            &result(json!({"analysis_type": "test_stub", "schema_version": 1,
                           "details": {"note": ""}})),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    let report = ace_core::takes::audit_report(db.pool())
        .await
        .expect("reads");
    assert_eq!(report.len(), 1, "{report:?}");
    assert_eq!(report[0].root, root);
    assert_eq!(report[0].module, "test_takes_name");
    assert_eq!(report[0].declined, "not named .dmg");
    assert_eq!(report[0].ended, "result");
}

/// A file's type step and modules that read its type (PLAN.md decision 25): `file_type`'s
/// stand-in, which writes `TypeFacts`, a module that takes PDFs, one that takes `.dmg` names, one
/// that takes everything, and one that depends on file_type and reads ace3's result.
mod typed {
    use ace_results::ObservableKind;
    use ace_results::types::file_type::TypeFacts;
    use ace_sdk::takes::{Case, Condition, Takes, Text, TypeFact};
    use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

    use crate::common::stubs::StubOutput;

    pub struct TypeStep;

    impl Module for TypeStep {
        const NAME: &'static str = "file_type";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        type Output = TypeFacts;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(TypeStep)
        }
    }

    impl Parser for TypeStep {
        fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<TypeFacts>, ModuleError> {
            Ok(Outcome::Skipped("a stub".to_owned()))
        }
    }

    macro_rules! reader {
        ($ty:ident, $name:literal, { $($extra:tt)* }, $takes:expr) => {
            pub struct $ty;

            impl Module for $ty {
                const NAME: &'static str = $name;
                const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
                $($extra)*
                type Output = StubOutput;
                type Settings = ();
                fn init(_: &()) -> Result<Self, ModuleError> {
                    Ok($ty)
                }
                fn takes(_: &()) -> Takes {
                    $takes
                }
            }

            impl Parser for $ty {
                fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<StubOutput>, ModuleError> {
                    Ok(Outcome::Skipped("a stub".to_owned()))
                }
            }
        };
    }

    reader!(
        Pdfs,
        "test_wants_pdf",
        {},
        Takes::everything().and(Condition::type_fact(TypeFact::IsPdfFile), "not a PDF")
    );
    reader!(
        Dmgs,
        "test_wants_dmg",
        {},
        Takes::everything().and(
            Condition::Name(Text::ends_with(".dmg", Case::Lower)),
            "not named .dmg"
        )
    );
    reader!(Everything, "test_wants_all", {}, Takes::everything());
    reader!(
        Ace3s,
        "test_reads_file_type",
        {
            const DEPENDS_ON: &'static [&'static str] = &["file_type"];
        },
        Takes::everything().and(Condition::result_true("file_type", "is_pdf_file"), "no PDF")
    );

    pub fn manifests() -> Vec<Manifest> {
        vec![
            Manifest::parser::<TypeStep>(),
            Manifest::parser::<Pdfs>(),
            Manifest::parser::<Dmgs>(),
            Manifest::parser::<Everything>(),
            Manifest::parser::<Ace3s>(),
        ]
    }
}

/// A mode that runs the type step and its readers, one that runs the readers alone, and one that
/// runs only modules that read nothing of the type.
fn typed_orchestrator() -> Orchestrator {
    let mode = |name: &str, keep: &dyn Fn(&str) -> bool| AnalysisMode {
        name: name.to_owned(),
        module_groups: Vec::new(),
        enabled_modules: typed::manifests()
            .iter()
            .map(|m| m.name.to_owned())
            .filter(|m| keep(m))
            .collect(),
        disabled_modules: Vec::new(),
    };
    let modes = Modes::ace3()
        .with_mode(mode("typed", &|_| true))
        .with_mode(mode("untyped", &|m| m != "file_type"))
        .with_mode(mode("plain", &|m| {
            m == "test_wants_dmg" || m == "test_wants_all"
        }));
    Orchestrator::new(Catalog::new(typed::manifests()), modes)
}

/// The type a PDF's bytes have.
fn pdf_facts() -> ace_results::types::file_type::TypeFacts {
    ace_results::types::file_type::TypeFacts {
        description: "PDF document, version 1.4".to_owned(),
        mime: "application/pdf".to_owned(),
        has_pdf_marker: true,
        ..Default::default()
    }
}

/// Keeps `facts` for `sha256`, as a type step in another root would have.
async fn keep_type(
    test_db: &TestDb,
    sha256: &str,
    facts: &ace_results::types::file_type::TypeFacts,
) {
    let mut tx = test_db.db().begin().await.expect("begins");
    ace_core::type_step::store_facts(&mut tx, sha256, facts)
        .await
        .expect("keeps the facts");
    tx.commit().await.expect("commits");
}

/// The file's tags and its `yara_meta`, in a root with one file.
async fn tags_and_types(test_db: &TestDb, root: uuid::Uuid) -> (Vec<String>, Vec<String>) {
    sqlx::query_as(
        "SELECT o.tags, f.yara_meta FROM analysis.observables o
         JOIN analysis.files f ON f.root_id = o.root_id AND f.observable_id = o.id
         WHERE o.root_id = $1 AND o.type = 'file'",
    )
    .bind(root)
    .fetch_one(test_db.db().pool())
    .await
    .expect("reads")
}

/// A root in `mode` with one file at `path`, started: what the core queued.
async fn typed_root(
    test_db: &TestDb,
    orchestrator: &Orchestrator,
    mode: &str,
    sha256: &str,
    path: &str,
) -> (uuid::Uuid, ace_core::tree::ObservableId) {
    let db = test_db.db();
    let (root, ids) = root_with(db, mode, &[(ObservableKind::File, sha256)]).await;
    let mut tx = db.begin().await.expect("begins");
    tree::add_file(&mut tx, root, ids[0], path, &[])
        .await
        .expect("adds");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    (root, ids[0])
}

/// The type step's worker, which ends it as the lease API's does (`queue::TaskEnded`).
async fn type_worker(test_db: &TestDb, orchestrator: &Orchestrator) -> ace_core::queue::Worker {
    worker(test_db, "typer", &["file_type"], Duration::from_secs(60))
        .await
        .with_ended(std::sync::Arc::new(orchestrator.clone()))
}

fn modules(tasks: &[(String, String, String)]) -> Vec<&str> {
    tasks.iter().map(|(module, _, _)| module.as_str()).collect()
}

/// PLAN.md decision 25: a new file's first task is its type step, alone; what it finds is kept by
/// sha256 and the file's other tasks are queued when it ends, the declarations reading the type;
/// where ace3's file_type would have run, the file has its tags, `yara_meta` types and result.
#[tokio::test]
async fn a_file_s_type_step_comes_first_and_its_end_queues_the_rest() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = typed_orchestrator();
    let sha256 = "a1".repeat(32);
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "doc.pdf").await;
    assert_eq!(modules(&tasks_of(db, root).await), ["file_type"]);

    let typer = type_worker(&test_db, &orchestrator).await;
    let task = typer.claim().await.expect("claims").expect("the type step");
    let facts = ace_results::types::file_type::TypeFacts {
        description: "PDF document, version 1.4".to_owned(),
        mime: "application/pdf".to_owned(),
        has_pdf_marker: true,
        ..Default::default()
    };
    let mut tx = db.begin().await.expect("begins");
    ace_core::type_step::store_facts(&mut tx, &sha256, &facts)
        .await
        .expect("keeps the facts");
    typer
        .finish_in(&mut tx, task.id, ace_core::queue::TaskState::Done, None)
        .await
        .expect("ends");
    tx.commit().await.expect("commits");

    // every reader but the .dmg one, which the name declines; the PDF one reads the type, and the
    // one that depends on file_type reads ace3's result built from it
    assert_eq!(
        modules(&tasks_of(db, root).await),
        [
            "file_type",
            "test_reads_file_type",
            "test_wants_all",
            "test_wants_pdf"
        ]
    );
    let (tags, yara_meta): (Vec<String>, Vec<String>) = sqlx::query_as(
        "SELECT o.tags, f.yara_meta FROM analysis.observables o
         JOIN analysis.files f ON f.root_id = o.root_id AND f.observable_id = o.id
         WHERE o.root_id = $1",
    )
    .bind(root)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(tags, ["pdf"]);
    assert_eq!(yara_meta, ["type=document.pdf"]);
    let form = ace_core::normal::normal_form(db.pool(), root)
        .await
        .expect("reads")
        .expect("a root");
    let shown = &form["observables"][format!("file:{sha256}")]["results"]["file_type"];
    assert_eq!(shown["details"]["is_pdf_file"], true);
    assert_eq!(shown["details"]["type"], "PDF document, version 1.4");
    assert_eq!(
        shown["summary"],
        "File Type Analysis: PDF document, version 1.4 (application/pdf) (pdf document)"
    );
    // nothing stored as a result
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM analysis.results WHERE root_id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("counts");
    assert_eq!(stored, 0);
}

/// PLAN.md decision 25: a type step that fails, in the module or by its lease running out on its
/// last attempt, still ends, and the file's other tasks are queued. The file's type is unknown, so
/// every declaration that reads it takes the file, and one that a known fact declines still
/// doesn't: a failure never keeps a module off a file it would have run on. The file shows no
/// file_type result, so the module that depends on it waits, as it did when file_type failed.
#[tokio::test]
async fn a_failed_type_step_keeps_no_module_off_the_file() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = typed_orchestrator();
    let expected = ["file_type", "test_wants_all", "test_wants_pdf"];

    // the module fails
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &"b1".repeat(32), "x.bin").await;
    let typer = type_worker(&test_db, &orchestrator).await;
    let task = typer.claim().await.expect("claims").expect("the type step");
    typer
        .fail(task.id, "libmagic crashed")
        .await
        .expect("fails");
    assert_eq!(modules(&tasks_of(db, root).await), expected);
    let shown: bool =
        sqlx::query_scalar("SELECT type_result FROM analysis.observables WHERE root_id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert!(!shown);

    // its lease runs out on its last attempt
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &"b2".repeat(32), "y.bin").await;
    let task = typer.claim().await.expect("claims").expect("the type step");
    sqlx::query(
        "UPDATE queue.tasks SET attempts = max_attempts, lease_expires_at = now() - interval '1 second'
         WHERE id = $1",
    )
    .bind(task.id.0)
    .execute(db.pool())
    .await
    .expect("expires");
    let reaped = ace_core::queue::reap_expired_leases(db, Some(&orchestrator))
        .await
        .expect("reaps");
    assert_eq!(reaped.failed, [task.id]);
    assert_eq!(modules(&tasks_of(db, root).await), expected);
    assert!(
        tasks_of(db, root)
            .await
            .iter()
            .all(|(module, _, state)| module != "file_type" || state == "failed")
    );
}

/// PLAN.md decision 25: where the mode doesn't run file_type but a module it runs declares on the
/// type, the file is still typed first, but shows no file_type result, as ace3's YARA-only mode has
/// none, and the module that depends on it isn't held back; a mode that runs file_type, set later,
/// gives the file its result.
#[tokio::test]
async fn a_file_is_typed_in_a_mode_without_file_type_and_shows_its_result_once_one_has_it() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = typed_orchestrator();
    let sha256 = "c1".repeat(32);
    let (root, _) = typed_root(&test_db, &orchestrator, "untyped", &sha256, "doc.pdf").await;
    assert_eq!(modules(&tasks_of(db, root).await), ["file_type"]);
    let typer = type_worker(&test_db, &orchestrator).await;
    let task = typer.claim().await.expect("claims").expect("the type step");
    let facts = ace_results::types::file_type::TypeFacts {
        mime: "application/pdf".to_owned(),
        has_pdf_marker: true,
        ..Default::default()
    };
    let mut tx = db.begin().await.expect("begins");
    ace_core::type_step::store_facts(&mut tx, &sha256, &facts)
        .await
        .expect("keeps");
    typer
        .finish_in(&mut tx, task.id, ace_core::queue::TaskState::Done, None)
        .await
        .expect("ends");
    tx.commit().await.expect("commits");
    // no file_type result, so the module that reads one has none and declines
    assert_eq!(
        modules(&tasks_of(db, root).await),
        ["file_type", "test_wants_all", "test_wants_pdf"]
    );
    let form = ace_core::normal::normal_form(db.pool(), root)
        .await
        .expect("reads")
        .expect("a root");
    let file = &form["observables"][format!("file:{sha256}")];
    assert!(file["results"].get("file_type").is_none());
    assert_eq!(file["tags"], json!({}));

    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .set_mode(&mut tx, root, "typed")
        .await
        .expect("changes the mode");
    tx.commit().await.expect("commits");
    let form = ace_core::normal::normal_form(db.pool(), root)
        .await
        .expect("reads")
        .expect("a root");
    let file = &form["observables"][format!("file:{sha256}")];
    assert_eq!(file["results"]["file_type"]["details"]["is_pdf_file"], true);
    assert_eq!(file["tags"], json!({"pdf": true}));
    assert!(modules(&tasks_of(db, root).await).contains(&"test_reads_file_type"));
}

/// PLAN.md decision 25: a file is typed only where something reads its type. In a mode whose
/// modules declare nothing on the type and that doesn't run file_type, as ace3's YARA-only mode,
/// the file has no type step and its tasks are queued at once; a mode that reads the type, set
/// later, types it then, and holds back only what is new.
#[tokio::test]
async fn a_file_is_typed_only_where_something_reads_its_type() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = typed_orchestrator();
    let (root, _) = typed_root(&test_db, &orchestrator, "plain", &"c2".repeat(32), "a.dmg").await;
    assert_eq!(
        modules(&tasks_of(db, root).await),
        ["test_wants_all", "test_wants_dmg"]
    );
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .set_mode(&mut tx, root, "typed")
        .await
        .expect("changes the mode");
    tx.commit().await.expect("commits");
    assert_eq!(
        modules(&tasks_of(db, root).await),
        ["file_type", "test_wants_all", "test_wants_dmg"]
    );
}

/// PLAN.md decision 25: a file whose bytes were typed in another root needs no type step. The core
/// reads the type kept for its sha256 when the file is added, settles its path, gives it ace3's
/// file_type result where that module would run, and queues the rest at once.
#[tokio::test]
async fn a_file_whose_bytes_were_typed_before_needs_no_type_step() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = typed_orchestrator();
    let sha256 = "d1".repeat(32);
    keep_type(&test_db, &sha256, &pdf_facts()).await;

    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "doc.pdf").await;
    assert_eq!(
        modules(&tasks_of(db, root).await),
        ["test_reads_file_type", "test_wants_all", "test_wants_pdf"]
    );
    let (tags, types) = tags_and_types(&test_db, root).await;
    assert_eq!(
        (tags, types),
        (vec!["pdf".to_owned()], vec!["type=document.pdf".to_owned()])
    );
    let form = ace_core::normal::normal_form(db.pool(), root)
        .await
        .expect("reads")
        .expect("a root");
    let shown = &form["observables"][format!("file:{sha256}")]["results"]["file_type"];
    assert_eq!(shown["details"]["is_pdf_file"], true);
    let settled: bool =
        sqlx::query_scalar("SELECT analyzed FROM analysis.files WHERE root_id = $1")
            .bind(root)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert!(
        settled,
        "the path the type was read under is the analyzed one"
    );

    // a name the kept type reads differently: is_pdf_file and ace3's result follow the name
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "doc.pdfparser").await;
    assert_eq!(modules(&tasks_of(db, root).await), ["test_wants_all"]);
    let (tags, types) = tags_and_types(&test_db, root).await;
    assert!(tags.is_empty() && types.is_empty(), "{tags:?} {types:?}");

    // where file_type doesn't run there is no result to show
    let (root, _) = typed_root(&test_db, &orchestrator, "untyped", &sha256, "doc.pdf").await;
    assert_eq!(
        modules(&tasks_of(db, root).await),
        ["test_wants_all", "test_wants_pdf"]
    );
    let (tags, _) = tags_and_types(&test_db, root).await;
    assert!(tags.is_empty());
}

/// PLAN.md decision 25: the JavaScript check is the one fact that isn't the bytes' alone. The type
/// step makes it only where the mime type or the name says JavaScript, so a type kept from a `.txt`
/// name lacks it, and the same bytes named `.js` get a type step that makes it. Kept with it, the
/// type serves every name, and each name gets what its own name gives: node refuses `.JS`.
#[tokio::test]
async fn a_kept_type_serves_a_javascript_name_only_once_it_has_the_javascript_check() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = typed_orchestrator();
    let sha256 = "e1".repeat(32);
    let mut facts = ace_results::types::file_type::TypeFacts {
        description: "ASCII text".to_owned(),
        mime: "text/plain".to_owned(),
        javascript: None,
        ..Default::default()
    };
    keep_type(&test_db, &sha256, &facts).await;

    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "x.txt").await;
    assert!(!modules(&tasks_of(db, root).await).contains(&"file_type"));
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "y.js").await;
    assert_eq!(modules(&tasks_of(db, root).await), ["file_type"]);

    // the step under the .js name makes the check, and the file's tasks follow
    let typer = type_worker(&test_db, &orchestrator).await;
    let task = typer.claim().await.expect("claims").expect("the type step");
    facts.javascript = Some(true);
    let mut tx = db.begin().await.expect("begins");
    ace_core::type_step::store_facts(&mut tx, &sha256, &facts)
        .await
        .expect("keeps the facts");
    typer
        .finish_in(&mut tx, task.id, ace_core::queue::TaskState::Done, None)
        .await
        .expect("ends");
    tx.commit().await.expect("commits");
    assert!(modules(&tasks_of(db, root).await).contains(&"test_wants_all"));
    let (_, types) = tags_and_types(&test_db, root).await;
    assert_eq!(types, ["type=script.javascript"]);

    // now kept with the check, it serves another .js name, and a name node refuses
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "z.js").await;
    assert!(!modules(&tasks_of(db, root).await).contains(&"file_type"));
    let (_, types) = tags_and_types(&test_db, root).await;
    assert_eq!(types, ["type=script.javascript"]);
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "w.JS").await;
    assert!(!modules(&tasks_of(db, root).await).contains(&"file_type"));
    let (_, types) = tags_and_types(&test_db, root).await;
    assert!(types.is_empty(), "{types:?}");
}

/// PLAN.md decision 25: a type step that fails keeps no type, so the same bytes in the next root
/// are typed again.
#[tokio::test]
async fn a_failed_type_step_keeps_nothing_and_the_next_root_types_the_bytes_again() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = typed_orchestrator();
    let sha256 = "f1".repeat(32);
    let (_, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "x.bin").await;
    let typer = type_worker(&test_db, &orchestrator).await;
    let task = typer.claim().await.expect("claims").expect("the type step");
    typer
        .fail(task.id, "libmagic crashed")
        .await
        .expect("fails");
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM store.file_types WHERE sha256 = $1")
        .bind(&sha256)
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(kept, 0);
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "x.bin").await;
    assert_eq!(modules(&tasks_of(db, root).await), ["file_type"]);
}

/// PLAN.md decisions 15 and 25: the kept type is read under the path the file will be analyzed
/// under, which is settled only once nothing nearer the root could still add a path. While a task
/// nearer the root is pending the file gets a type step, whose lease waits for the path as any
/// file's first task does; and a type kept before migration 0070, without the newer facts, is no
/// type at all.
#[tokio::test]
async fn a_kept_type_waits_for_the_file_s_path_to_be_settled() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = typed_orchestrator();
    let sha256 = "a2".repeat(32);
    keep_type(&test_db, &sha256, &pdf_facts()).await;
    let (root, ids) = root_with(db, "typed", &[(ObservableKind::Fqdn, "example.com")]).await;
    let mut tx = db.begin().await.expect("begins");
    ace_core::queue::enqueue(&mut tx, root, ids[0], "test_wants_all")
        .await
        .expect("queues");
    let file = tree::upsert_observable_at(
        &mut tx,
        root,
        &ace_results::NewObservable::new(ObservableKind::File, &sha256),
        1,
    )
    .await
    .expect("adds")
    .id;
    tree::add_file(&mut tx, root, file, "a/doc.pdf", &[])
        .await
        .expect("adds");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let on_file: Vec<String> = sqlx::query_scalar(
        "SELECT module FROM queue.tasks WHERE root_id = $1 AND observable_id = $2 ORDER BY module",
    )
    .bind(root)
    .bind(file.0)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(on_file, ["file_type"]);

    // a row from before migration 0070 is no type
    let sha256 = "a3".repeat(32);
    keep_type(&test_db, &sha256, &pdf_facts()).await;
    sqlx::query("UPDATE store.file_types SET has_har_header = NULL WHERE sha256 = $1")
        .bind(&sha256)
        .execute(db.pool())
        .await
        .expect("updates");
    assert!(
        ace_core::type_step::facts_for(db.pool(), &sha256)
            .await
            .expect("reads")
            .is_none()
    );
    let (root, _) = typed_root(&test_db, &orchestrator, "typed", &sha256, "doc.pdf").await;
    assert_eq!(modules(&tasks_of(db, root).await), ["file_type"]);
}

/// Modules whose results the analysis cache keeps (PLAN.md decision 26): a lookup on an fqdn, and a
/// parser on a file that adds a file named after the one it read.
mod cached {
    use std::time::Duration;

    use ace_results::ObservableKind;
    use ace_results::types::sandbox::QrCodeAnalysis;
    use ace_sdk::cache::{Cache, CachePaths};
    use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

    pub struct CachedLookup;

    impl Module for CachedLookup {
        const NAME: &'static str = "test_cached";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const CACHE: Option<Cache> = Some(Cache::new(1, Duration::from_secs(86_400)));
        type Output = QrCodeAnalysis;
        type Settings = serde_json::Value;

        fn init(_: &serde_json::Value) -> Result<Self, ModuleError> {
            Ok(CachedLookup)
        }
    }

    impl Lookup for CachedLookup {
        const TCP_PORTS: &'static [u16] = &[];

        async fn analyze(
            &self,
            _: &TaskContext<serde_json::Value>,
        ) -> Result<Outcome<QrCodeAnalysis>, ModuleError> {
            Ok(Outcome::Skipped("a stub".to_owned()))
        }
    }

    pub fn named(input: &str) -> Vec<String> {
        vec![format!("{input}.cached")]
    }

    pub struct CachedFiles;

    impl Module for CachedFiles {
        const NAME: &'static str = "test_cached_files";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
        const CACHE: Option<Cache> = Some(Cache {
            paths: CachePaths::Named(named),
            ..Cache::new(1, Duration::from_secs(86_400))
        });
        type Output = QrCodeAnalysis;
        type Settings = ();

        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(CachedFiles)
        }
    }

    impl Parser for CachedFiles {
        fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<QrCodeAnalysis>, ModuleError> {
            Ok(Outcome::Skipped("a stub".to_owned()))
        }
    }

    /// Keyed on the `newly-registered` read's answer, as the newly registered domains module is.
    pub struct CachedNrd;

    impl Module for CachedNrd {
        const NAME: &'static str = "test_cached_nrd";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const READS: &'static [ace_sdk::reads::Read] =
            &[<ace_sdk::reads::NewlyRegistered as ace_sdk::reads::ReadKind>::READ];
        const CACHE: Option<Cache> = Some(Cache {
            reads: &[<ace_sdk::reads::NewlyRegistered as ace_sdk::reads::ReadKind>::READ],
            ..Cache::new(1, Duration::from_secs(86_400))
        });
        type Output = QrCodeAnalysis;
        type Settings = ();

        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(CachedNrd)
        }
    }

    impl Lookup for CachedNrd {
        const TCP_PORTS: &'static [u16] = &[];

        async fn analyze(
            &self,
            _: &TaskContext<()>,
        ) -> Result<Outcome<QrCodeAnalysis>, ModuleError> {
            Ok(Outcome::Skipped("a stub".to_owned()))
        }
    }

    pub const LOOKUP: Manifest = Manifest::lookup::<CachedLookup>();
    pub const FILES: Manifest = Manifest::parser::<CachedFiles>();
    pub const NRD: Manifest = Manifest::lookup::<CachedNrd>();
}

fn cache_orchestrator(settings: Option<serde_json::Value>) -> Orchestrator {
    let mut lookup = ace_sdk::Component::of(cached::LOOKUP);
    lookup.settings = settings;
    let modes = Modes::ace3()
        .with_mode(AnalysisMode {
            name: "cache_test".to_owned(),
            module_groups: Vec::new(),
            enabled_modules: vec!["test_cached".to_owned(), "test_cached_files".to_owned()],
            disabled_modules: Vec::new(),
        })
        .with_mode(AnalysisMode {
            name: "cache_nrd".to_owned(),
            module_groups: Vec::new(),
            enabled_modules: vec!["test_cached_nrd".to_owned()],
            disabled_modules: Vec::new(),
        });
    Orchestrator::new(
        Catalog::of([
            lookup,
            ace_sdk::Component::of(cached::FILES),
            ace_sdk::Component::of(cached::NRD),
        ]),
        modes,
    )
}

async fn start(db: &ace_core::db::Db, orchestrator: &Orchestrator, root: uuid::Uuid) {
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
}

async fn kept_rows(db: &ace_core::db::Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM cache.results")
        .fetch_one(db.pool())
        .await
        .expect("counts")
}

/// Claims the one task of `module` and lands `envelope` as its result.
async fn land_one(
    test_db: &TestDb,
    orchestrator: &Orchestrator,
    module: &str,
    envelope: serde_json::Value,
) {
    let db = test_db.db();
    let pool = worker(test_db, module, &[module], Duration::from_secs(60)).await;
    let task = pool.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result_with(
            &mut tx,
            &pool,
            &task,
            &result(envelope),
            &std::collections::BTreeMap::new(),
            false,
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
}

/// The kept result's row in a root: its summary, its details and its `cached_at`.
async fn result_in(
    db: &ace_core::db::Db,
    root: uuid::Uuid,
    module: &str,
) -> Option<(
    Option<String>,
    serde_json::Value,
    Option<chrono::DateTime<chrono::Utc>>,
)> {
    sqlx::query_as(
        "SELECT summary, details, cached_at FROM analysis.results WHERE root_id = $1 AND module = $2",
    )
    .bind(root)
    .bind(module)
    .fetch_optional(db.pool())
    .await
    .expect("reads")
}

fn found() -> serde_json::Value {
    json!({
        "analysis_type": "qr_code_analysis", "schema_version": 1,
        "details": {"extracted_text": "http://found.example/", "inverted": false},
        "summary": "found it",
        "analyzed": {"tags": ["seen"]},
        "observables": [{"type": "fqdn", "value": "child.example"}],
    })
}

/// A cacheable module's result is kept, and the next root with the same observable gets it as the
/// module's result, marked with when the task that made it ended, with what it adds, and no task.
#[tokio::test]
async fn a_kept_result_stands_in_for_the_task_in_a_later_root() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = cache_orchestrator(None);
    let (first, _) = root_with(db, "cache_test", &[(ObservableKind::Fqdn, "kept.example")]).await;
    start(db, &orchestrator, first).await;
    assert_eq!(
        tasks_of(db, first).await,
        [(
            "test_cached".to_owned(),
            "kept.example".to_owned(),
            "queued".to_owned()
        )]
    );
    land_one(&test_db, &orchestrator, "test_cached", found()).await;
    assert_eq!(kept_rows(db).await, 1);
    let (summary, details, cached_at) =
        result_in(db, first, "test_cached").await.expect("a result");
    assert_eq!(cached_at, None, "a task's own result isn't from the cache");

    let (second, _) = root_with(db, "cache_test", &[(ObservableKind::Fqdn, "kept.example")]).await;
    start(db, &orchestrator, second).await;
    // no task for the kept one; the fqdn its result added has one of its own, a miss
    assert_eq!(
        tasks_of(db, second).await,
        [(
            "test_cached".to_owned(),
            "child.example".to_owned(),
            "queued".to_owned()
        )]
    );
    let created: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT created_at FROM cache.results")
            .fetch_one(db.pool())
            .await
            .expect("reads");
    let hit = result_in(db, second, "test_cached")
        .await
        .expect("a result");
    assert_eq!(hit, (summary, details, Some(created)));
    let tags: Vec<String> = sqlx::query_scalar(
        "SELECT tags FROM analysis.observables WHERE root_id = $1 AND value = 'kept.example'",
    )
    .bind(second)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(tags, ["seen"]);
    let added: Vec<String> = sqlx::query_scalar(
        "SELECT o.value FROM analysis.result_additions a
         JOIN analysis.observables o ON o.root_id = a.root_id AND o.id = a.observable_id
         WHERE a.root_id = $1",
    )
    .bind(second)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(added, ["child.example"]);
    // the pass's metrics count the first root's miss and keep and the second's hit and miss
    let activity: Vec<(uuid::Uuid, i32, i32, i32)> = sqlx::query_as(
        "SELECT root_id, hits, misses, writes FROM cache.activity
         WHERE module = 'test_cached' ORDER BY hits, root_id",
    )
    .fetch_all(db.pool())
    .await
    .expect("reads");
    let mut expected = vec![(first, 0, 2, 1), (second, 1, 1, 0)];
    expected.sort_by_key(|(root, hits, ..)| (*hits, *root));
    assert_eq!(
        activity, expected,
        "first: kept.example and child.example missed"
    );
    // a hit's root is in a pass, as a task's would be
    let open: bool =
        sqlx::query_scalar("SELECT pass > completed_pass FROM analysis.roots WHERE id = $1")
            .bind(second)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert!(open);
}

/// PLAN.md decision 47: a result its module asked not to be kept (`Outcome::DoneNotKept`, as a
/// lookup answers for a hash its vendor doesn't know) lands in its root as any result does, isn't
/// kept, and the next root's lookup misses and queues a task; a plain `Done` is still kept.
#[tokio::test]
async fn a_result_its_module_asked_not_to_keep_lands_and_isn_t_kept() {
    use ace_core::orchestrator::Ending;
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = cache_orchestrator(None);
    let queued = |value: &str| {
        (
            "test_cached".to_owned(),
            value.to_owned(),
            "queued".to_owned(),
        )
    };
    let land = |ending: Ending| {
        let (test_db, orchestrator) = (&test_db, &orchestrator);
        async move {
            let pool = worker(
                test_db,
                "test_cached",
                &["test_cached"],
                Duration::from_secs(60),
            )
            .await;
            let task = pool.claim().await.expect("claims").expect("a task");
            let mut tx = test_db.db().begin().await.expect("begins");
            orchestrator
                .land_ending(
                    &mut tx,
                    &pool,
                    &task,
                    &result(json!({
                        "analysis_type": "qr_code_analysis", "schema_version": 1,
                        "details": {"extracted_text": "", "inverted": false},
                        "summary": "unknown",
                    })),
                    &std::collections::BTreeMap::new(),
                    false,
                    ending,
                )
                .await
                .expect("lands");
            tx.commit().await.expect("commits");
        }
    };

    let (first, _) = root_with(
        db,
        "cache_test",
        &[(ObservableKind::Fqdn, "unknown.example")],
    )
    .await;
    start(db, &orchestrator, first).await;
    land(Ending::DoneNotKept).await;
    let (summary, _, cached_at) = result_in(db, first, "test_cached")
        .await
        .expect("it lands in its root");
    assert_eq!((summary.as_deref(), cached_at), (Some("unknown"), None));
    assert_eq!(
        tasks_of(db, first).await,
        [(
            "test_cached".to_owned(),
            "unknown.example".to_owned(),
            "done".to_owned()
        )]
    );
    assert_eq!(kept_rows(db).await, 0, "not kept");
    // the next root misses: no result from the cache, and a task of its own
    let (second, _) = root_with(
        db,
        "cache_test",
        &[(ObservableKind::Fqdn, "unknown.example")],
    )
    .await;
    start(db, &orchestrator, second).await;
    assert_eq!(result_in(db, second, "test_cached").await, None);
    assert_eq!(tasks_of(db, second).await, [queued("unknown.example")]);
    let misses: i32 = sqlx::query_scalar(
        "SELECT misses FROM cache.activity WHERE module = 'test_cached' AND root_id = $1",
    )
    .bind(second)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(misses, 1);
    // that task ends with a plain result, which is kept, and a third root takes it
    land(Ending::Done).await;
    assert_eq!(kept_rows(db).await, 1);
    let (third, _) = root_with(
        db,
        "cache_test",
        &[(ObservableKind::Fqdn, "unknown.example")],
    )
    .await;
    start(db, &orchestrator, third).await;
    assert!(tasks_of(db, third).await.is_empty(), "a hit, no task");
    let (_, _, cached_at) = result_in(db, third, "test_cached")
        .await
        .expect("the kept result");
    assert!(cached_at.is_some());
}

/// What isn't kept (a result with an error) and what misses: other settings, an expired row, and the
/// cache turned off, which neither looks up nor keeps.
#[tokio::test]
async fn an_error_isnt_kept_and_other_settings_an_expired_row_or_the_switch_miss() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = cache_orchestrator(None);
    let root = |value: &'static str| async move {
        root_with(db, "cache_test", &[(ObservableKind::Fqdn, value)])
            .await
            .0
    };

    // a result whose module said it failed is not kept
    let failed = root("failed.example").await;
    start(db, &orchestrator, failed).await;
    let mut errored = found();
    errored["error"] = json!("the lookup failed");
    land_one(&test_db, &orchestrator, "test_cached", errored).await;
    assert_eq!(kept_rows(db).await, 0);

    // kept once; then a root under other settings misses
    let kept = root("kept.example").await;
    start(db, &orchestrator, kept).await;
    land_one(&test_db, &orchestrator, "test_cached", found()).await;
    assert_eq!(kept_rows(db).await, 1);
    let other = cache_orchestrator(Some(json!({"anything": 1})));
    let elsewhere = root("kept.example").await;
    start(db, &other, elsewhere).await;
    assert_eq!(result_in(db, elsewhere, "test_cached").await, None);
    assert!(tasks_of(db, elsewhere).await.contains(&(
        "test_cached".to_owned(),
        "kept.example".to_owned(),
        "queued".to_owned()
    )));

    // with the cache off nothing is looked up or kept
    let off = cache_orchestrator(None).with_cache(ace_core::cache::CacheSettings::off());
    let unseen = root("kept.example").await;
    start(db, &off, unseen).await;
    assert_eq!(result_in(db, unseen, "test_cached").await, None);

    // an expired row is no hit
    sqlx::query("UPDATE cache.results SET expires_at = now()")
        .execute(db.pool())
        .await
        .expect("expires");
    let later = root("kept.example").await;
    start(db, &orchestrator, later).await;
    assert_eq!(result_in(db, later, "test_cached").await, None);
}

/// A kept result's file is held by its row, and a hit names it after the new root's path, puts it in
/// the root and holds it for the root; a result that adds a file at a path its module doesn't name
/// isn't kept.
#[tokio::test]
async fn a_kept_file_is_named_after_the_new_root_s_path_and_held() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = cache_orchestrator(None);
    let (input, output) = ("1".repeat(64), "2".repeat(64));
    for sha256 in [&input, &output] {
        sqlx::query("INSERT INTO store.objects (pool, sha256, size) VALUES ('alert_files', $1, 3)")
            .bind(sha256)
            .execute(db.pool())
            .await
            .expect("an object");
    }
    let root_at = |path: &'static str| {
        let input = input.clone();
        async move {
            let (root, ids) = root_with(db, "cache_test", &[(ObservableKind::File, &input)]).await;
            let mut tx = db.begin().await.expect("begins");
            tree::add_file(&mut tx, root, ids[0], path, &[])
                .await
                .expect("a path");
            tx.commit().await.expect("commits");
            root
        }
    };
    let envelope = |path: &str| {
        json!({
            "analysis_type": "qr_code_analysis", "schema_version": 1,
            "details": {"extracted_text": null, "inverted": false},
            "files": [{"path": path, "sha256": output, "size": 3, "tags": ["qr-code"]}],
        })
    };
    let first = root_at("a/x.png").await;
    start(db, &orchestrator, first).await;
    land_one(
        &test_db,
        &orchestrator,
        "test_cached_files",
        envelope("a/x.png.cached"),
    )
    .await;
    let (places, files): (Vec<i32>, Vec<String>) =
        sqlx::query_as("SELECT file_paths, files FROM cache.results")
            .fetch_one(db.pool())
            .await
            .expect("a row");
    assert_eq!((places, files), (vec![0], vec![output.clone()]));
    let held: (String, bool) = sqlx::query_as(
        "SELECT h.holder_id, h.expires_at = r.expires_at FROM store.holds h
         JOIN cache.results r ON r.id::text = h.holder_id
         WHERE h.holder_kind = 'cache' AND h.sha256 = $1",
    )
    .bind(&output)
    .fetch_one(db.pool())
    .await
    .expect("the row holds its file until it expires");
    assert!(held.1, "{held:?}");

    let second = root_at("b/y.png").await;
    start(db, &orchestrator, second).await;
    // no task for the file it read; the file the hit added gets its own, a miss
    assert_eq!(
        tasks_of(db, second).await,
        [(
            "test_cached_files".to_owned(),
            output.clone(),
            "queued".to_owned()
        )]
    );
    let paths: Vec<String> = sqlx::query_scalar(
        "SELECT f.path FROM analysis.files f JOIN analysis.observables o
           ON o.root_id = f.root_id AND o.id = f.observable_id
         WHERE f.root_id = $1 AND o.value = $2",
    )
    .bind(second)
    .bind(&output)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(paths, ["b/y.png.cached"]);
    let root_hold: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM store.holds WHERE holder_kind = 'root' AND holder_id = $1 AND sha256 = $2",
    )
    .bind(second.to_string())
    .bind(&output)
    .fetch_one(db.pool())
    .await
    .expect("counts");
    assert_eq!(root_hold, 1);
    // the hit settled the file's path, as its lease would have
    let analyzed: Vec<String> =
        sqlx::query_scalar("SELECT path FROM analysis.files WHERE root_id = $1 AND analyzed")
            .bind(second)
            .fetch_all(db.pool())
            .await
            .expect("reads");
    assert_eq!(analyzed, ["b/y.png"]);

    // a file the module didn't name after its input isn't kept
    sqlx::query("DELETE FROM cache.results")
        .execute(db.pool())
        .await
        .expect("empties");
    let third = root_at("c/z.png").await;
    start(db, &orchestrator, third).await;
    land_one(
        &test_db,
        &orchestrator,
        "test_cached_files",
        envelope("elsewhere.cached"),
    )
    .await;
    assert_eq!(kept_rows(db).await, 0);
}

/// A module keyed on the `newly-registered` read's answer gets a hit while the name's listing is the
/// same, and misses once it changes, as ace3's key changes with its database's version.
#[tokio::test]
async fn a_keyed_read_s_answer_is_in_the_key() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = cache_orchestrator(None);
    sqlx::query("INSERT INTO nrd.domains (domain) VALUES ('new.example')")
        .execute(db.pool())
        .await
        .expect("lists it");
    let root = || async {
        root_with(db, "cache_nrd", &[(ObservableKind::Fqdn, "new.example")])
            .await
            .0
    };
    let first = root().await;
    start(db, &orchestrator, first).await;
    let tagged = json!({
        "analysis_type": "qr_code_analysis", "schema_version": 1,
        "details": {"extracted_text": null, "inverted": false},
        "analyzed": {"tags": ["suspect:nrd"]},
    });
    land_one(&test_db, &orchestrator, "test_cached_nrd", tagged.clone()).await;
    let second = root().await;
    start(db, &orchestrator, second).await;
    assert!(
        result_in(db, second, "test_cached_nrd")
            .await
            .expect("a hit")
            .2
            .is_some()
    );
    sqlx::query("DELETE FROM nrd.domains")
        .execute(db.pool())
        .await
        .expect("empties");
    let third = root().await;
    start(db, &orchestrator, third).await;
    assert_eq!(
        result_in(db, third, "test_cached_nrd").await,
        None,
        "the answer changed"
    );
    assert!(tasks_of(db, third).await.contains(&(
        "test_cached_nrd".to_owned(),
        "new.example".to_owned(),
        "queued".to_owned()
    )));
}

/// A lookup that does nothing, held to an automation limit in the tests below.
mod limited {
    use ace_results::ObservableKind;
    use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};

    use super::common::stubs::StubOutput;

    pub struct Limited;

    impl Module for Limited {
        const NAME: &'static str = "test_limited";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const AUTOMATION_LIMIT: Option<u32> = Some(2);
        type Output = StubOutput;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(Limited)
        }
    }

    impl Lookup for Limited {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, _: &TaskContext<()>) -> Result<Outcome<StubOutput>, ModuleError> {
            Ok(Outcome::Skipped("a stub".to_owned()))
        }
    }
}

/// ace3's automation limit (`ace_core::limits`): a root holds at most the limit of a type's results
/// and tasks, an observable with `ignore_automation_limits` isn't held to it but counts, the work
/// over it is recorded, and a task that ends with no result frees a place, which the work held back
/// takes, oldest first. The same with the module cacheable, whose limit is checked where its lookup
/// is made, and with a second instance, which counts with the first.
#[tokio::test]
async fn the_automation_limit_holds_a_root_to_its_limit_and_a_skip_frees_a_place() {
    use ace_core::limits::IGNORE_AUTOMATION_LIMITS;
    use ace_sdk::Component;
    for (cacheable, instance) in [(false, false), (true, false), (false, true)] {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let mut manifest = ace_sdk::Manifest::lookup::<limited::Limited>();
        let mut component = Component::of(manifest);
        if cacheable {
            manifest.cache = Some(ace_sdk::cache::Cache::new(1, Duration::from_secs(600)));
            component = Component {
                cache_ttl: Some(Duration::from_secs(600)),
                ..Component::of(manifest)
            };
        }
        let mut components = vec![component.clone()];
        if instance {
            // a second instance of the same type, with no limit of its own, counts with the first
            components.push(Component {
                key: "test_limited_b".to_owned(),
                automation_limit: None,
                ..component.clone()
            });
        }
        let modes = Modes::ace3().with_mode(AnalysisMode {
            name: "limits".to_owned(),
            module_groups: Vec::new(),
            enabled_modules: components.iter().map(|c| c.key.clone()).collect(),
            disabled_modules: Vec::new(),
        });
        let orchestrator = Orchestrator::new(Catalog::of(components), modes);
        let mut tx = db.begin().await.expect("begins");
        let root = tree::NewRoot::new("limits");
        tree::create_root(&mut tx, &root).await.expect("creates");
        for (value, lifted) in [
            ("a.example", false),
            ("b.example", false),
            ("c.example", false),
            ("d.example", true),
        ] {
            let mut observable = ace_results::NewObservable::new(ObservableKind::Fqdn, value);
            if lifted {
                observable.directives = vec![IGNORE_AUTOMATION_LIMITS.to_owned()];
            }
            tree::upsert_observable(&mut tx, root.id, &observable)
                .await
                .expect("adds");
        }
        orchestrator.start(&mut tx, root.id).await.expect("starts");
        tx.commit().await.expect("commits");
        let root = root.id;
        let limited = |module: &'static str| async move {
            sqlx::query_scalar::<_, String>(
                "SELECT o.value FROM analysis.automation_limited l
                 JOIN analysis.observables o ON o.root_id = l.root_id AND o.id = l.observable_id
                 WHERE l.root_id = $1 AND l.module = $2 ORDER BY o.value",
            )
            .bind(root)
            .bind(module)
            .fetch_all(db.pool())
            .await
            .expect("reads")
        };
        let queued = |module: &'static str| async move {
            tasks_of(db, root)
                .await
                .into_iter()
                .filter(|(m, _, state)| m == module && state == "queued")
                .map(|(_, value, _)| value)
                .collect::<BTreeSet<String>>()
        };
        let set = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect();
        let what = format!("cacheable {cacheable}, an instance {instance}");
        if instance {
            // each instance's tasks count against the first's limit: two of eight places taken
            // by the first two observables of either, the lifted one queued for both
            let first = queued("test_limited").await;
            let second = queued("test_limited_b").await;
            assert_eq!(first, set(&["a.example", "d.example"]), "{what}");
            assert_eq!(
                second,
                set(&["a.example", "b.example", "c.example", "d.example"]),
                "{what}: the instance with no limit isn't held"
            );
            assert_eq!(
                limited("test_limited").await,
                ["b.example", "c.example"],
                "{what}"
            );
            continue;
        }
        // two places, and the lifted observable queued over them
        assert_eq!(
            queued("test_limited").await,
            set(&["a.example", "b.example", "d.example"]),
            "{what}"
        );
        assert_eq!(limited("test_limited").await, ["c.example"], "{what}");
        let worker = worker(&test_db, "w", &["test_limited"], Duration::from_secs(60))
            .await
            .with_ended(std::sync::Arc::new(orchestrator.clone()));
        let end_one = |value: &'static str| {
            let worker = worker.clone();
            async move {
                let id: i64 = sqlx::query_scalar(
                    "SELECT t.id FROM queue.tasks t
                     JOIN analysis.observables o ON o.root_id = t.root_id AND o.id = t.observable_id
                     WHERE t.root_id = $1 AND o.value = $2",
                )
                .bind(root)
                .bind(value)
                .fetch_one(db.pool())
                .await
                .expect("a task");
                loop {
                    let task = worker.claim().await.expect("claims").expect("a task");
                    if task.id.0 == id {
                        worker.complete(task.id).await.expect("skips");
                        return;
                    }
                    worker.release(task.id).await.expect("releases");
                }
            }
        };
        // a's skip frees a place, but d's task still counts: c waits
        end_one("a.example").await;
        assert_eq!(limited("test_limited").await, ["c.example"], "{what}");
        // b's frees another: c takes it, and its record goes
        end_one("b.example").await;
        assert!(queued("test_limited").await.contains("c.example"), "{what}");
        assert!(limited("test_limited").await.is_empty(), "{what}");
    }
}

/// Modules for the tests of a dependency that won't store a result (PLAN.md decision 30):
/// `test_dep` takes an FQDN its declaration doesn't decline, `test_dependent` takes an FQDN or a file
/// and depends on it, and `test_chained` depends on `test_dependent`.
mod settles {
    use ace_results::ObservableKind;
    use ace_sdk::takes::{Condition, Takes};
    use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};

    use super::common::stubs::StubOutput;

    pub const DECLINE: &str = "test_decline";
    pub const SKIP: &str = "test_skip";

    macro_rules! stub {
        ($ty:ident) => {
            pub struct $ty;

            impl Lookup for $ty {
                const TCP_PORTS: &'static [u16] = &[];
                async fn analyze(
                    &self,
                    _: &TaskContext<()>,
                ) -> Result<Outcome<StubOutput>, ModuleError> {
                    Ok(Outcome::Skipped("a stub".to_owned()))
                }
            }
        };
    }

    stub!(Dep);
    stub!(Dependent);
    stub!(Chained);

    impl Module for Dep {
        const NAME: &'static str = "test_dep";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const SKIP_DIRECTIVES: &'static [&'static str] = &[SKIP];
        type Output = StubOutput;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(Dep)
        }
        fn takes(_: &()) -> Takes {
            Takes::everything().and(
                Condition::Directive(DECLINE.to_owned()).negated(),
                "the test's directive",
            )
        }
    }

    impl Module for Dependent {
        const NAME: &'static str = "test_dependent";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn, ObservableKind::File];
        const DEPENDS_ON: &'static [&'static str] = &["test_dep"];
        type Output = StubOutput;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(Dependent)
        }
    }

    impl Module for Chained {
        const NAME: &'static str = "test_chained";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const DEPENDS_ON: &'static [&'static str] = &["test_dependent"];
        type Output = StubOutput;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(Chained)
        }
    }

    pub fn manifests() -> Vec<ace_sdk::Manifest> {
        vec![
            ace_sdk::Manifest::lookup::<Dep>(),
            ace_sdk::Manifest::lookup::<Dependent>(),
            ace_sdk::Manifest::lookup::<Chained>(),
        ]
    }
}

fn settles_modes() -> Modes {
    Modes::ace3().with_mode(AnalysisMode {
        name: "settles".to_owned(),
        module_groups: Vec::new(),
        enabled_modules: strings(&["test_dep", "test_dependent", "test_chained"]),
        disabled_modules: Vec::new(),
    })
}

/// What settles a dependency, as ace3's `_seed_declared_dependencies` counts one met: a result, a
/// task that ended, or no task because the dependency doesn't take the observable; not a task still
/// to end, and not one that waits on its own dependency.
#[test]
fn a_dependency_settles_when_it_wont_store_a_result() {
    use ace_core::eligibility::{TaskSeen, settle};
    fn settled<'a>(
        catalog: &'a Catalog,
        facts: Facts<'_>,
        results: &[&'a str],
        tasks: &[(&str, TaskSeen)],
    ) -> BTreeSet<&'a str> {
        let modes = settles_modes();
        let mode_modules = modes.modules_in("settles");
        let mut settled: BTreeSet<&str> = results.iter().copied().collect();
        settle(catalog, facts, &mode_modules, &mut settled, |key| {
            tasks
                .iter()
                .find(|(k, _)| *k == key)
                .map_or(TaskSeen::None, |(_, seen)| *seen)
        });
        settled
    }
    let catalog = Catalog::new(settles::manifests());
    let skip = strings(&[settles::SKIP]);
    let facts = |kind, directives| Facts {
        kind,
        directives,
        exclude_modules: &[],
        limit_modules: &[],
    };
    let fqdn = facts(ObservableKind::Fqdn, &[]);
    let kept_off = facts(ObservableKind::Fqdn, &skip);
    let file = facts(ObservableKind::File, &[]);
    let set = |keys: &[&'static str]| keys.iter().copied().collect::<BTreeSet<&str>>();
    // nothing ran yet: the dependency will, and the rest wait on it
    assert_eq!(settled(&catalog, fqdn, &[], &[]), set(&[]));
    assert_eq!(
        settled(&catalog, fqdn, &[], &[("test_dep", TaskSeen::Active)]),
        set(&[]),
        "a task still to end"
    );
    assert_eq!(
        settled(
            &catalog,
            fqdn,
            &["test_dep"],
            &[("test_dep", TaskSeen::Ended)]
        ),
        set(&["test_dep"]),
        "a result"
    );
    assert_eq!(
        settled(&catalog, fqdn, &[], &[("test_dep", TaskSeen::Ended)]),
        set(&["test_dep"]),
        "a task that ended with no result: skipped or failed"
    );
    // a dependency that doesn't take the observable, and what doesn't take it either
    assert_eq!(
        settled(&catalog, file, &[], &[]),
        set(&["test_dep", "test_chained"]),
        "a type it doesn't take"
    );
    assert_eq!(
        settled(&catalog, kept_off, &[], &[]),
        set(&["test_dep"]),
        "a directive that keeps it off"
    );
    assert_eq!(
        settled(
            &catalog,
            kept_off,
            &[],
            &[("test_dependent", TaskSeen::Ended)]
        ),
        set(&["test_dep", "test_dependent"]),
    );
    // the rule over them
    let modes = settles_modes();
    let mode_modules = modes.modules_in("settles");
    let component = catalog.component("test_dependent").expect("known");
    assert_eq!(
        check(component, fqdn, &mode_modules, &set(&[])),
        Err(Ineligible::WaitingFor("test_dep".to_owned()))
    );
    assert_eq!(
        check(
            component,
            kept_off,
            &mode_modules,
            &settled(&catalog, kept_off, &[], &[])
        ),
        Ok(())
    );
}

/// A dependency that ended with no result, or that gets no task, lets what depends on it run, as
/// ace3 counts a dependency that declined, was skipped, failed or doesn't take the observable as met
/// (PLAN.md decision 30); one that was cancelled leaves it waiting (ace3 #846). In both of the
/// declarations' modes: applied, where a declined dependency gets no task, and audited, where its
/// task is queued and ends skipped.
#[tokio::test]
async fn a_dependency_that_stores_no_result_lets_its_dependents_run() {
    use ace_core::takes::TakesMode;
    for takes in [TakesMode::Applied, TakesMode::Audit] {
        let test_db = TestDb::new().await;
        let db = test_db.db();
        let orchestrator = Orchestrator::new(Catalog::new(settles::manifests()), settles_modes())
            .with_takes(takes);
        let mut tx = db.begin().await.expect("begins");
        let new_root = tree::NewRoot::new("settles");
        tree::create_root(&mut tx, &new_root)
            .await
            .expect("creates");
        let root = new_root.id;
        for (kind, value, directives) in [
            (ObservableKind::Fqdn, "result.example", &[][..]),
            (ObservableKind::Fqdn, "skipped.example", &[]),
            (ObservableKind::Fqdn, "failed.example", &[]),
            (ObservableKind::Fqdn, "expired.example", &[]),
            (ObservableKind::Fqdn, "cancelled.example", &[]),
            (
                ObservableKind::Fqdn,
                "declined.example",
                &[settles::DECLINE],
            ),
            (ObservableKind::Fqdn, "kept-off.example", &[settles::SKIP]),
            (ObservableKind::File, EMAIL_SHA256, &[]),
        ] {
            let mut observable = ace_results::NewObservable::new(kind, value);
            observable.directives = strings(directives);
            tree::upsert_observable(&mut tx, root, &observable)
                .await
                .expect("adds");
        }
        orchestrator.start(&mut tx, root).await.expect("starts");
        tx.commit().await.expect("commits");
        let state = |module: &'static str, value: &'static str| async move {
            tasks_of(db, root)
                .await
                .into_iter()
                .find(|(m, v, _)| m == module && v == value)
                .map(|(_, _, state)| state)
        };
        let what = format!("{takes:?}");
        let queued = Some("queued".to_owned());
        // waiting on the dependency's task
        assert_eq!(state("test_dep", "result.example").await, queued, "{what}");
        assert_eq!(
            state("test_dependent", "result.example").await,
            None,
            "{what}"
        );
        // no task for a dependency that doesn't take the observable: met at once
        assert_eq!(state("test_dep", "kept-off.example").await, None, "{what}");
        assert_eq!(
            state("test_dependent", "kept-off.example").await,
            queued,
            "{what}: a directive keeps the dependency off"
        );
        assert_eq!(
            state("test_dependent", EMAIL_SHA256).await,
            queued,
            "{what}: the dependency doesn't take files"
        );
        // its declaration declines it: no task when applied, a marked one when audited
        if takes == TakesMode::Applied {
            assert_eq!(state("test_dep", "declined.example").await, None, "{what}");
            assert_eq!(
                state("test_dependent", "declined.example").await,
                queued,
                "{what}: declined"
            );
        } else {
            assert_eq!(
                state("test_dep", "declined.example").await,
                queued,
                "{what}"
            );
            assert_eq!(
                state("test_dependent", "declined.example").await,
                None,
                "{what}"
            );
        }

        let worker = worker(&test_db, "w", &["test_dep"], Duration::from_secs(60))
            .await
            .with_ended(std::sync::Arc::new(orchestrator.clone()));
        // every task of the dependency, claimed at once and ended one at a time below
        let mut claimed = Vec::new();
        while let Some(task) = worker.claim().await.expect("claims") {
            claimed.push(task);
        }
        let task_on = |value: &'static str| {
            let claimed = &claimed;
            async move {
                let id: i64 = sqlx::query_scalar(
                    "SELECT t.id FROM queue.tasks t
                     JOIN analysis.observables o ON o.root_id = t.root_id AND o.id = t.observable_id
                     WHERE t.root_id = $1 AND o.value = $2 AND t.module = 'test_dep'",
                )
                .bind(root)
                .bind(value)
                .fetch_one(db.pool())
                .await
                .expect("a task");
                claimed
                    .iter()
                    .find(|task: &&ace_core::queue::Task| task.id.0 == id)
                    .expect("claimed")
                    .clone()
            }
        };

        // a result
        let task = task_on("result.example").await;
        let mut tx = db.begin().await.expect("begins");
        orchestrator
            .land_result(
                &mut tx,
                &worker,
                &task,
                &result(json!({
                    "analysis_type": "test_stub",
                    "schema_version": 1,
                    "details": {},
                })),
            )
            .await
            .expect("lands");
        tx.commit().await.expect("commits");
        assert_eq!(
            state("test_dependent", "result.example").await,
            queued,
            "{what}"
        );
        assert_eq!(
            state("test_chained", "result.example").await,
            None,
            "{what}: waits on test_dependent, which waited itself"
        );

        // skipped, which is how a declined task ends when audited
        let task = task_on("skipped.example").await;
        worker.complete(task.id).await.expect("skips");
        assert_eq!(
            state("test_dependent", "skipped.example").await,
            queued,
            "{what}"
        );
        if takes == TakesMode::Audit {
            let task = task_on("declined.example").await;
            worker.complete(task.id).await.expect("skips");
            assert_eq!(
                state("test_dependent", "declined.example").await,
                queued,
                "{what}: declined"
            );
        }

        // failed
        let task = task_on("failed.example").await;
        worker.fail(task.id, "it broke").await.expect("fails");
        assert_eq!(
            state("test_dependent", "failed.example").await,
            queued,
            "{what}"
        );

        // its lease ran out on its last attempt, as when it passes its deadline
        let task = task_on("expired.example").await;
        sqlx::query(
            "UPDATE queue.tasks SET attempts = max_attempts, lease_expires_at = now() - interval '1 second'
             WHERE id = $1",
        )
        .bind(task.id.0)
        .execute(db.pool())
        .await
        .expect("expires");
        let reaped = ace_core::queue::reap_expired_leases(db, Some(&orchestrator))
            .await
            .expect("reaps");
        assert_eq!(reaped.failed, [task.id], "{what}");
        assert_eq!(
            state("test_dependent", "expired.example").await,
            queued,
            "{what}"
        );

        // cancelled: it may run again, so what depends on it waits
        let task = task_on("cancelled.example").await;
        worker.cancelled(task.id).await.expect("cancels");
        assert_eq!(
            state("test_dep", "cancelled.example").await.as_deref(),
            Some("cancelled"),
            "{what}"
        );
        assert_eq!(
            state("test_dependent", "cancelled.example").await,
            None,
            "{what}: a cancelled dependency"
        );
    }
}

/// A dependency its automation limit holds gets no task, which ace3 counts as met: its `accepts`
/// is false over the limit (PLAN.md decision 30).
#[tokio::test]
async fn a_dependency_its_automation_limit_holds_lets_its_dependents_run() {
    use ace_sdk::Component;
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let components = settles::manifests().into_iter().map(|manifest| {
        let component = Component::of(manifest);
        if component.key == "test_dep" {
            Component {
                automation_limit: Some(1),
                ..component
            }
        } else {
            component
        }
    });
    let orchestrator = Orchestrator::new(Catalog::of(components), settles_modes());
    let (root, _) = root_with(
        db,
        "settles",
        &[
            (ObservableKind::Fqdn, "a.example"),
            (ObservableKind::Fqdn, "b.example"),
        ],
    )
    .await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");
    let tasks = tasks_of(db, root).await;
    let state = |module: &str, value: &str| {
        tasks
            .iter()
            .find(|(m, v, _)| m == module && v == value)
            .map(|(_, _, state)| state.as_str())
    };
    // the first takes the one place and its dependent waits; the second is held, and its runs
    assert_eq!(state("test_dep", "a.example"), Some("queued"));
    assert_eq!(state("test_dependent", "a.example"), None);
    assert_eq!(state("test_dep", "b.example"), None);
    assert_eq!(state("test_dependent", "b.example"), Some("queued"));
}

// ----- PLAN.md decision 34: a module's incomplete result, run again on a change

/// Two lookups on an fqdn that do nothing themselves (the tests end their tasks), and one limited to
/// one result of its type in a root, ace3's `automation_limit`.
mod rerun {
    use ace_results::ObservableKind;
    use ace_results::types::sandbox::QrCodeAnalysis;
    use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};

    macro_rules! stub {
        ($ty:ident, $name:literal, $limit:expr) => {
            pub struct $ty;
            impl Module for $ty {
                const NAME: &'static str = $name;
                const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
                const AUTOMATION_LIMIT: Option<u32> = $limit;
                type Output = QrCodeAnalysis;
                type Settings = ();
                fn init(_: &()) -> Result<Self, ModuleError> {
                    Ok($ty)
                }
            }
            impl Lookup for $ty {
                const TCP_PORTS: &'static [u16] = &[];
                async fn analyze(
                    &self,
                    _: &TaskContext<()>,
                ) -> Result<Outcome<QrCodeAnalysis>, ModuleError> {
                    Ok(Outcome::Skipped("a stub".to_owned()))
                }
            }
        };
    }
    stub!(Unfinished, "test_unfinished", None);
    stub!(Other, "test_other", None);
    stub!(Limited, "test_limited", Some(1));

    pub const UNFINISHED: Manifest = Manifest::lookup::<Unfinished>();
    pub const OTHER: Manifest = Manifest::lookup::<Other>();
    pub const LIMITED: Manifest = Manifest::lookup::<Limited>();
}

/// The modes: `rerun_test` runs the three, and `rerun_other_mode` only `test_other`.
fn rerun_orchestrator() -> Orchestrator {
    let modules = ["test_unfinished", "test_other", "test_limited"];
    let mode = |name: &str, enabled: &[&str]| AnalysisMode {
        name: name.to_owned(),
        module_groups: Vec::new(),
        enabled_modules: enabled.iter().map(|m| (*m).to_owned()).collect(),
        disabled_modules: Vec::new(),
    };
    let modes = Modes::ace3()
        .with_mode(mode("rerun_test", &modules))
        .with_mode(mode("rerun_other_mode", &["test_other"]))
        .with_mode(mode("rerun_alone", &["test_unfinished"]));
    Orchestrator::new(
        Catalog::new([rerun::UNFINISHED, rerun::OTHER, rerun::LIMITED]),
        modes,
    )
}

/// Claims `module`'s due task and lands `envelope`, as incomplete or not.
async fn land_as(
    test_db: &TestDb,
    orchestrator: &Orchestrator,
    module: &str,
    envelope: serde_json::Value,
    incomplete: bool,
) {
    let db = test_db.db();
    let pool = worker(test_db, module, &[module], Duration::from_secs(60)).await;
    let task = pool.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_ending(
            &mut tx,
            &pool,
            &task,
            &result(envelope),
            &std::collections::BTreeMap::new(),
            false,
            if incomplete {
                ace_core::orchestrator::Ending::Incomplete
            } else {
                ace_core::orchestrator::Ending::Done
            },
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
}

fn qr(text: &str) -> serde_json::Value {
    json!({
        "analysis_type": "qr_code_analysis", "schema_version": 1,
        "details": {"extracted_text": text, "inverted": false},
        "summary": text,
    })
}

/// The state of `module`'s task on the root's first observable, and whether it ended incomplete.
async fn state_of(db: &ace_core::db::Db, root: uuid::Uuid, module: &str) -> (String, bool) {
    sqlx::query_as(
        "SELECT state::text, incomplete FROM queue.tasks WHERE root_id = $1 AND module = $2
         AND observable_id = (SELECT min(id) FROM analysis.observables WHERE root_id = $1)",
    )
    .bind(root)
    .bind(module)
    .fetch_one(db.pool())
    .await
    .expect("a task")
}

async fn eligible_again(
    db: &ace_core::db::Db,
    orchestrator: &Orchestrator,
    root: uuid::Uuid,
    on: tree::ObservableId,
) {
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .queue_eligible(&mut tx, root, Scope::Observables(&[on]), false)
        .await
        .expect("eligibility");
    tx.commit().await.expect("commits");
}

/// ace3's engine runs a module again on an analysis it returned INCOMPLETE from whenever the
/// observable gains a tag, a directive, a relationship or an analysis, and in the root's next pass,
/// with no limit; each run's result replaces the last, keeping what earlier runs added once. The
/// first incomplete result is itself an analysis added, so it runs once more at once, as ace3's
/// work stack holds the observable again; a rerun that changes nothing doesn't. A complete run ends
/// it, a failed task stays failed, and the root completes between runs.
#[tokio::test]
async fn an_incomplete_result_runs_again_on_each_change_and_on_the_next_pass() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = rerun_orchestrator();
    let (root, ids) = root_with(db, "rerun_test", &[(ObservableKind::Fqdn, "a.example")]).await;
    let fqdn = ids[0];
    start(db, &orchestrator, root).await;
    let mut first = qr("first");
    // an observable no module of the test takes, so the only task is the one under test
    first["observables"] = json!([{"type": "ipv4", "value": "192.0.2.1"}]);
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        first.clone(),
        true,
    )
    .await;
    assert_eq!(
        state_of(db, root, "test_unfinished").await,
        ("queued".to_owned(), true),
        "its own first result is an analysis added: it runs once more"
    );
    // the rerun replaces the result, with what it adds and detects once each
    let mut second = first.clone();
    second["details"]["extracted_text"] = json!("second");
    second["summary"] = json!("second");
    land_as(&test_db, &orchestrator, "test_unfinished", second, true).await;
    assert_eq!(
        state_of(db, root, "test_unfinished").await,
        ("done".to_owned(), true),
        "a rerun that changes nothing doesn't run again"
    );
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT r.summary,
                (SELECT count(*) FROM analysis.result_additions a WHERE a.result_id = r.id)
         FROM analysis.results r WHERE r.root_id = $1 AND r.module = 'test_unfinished'
           AND r.observable_id = $2",
    )
    .bind(root)
    .bind(fqdn.0)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    assert_eq!(rows, [("second".to_owned(), 1)]);

    // another module's result on the observable, with a tag: an analysis and a tag added
    let mut tagged = qr("other");
    tagged["analyzed"] = json!({"tags": ["new_tag"]});
    land_as(&test_db, &orchestrator, "test_other", tagged, false).await;
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "queued");
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("third"),
        true,
    )
    .await;
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "done");

    // a directive, then a relationship, each made outside a result, as a hook makes one
    for change in [
        "UPDATE analysis.observables SET directives = directives || '{crawl}' WHERE id = $1",
        "INSERT INTO analysis.relationships (root_id, observable_id, kind, target_type, target_value)
         SELECT root_id, id, 'related_to', 'ipv4', '192.0.2.1' FROM analysis.observables
         WHERE id = $1",
    ] {
        sqlx::query(change).bind(fqdn.0).execute(db.pool()).await.expect("changes");
        eligible_again(db, &orchestrator, root, fqdn).await;
        assert_eq!(state_of(db, root, "test_unfinished").await.0, "queued", "{change}");
        land_as(&test_db, &orchestrator, "test_unfinished", qr("again"), true).await;
    }
    // the same tag again is no change
    sqlx::query("UPDATE analysis.observables SET tags = tags WHERE id = $1")
        .bind(fqdn.0)
        .execute(db.pool())
        .await
        .expect("updates");
    eligible_again(db, &orchestrator, root, fqdn).await;
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "done");

    // a mode set to the one it has is no new pass; the root's next pass runs it again, changed or not
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .set_mode(&mut tx, root, "rerun_test")
        .await
        .expect("the same mode");
    tx.commit().await.expect("commits");
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "done");
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .new_pass(&mut tx, root, "rerun_test")
        .await
        .expect("a new pass");
    tx.commit().await.expect("commits");
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "queued");
    // a complete run ends it: no change runs it again
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("done"),
        false,
    )
    .await;
    assert_eq!(
        state_of(db, root, "test_unfinished").await,
        ("done".to_owned(), false)
    );
    sqlx::query("UPDATE analysis.observables SET tags = tags || '{later}' WHERE id = $1")
        .bind(fqdn.0)
        .execute(db.pool())
        .await
        .expect("tags");
    eligible_again(db, &orchestrator, root, fqdn).await;
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "done");
    let summary: String = sqlx::query_scalar(
        "SELECT summary FROM analysis.results WHERE root_id = $1 AND module = 'test_unfinished'
           AND observable_id = $2",
    )
    .bind(root)
    .bind(fqdn.0)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(summary, "done");
}

/// PLAN.md decision 37: a result relates an observable already in the root to others, as ace3's
/// `add_relationship`. A new relationship is a change to the observable, as ace3's
/// EVENT_RELATIONSHIP_ADDED puts it back on the work stack, so an incomplete task on it runs again
/// (decision 34); the same one again is none. A target neither in the root nor added by the result
/// is refused at a task's end (`check_relationship_targets`), and dropped by a landing that didn't
/// check, such as a cache hit in another root.
#[tokio::test]
async fn a_relationship_a_result_adds_to_its_observable_is_a_change() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = rerun_orchestrator();
    let (root, ids) = root_with(
        db,
        "rerun_test",
        &[
            (ObservableKind::Fqdn, "a.example"),
            (ObservableKind::Ipv4, "192.0.2.1"),
        ],
    )
    .await;
    let fqdn = ids[0];
    let changes = || async {
        sqlx::query_scalar::<_, i64>("SELECT changes FROM analysis.observables WHERE id = $1")
            .bind(fqdn.0)
            .fetch_one(db.pool())
            .await
            .expect("reads")
    };
    let related = |value: &str| {
        ace_results::Relationship::new(
            ace_results::RelationshipKind::DeliveredTo,
            ObservableRef::new(ObservableKind::Ipv4, value),
        )
    };
    let additions = ace_results::ObservableAdditions {
        relationships: vec![related("192.0.2.1")],
        ..ace_results::ObservableAdditions::default()
    };
    let before = changes().await;
    for (time, counted) in [("first", 1), ("again, no change", 1)] {
        let mut tx = db.begin().await.expect("begins");
        tree::add_to_observable(&mut tx, root, fqdn, &additions)
            .await
            .expect("adds");
        tx.commit().await.expect("commits");
        assert_eq!(changes().await, before + counted, "{time}");
    }

    // an incomplete task on the fqdn runs again on a relationship it gains
    start(db, &orchestrator, root).await;
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("first"),
        true,
    )
    .await;
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("second"),
        true,
    )
    .await;
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "done");
    let mut tx = db.begin().await.expect("begins");
    let mut more = additions.clone();
    more.relationships = vec![ace_results::Relationship::new(
        ace_results::RelationshipKind::RelatedTo,
        ObservableRef::new(ObservableKind::Ipv4, "192.0.2.1"),
    )];
    tree::add_to_observable(&mut tx, root, fqdn, &more)
        .await
        .expect("adds");
    tx.commit().await.expect("commits");
    eligible_again(db, &orchestrator, root, fqdn).await;
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "queued");

    // a target the root holds, one the result adds, and one neither: the check refuses the third,
    // and a landing without the check drops it alone
    let mut relating = qr("relating");
    relating["observables"] = json!([{"type": "ipv4", "value": "192.0.2.2"}]);
    relating["analyzed"] = json!({"relationships": [
        {"type": "delivered_to", "target": {"type": "ipv4", "value": "192.0.2.1"}},
        {"type": "delivered_to", "target": {"type": "ipv4", "value": "192.0.2.2"}},
        {"type": "delivered_to", "target": {"type": "ipv4", "value": "192.0.2.3"}},
    ]});
    let refused = orchestrator
        .check_relationship_targets(db.pool(), root, &result(relating.clone()))
        .await
        .expect("reads")
        .expect_err("refused");
    assert!(
        refused.error.contains("ipv4:192.0.2.3") && !refused.error.contains("192.0.2.2"),
        "{}",
        refused.error
    );
    let mut fine = relating.clone();
    fine["analyzed"]["relationships"]
        .as_array_mut()
        .expect("a list")
        .pop();
    orchestrator
        .check_relationship_targets(db.pool(), root, &result(fine))
        .await
        .expect("reads")
        .expect("takes a target in the root and one the result adds");
    land_as(&test_db, &orchestrator, "test_other", relating, false).await;
    let relationships = tree::relationships(db.pool(), root, fqdn)
        .await
        .expect("reads");
    assert_eq!(
        relationships,
        [
            related("192.0.2.1"),
            related("192.0.2.2"),
            ace_results::Relationship::new(
                ace_results::RelationshipKind::RelatedTo,
                ObservableRef::new(ObservableKind::Ipv4, "192.0.2.1"),
            ),
        ]
    );
}

/// A root whose only task ended incomplete completes, as ace3's analysis ends with an incomplete
/// analysis in it, and completes again after the rerun a change brings.
#[tokio::test]
async fn an_incomplete_task_holds_no_root_open() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = rerun_orchestrator();
    let (root, ids) = root_with(db, "rerun_alone", &[(ObservableKind::Fqdn, "d.example")]).await;
    start(db, &orchestrator, root).await;
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("first"),
        true,
    )
    .await;
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("second"),
        true,
    )
    .await;
    let passes = ace_core::queue::completions(db, root).await.expect("reads");
    assert_eq!(passes.len(), 1, "it completed with its task incomplete");
    sqlx::query("UPDATE analysis.observables SET tags = tags || '{later}' WHERE id = $1")
        .bind(ids[0].0)
        .execute(db.pool())
        .await
        .expect("tags");
    eligible_again(db, &orchestrator, root, ids[0]).await;
    assert_eq!(state_of(db, root, "test_unfinished").await.0, "queued");
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("third"),
        true,
    )
    .await;
    let passes = ace_core::queue::completions(db, root).await.expect("reads");
    assert_eq!(passes.len(), 2, "and again after its rerun");
}

/// A rerun is a task's end like any other: a task that ends failed on a rerun stays failed whatever
/// changes; a root that is cancelled reruns nothing; a mode that doesn't run the module doesn't run
/// it again; and a module at its automation limit isn't run again, its own result counting, as ace3
/// counts the analysis it would rerun.
#[tokio::test]
async fn a_rerun_keeps_failed_tasks_failed_and_the_mode_cancellation_and_limit_rules() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = rerun_orchestrator();
    let (root, ids) = root_with(db, "rerun_test", &[(ObservableKind::Fqdn, "b.example")]).await;
    let fqdn = ids[0];
    start(db, &orchestrator, root).await;
    // the limited module, incomplete, is at its limit with its own result: not run again
    land_as(&test_db, &orchestrator, "test_limited", qr("limited"), true).await;
    assert_eq!(
        state_of(db, root, "test_limited").await,
        ("done".to_owned(), true),
        "its own result holds it at its limit of 1"
    );
    // the first incomplete one runs again at once, then fails
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("first"),
        true,
    )
    .await;
    let pool = worker(&test_db, "w", &["test_unfinished"], Duration::from_secs(60)).await;
    let task = pool.claim().await.expect("claims").expect("the rerun");
    pool.fail(task.id, "the vendor broke").await.expect("fails");
    sqlx::query("UPDATE analysis.observables SET tags = tags || '{after}' WHERE id = $1")
        .bind(fqdn.0)
        .execute(db.pool())
        .await
        .expect("tags");
    eligible_again(db, &orchestrator, root, fqdn).await;
    assert_eq!(
        state_of(db, root, "test_unfinished").await,
        ("failed".to_owned(), false),
        "a failed task stays failed"
    );
    // another root: the mode that doesn't run it, then a cancellation
    let (other, ids) = root_with(db, "rerun_test", &[(ObservableKind::Fqdn, "c.example")]).await;
    start(db, &orchestrator, other).await;
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("first"),
        true,
    )
    .await;
    land_as(
        &test_db,
        &orchestrator,
        "test_unfinished",
        qr("second"),
        true,
    )
    .await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .set_mode(&mut tx, other, "rerun_other_mode")
        .await
        .expect("switches");
    tx.commit().await.expect("commits");
    assert_eq!(
        state_of(db, other, "test_unfinished").await.0,
        "done",
        "outside the mode"
    );
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .set_mode(&mut tx, other, "rerun_test")
        .await
        .expect("switches back");
    ace_core::queue::cancel_root(&mut tx, other)
        .await
        .expect("cancels");
    tx.commit().await.expect("commits");
    sqlx::query("UPDATE analysis.observables SET tags = tags || '{x}' WHERE id = $1")
        .bind(ids[0].0)
        .execute(db.pool())
        .await
        .expect("tags");
    eligible_again(db, &orchestrator, other, ids[0]).await;
    assert_ne!(
        state_of(db, other, "test_unfinished").await.0,
        "queued",
        "a cancelled root runs nothing again"
    );
}

/// The analysis cache keeps no incomplete result, as ace3's keeps only a COMPLETED one; the same
/// result complete is kept.
#[tokio::test]
async fn an_incomplete_result_isnt_kept() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = cache_orchestrator(None);
    let (root, _) = root_with(db, "cache_test", &[(ObservableKind::Fqdn, "k.example")]).await;
    start(db, &orchestrator, root).await;
    land_as(&test_db, &orchestrator, "test_cached", found(), true).await;
    assert_eq!(kept_rows(db).await, 0, "incomplete isn't kept");
    // its rerun, complete, is
    land_as(&test_db, &orchestrator, "test_cached", found(), false).await;
    assert_eq!(kept_rows(db).await, 1);
}

/// PLAN.md decision 44: what a result adds, to its own observable and with the observables it adds,
/// is recorded as its module's, and a directive whose source no one recorded has none; the
/// observable's directives, which every other rule reads, are as before.
#[tokio::test]
async fn a_result_s_directives_are_its_module_s() {
    use ace_sdk::directives::{DirectiveSource, SourcedDirective};
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = orchestrator();
    let (root, ids) = root_with(db, "email", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    file_type_says_email(db, root, ids[0]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .queue_eligible(&mut tx, root, Scope::All, false)
        .await
        .expect("queues");
    // a directive a submission stamped, and one from before sources were recorded
    sqlx::query(
        "UPDATE analysis.observables SET directives = '{sandbox,old}' WHERE root_id = $1 AND id = $2",
    )
    .bind(root)
    .bind(ids[0].0)
    .execute(tx.conn())
    .await
    .expect("stamps them");
    tree::record_directive_sources(
        &mut tx,
        root,
        ids[0],
        &strings(&["sandbox"]),
        tree::DirectivesFrom::submission("api_key:1"),
    )
    .await
    .expect("records");
    sqlx::query(
        "INSERT INTO analysis.directive_sources (root_id, observable_id, directive, source, added_by)
         VALUES ($1, $2, 'old', 'unrecorded', '')",
    )
    .bind(root)
    .bind(ids[0].0)
    .execute(tx.conn())
    .await
    .expect("records an unrecorded one");
    tx.commit().await.expect("commits");
    let scanner = worker(
        &test_db,
        "yara",
        &["yara_scanner_v3_4"],
        Duration::from_secs(60),
    )
    .await;
    let task = scanner.claim().await.expect("claims").expect("a task");
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .land_result(
            &mut tx,
            &scanner,
            &task,
            &result(json!({
                "analysis_type": "yara_scan_results",
                "schema_version": 1,
                "details": {"matches": []},
                "analyzed": {"directives": ["sandbox", "extract_urls"]},
                "observables": [
                    {"type": "fqdn", "value": "c2.example.com", "directives": ["crawl"]}
                ],
            })),
        )
        .await
        .expect("lands");
    tx.commit().await.expect("commits");
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT o.value, s.directive, s.source, s.added_by FROM analysis.directive_sources s
         JOIN analysis.observables o ON o.root_id = s.root_id AND o.id = s.observable_id
         WHERE s.root_id = $1 ORDER BY o.value, s.directive, s.source",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    let row = |value: &str, directive: &str, source: &str, by: &str| {
        (
            value.to_owned(),
            directive.to_owned(),
            source.to_owned(),
            by.to_owned(),
        )
    };
    assert_eq!(
        rows,
        [
            row(EMAIL_SHA256, "extract_urls", "module", "yara_scanner_v3_4"),
            row(EMAIL_SHA256, "old", "unrecorded", ""),
            row(EMAIL_SHA256, "sandbox", "module", "yara_scanner_v3_4"),
            row(EMAIL_SHA256, "sandbox", "submission", "api_key:1"),
            row("c2.example.com", "crawl", "module", "yara_scanner_v3_4"),
        ]
    );
    // as a lease and the core's declarations read them: no unrecorded one, each pair once
    assert_eq!(
        tree::directive_sources(db.pool(), root, ids[0])
            .await
            .expect("reads"),
        [
            SourcedDirective::new("extract_urls", DirectiveSource::Module),
            SourcedDirective::new("sandbox", DirectiveSource::Submission),
            SourcedDirective::new("sandbox", DirectiveSource::Module),
        ]
    );
    let directives: Vec<String> = sqlx::query_scalar(
        "SELECT directives FROM analysis.observables WHERE root_id = $1 AND id = $2",
    )
    .bind(root)
    .bind(ids[0].0)
    .fetch_one(db.pool())
    .await
    .expect("reads");
    assert_eq!(directives, ["sandbox", "old", "extract_urls"]);
}

/// PLAN.md decision 65: a catalog a reload of the settings files makes replaces the components for
/// every clone of the orchestrator, and what a caller took before keeps its own.
#[test]
fn a_replaced_catalog_is_every_clone_s() {
    let orchestrator = Orchestrator::new(Catalog::new(manifests()), Modes::ace3());
    let clone = orchestrator.clone();
    let before = orchestrator.catalog();
    let all = before.keys().len();
    assert!(all > 1);
    clone.replace_catalog(Catalog::new(manifests().into_iter().take(1)));
    assert_eq!(
        orchestrator.catalog().keys().len(),
        1,
        "the original sees it"
    );
    assert_eq!(before.keys().len(), all, "a snapshot keeps its own");
}

/// A crawler, an unpacker, a hasher and a hash lookup that skips hashes of what the crawler
/// fetched, for `Condition::HashesOnlyFilesFrom` (PLAN.md decision 69).
mod crawled {
    use ace_results::ObservableKind;
    use ace_sdk::takes::{Condition, Match, Takes, Text};
    use ace_sdk::{Lookup, Manifest, Module, ModuleError, Outcome, TaskContext};

    use crate::common::stubs::StubOutput;

    macro_rules! stub {
        ($ty:ident, $name:literal, $input:ident, $takes:expr) => {
            pub struct $ty;

            impl Module for $ty {
                const NAME: &'static str = $name;
                const INPUTS: &'static [ObservableKind] = &[ObservableKind::$input];
                type Output = StubOutput;
                type Settings = ();

                fn init(_: &()) -> Result<Self, ModuleError> {
                    Ok($ty)
                }

                fn takes(_: &()) -> Takes {
                    $takes
                }
            }

            impl Lookup for $ty {
                const TCP_PORTS: &'static [u16] = &[];

                async fn analyze(
                    &self,
                    _: &TaskContext<()>,
                ) -> Result<Outcome<StubOutput>, ModuleError> {
                    Ok(Outcome::Skipped("a stub".to_owned()))
                }
            }
        };
    }

    stub!(Crawler, "test_crawler", Url, Takes::everything());
    stub!(Unpacker, "test_unpacker", File, Takes::everything());
    stub!(Hasher, "test_hasher", File, Takes::everything());
    stub!(
        HashLookup,
        "test_hash_lookup",
        Sha256,
        Takes::everything().and(
            Condition::HashesOnlyFilesFrom {
                module: "test_crawler".to_owned(),
                except: ["crawl/*/downloads/*", "crawl/*/script.js"]
                    .map(|pattern| Text::exact(Match::Glob {
                        pattern: pattern.to_owned(),
                        prefix: String::new(),
                    }))
                    .to_vec(),
            }
            .negated(),
            "a hash of what the crawler fetched"
        )
    );

    pub fn manifests() -> Vec<Manifest> {
        vec![
            Manifest::lookup::<Crawler>(),
            Manifest::lookup::<Unpacker>(),
            Manifest::lookup::<Hasher>(),
            Manifest::lookup::<HashLookup>(),
        ]
    }
}

/// Lands a result of `module` on each of its tasks until none is left, the tasks its results
/// queue among them, each built by `envelope` from the task's observable's value.
async fn land_every(
    test_db: &TestDb,
    orchestrator: &Orchestrator,
    module: &str,
    envelope: impl Fn(&str) -> serde_json::Value,
) {
    let db = test_db.db();
    let worker = worker(test_db, module, &[module], Duration::from_secs(60)).await;
    while let Some(task) = worker.claim().await.expect("claims") {
        let mut tx = db.begin().await.expect("begins");
        orchestrator
            .land_result(
                &mut tx,
                &worker,
                &task,
                &result(envelope(&task.observable.value)),
            )
            .await
            .expect("lands");
        tx.commit().await.expect("commits");
    }
}

/// PLAN.md decision 69: the core declines a hash lookup on a hash whose files all came from the
/// crawler at paths it doesn't except, directly or extracted from such a file, and takes every
/// other: a payload under an except glob, something extracted from one, a file that is also an
/// attachment, one that came with the submission, a hash that also names one of those, a file the
/// walk reaches twice, and a hash that names no file.
#[tokio::test]
async fn a_hash_of_only_what_the_crawler_fetched_is_declined() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mode = AnalysisMode {
        name: "crawl".to_owned(),
        module_groups: Vec::new(),
        enabled_modules: crawled::manifests()
            .iter()
            .map(|m| m.name.to_owned())
            .collect(),
        disabled_modules: Vec::new(),
    };
    let orchestrator = Orchestrator::new(
        Catalog::new(crawled::manifests()),
        Modes::ace3().with_mode(mode),
    );
    let file = |n: u8| format!("{n:02x}").repeat(32);
    let (page, inner, payload, script, both, email, looped, looped_too, deep, from_payload) = (
        file(0xa1),
        file(0xa2),
        file(0xa3),
        file(0xa4),
        file(0xa5),
        file(0xa6),
        file(0xa7),
        file(0xa8),
        file(0xa9),
        file(0xaa),
    );
    let (two, no_file) = (file(0xc0), file(0xd0));
    let (root, ids) = root_with(
        db,
        "crawl",
        &[
            (ObservableKind::Url, "https://crawled.example/"),
            (ObservableKind::File, email.as_str()),
            (ObservableKind::Sha256, no_file.as_str()),
        ],
    )
    .await;
    let mut tx = db.begin().await.expect("begins");
    tree::add_file(&mut tx, root, ids[1], "e.eml", &[])
        .await
        .expect("adds");
    orchestrator.start(&mut tx, root).await.expect("starts");
    tx.commit().await.expect("commits");

    let files = |files: &[(&str, &str)]| {
        let files: Vec<_> = files
            .iter()
            .map(|(path, sha256)| json!({"path": path, "sha256": sha256, "size": 1}))
            .collect();
        json!({"analysis_type": "test_stub", "schema_version": 1, "details": {"note": ""},
               "files": files})
    };
    land_every(&test_db, &orchestrator, "test_crawler", |_| {
        files(&[
            ("crawl/j/dom.html", &page),
            ("crawl/j/downloads/x.zip", &payload),
            ("crawl/j/script.js", &script),
            ("crawl/j/b.html", &both),
            ("crawl/j/l.html", &looped),
            ("crawl/j/a/script.js", &deep),
        ])
    })
    .await;
    // every unpacking ends before any hash is added, as each file's own additions come before
    // the result on it that adds its hash
    land_every(&test_db, &orchestrator, "test_unpacker", |on| {
        if on == page {
            files(&[("dom.html.extracted/i", &inner)])
        } else if on == payload {
            files(&[("x.zip.extracted/i", &from_payload)])
        } else if on == email {
            files(&[("e.eml.parts/b.html", &both)])
        } else if on == looped {
            files(&[("l.html.extracted/m", &looped_too)])
        } else if on == looped_too {
            files(&[("m.extracted/l.html", &looped)])
        } else {
            files(&[])
        }
    })
    .await;
    let hash_of = |hash: &str, files: &[&str]| {
        let relationships: Vec<_> = files
            .iter()
            .map(|f| json!({"type": "is_hash_of", "target": {"type": "file", "value": f}}))
            .collect();
        json!({"type": "sha256", "value": hash, "relationships": relationships})
    };
    let hash = |file: &str| file.chars().rev().collect::<String>();
    land_every(&test_db, &orchestrator, "test_hasher", |on| {
        let mut observables = vec![hash_of(&hash(on), &[on])];
        if on == page {
            observables.push(hash_of(&two, &[&page, &email]));
        }
        json!({"analysis_type": "test_stub", "schema_version": 1, "details": {"note": ""},
               "observables": observables})
    })
    .await;

    let looked_up: BTreeSet<String> = tasks_of(db, root)
        .await
        .into_iter()
        .filter(|(module, _, _)| module == "test_hash_lookup")
        .map(|(_, value, _)| value)
        .collect();
    let expected: BTreeSet<String> = [
        hash(&payload),
        hash(&from_payload),
        hash(&script),
        hash(&deep),
        hash(&both),
        hash(&email),
        hash(&looped),
        hash(&looped_too),
        two.clone(),
        no_file.clone(),
    ]
    .into_iter()
    .collect();
    assert_eq!(looked_up, expected);
    // every hash was added, so the two declined are the crawled page and what it held
    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT value FROM analysis.observables WHERE root_id = $1 AND type = 'sha256'",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .expect("reads");
    let hashes: BTreeSet<String> = hashes.into_iter().collect();
    let declined: BTreeSet<String> = hashes.difference(&looked_up).cloned().collect();
    assert_eq!(declined, [hash(&page), hash(&inner)].into_iter().collect());

    // the facts the core decides on: one query loads the origins of every file the batch's hashes
    // name, and of each file up the tree from them
    let named: Vec<ace_core::tree::ObservableId> = sqlx::query_scalar(
        "SELECT id FROM analysis.observables WHERE root_id = $1 AND type = 'sha256'",
    )
    .bind(root)
    .fetch_all(db.pool())
    .await
    .map(|ids: Vec<i64>| ids.into_iter().map(ace_core::tree::ObservableId).collect())
    .expect("reads");
    let needs = ace_core::takes::Needs {
        file_origins: true,
        ..Default::default()
    };
    let mut tx = db.begin().await.expect("begins");
    let held = ace_core::takes::held(&mut tx, root, &named, &needs)
        .await
        .expect("reads");
    let origins = held
        .values()
        .next()
        .and_then(|h| h.origins.clone())
        .expect("origins");
    assert!(
        held.values().all(|h| h
            .origins
            .as_ref()
            .is_some_and(|o| std::sync::Arc::ptr_eq(o, &origins))),
        "one load, shared by the batch"
    );
    assert_eq!(origins.files[&email], [ace_sdk::takes::Origin::Submission]);
    assert_eq!(
        origins.files[&inner],
        [ace_sdk::takes::Origin::Result {
            module: "test_unpacker".to_owned(),
            path: Some("dom.html.extracted/i".to_owned()),
            on_file: Some(page.clone()),
        }]
    );
    assert_eq!(origins.files[&looped].len(), 2);
    // without the fact, as on a lease, the declaration takes the crawled page's hash
    let lookup = Catalog::new(crawled::manifests());
    let lookup = lookup.component("test_hash_lookup").expect("a component");
    let page_hash = held
        .values()
        .find(|h| {
            h.relationships
                .iter()
                .any(|r| r.target.value == page && h.relationships.len() == 1)
        })
        .expect("the page's hash");
    let facts = page_hash.facts(ObservableKind::Sha256, &[], "crawl");
    assert!(lookup.takes.check(&facts).is_err());
    let unknown = ace_sdk::takes::Facts {
        origins: None,
        ..facts
    };
    assert!(lookup.takes.check(&unknown).is_ok());
    tx.rollback().await.expect("rolls back");
}
