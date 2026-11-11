//! PLAN.md 2.10: eligibility. A table covers each rule; landing results queues what became
//! eligible; a detection mid-analysis turns the root into an alert in correlation mode and
//! queues the correlation group's modules for the observables already in the tree; and a
//! cancelled dependency leaves its dependents waiting, not failed (ace3 #846).

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use ace_core::eligibility::{Catalog, Facts, Ineligible, check};
use ace_core::modes::{AnalysisMode, Modes};
use ace_core::orchestrator::{Orchestrator, Scope};
use ace_core::testing::TestDb;
use ace_core::tree;
use ace_results::{ObservableKind, ObservableRef};
use serde_json::json;

use common::{manifests, result, root_with, tasks_of, worker};

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
        tags: &'static [&'static str],
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
        tags: &[],
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
                "a whitelisted directive keeps every module off, as ace3's executor skips the observable",
                "archive",
                FILE,
                "email",
                Err(Ineligible::Whitelisted),
            )
        },
        Case {
            tags: &["whitelisted"],
            ..case(
                "so does a whitelisted tag",
                "rdap_analyzer",
                FQDN,
                "correlation",
                Err(Ineligible::Whitelisted),
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
        let tags = strings(case.tags);
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
                tags: &tags,
                directives: &directives,
                exclude_modules: &exclude,
            },
            &mode_modules,
            &results,
        );
        assert_eq!(got, case.expected, "{}", case.what);
    }
}

#[tokio::test]
async fn a_detection_mid_analysis_queues_the_correlation_group_for_the_tree() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = orchestrator();
    let (root, _) = root_with(
        db,
        "email",
        &[
            (ObservableKind::File, EMAIL_SHA256),
            (ObservableKind::Fqdn, "evil.example.com"),
        ],
    )
    .await;
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

/// ace3's executor: a result that whitelists the observable it analyzed stops the root's analysis, and
/// a detection in a root holding a whitelisted observable doesn't make it an alert.
#[tokio::test]
async fn a_whitelisting_result_stops_the_root_and_nothing_in_it_alerts() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let orchestrator = orchestrator();
    let (root, _) = root_with(db, "email", &[(ObservableKind::File, EMAIL_SHA256)]).await;
    let mut tx = db.begin().await.expect("begins");
    orchestrator
        .queue_eligible(&mut tx, root, Scope::All, false)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");

    // the email module whitelists the email, as for a whitelisted sender
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
    assert_eq!(landed.queued, []);
    assert_eq!(landed.mode_changed_to, None);
    let state =
        |module: &str, state: &str| (module.to_owned(), EMAIL_SHA256.to_owned(), state.to_owned());
    assert_eq!(
        tasks_of(db, root).await,
        [
            state("archive", "cancelled"),
            state("email_analyzer", "done"),
            state("yara_scanner_v3_4", "cancelled"),
        ],
        "the rest of the root's analysis stopped"
    );

    // a whitelisted observable gets no tasks, and a detection elsewhere in its root doesn't alert
    const OTHER_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    let (other, ids) = root_with(
        db,
        "email",
        &[
            (ObservableKind::File, EMAIL_SHA256),
            (ObservableKind::File, OTHER_SHA256),
        ],
    )
    .await;
    let mut tx = db.begin().await.expect("begins");
    tree::add_to_observable(
        &mut tx,
        other,
        ids[0],
        &serde_json::from_value(json!({"tags": ["whitelisted"]})).expect("additions"),
    )
    .await
    .expect("tags");
    orchestrator
        .queue_eligible(&mut tx, other, Scope::All, false)
        .await
        .expect("queues");
    tx.commit().await.expect("commits");
    let queued = |module: &str| {
        (
            module.to_owned(),
            OTHER_SHA256.to_owned(),
            "queued".to_owned(),
        )
    };
    assert_eq!(
        tasks_of(db, other).await,
        [
            queued("archive"),
            queued("email_analyzer"),
            queued("yara_scanner_v3_4")
        ],
        "the whitelisted file is analyzed by nothing"
    );
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
    assert_eq!(landed.mode_changed_to, None);
    let alerted: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT alerted_at FROM analysis.roots WHERE id = $1")
            .bind(other)
            .fetch_one(db.pool())
            .await
            .expect("reads");
    assert_eq!(
        alerted, None,
        "a root holding a whitelisted observable doesn't alert"
    );
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
/// email's body. A cycle ends, an email with no body is one, and nothing above a root is none.
#[tokio::test]
async fn a_file_finds_the_body_of_the_email_that_carried_it() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let hash = |c: &str| c.repeat(64);
    let (outer, nested, zip, doc, body, inner_body) = (
        hash("a"),
        hash("b"),
        hash("c"),
        hash("d"),
        hash("e"),
        hash("f"),
    );
    let values = [&outer, &nested, &zip, &doc, &body, &inner_body];
    let files: Vec<(ObservableKind, &str)> = values
        .iter()
        .map(|value| (ObservableKind::File, value.as_str()))
        .collect();
    let (root, ids) = root_with(db, "test", &files).await;
    let (outer_id, nested_id, zip_id, doc_id, body_id, inner_id) =
        (ids[0], ids[1], ids[2], ids[3], ids[4], ids[5]);
    let message = json!({"email": {}});

    // the outer email adds the nested one, its body, and the nested one's zip, as ace3's does
    add_result(
        db,
        root,
        outer_id,
        "email_analysis",
        message.clone(),
        &[
            (body_id, Some("email.rfc822.unknown_text_plain_000.txt")),
            (nested_id, Some("email.rfc822.email_000.rfc822")),
            (zip_id, Some("a_000.zip")),
        ],
    )
    .await;
    let outer_body = tree::EmailBodyFile {
        path: "email.rfc822.unknown_text_plain_000.txt".to_owned(),
        sha256: body.clone(),
    };
    assert_eq!(
        tree::carrying_email(db.pool(), root, zip_id)
            .await
            .expect("reads"),
        Some(Some(outer_body))
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
    let inner = tree::EmailBodyFile {
        path: "x/email.rfc822.unknown_text_html_000.html".to_owned(),
        sha256: inner_body.clone(),
    };
    assert_eq!(
        tree::carrying_email(db.pool(), root, doc_id)
            .await
            .expect("reads"),
        Some(Some(inner.clone()))
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
        Some(Some(inner))
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

    // an email with no text part is still an email
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
        Some(None)
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
        [("email_analyzer".to_owned(), json!({"first": true}))]
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
        sqlx::query("INSERT INTO store.objects (pool, sha256, size, mime_type) VALUES ('alert_files', $1, $2, 'text/html')")
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
    assert!(!view.whitelisted && !view.truncated);
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
