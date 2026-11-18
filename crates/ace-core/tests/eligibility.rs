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
                limit_modules: &[],
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

/// ace3's executor: a result that whitelists the observable it analyzed stops the root's analysis, and
/// a detection in a root holding a whitelisted observable doesn't make it an alert.
#[tokio::test]
async fn a_whitelisting_result_stops_the_root_and_nothing_in_it_alerts() {
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
    file_type_says_email(db, other, ids[1]).await;
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
/// however long its wait had grown, with its delay's record as it was: its state, its count and its
/// first delay. Nothing else moves: not while another module's task is left, a module's own delay
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
        let state = json!({(ace_core::queue::HELD_BACK_BY): by.as_str(), "step": 6});
        last.delay(task.id, minute, &state).await.expect("delays");
        held.push(task.id);
    }
    assert_eq!(held.len(), 3);
    let record = || async {
        sqlx::query_as::<_, (i64, i32, chrono::DateTime<chrono::Utc>, serde_json::Value)>(
            "SELECT id, delays, first_delayed_at, delay_state FROM queue.tasks
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
        let delayed = task.delayed.as_ref().expect("its delay's record");
        assert_eq!(
            delayed.state,
            json!({"held_back_by": "others", "step": 6}),
            "the state the lease reads its next wait from"
        );
        assert_eq!(delayed.delays, 1);
        woken.push(task.id);
    }
    assert_eq!(
        woken.len(),
        2,
        "the one waiting for a task below keeps its wait"
    );
    assert_eq!(
        record().await,
        before,
        "nothing of the delays' record moved"
    );
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
/// another module's and the others' wait stands; a task's end, or the lease when it holds that one
/// back for a task below it (`queue::wake_held_back_now`), wakes them then. A cancelled root's tasks
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
    let held_back =
        |by: tree::HeldBack| json!({(ace_core::queue::HELD_BACK_BY): by.as_str(), "step": 0});
    let last = worker(&test_db, "last", &["xlmdeobfuscator"], lease).await;
    queue(ids[1], "xlmdeobfuscator").await;
    let first = last.claim().await.expect("claims").expect("the task");
    last.delay(first.id, minute, &held_back(tree::HeldBack::ByOthers))
        .await
        .expect("delays");
    // one that hasn't asked, and the last other task
    queue(ids[0], "xlmdeobfuscator").await;
    queue(ids[0], "archive").await;
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
    last.delay(fresh.id, minute, &held_back(tree::HeldBack::ByLastBelow))
        .await
        .expect("delays");
    assert_eq!(
        ace_core::queue::wake_held_back_now(db, root)
            .await
            .expect("wakes"),
        1
    );
    let woken = last.claim().await.expect("claims").expect("the first");
    assert_eq!(woken.id, first.id);
    assert_eq!(
        ace_core::queue::wake_held_back_now(db, root)
            .await
            .expect("wakes"),
        0,
        "none is left waiting for the others"
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
    last.delay(task.id, minute, &held_back(tree::HeldBack::ByOthers))
        .await
        .expect("delays");
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
    let hooks = ace_core::hooks::Hooks::from_section(&overlay.hooks).expect("rules that compile");
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
        orchestrator.catalog().clone(),
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
        orchestrator.catalog().clone(),
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

#[test]
fn the_hooks_refuse_rules_ace3_would_skip() {
    let refused = |yaml: &str| {
        let overlay = ace_sdk::Overlay::from_yaml(yaml);
        match overlay {
            Err(e) => e.to_string(),
            Ok(o) => ace_core::hooks::Hooks::from_section(&o.hooks)
                .expect_err("refused")
                .to_string(),
        }
    };
    let rules =
        |rule: &str| format!("hooks:\n  observable_modifier:\n    rules:\n      - {rule}\n");
    assert!(
        refused(&rules("{name: a}")).contains("uuid"),
        "a uuid is required"
    );
    assert!(refused(&rules("{uuid: u, phase: later}")).contains("phase"));
    assert!(
        refused(&rules("{uuid: u, conditions: {value_pattern: '(?=x)'}}"))
            .contains("doesn't compile"),
        "a look-around needs backtracking, which the regex crate doesn't do"
    );
    assert!(refused(&rules("{uuid: u, conditions: {observable_types: [nope]}}")).contains("nope"));
    assert!(
        refused(&rules(
            "{uuid: u, conditions: {tree_conditions: [{observable_match: {size: x}}]}}"
        ))
        .contains("observable_match")
    );
    assert!(
        refused(&rules(&format!(
            "{{uuid: u, conditions: {{value_pattern: '{}'}}}}",
            "a".repeat(1025)
        )))
        .contains("at most 1024 bytes")
    );
    let many: String = (0..1001)
        .map(|i| format!("      - {{uuid: u{i}}}\n"))
        .collect();
    assert!(
        refused(&format!(
            "hooks:\n  observable_modifier:\n    rules:\n{many}"
        ))
        .contains("at most 1000 rules")
    );
    assert!(refused(&rules("{uuid: u, actions: {explode: true}}")).contains("explode"));
    // no section, and a section of disabled rules, run nothing
    let none = ace_core::hooks::Hooks::from_section(&ace_sdk::hooks::HooksSection::default())
        .expect("none");
    assert!(none.names().is_empty());
    let off = ace_sdk::Overlay::from_yaml(&rules("{uuid: u, enabled: false}")).expect("parses");
    assert!(
        ace_core::hooks::Hooks::from_section(&off.hooks)
            .expect("compiles")
            .names()
            .is_empty()
    );
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
        {
            const READS_ADDED_BY: bool = true;
        },
        Takes::everything().and(Condition::added_by("test_carrier2"), "not test_carrier2's")
    );
    declaring!(
        ByMode,
        "test_takes_mode",
        parser,
        {
            const READS_TREE: bool = true;
        },
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

/// The type step's worker, which ends it as the lease API's does (`queue::TypeStepEnded`).
async fn type_worker(test_db: &TestDb, orchestrator: &Orchestrator) -> ace_core::queue::Worker {
    worker(test_db, "typer", &["file_type"], Duration::from_secs(60))
        .await
        .with_type_step(std::sync::Arc::new(orchestrator.clone()))
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
