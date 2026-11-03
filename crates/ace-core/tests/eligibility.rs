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
use ace_results::ObservableKind;
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
}

fn orchestrator() -> Orchestrator {
    Orchestrator::new(Catalog::new(manifests()), modes())
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn each_rule() {
    use ObservableKind::*;
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
            File,
            "email",
            Ok(()),
        ),
        case(
            "takes a type that extends its input",
            "rdap_analyzer",
            EmailDkimSigningDomain,
            "correlation",
            Ok(()),
        ),
        case(
            "doesn't take the type",
            "email_analyzer",
            Fqdn,
            "email",
            Err(Ineligible::NotAnInput),
        ),
        case(
            "the mode doesn't run its group",
            "rdap_analyzer",
            Fqdn,
            "email",
            Err(Ineligible::NotInMode),
        ),
        case(
            "no group names it",
            "splunk_api",
            Fqdn,
            "analysis",
            Err(Ineligible::NotInMode),
        ),
        case(
            "the mode enables it by name",
            "alert_added_to_event",
            Fqdn,
            "dispositioned",
            Ok(()),
        ),
        case(
            "the mode disables it",
            "yara_scanner_v3_4",
            File,
            "test",
            Err(Ineligible::NotInMode),
        ),
        case(
            "an unknown mode runs nothing",
            "email_analyzer",
            File,
            "no_such_mode",
            Err(Ineligible::NotInMode),
        ),
        Case {
            directives: &["no_scan"],
            ..case(
                "no_scan keeps the YARA module off",
                "yara_scanner_v3_4",
                File,
                "email",
                Err(Ineligible::Directive("no_scan".to_owned())),
            )
        },
        Case {
            directives: &["no_scan"],
            ..case(
                "no_scan leaves other modules alone",
                "archive",
                File,
                "email",
                Ok(()),
            )
        },
        Case {
            directives: &["original_email", "exclude_all"],
            ..case(
                "exclude_all keeps every module off",
                "archive",
                File,
                "email",
                Err(Ineligible::Directive("exclude_all".to_owned())),
            )
        },
        Case {
            exclude: &["archive"],
            ..case(
                "the observable excludes it",
                "archive",
                File,
                "email",
                Err(Ineligible::Excluded),
            )
        },
        case(
            "a dependency has no result yet",
            "test_depends_on_archive",
            File,
            "test",
            Err(Ineligible::WaitingFor("archive".to_owned())),
        ),
        Case {
            results: &["archive"],
            ..case(
                "a dependency has a result",
                "test_depends_on_archive",
                File,
                "test",
                Ok(()),
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
        let got = check(
            component,
            Facts {
                kind: case.kind,
                directives: &directives,
                exclude_modules: &exclude,
            },
            &modes.modules_in(case.mode),
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
