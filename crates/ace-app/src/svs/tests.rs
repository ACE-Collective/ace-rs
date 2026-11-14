//! test_svs_cli.py's cases for `ace svs yara validate`, `layout` and `prune`, and the parts of the report
//! the replay's tests don't reach.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use ace_core::svs::yara::corpus::Skipped;
use ace_core::svs::yara::diff::{Category, Outcome, ResultRow};
use ace_core::svs::yara::layout::NotLoaded;
use ace_core::svs::yara::replay::{FileError, RuleRef, Timing};
use ace_core::testing::TestDb;
use serde_json::json;

use super::*;

fn base() -> String {
    "a".repeat(40)
}

fn head() -> String {
    "b".repeat(40)
}

fn row(
    category: Category,
    label: Option<&str>,
    source: Option<&str>,
    note: Option<&str>,
) -> ResultRow {
    ResultRow {
        sha256: "c".repeat(64),
        rule_uuid: "11111111-1111-1111-1111-111111111111".to_owned(),
        rule_name: "one".to_owned(),
        namespace: Some("acme".to_owned()),
        label: label.map(str::to_owned),
        label_source: source.map(str::to_owned),
        base: Outcome::Match,
        head: Outcome::Miss,
        raw_base: true,
        raw_head: false,
        category,
        note: note.map(str::to_owned),
    }
}

/// test_svs_cli.py's `test_the_report_prints_every_section`.
#[test]
fn the_report_prints_every_section() {
    let rule = RuleRef {
        uuid: Some("22222222-2222-2222-2222-222222222222".to_owned()),
        name: "two".to_owned(),
        file: "yara/acme/two.yar".to_owned(),
    };
    let mut result = ReplayResult::new("rules", &base(), &head());
    result.head = SideReport {
        namespaces: vec!["acme".to_owned()],
        absent_namespaces: vec!["gone".to_owned()],
        rule_count: 3,
        file_errors: vec![FileError {
            file: "yara/acme/broken.yar".to_owned(),
            namespace: "acme".to_owned(),
            error: "syntax error".to_owned(),
            dropped: vec![rule.clone()],
        }],
        include_warnings: vec![
            json!({"file": "yara/acme/a.yar", "include": "missing.yar", "error": "not found"}),
        ],
        not_loaded: vec![NotLoaded {
            path: "yara/acme/deeper/nested.yar".to_owned(),
            reason: "nested".to_owned(),
        }],
        skipped_members: vec![("yara/acme/link.yar".to_owned(), "symlink".to_owned())],
        warnings: vec!["string $a slows down scanning".to_owned()],
        timings: BTreeMap::from([(
            "acme".to_owned(),
            Timing {
                scan_seconds: 1.5,
                ..Timing::default()
            },
        )]),
        ..SideReport::new(&head())
    };
    result.diffed = true;
    (result.files, result.units, result.samples, result.bytes) = (2, 3, 2, 100);
    result.duration_seconds = 2.25;
    result.skipped = vec![Skipped {
        sha256: "d".repeat(64),
        file_path: None,
        reason: "missing".to_owned(),
        detail: "no bytes".to_owned(),
    }];
    result.truncated_paths = 1;
    result.added_rules = vec![rule.clone()];
    result.counts = BTreeMap::from([
        ("regression".to_owned(), 1),
        ("new_fp_other_rule".to_owned(), 1),
        ("unlabeled_change".to_owned(), 1),
        ("unchanged".to_owned(), 0),
    ]);
    result.rows = vec![
        row(
            Category::Regression,
            Some("tp"),
            Some("analyst"),
            Some("a note"),
        ),
        row(Category::NewFpOtherRule, None, None, None),
        row(Category::UnlabeledChange, None, None, None),
    ];
    result.not_testable = vec![ace_core::svs::yara::replay::NotTestable {
        uuid: None,
        name: "anonymous".to_owned(),
        file: "yara/acme/anon.yar".to_owned(),
        reason: "no uuid".to_owned(),
    }];
    result.full_path_rules = vec![rule.clone()];

    let text = report(&result);
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(
        lines[0],
        format!(
            "repository rules: base {}, head {}",
            &base()[..12],
            &head()[..12]
        )
    );
    assert_eq!(
        lines[1],
        "corpus: 2 files, 3 scans, 2 samples, 100 bytes (2.2s)"
    );
    let uuid = rule.uuid.as_deref().unwrap();
    let c = "c".repeat(64);
    for expected in [
        "  1 not replayed:".to_owned(),
        format!("    {}  missing no bytes", "d".repeat(64)),
        "  1 scans use a path that was cut when it was stored".to_owned(),
        format!("base {}: 0 rules in 0 namespaces (none)", &base()[..12]),
        format!("head {}: 3 rules in 1 namespaces (acme)", &head()[..12]),
        "  namespace gone does not exist in this commit".to_owned(),
        "  yara/acme/broken.yar does not compile, its 1 rule(s) are dropped: syntax error"
            .to_owned(),
        "  yara/acme/a.yar: include missing.yar: not found".to_owned(),
        "  not loaded: yara/acme/deeper/nested.yar (nested)".to_owned(),
        "  not exported: yara/acme/link.yar (symlink)".to_owned(),
        "rules: 1 added, 0 removed, 0 changed".to_owned(),
        format!("  added two ({uuid}) in yara/acme/two.yar"),
        // a zero count is left out
        "counts: regression 1, new_fp_other_rule 1, unlabeled_change 1".to_owned(),
        "Regressions (1):".to_owned(),
        format!(
            "  {c} one (11111111-1111-1111-1111-111111111111) tp (analyst): base match, head miss -- a note"
        ),
        "New false positives on another rule's sample (1):".to_owned(),
        format!(
            "  {c} one (11111111-1111-1111-1111-111111111111) another rule's sample: base match, head miss"
        ),
        "Unlabeled changes (1):".to_owned(),
        format!(
            "  {c} one (11111111-1111-1111-1111-111111111111) unlabeled: base match, head miss"
        ),
        "not testable: anonymous (None) in yara/acme/anon.yar: no uuid".to_owned(),
        format!(
            "filters on full_path, which a replay cannot reproduce: two ({uuid}) in yara/acme/two.yar"
        ),
        "head compiler warning: string $a slows down scanning".to_owned(),
        "scan time per namespace (base / head):".to_owned(),
        "  acme: - / 1.50s".to_owned(),
    ] {
        assert!(
            lines.contains(&expected.as_str()),
            "{expected:?} in\n{text}"
        );
    }
    // bands with no rows have no heading
    assert!(!lines.iter().any(|l| l.starts_with("Improvements")));
}

/// A stand-in for the replay, as ace3's tests patch `run_replay`.
struct FakeReplay {
    calls: Mutex<Vec<ReplayRequest>>,
    outcome: Result<ReplayResult, ReplayError>,
}

impl Replay for FakeReplay {
    fn replay<'a>(
        &'a self,
        request: &'a ReplayRequest,
        _cancel: &'a CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<ReplayResult, ReplayError>> + Send + 'a>> {
        self.calls.lock().unwrap().push(request.clone());
        Box::pin(async move { self.outcome.clone() })
    }
}

fn fake(outcome: Result<ReplayResult, ReplayError>) -> FakeReplay {
    FakeReplay {
        calls: Mutex::new(Vec::new()),
        outcome,
    }
}

fn validate_args(branch: Option<&str>, json: bool) -> ValidateArgs {
    ValidateArgs {
        repository: "rules".to_owned(),
        base: base(),
        head: head(),
        branch: branch.map(str::to_owned),
        json,
    }
}

fn retired() -> BTreeSet<(String, String)> {
    BTreeSet::from([("e".repeat(64), "rule".to_owned())])
}

/// test_svs_cli.py's `test_validate_prints_the_report`.
#[tokio::test]
async fn validate_prints_the_report() {
    let replay = fake(Ok(ReplayResult::new("rules", &base(), &head())));
    let (mut out, mut err) = (String::new(), String::new());

    let code = validate(
        &validate_args(Some("feature"), false),
        &replay,
        retired(),
        &mut out,
        &mut err,
    )
    .await;

    assert_eq!(code, 0);
    // retired samples are passed along, so they're only counted
    let calls = replay.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        [ReplayRequest {
            repository: "rules".to_owned(),
            base_sha: base(),
            head_sha: head(),
            branch: Some("feature".to_owned()),
            retired: retired(),
        }]
    );
    assert!(out.starts_with(&format!(
        "repository rules: base {}, head {}\n",
        &base()[..12],
        &head()[..12]
    )));
    assert!(out.contains("nothing was compared: a ruleset would not load"));
}

/// test_svs_cli.py's `test_validate_as_json`.
#[tokio::test]
async fn validate_as_json() {
    let replay = fake(Ok(ReplayResult::new("rules", &base(), &head())));
    let (mut out, mut err) = (String::new(), String::new());
    assert_eq!(
        validate(
            &validate_args(None, true),
            &replay,
            retired(),
            &mut out,
            &mut err
        )
        .await,
        0
    );
    let document: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    assert_eq!(
        (
            document["repository"].clone(),
            document["base_sha"].clone(),
            document["head_sha"].clone()
        ),
        (json!("rules"), json!(base()), json!(head()))
    );
}

/// test_svs_cli.py's `test_validate_failure`.
#[tokio::test]
async fn validate_failure() {
    let replay = fake(Err(ReplayError::Failed("unknown commit".to_owned())));
    let (mut out, mut err) = (String::new(), String::new());
    assert_eq!(
        validate(
            &validate_args(None, false),
            &replay,
            retired(),
            &mut out,
            &mut err
        )
        .await,
        1
    );
    assert_eq!(out, "");
    assert_eq!(err, "validation failed: unknown commit\n");
}

/// test_svs_cli.py's `test_layout_prints_every_repository`, for ace4's one layout: a signature directory,
/// or the repository's top. ace3's linked layout and its configuration errors have no counterpart (`layout`'s
/// docs in `ace_core::svs::yara`).
#[test]
fn layout_prints_every_repository() {
    let section = ace_sdk::Overlay::from_yaml(
        "svs:
           yara:
             repositories:
               contained_rules: {url: /x, branch: main, signature_dir: signatures}
               root_rules: {url: /y, branch: main, signature_dir: ''}
               default_rules: {url: /z, branch: main}",
    )
    .expect("parses")
    .svs
    .yara;
    let config = ValidationConfig::from_section(&section).expect("valid");
    assert_eq!(
        layout(&config),
        "contained_rules: every directory of signatures is a namespace\n\
         default_rules: every directory of yara is a namespace\n\
         root_rules: every directory of the repository root is a namespace\n"
    );
}

/// A repository's SSH key comes through the overlay's `secrets:`, here a file as a Compose secret is: the
/// key's text, and only the secrets the repositories name. One whose file is missing is left unset.
#[test]
fn the_ssh_keys_come_from_the_overlay_s_secrets() {
    let dir = tempfile::tempdir().expect("a directory");
    let key = dir.path().join("rules_key");
    std::fs::write(&key, "-----BEGIN KEY-----\nabc\n-----END KEY-----\n").expect("writes it");
    let overlay = ace_sdk::Overlay::from_yaml(&format!(
        "secrets:\n  rules_key: file:{}\n  missing_key: file:{}\n  unrelated: file:{}\n\
         svs:\n  yara:\n    repositories:\n      \
           keyed: {{url: /x, branch: main, ssh_key: rules_key}}\n      \
           missing: {{url: /y, branch: main, ssh_key: missing_key}}\n      \
           plain: {{url: /z, branch: main}}\n",
        key.display(),
        dir.path().join("nothing").display(),
        key.display(),
    ))
    .expect("parses");
    let config = ValidationConfig::from_section(&overlay.svs.yara).expect("valid");
    let config = with_ssh_keys(config, &overlay);
    assert_eq!(
        config
            .ssh_key("keyed")
            .expect("set")
            .map(|key| key.expose().to_owned()),
        Some("-----BEGIN KEY-----\nabc\n-----END KEY-----".to_owned())
    );
    assert!(
        config
            .ssh_key("missing")
            .expect_err("unset")
            .contains("missing_key")
    );
    assert_eq!(config.ssh_key("plain"), Ok(None));
    assert_eq!(config.ssh_keys.keys().collect::<Vec<_>>(), ["keyed"]);
}

/// test_svs_cli.py's `test_layout_with_no_repositories`.
#[test]
fn layout_with_no_repositories() {
    assert_eq!(layout(&ValidationConfig::default()), "");
}

/// test_svs_cli.py's `test_prune_dry_run_and_force`: ace4 has no primary node, so there's no `--force`
/// and ace3's `test_prune_skips_a_node_that_is_not_primary` has no counterpart.
#[tokio::test]
async fn prune_dry_run_and_prune() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let mut ids = Vec::new();
    for (head, days) in [("a", 91), ("b", 0)] {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO svs.validations
                 (uuid, repository, base_sha, head_sha, branch, requested_by, state, created_at,
                  finished_at)
             VALUES (gen_random_uuid(), 'rules', repeat('0', 40), repeat($1, 40), 'main',
                     '{\"kind\": \"internal\", \"id\": \"test\"}', 'completed',
                     now() - make_interval(days => $2), now() - make_interval(days => $2))
             RETURNING id",
        )
        .bind(head)
        .bind(days)
        .fetch_one(db.pool())
        .await
        .expect("a validation");
        ids.push(id);
    }
    let service = ace_service::Service::new(
        db.clone(),
        ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new(vec![]),
            ace_core::modes::Modes::ace3(),
        ),
    );

    assert_eq!(
        prune(&service, true).await.expect("counts"),
        "would remove 1 validations\n"
    );
    assert_eq!(
        prune(&service, false).await.expect("prunes"),
        "removed 1 validations\n"
    );

    let left: Vec<i64> = sqlx::query_scalar("SELECT id FROM svs.validations")
        .fetch_all(db.pool())
        .await
        .expect("reads");
    assert_eq!(left, ids[1..]);
}

/// test_replay.py's `test_a_head_that_would_not_load_is_not_compared`, its report: a side whose rules
/// wouldn't load says so, and nothing was compared.
#[test]
fn the_report_says_a_ruleset_would_not_load() {
    let mut result = ReplayResult::new("rules", &base(), &head());
    result.head.ruleset_error = Some("duplicate rule `one`".to_owned());
    result.head.loads = false;
    let text = report(&result);
    assert!(text.contains("  the ruleset would not load, so production keeps its previous rules: duplicate rule `one`\n"), "{text}");
    assert!(text.contains("nothing was compared: a ruleset would not load\n"));
}
