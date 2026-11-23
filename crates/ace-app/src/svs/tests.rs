//! test_svs_cli.py's cases for `ace svs yara validate`, `layout` and `prune`, and the parts of the report
//! the replay's tests don't reach; then its catalog refresh and test_catalog.py's cases of `ace svs catalog`
//! (PLAN.md 7.10 batch 4), `ace svs attack extract`, and test_coverage.py's and test_worklist.py's cases of
//! `ace svs coverage` (batch 8).

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

/// test_svs_cli.py's `test_layout_prints_every_repository`, for ace-rs's one layout: a signature directory,
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

/// test_svs_cli.py's `test_prune_dry_run_and_force`: ace-rs has no primary node, so there's no `--force`
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

// ---- `ace svs catalog` and `ace svs attack` (PLAN.md 7.10 batch 4) ----

const ART: &str = "art_unittest";
const ART_GUID: &str = "aaaaaaaa-1111-4111-8111-111111111111";
const T1003: &str = "atomics/T1003/T1003.yaml";

/// An atomic file of T1003 with one test, and one more with no guid when `no_guid`.
fn atomics(no_guid: bool) -> String {
    let test = |name: &str, guid: &str| {
        format!(
            "- name: {name}\n{guid}  supported_platforms: [windows]\n  executor: {{name: powershell, command: whoami}}\n"
        )
    };
    let mut text = format!(
        "attack_technique: T1003\ndisplay_name: OS Credential Dumping\natomic_tests:\n{}",
        test("Dump", &format!("  auto_generated_guid: {ART_GUID}\n"))
    );
    if no_guid {
        text.push_str(&test("No guid", ""));
    }
    text
}

/// A catalog repository as a bare origin with a working clone, and the settings of a catalog that lists
/// the repositories `listed`, each by its name and URL.
struct ArtRepo {
    repo: ace_core::testing::rule_repo::RuleRepo,
    tmp: tempfile::TempDir,
}

fn art_repo() -> ArtRepo {
    let tmp = tempfile::tempdir().expect("a directory");
    let repo = ace_core::testing::rule_repo::RuleRepo::new(&tmp.path().join("art"));
    ArtRepo { repo, tmp }
}

impl ArtRepo {
    fn url(&self) -> String {
        self.repo.origin.to_string_lossy().into_owned()
    }

    fn config(&self, listed: &[(&str, String)]) -> ace_core::svs::catalog::CatalogConfig {
        let section = ace_sdk::SvsCatalogSection {
            repositories: listed
                .iter()
                .map(|(name, url)| {
                    (
                        (*name).to_owned(),
                        ace_sdk::SvsCatalogRepository {
                            url: url.clone(),
                            branch: "main".to_owned(),
                            ssh_key: None,
                        },
                    )
                })
                .collect(),
            mirror_dir: Some(self.tmp.path().join("mirrors")),
            ..ace_sdk::SvsCatalogSection::default()
        };
        ace_core::svs::catalog::CatalogConfig::from_section(&section).expect("valid settings")
    }
}

fn catalog_service(
    db: &Db,
    config: &ace_core::svs::catalog::CatalogConfig,
) -> ace_service::Service {
    ace_service::Service::new(
        db.clone(),
        ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new(vec![]),
            ace_core::modes::Modes::ace3(),
        ),
    )
    .with_catalog(config.clone())
}

/// test_svs_cli.py's `test_catalog_refresh_with_no_repositories`.
#[tokio::test]
async fn catalog_refresh_with_no_repositories() {
    let test_db = TestDb::new().await;
    let config = ace_core::svs::catalog::CatalogConfig::default();
    let service = catalog_service(test_db.db(), &config);
    assert_eq!(
        catalog_refresh(&service, None, false)
            .await
            .expect("refreshes"),
        ("svs.catalog.repositories is empty\n".to_owned(), 0)
    );
    assert_eq!(
        catalog_status(test_db.db(), &config).await.expect("reads"),
        ""
    );
}

/// test_catalog.py's `test_cli_refresh_and_status`: a refresh says what it read and skipped, a second
/// one that the commit was already read, and the status the repository's tests and commit.
#[tokio::test]
async fn cli_refresh_and_status() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let art = art_repo();
    let commit = art.repo.commit(&[(T1003, &atomics(true))], "main");
    let config = art.config(&[(ART, art.url())]);
    let service = catalog_service(db, &config);

    let (out, code) = catalog_refresh(&service, None, false)
        .await
        .expect("refreshes");
    assert_eq!(code, 0);
    assert_eq!(
        out,
        format!(
            "{ART} @ {}: 1 tests (1 added, 0 changed, 0 removed, 1 skipped)\n  \
             skipped {T1003} (No guid): no auto_generated_guid\n",
            &commit[..12]
        )
    );

    let (out, code) = catalog_refresh(&service, Some(ART), false)
        .await
        .expect("refreshes");
    assert_eq!(
        (out, code),
        (
            format!(
                "{ART} @ {}: already read (--force to read it again)\n",
                &commit[..12]
            ),
            0
        )
    );
    let (out, _) = catalog_refresh(&service, Some(ART), true)
        .await
        .expect("refreshes");
    assert!(
        out.starts_with(&format!(
            "{ART} @ {}: 1 tests (0 added, 0 changed, 0 removed, 1 skipped)\n",
            &commit[..12]
        )),
        "{out}"
    );

    let status = catalog_status(db, &config).await.expect("reads");
    assert!(
        status.starts_with(&format!("{ART}: 1 tests at {}, read 20", &commit[..12]))
            && status.ends_with(" UTC, 1 skipped, 0 removed since\n"),
        "{status}"
    );
}

/// test_catalog.py's `test_cli_refresh_reports_a_retired_repository`.
#[tokio::test]
async fn cli_refresh_reports_a_retired_repository() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let art = art_repo();
    let commit = art.repo.commit(&[(T1003, &atomics(false))], "main");
    catalog_refresh(
        &catalog_service(db, &art.config(&[(ART, art.url())])),
        None,
        false,
    )
    .await
    .expect("refreshes");
    let unlisted = art.config(&[]);

    assert_eq!(
        catalog_refresh(&catalog_service(db, &unlisted), None, false)
            .await
            .expect("refreshes"),
        (
            format!("{ART}: no longer in svs.catalog.repositories, 1 tests removed\n"),
            0
        )
    );
    let status = catalog_status(db, &unlisted).await.expect("reads");
    assert!(
        status.starts_with(&format!(
            "{ART} ({}): 0 tests at {}",
            ace_core::svs::catalog::RETIRED_ERROR,
            &commit[..12]
        )),
        "{status}"
    );
    assert!(
        status.ends_with(", 0 skipped, 1 removed since\n"),
        "{status}"
    );
}

/// test_catalog.py's `test_cli_refresh_reports_an_error`: a repository that can't be read fails the
/// command, and the status says it was never read, with the error. ace3's repository has no `git_repo_*`
/// section; here it has nothing to fetch from.
#[tokio::test]
async fn cli_refresh_reports_an_error() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let art = art_repo();
    art.repo.commit(&[(T1003, &atomics(false))], "main");
    let missing = art
        .tmp
        .path()
        .join("missing")
        .to_string_lossy()
        .into_owned();
    let config = art.config(&[(ART, art.url()), ("nowhere", missing.clone())]);
    let service = catalog_service(db, &config);

    let (out, code) = catalog_refresh(&service, None, false)
        .await
        .expect("refreshes");
    assert_eq!(code, 1);
    let lines: Vec<&str> = out.lines().collect();
    assert!(
        lines[0].starts_with(&format!("{ART} @ ")) && lines[0].contains(": 1 tests (1 added"),
        "{out}"
    );
    assert!(
        lines[1].starts_with("nowhere: unable to fetch main of repository nowhere"),
        "{out}"
    );
    assert!(!out.contains(&missing), "the URL isn't shown: {out}");

    let status = catalog_status(db, &config).await.expect("reads");
    assert!(
        status.contains(
            "\nnowhere: never read; last error: unable to fetch main of repository nowhere"
        ),
        "{status}"
    );
    // a repository the overlay doesn't list, asked for by name
    let (out, code) = catalog_refresh(&service, Some("elsewhere"), false)
        .await
        .expect("refreshes");
    assert_eq!(
        (out.as_str(), code),
        (
            "elsewhere: elsewhere is not in svs.catalog.repositories\n",
            1
        )
    );
    let status = catalog_status(db, &config).await.expect("reads");
    assert!(
        status.contains(
            "elsewhere (no longer in svs.catalog.repositories): never read; last error: elsewhere is not"
        ),
        "{status}"
    );
}

/// `ace svs attack extract`, ace3's `bin/update-attack-catalog`: the extract of a bundle is written as
/// `<release>.json` in the output directory, whole or not at all, with a line saying what it holds; a
/// bundle of another release writes nothing.
#[test]
fn attack_extract_writes_the_extract() {
    let tmp = tempfile::tempdir().expect("a directory");
    let bundle = tmp.path().join("bundle.json");
    let reference = |id: &str| json!([{"source_name": "mitre-attack", "external_id": id}]);
    std::fs::write(
        &bundle,
        json!({"type": "bundle", "objects": [
            {"type": "x-mitre-collection", "name": "Enterprise ATT&CK", "x_mitre_version": "99.0"},
            {"type": "x-mitre-tactic", "id": "tactic--1", "name": "Execution",
             "x_mitre_shortname": "execution", "external_references": reference("TA0002")},
            {"type": "x-mitre-matrix", "tactic_refs": ["tactic--1"]},
            {"type": "attack-pattern", "id": "ap--1", "name": "Command and Scripting Interpreter",
             "external_references": reference("T1059"), "x_mitre_platforms": ["Windows"],
             "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]},
            {"type": "attack-pattern", "id": "ap--2", "name": "Gone", "revoked": true,
             "external_references": reference("T1064")},
            {"type": "relationship", "relationship_type": "revoked-by", "source_ref": "ap--2",
             "target_ref": "ap--1"},
        ]})
        .to_string(),
    )
    .expect("writes the bundle");
    let out_dir = tmp.path().join("out").join("attack");
    let args = |release: &str| AttackExtractArgs {
        release: release.to_owned(),
        input: bundle.clone(),
        previous: None,
        output_dir: out_dir.clone(),
    };

    let said = attack_extract(&args("99")).expect("builds");
    let path = out_dir.join("v99.0.json");
    assert_eq!(
        said,
        format!(
            "wrote {}: 1 techniques, 1 tactics, 1 revoked, 0 renamed\n",
            path.display()
        )
    );
    let text = std::fs::read_to_string(&path).expect("the extract");
    let catalog =
        ace_core::svs::attack::AttackCatalog::load(&text, "v99.0.json").expect("it loads");
    assert_eq!(catalog.release, "v99.0");
    assert_eq!(catalog.resolve("T1064").expect("an id").technique, "T1059");
    let source: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    assert!(
        source["source"]["url"]
            .as_str()
            .is_some_and(|url| url.ends_with("/enterprise-attack-99.0.json")),
        "{source}"
    );
    // only the extract is left in the directory
    let names: Vec<String> = std::fs::read_dir(&out_dir)
        .expect("lists")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, ["v99.0.json"]);

    let error = attack_extract(&args("v98.0")).expect_err("another release");
    assert!(
        error
            .to_string()
            .contains("the bundle is ATT&CK Enterprise ATT&CK 99.0, not v98.0"),
        "{error}"
    );
    assert!(!out_dir.join("v98.0.json").exists());
    assert!(attack_extract(&args("latest")).is_err());
}

fn coverage_service(db: &Db) -> ace_service::Service {
    ace_service::Service::new(
        db.clone(),
        ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new(vec![]),
            ace_core::modes::Modes::ace3(),
        ),
    )
    .with_attack_catalog(std::sync::Arc::new(ace_core::testing::attack_catalog()))
}

/// A database that fails the refresh: coverage's rows are refused. ace3 patches the tags' reader to raise.
async fn break_coverage(db: &Db) {
    sqlx::raw_sql(
        "CREATE FUNCTION svs.boom() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'boom'; END $$;
         CREATE TRIGGER boom BEFORE INSERT OR UPDATE ON svs.coverage
             FOR EACH ROW EXECUTE FUNCTION svs.boom();",
    )
    .execute(db.pool())
    .await
    .expect("breaks coverage");
}

/// test_coverage.py's `TestRefresh.test_cli`: the status before any refresh, a refresh's line, and the
/// status after it. ace3's "not the primary node" skip has no counterpart: there's no primary node.
#[tokio::test]
async fn coverage_cli_refresh_and_status() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = coverage_service(db);
    assert_eq!(
        coverage_status(db).await.expect("reads"),
        "coverage has never been refreshed\nworklist: empty\n"
    );

    let (out, code) = coverage_refresh(&service).await.expect("runs");
    assert_eq!(code, 0, "{out}");
    assert!(
        out.starts_with("5 rows: 5 changed (5 new, 0 retired) in ") && out.ends_with("ms\n"),
        "{out}"
    );

    let status = coverage_status(db).await.expect("reads");
    let mut lines = status.lines();
    let first = lines.next().expect("the refresh's line");
    assert!(
        first.starts_with("refreshed 20")
            && first.contains(" against ATT&CK v99.0 in ")
            && first
                .ends_with("ms: 5 rows, 5 changed, 0 retired; 0 unknown and 0 ignored mitre: tags"),
        "{status}"
    );
    assert_eq!(
        lines.collect::<Vec<_>>(),
        ["  macos: 2 none", "  windows: 3 none", "worklist: empty"]
    );
}

/// test_coverage.py's `TestRefresh.test_cli_reports_a_failure`: a failed refresh exits 1 saying why, and
/// the status says the latest refresh failed.
#[tokio::test]
async fn coverage_cli_reports_a_failure() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = coverage_service(db);
    break_coverage(db).await;
    let (out, code) = coverage_refresh(&service).await.expect("runs");
    assert_eq!(code, 1);
    assert!(
        out.starts_with("coverage refresh failed: ") && out.contains("boom"),
        "{out}"
    );
    let status = coverage_status(db).await.expect("reads");
    assert!(
        status.starts_with("coverage has never been refreshed\nthe latest refresh failed: ")
            && status.contains("boom"),
        "{status}"
    );
}

/// test_coverage.py's `TestSnapshot.test_cli`: a snapshot's line names today, UTC, and the release, and a
/// failed one exits 1 saying why.
#[tokio::test]
async fn coverage_cli_snapshot() {
    let test_db = TestDb::new().await;
    let db = test_db.db();
    let service = coverage_service(db);
    let before = chrono::Utc::now().date_naive();
    let (out, code) = coverage_snapshot(&service).await.expect("runs");
    assert_eq!(code, 0, "{out}");
    let today = chrono::Utc::now().date_naive();
    assert!(
        [before, today]
            .iter()
            .any(|day| out == format!("snapshot of {day} against ATT&CK v99.0: 5 rows\n")),
        "{out}"
    );
    let filed: i64 = sqlx::query_scalar("SELECT count(*) FROM svs.coverage_snapshots")
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(filed, 5);

    // a catalog test the next refresh has rows for, and can't write
    sqlx::query(
        "INSERT INTO svs.catalog_tests
             (guid, repository, technique, name, platforms, test, content_hash, commit, path)
         VALUES ('aaaaaaaa-1111-4111-8111-111111111111', 'art', 'T1234.001', 'a test', '{windows}',
                 '{}', repeat('0', 64), repeat('a', 40), 'atomics/T1234.001/T1234.001.yaml')",
    )
    .execute(db.pool())
    .await
    .expect("adds a test");
    break_coverage(db).await;
    let (out, code) = coverage_snapshot(&service).await.expect("runs");
    assert_eq!(code, 1);
    assert!(
        out.starts_with("coverage snapshot failed: ") && out.contains("boom"),
        "{out}"
    );
    let filed: i64 = sqlx::query_scalar("SELECT count(*) FROM svs.coverage_snapshots")
        .fetch_one(db.pool())
        .await
        .expect("counts");
    assert_eq!(filed, 5, "the failed snapshot filed nothing");
}

/// test_worklist.py's `test_cli_status_counts_the_worklist`, and the status's lines from a state: every
/// platform's rows per state, worst first, and the worklist's per status, in ace3's order.
#[test]
fn coverage_status_counts_the_worklist() {
    let counts = |pairs: &[(&str, i64)]| -> BTreeMap<String, i64> {
        pairs
            .iter()
            .map(|(name, count)| ((*name).to_owned(), *count))
            .collect()
    };
    let status = ace_service::SvsCoverageStatus {
        state: Some(ace_service::SvsCoverageRefreshState {
            attack_release: Some("v99.0".to_owned()),
            refreshed_at: Some("2026-10-17T12:00:00Z".parse().expect("a time")),
            duration_ms: Some(42),
            rows: 5,
            changed: 2,
            retired: 1,
            unknown_tags: 3,
            ignored_tags: 4,
            error: Some("boom".to_owned()),
        }),
        counts: [
            (
                "windows".to_owned(),
                counts(&[("none", 1), ("manual", 1), ("failing", 2)]),
            ),
            ("macos".to_owned(), counts(&[("none", 2)])),
        ]
        .into(),
        worklist: counts(&[("undeclared", 1), ("open", 1), ("retired", 7)]),
    };
    assert_eq!(
        coverage_status_report(&status),
        "refreshed 2026-10-17 12:00:00 UTC against ATT&CK v99.0 in 42ms: 5 rows, 2 changed, 1 retired; \
         3 unknown and 4 ignored mitre: tags\n\
         the latest refresh failed: boom\n  macos: 2 none\n  windows: 2 failing, 1 manual, 1 none\n\
         worklist: 1 open, 1 undeclared, 7 retired\n"
    );
}
