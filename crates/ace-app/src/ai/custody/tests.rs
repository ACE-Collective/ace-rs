//! ace3's `tests/aceapi_ai/test_startup_checks.py`, one test a case, each building the violating and
//! the passing process directly as ace3's do.
//!
//! | ace3's case | here |
//! |---|---|
//! | `TestEncryptionCapability::test_saq_enc_present_fails` | `the_encryption_key_in_the_environment_fails` |
//! | `::test_unlocked_encryption_fails` | `a_role_that_reads_the_email_archive_fails` |
//! | `::test_locked_and_unset_passes` | `no_key_and_no_archive_access_passes` |
//! | `TestLocalOverlay::test_missing_env_var_fails` | `an_overlay_with_another_process_s_sections_fails` |
//! | `::test_set_env_var_passes` | `an_overlay_of_its_own_sections_passes` |
//! | `TestInfraSecrets::test_unittest_config_fails` | `the_lease_tokens_and_the_gui_s_sessions_fail` |
//! | `::test_sentineled_config_passes` | `no_token_and_no_session_access_passes` |
//! | `TestBackendCredentials::test_missing_backend_credential_fails` | `ai`'s `a_backend_without_its_credential_stops_the_server` (7.15), and `a_backend_that_can_t_be_built_is_a_failure_with_the_rest` |
//! | `::test_backends_with_credentials_pass` | the same test of `ai`'s, and `the_enabled_backends_secrets_are_what_is_declared` |
//! | `TestSecretLiteralAllowlist::test_declared_literal_passes` | `a_secret_a_backend_declares_passes` |
//! | `::test_undeclared_literal_fails` | `a_secret_no_backend_declares_fails` |
//! | `::test_stray_literal_in_unittest_config_is_flagged` | `another_process_s_secret_in_reach_is_flagged` |
//! | `::test_encrypted_refs_elsewhere_are_permitted` | `a_secret_out_of_reach_is_permitted` |
//! | `TestRunStartupChecks::test_unittest_environment_refuses_boot` | `a_process_set_up_as_ace_serve_refuses_to_start` |
//! | `::test_conforming_environment_boots` | `a_conforming_process_starts` |
//! | `test_advisory_sweep_flags_plaintext_looking_fields` | `the_advisory_sweep_flags_what_reads_as_a_credential` |
//!
//! `custody`'s docs say what each check asserts in ace4's terms. The rest are ace4's own: the
//! bucket's credential, the database role past or short of its grants, and `ace serve`'s refusal of
//! an `ai_api` section. `ace-service`'s `the_ai_role_holds_what_its_migration_grants_and_no_more`
//! checks the role itself against Postgres.

use std::collections::BTreeSet;

use ace_core::testing::TestDb;
use ace_service::ai::role::{GRANTED, GRANTED_COLUMNS, ROLE, SCHEMAS};

use super::*;

/// The role as migration 0064 grants it, held by a login that is its member.
fn ai_role() -> RolePrivileges {
    RolePrivileges {
        user: "ace4_ai_login".to_owned(),
        powers: Vec::new(),
        member_of: BTreeSet::from([ROLE.to_owned()]),
        schemas: SCHEMAS
            .iter()
            .chain(&["public"])
            .map(|schema| (*schema).to_owned())
            .collect(),
        tables: GRANTED
            .iter()
            .flat_map(|(relation, privileges)| {
                privileges
                    .iter()
                    .map(|privilege| ((*relation).to_owned(), (*privilege).to_owned()))
            })
            .collect(),
        columns: GRANTED_COLUMNS
            .iter()
            .flat_map(|(relation, columns, privilege)| {
                columns.iter().map(|column| {
                    (
                        (*relation).to_owned(),
                        (*column).to_owned(),
                        (*privilege).to_owned(),
                    )
                })
            })
            .collect(),
    }
}

/// The role with `SELECT` on these relations too.
fn reading(relations: &[&str]) -> RolePrivileges {
    let mut role = ai_role();
    for relation in relations {
        role.tables
            .insert(((*relation).to_owned(), "SELECT".to_owned()));
    }
    role
}

fn sections(text: &str) -> BTreeMap<String, Value> {
    Overlay::sections(text).expect("parses")
}

/// An AI overlay with a Splunk backend on its read-only instance, whose connection names one
/// secret, as ace3's `etc/saq.ai.yaml` gives `splunk_config_ai_readonly` a token.
const AI_OVERLAY: &str = "connections:\n  ai_readonly:\n    type: splunk\n    settings: {host: \
     splunk.example.com, timezone: GMT}\n    secrets: {token: splunk_ai_readonly_token}\nai_api:\n  \
     enabled: true\n  backends:\n    splunk:\n      type: splunk\n      enabled: true\n      \
     connections: {splunk: ai_readonly}\nsecrets:\n  splunk_ai_readonly_token: \
     env:ACE4_SPLUNK_AI_TOKEN\n";

fn overlay(text: &str) -> Overlay {
    Overlay::from_yaml(text).expect("parses")
}

/// What `ace serve-ai` is meant to hold: the database, its overlay, its backend's token.
fn conforming() -> (Holdings, Overlay) {
    let holdings = Holdings {
        env: Environment::of(&[
            (
                "ACE4_DATABASE_URL",
                "postgres://ace4_ai_login:x@postgres/ace4",
            ),
            ("ACE4_OVERLAY", "/etc/ace4/ai.yaml"),
            ("ACE4_AI_LISTEN", "0.0.0.0:8001"),
            ("ACE4_SPLUNK_AI_TOKEN", "readonly-token"),
        ]),
        sections: sections(AI_OVERLAY),
        role: ai_role(),
    };
    (holdings, overlay(AI_OVERLAY))
}

// --- TestEncryptionCapability ---

#[test]
fn the_encryption_key_in_the_environment_fails() {
    // set, or set to nothing as Compose passes an unset variable on: either way it was handed over
    for value in [
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "",
    ] {
        let mut failures = Vec::new();
        let env = Environment::of(&[(ENCRYPTION_KEY, value)]);
        check_no_encryption_capability(&env, &ai_role(), &mut failures);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].contains("ACE4_ENCRYPTION_KEY"), "{failures:?}");
        assert!(
            value.is_empty() || !failures[0].contains(value),
            "the key isn't in the message"
        );
    }
}

#[test]
fn a_role_that_reads_the_email_archive_fails() {
    let mut failures = Vec::new();
    let role = reading(&["email_archive.archive"]);
    check_no_encryption_capability(&Environment::default(), &role, &mut failures);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].contains("can read the email archive")
            && failures[0].contains("email_archive.archive"),
        "{failures:?}"
    );
}

#[test]
fn no_key_and_no_archive_access_passes() {
    let mut failures = Vec::new();
    check_no_encryption_capability(&Environment::default(), &ai_role(), &mut failures);
    assert_eq!(failures, Vec::<String>::new());
}

// --- TestLocalOverlay ---

#[test]
fn an_overlay_with_another_process_s_sections_fails() {
    // the site's whole overlay, as `ace serve` and the pools read it
    let site = format!(
        "{AI_OVERLAY}modules: {{rdap_analyzer: {{settings: {{api_key: s3cr3t-value}}}}}}\n\
         svs: {{catalog: {{repositories: {{art: {{url: 'https://token@git.example/art.git', \
         branch: main}}}}}}}}\n"
    );
    let mut failures = Vec::new();
    check_overlay_is_its_own(&sections(&site), &mut failures);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].contains("modules, svs") && !failures[0].contains("s3cr3t-value"),
        "{failures:?}"
    );
}

#[test]
fn an_overlay_of_its_own_sections_passes() {
    for text in [
        "",
        AI_OVERLAY,
        "ai_api: {enabled: false}\ndispositions: {SITE_CHECKED: {rank: 45, css: info}}\n\
         disposition_classification: {SITE_CHECKED: fp}\nsecrets: {}\n",
    ] {
        let mut failures = Vec::new();
        check_overlay_is_its_own(&sections(text), &mut failures);
        assert_eq!(failures, Vec::<String>::new(), "{text}");
    }
}

// --- TestInfraSecrets ---

#[test]
fn the_lease_tokens_and_the_gui_s_sessions_fail() {
    // as `ace serve` is set up: the pools' tokens, the admin token, and a role that reads sessions
    let env = Environment::of(&[
        ("ACE4_POOL_TOKEN_PARSERS", "ace4-dev-parsers-token"),
        ("ACE4_POOL_TOKEN_LOOKUPS", "ace4-dev-lookups-token"),
        ("ACE4_ADMIN_TOKEN", "ace4-dev-admin-token"),
    ]);
    let mut failures = Vec::new();
    check_infra_secrets(&env, &reading(&[SESSIONS]), &mut failures);
    assert_eq!(failures.len(), 2, "{failures:?}");
    assert!(
        failures[0].contains("ACE4_ADMIN_TOKEN")
            && failures[0].contains("ACE4_POOL_TOKEN_LOOKUPS")
            && failures[0].contains("ACE4_POOL_TOKEN_PARSERS")
            && !failures[0].contains("ace4-dev-"),
        "{failures:?}"
    );
    assert!(failures[1].contains("service.sessions"), "{failures:?}");

    // a pool's own variable, and a key to the main API, each alone
    for name in ["ACE4_POOL_TOKEN", "ACE4_API_KEY"] {
        let mut failures = Vec::new();
        check_infra_secrets(&Environment::of(&[(name, "x")]), &ai_role(), &mut failures);
        assert_eq!(failures.len(), 1, "{name}: {failures:?}");
    }
}

#[test]
fn no_token_and_no_session_access_passes() {
    let (holdings, _) = conforming();
    let mut failures = Vec::new();
    check_infra_secrets(&holdings.env, &holdings.role, &mut failures);
    assert_eq!(failures, Vec::<String>::new());
}

// --- TestBackendCredentials ---

#[test]
fn the_enabled_backends_secrets_are_what_is_declared() {
    assert_eq!(
        declared_secrets(&overlay(AI_OVERLAY)),
        ["splunk_ai_readonly_token"]
    );
    // a backend that isn't enabled, or an API that isn't, declares nothing
    let disabled = AI_OVERLAY.replace("      enabled: true\n", "      enabled: false\n");
    assert!(declared_secrets(&overlay(&disabled)).is_empty());
    let off = AI_OVERLAY.replace(
        "  enabled: true\n  backends",
        "  enabled: false\n  backends",
    );
    assert!(declared_secrets(&overlay(&off)).is_empty());
}

#[test]
fn a_backend_that_can_t_be_built_is_a_failure_with_the_rest() {
    let (holdings, overlay) = conforming();
    let error = run(
        &holdings,
        &overlay,
        Err("backends.splunk: splunk token is not set".to_owned()),
    )
    .expect_err("refused");
    assert!(
        error.contains("custody checks failed") && error.contains("backends.splunk"),
        "{error}"
    );
}

// --- TestSecretLiteralAllowlist ---

#[test]
fn a_secret_a_backend_declares_passes() {
    let (holdings, overlay) = conforming();
    let mut failures = Vec::new();
    check_secret_allowlist(
        &overlay,
        &["splunk_ai_readonly_token".to_owned()],
        &holdings.env,
        &mut failures,
    );
    assert_eq!(failures, Vec::<String>::new());
}

#[test]
fn a_secret_no_backend_declares_fails() {
    let (holdings, overlay) = conforming();
    let mut failures = Vec::new();
    check_secret_allowlist(&overlay, &[], &holdings.env, &mut failures);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].contains("splunk_ai_readonly_token") && !failures[0].contains("readonly-token"),
        "{failures:?}"
    );
}

#[test]
fn another_process_s_secret_in_reach_is_flagged() {
    // the lookups pool's Splunk password, and a file secret, in the AI process's reach
    let dir = tempfile::tempdir().expect("a directory");
    let file = dir.path().join("resolver_token");
    std::fs::write(&file, "a-live-token\n").expect("writes");
    let text = format!(
        "{AI_OVERLAY}  splunk_default_password: env:ACE4_SPLUNK_PASSWORD\n  resolver_token: file:{}\n",
        file.display()
    );
    let overlay = overlay(&text);
    let env = Environment::of(&[
        ("ACE4_SPLUNK_AI_TOKEN", "readonly-token"),
        ("ACE4_SPLUNK_PASSWORD", "the-hunters-password"),
    ]);
    let mut failures = Vec::new();
    check_secret_allowlist(&overlay, &declared_secrets(&overlay), &env, &mut failures);
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(
        failures[0].contains("resolver_token, splunk_default_password")
            && !failures[0].contains("splunk_ai_readonly_token")
            && !failures[0].contains("the-hunters-password")
            && !failures[0].contains("a-live-token"),
        "{failures:?}"
    );
}

#[test]
fn a_secret_out_of_reach_is_permitted() {
    // named in the overlay, and this process can't read it: a variable that isn't set, one set to
    // nothing, a file that isn't there. ace3 permits a reference its container can't decrypt.
    let text = format!(
        "{AI_OVERLAY}  splunk_default_password: env:ACE4_SPLUNK_PASSWORD\n  empty: env:ACE4_EMPTY\n  \
         resolver_token: file:/run/secrets/not-mounted-here\n"
    );
    let overlay = overlay(&text);
    let env = Environment::of(&[
        ("ACE4_SPLUNK_AI_TOKEN", "readonly-token"),
        ("ACE4_EMPTY", ""),
    ]);
    let mut failures = Vec::new();
    check_secret_allowlist(&overlay, &declared_secrets(&overlay), &env, &mut failures);
    assert_eq!(failures, Vec::<String>::new());
}

// --- TestRunStartupChecks ---

#[test]
fn a_process_set_up_as_ace_serve_refuses_to_start() {
    // ace3's unit-test environment holds SAQ_ENC; `ace serve`'s holds the key and the rest
    let (mut holdings, overlay) = conforming();
    holdings.env = Environment::of(&[
        (
            ENCRYPTION_KEY,
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        ),
        ("ACE4_ADMIN_TOKEN", "ace4-dev-admin-token"),
        ("ACE4_POOL_TOKEN_PARSERS", "ace4-dev-parsers-token"),
        ("ACE4_BUCKET_ACCESS_KEY", "ace4-dev"),
        ("ACE4_BUCKET_SECRET_KEY", "ace4-dev-secret"),
        ("ACE4_SPLUNK_AI_TOKEN", "readonly-token"),
    ]);
    let error = run(&holdings, &overlay, Ok(())).expect_err("refused");
    assert!(
        error.starts_with("AI API custody checks failed, refusing to start:"),
        "{error}"
    );
    // every failure at once, and no value of any of them
    for named in [
        "ACE4_ENCRYPTION_KEY",
        "ACE4_ADMIN_TOKEN",
        "ACE4_POOL_TOKEN_PARSERS",
        "ACE4_BUCKET_ACCESS_KEY",
        "ACE4_BUCKET_SECRET_KEY",
    ] {
        assert!(error.contains(named), "{named}: {error}");
    }
    for value in [
        "00112233",
        "ace4-dev-admin-token",
        "ace4-dev-secret",
        "readonly-token",
    ] {
        assert!(!error.contains(value), "{value}: {error}");
    }
    assert_eq!(error.matches("\n  - ").count(), 3, "{error}");

    // the key alone is enough, as SAQ_ENC is
    let (mut holdings, overlay) = conforming();
    holdings.env = Environment::of(&[(ENCRYPTION_KEY, "")]);
    assert!(run(&holdings, &overlay, Ok(())).is_err());
}

#[test]
fn a_conforming_process_starts() {
    let (holdings, overlay) = conforming();
    assert_eq!(
        run(&holdings, &overlay, Ok(())),
        Ok(Passed {
            declared: vec!["splunk_ai_readonly_token".to_owned()],
            warnings: Vec::new(),
        })
    );
    // and one with no overlay at all: nothing enabled, nothing declared, nothing held
    let bare = Holdings {
        env: Environment::of(&[(
            "ACE4_DATABASE_URL",
            "postgres://ace4_ai_login:x@postgres/ace4",
        )]),
        sections: BTreeMap::new(),
        role: ai_role(),
    };
    assert_eq!(
        run(&bare, &Overlay::default(), Ok(())),
        Ok(Passed {
            declared: Vec::new(),
            warnings: Vec::new(),
        })
    );
}

// --- the advisory sweep ---

#[test]
fn the_advisory_sweep_flags_what_reads_as_a_credential() {
    let text = "ai_api:\n  enabled: true\n  backends:\n    site:\n      type: fake\n      settings:\n        \
                api_key: a-real-looking-value\n        nested: {client_secret: another, tokens: \
                [{token: third}], password: 'env:FROM_ELSEWHERE', keyfile_token: 'file:/run/x', \
                note: not a credential, empty_token: ''}\nsecrets:\n  site_password: \
                env:ACE4_SITE_PASSWORD\n";
    let warnings = advisory_sweep(&sections(text));
    assert_eq!(
        warnings,
        [
            "ai_api.backends.site.settings.api_key",
            "ai_api.backends.site.settings.nested.client_secret",
            "ai_api.backends.site.settings.nested.tokens[0].token",
        ]
    );
    // it warns and doesn't refuse: the name is a guess
    let (mut holdings, _) = conforming();
    holdings.sections = sections(text);
    holdings.env = Environment::default();
    let passed = run(&holdings, &overlay(text), Ok(())).expect("starts");
    assert_eq!(passed.warnings.len(), 3);
    // a source in secrets: stays silent, as ace3's sweep leaves its own store's password out
    assert!(advisory_sweep(&sections(AI_OVERLAY)).is_empty());
    // a connection's secrets: names secrets, and its settings are swept as any others
    let text = "connections:\n  ai_readonly:\n    type: splunk\n    settings: {host: h, token: \
                written-here}\n    secrets: {token: splunk_ai_readonly_token}\n";
    assert_eq!(
        advisory_sweep(&sections(text)),
        ["connections.ai_readonly.settings.token"]
    );
}

// --- ace4's own ---

#[test]
fn the_bucket_s_credential_fails() {
    for name in BUCKET_CREDENTIALS {
        let mut failures = Vec::new();
        check_no_bucket_credential(
            &Environment::of(&[(name, "ace4-dev-secret")]),
            &mut failures,
        );
        assert_eq!(failures.len(), 1, "{name}");
        assert!(failures[0].contains(name) && !failures[0].contains("ace4-dev-secret"));
    }
    // where the bucket is isn't a credential
    let mut failures = Vec::new();
    let env = Environment::of(&[
        ("ACE4_BUCKET_ENDPOINT", "http://bucket:8333"),
        ("ACE4_BUCKET_NAME", "ace4"),
    ]);
    check_no_bucket_credential(&env, &mut failures);
    assert_eq!(failures, Vec::<String>::new());
}

#[test]
fn a_role_past_or_short_of_its_grants_fails() {
    let mut failures = Vec::new();
    check_role(&ai_role(), &mut failures);
    assert_eq!(failures, Vec::<String>::new());

    // the schema's owner, as `ace serve` connects
    let mut owner = reading(&["service.sessions", "store.objects"]);
    owner.user = "ace4".to_owned();
    owner.powers = vec!["superuser".to_owned(), "owner of the database".to_owned()];
    owner.member_of.clear();
    owner
        .tables
        .insert(("analysis.roots".to_owned(), "UPDATE".to_owned()));
    owner.columns.insert((
        "service.users".to_owned(),
        "password_hash".to_owned(),
        "SELECT".to_owned(),
    ));
    owner.schemas.insert("store".to_owned());
    let mut failures = Vec::new();
    check_role(&owner, &mut failures);
    assert_eq!(failures.len(), 1, "{failures:?}");
    for excess in [
        "superuser",
        "owner of the database",
        "schema store",
        "UPDATE on analysis.roots",
        "SELECT on service.sessions",
        "SELECT on store.objects",
        "SELECT on service.users.password_hash",
    ] {
        assert!(failures[0].contains(excess), "{excess}: {failures:?}");
    }

    // a member of another role as well
    let mut also = ai_role();
    also.member_of.insert("pg_read_all_data".to_owned());
    let mut failures = Vec::new();
    check_role(&also, &mut failures);
    assert!(
        failures[0].contains("member of the role pg_read_all_data"),
        "{failures:?}"
    );

    // a role with less can't serve, and says what it lacks
    let mut less = ai_role();
    less.tables
        .remove(&("service.audit".to_owned(), "INSERT".to_owned()));
    let mut failures = Vec::new();
    check_role(&less, &mut failures);
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("lacks") && failures[0].contains("INSERT on service.audit"));
}

#[test]
fn ace_serve_refuses_an_ai_api_section() {
    assert_eq!(not_ace_serve_s(&Overlay::default()), Ok(()));
    assert_eq!(
        not_ace_serve_s(&overlay("secrets: {t: 'env:T'}\nmodules: {}\n")),
        Ok(())
    );
    for text in [
        "ai_api: {enabled: true}",
        "ai_api: {backends: {fake: {type: fake}}}",
        AI_OVERLAY,
    ] {
        let error = not_ace_serve_s(&overlay(text)).expect_err("refused");
        assert!(error.contains("ace serve-ai"), "{error}");
    }
}

/// The whole of it against a database: the service `ace serve-ai` builds from its overlay, under the
/// role, and the checks over what the catalog says of the role and of the owner.
#[tokio::test]
async fn the_checks_read_the_role_from_the_database() {
    let test_db = TestDb::new().await;
    let app = crate::App::new();
    let as_role = ace_core::Db::connect(&test_db.config().clone().role(ROLE))
        .await
        .expect("connects as the role");
    let text = "ai_api: {enabled: true, backends: {fake: {type: fake, enabled: true}}}\n";
    let on = overlay(text);
    let no_env = |_: &str| None;
    let service =
        crate::serve_ai::service(&app, &on, as_role.clone(), &no_env, None).expect("builds");
    assert_eq!(service.ai_surface().expect("on").backend_names(), ["fake"]);
    // off, there is no surface; a backend that can't be built is the error
    let off = crate::serve_ai::service(&app, &Overlay::default(), as_role.clone(), &no_env, None)
        .expect("builds");
    assert!(off.ai_surface().is_none());
    let broken =
        crate::serve_ai::service(&app, &overlay(AI_OVERLAY), as_role.clone(), &no_env, None)
            .map(|_| ())
            .expect_err("no credential");
    assert!(broken.contains("backends.splunk"), "{broken}");

    // the role itself passes; the role the tests connect as, which owns the schema, doesn't
    let role = ace_service::ai::role::role_privileges_of(test_db.db(), ROLE)
        .await
        .expect("reads");
    let holdings = Holdings {
        env: Environment::default(),
        sections: sections(text),
        role,
    };
    assert_eq!(
        run(&holdings, &on, Ok(())),
        Ok(Passed {
            declared: Vec::new(),
            warnings: Vec::new(),
        })
    );
    let owner = ace_service::ai::role::role_privileges(test_db.db())
        .await
        .expect("reads");
    let holdings = Holdings {
        role: owner,
        ..holdings
    };
    let error = run(&holdings, &on, Ok(())).expect_err("refused");
    for named in [
        "superuser",
        "can read the email archive",
        "service.sessions",
    ] {
        assert!(error.contains(named), "{named}: {error}");
    }
    // it can do too much, and nothing the API needs is beyond it
    assert!(!error.contains("lacks what the AI API needs"), "{error}");

    // the migration the binary was built with is the one a migrated database is at
    assert_eq!(
        ace_service::ai::role::schema_version(&as_role)
            .await
            .expect("reads"),
        Some(ace_core::db::latest_migration())
    );
}
