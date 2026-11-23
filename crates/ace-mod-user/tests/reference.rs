//! PLAN.md 7.4: the user module against ace3's reference dumps. ace3 asked
//! tools/ace3/dumps/fake_ldap.py, which served tools/ace3/dumps/fixtures/ldap/directory.json in
//! plaintext, as ace3 binds; here `ace_testkit::ldap` serves the same directory the same way, with
//! `allow_plaintext` set as the overlay must set it for that. Each run's subtree searches are the
//! ones ace3 made, and every difference in the results is listed in differences.md, next to this
//! file. The TLS tests follow.

use std::path::{Path, PathBuf};

use ace_mod_user::UserAnalyzer;
use ace_results::ObservableKind;
use ace_sdk::{ModuleError, Outcome};
use ace_testkit::ldap::{LdapFake, Transport};
use ace_testkit::reference::{Dump, ListedDifferences, diff, dumps_dir, normal_form};
use ace_testkit::{Harness, HarnessError};
use serde_json::{Value, json};

fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/ace3/dumps/fixtures/ldap/directory.json")
}

fn settings(server: &str) -> Value {
    json!({
        "server": server,
        "bind_user": "CN=ace-rs,OU=Service,DC=company,DC=example",
        "base_dn": "DC=company,DC=example",
        "top_user": "ceo",
        "local_email_domains": ["company.example"],
    })
}

/// The searches a recording holds of entries under the base, which are the module's own; the root
/// DSE's and the schema's are each client's.
fn user_searches(searches: &[Value]) -> Vec<Value> {
    searches
        .iter()
        .filter(|s| s["scope"] == "subtree")
        .cloned()
        .collect()
}

#[tokio::test]
async fn matches_the_reference_dumps_or_lists_each_difference() {
    let listed = ListedDifferences::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differences.md"),
    )
    .expect("differences.md reads");
    let mut compared = Vec::new();
    let dumps: Vec<Dump> = Dump::all("user_analyzer")
        .expect("the dumps read")
        .into_iter()
        .filter(|d| !d.name.ends_with(".ldap"))
        .collect();
    assert_eq!(dumps.len(), 16);
    for dump in dumps {
        let input = &dump.value["input"];
        let kind: ObservableKind = input["observable"]["type"]
            .as_str()
            .expect("a type")
            .parse()
            .expect("a kind");
        let value = input["observable"]["value"].as_str().expect("a value");
        let label = input["label"].as_str().expect("a label");
        let page_limit = usize::from(label.ends_with("with 1 entry a page"));
        let fake = LdapFake::start(&directory(), Transport::Plain, page_limit)
            .await
            .expect("the fake starts");
        let mut block = settings(&fake.url());
        block["allow_plaintext"] = json!(true);
        let harness = Harness::<UserAnalyzer>::with_settings(block)
            .expect("harness")
            .secret(ace_mod_user::PASSWORD, "ace-rs-fake-password");
        let mut observable = harness.observable(kind, value);
        observable.directives = input["directives"]
            .as_array()
            .expect("directives")
            .iter()
            .map(|d| d.as_str().expect("a directive").to_owned())
            .collect();
        let outcome = harness
            .run_lookup(observable)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", dump.name));
        let recorded: Value = serde_json::from_str(
            &std::fs::read_to_string(dumps_dir().join(format!("{}.ldap.json", dump.name)))
                .expect("the recording reads"),
        )
        .expect("JSON");
        assert_eq!(
            user_searches(&fake.searches()),
            user_searches(recorded["searches"].as_array().expect("searches")),
            "{}: the searches ace3 made",
            dump.name
        );
        if dump.short_name() == "user_jdoe" {
            ace_testkit::check_view_fixture("user_jdoe", &outcome);
        }
        compared.push((
            dump.short_name().to_owned(),
            diff(&dump.normal_form("UserAnalysis"), &normal_form(&outcome)),
        ));
    }
    if let Err(report) = listed.check(&compared, &[]) {
        panic!("{report}");
    }
}

/// The module's default is TLS: an `ldaps://` server whose certificate the overlay's CA file
/// vouches for is found, the same server without the CA file is refused before a bind, and an
/// `ldap://` server is asked to StartTLS before the bind, which the fake refuses in the clear.
#[tokio::test]
async fn tls_is_verified_and_starttls_comes_before_the_bind() {
    for transport in [Transport::Ldaps, Transport::StartTls] {
        let fake = LdapFake::start(&directory(), transport, 0)
            .await
            .expect("the fake starts");
        let dir = tempfile_dir();
        let ca = dir.join(format!("ca-{transport:?}.pem"));
        std::fs::write(&ca, fake.ca_pem().expect("a certificate")).expect("writes");

        let untrusted = Harness::<UserAnalyzer>::with_settings(settings(&fake.url()))
            .expect("harness")
            .secret(ace_mod_user::PASSWORD, "ace-rs-fake-password");
        let err = untrusted
            .run_lookup(untrusted.observable(ObservableKind::User, "jdoe"))
            .await
            .expect_err("an untrusted certificate");
        assert!(
            matches!(err, HarnessError::Module(_)),
            "{transport:?}: {err}"
        );
        assert!(
            fake.binds().is_empty(),
            "{transport:?}: no bind without TLS"
        );

        let mut block = settings(&fake.url());
        block["ca_certificates"] = json!(ca);
        let trusted = Harness::<UserAnalyzer>::with_settings(block)
            .expect("harness")
            .secret(ace_mod_user::PASSWORD, "ace-rs-fake-password");
        let outcome = trusted
            .run_lookup(trusted.observable(ObservableKind::User, "jdoe"))
            .await
            .unwrap_or_else(|e| panic!("{transport:?}: {e}"));
        let Outcome::Done(result) = outcome else {
            panic!("{transport:?}: a result");
        };
        assert_eq!(result.analyzed.tags, ["executive"], "{transport:?}");
        assert_eq!(
            fake.binds(),
            [(
                "CN=ace-rs,OU=Service,DC=company,DC=example".to_owned(),
                true
            )],
            "{transport:?}"
        );
    }
}

/// Plain LDAP isn't used unless the overlay allows it: an `ldap://` server that doesn't offer
/// StartTLS fails the task, and the password is never sent.
#[tokio::test]
async fn plain_ldap_needs_allow_plaintext() {
    let fake = LdapFake::start(&directory(), Transport::Plain, 0)
        .await
        .expect("the fake starts");
    let harness = Harness::<UserAnalyzer>::with_settings(settings(&fake.url()))
        .expect("harness")
        .secret(ace_mod_user::PASSWORD, "ace-rs-fake-password");
    let err = harness
        .run_lookup(harness.observable(ObservableKind::User, "jdoe"))
        .await
        .expect_err("StartTLS refused");
    assert!(matches!(err, HarnessError::Module(_)), "{err}");
    assert!(fake.binds().is_empty());
}

/// A wrong password is the site's configuration, a failure another attempt won't fix; a server
/// that isn't there is unavailable, so the task runs again later.
#[tokio::test]
async fn a_refused_bind_fails_and_a_missing_server_is_unavailable() {
    let fake = LdapFake::start(&directory(), Transport::Plain, 0)
        .await
        .expect("the fake starts");
    let mut block = settings(&fake.url());
    block["allow_plaintext"] = json!(true);
    let harness = Harness::<UserAnalyzer>::with_settings(block.clone())
        .expect("harness")
        .secret(ace_mod_user::PASSWORD, "wrong");
    let err = harness
        .run_lookup(harness.observable(ObservableKind::User, "jdoe"))
        .await
        .expect_err("refused");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Other(_))),
        "{err}"
    );
    let port = fake.port();
    drop(fake);
    block["server"] = json!(format!("ldap://127.0.0.1:{port}"));
    let harness = Harness::<UserAnalyzer>::with_settings(block)
        .expect("harness")
        .secret(ace_mod_user::PASSWORD, "ace-rs-fake-password");
    let err = harness
        .run_lookup(harness.observable(ObservableKind::User, "jdoe"))
        .await
        .expect_err("no server");
    assert!(
        matches!(err, HarnessError::Module(ModuleError::Unavailable(_))),
        "{err}"
    );
}

fn tempfile_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ace-mod-user-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    dir
}
