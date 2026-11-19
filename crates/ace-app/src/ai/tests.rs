//! PLAN.md 7.15: the overlay's `ai_api` section as a surface, and ace3's Splunk backend against a
//! recorded splunkd. No test reaches a real data source: the Splunk here is `ace-testkit`'s replay of
//! exchanges recorded from ace3's fake.
//!
//! ace3's cases, and where each is:
//!
//! | `tests/saq/ai_query/test_registry.py` | here |
//! |---|---|
//! | `test_ai_query_backend_config_loaded_from_prefix_scan` | `a_backend_s_entry_takes_ace3_s_defaults` |
//! | `test_unknown_backend_config_raises` | `only_enabled_backends_are_built` (a name with no entry has no backend) |
//! | `test_config_parse_does_not_import_backend_module` | `a_type_the_binary_lacks_parses_and_then_stops_the_server` |
//! | `test_registry_builds_enabled_backends` | `only_enabled_backends_are_built` |
//! | `test_load_backend_rejects_non_backend_class` | none: a factory returns a backend or an error, by its type |
//! | `test_fake_backend_*` (4) | `ace-service`'s `ai` tests |
//!
//! | `tests/saq/ai_query/test_splunk_backend.py` | here |
//! |---|---|
//! | `test_config_revalidated_against_backend_model` | `the_splunk_backend_reads_its_settings` |
//! | `test_validate_request_rejections` | `the_splunk_backend_refuses_what_ace3_s_does` |
//! | `test_execute_builds_client_per_request_and_appends_fields` | `a_query_is_one_search_with_its_window_and_fields` (one client, `ai`'s docs) |
//! | `test_execute_applies_config_defaults` | `a_query_is_one_search_with_its_window_and_fields` |
//! | `test_execute_truncation_at_limit` | `rows_at_the_limit_are_truncated_and_say_so` |
//! | `test_execute_filters_splunk_messages` | none: the client reads a job's results, which hold no message |
//! | `test_execute_maps_remote_errors` (3) | `a_failed_search_maps_as_ace3_s`, `a_splunk_that_refuses_is_a_502` |
//! | `test_validate_startup_rejects_encrypted_ref` | none: a secret comes from the environment or a file |
//! | `test_validate_startup_rejects_missing_credential` | `a_backend_without_its_credential_stops_the_server` |
//! | `test_validate_startup_returns_owned_paths` | `a_backend_gets_only_the_secrets_it_lists` |
//!
//! `tests/aceapi_ai/test_startup_checks.py`'s 16 cases are about ace3's separate container, which is
//! `ace serve-ai` here (`serve_ai`'s docs). Its two `TestBackendCredentials` cases are
//! `a_backend_without_its_credential_stops_the_server`, which also builds the backend once its
//! credential is there. The other 14 are `custody`'s tests, which map each.

use std::time::Duration;

use ace_core::testing::TestDb;
use ace_sdk::Overlay;
use ace_service::ai::{AiLimits, AiQueryBackend, AiQueryError, AiQueryRequest};
use ace_testkit::replay::HttpReplay;
use chrono::{TimeDelta, TimeZone, Utc};
use serde_json::{Map, json};

use super::*;

const SPLUNKD: &str = "https://127.0.0.1:8089";

async fn splunkd() -> HttpReplay {
    HttpReplay::start(
        &ace_testkit::reference::dumps_dir().join("proxy_domain_lookup/fqdn_www.example.com.http"),
        &[],
    )
    .await
    .expect("the recording loads")
}

fn no_env(_: &str) -> Option<String> {
    None
}

fn env(name: &str) -> Option<String> {
    (name == "AI_SPLUNK_PASSWORD").then(|| "ace4-fake-password".to_owned())
}

fn setup(replay: &HttpReplay) -> AiBackendSetup {
    AiBackendSetup {
        name: "splunk".to_owned(),
        settings: Some(json!({
            "splunk": {
                "host": "splunk.example.com",
                "base_url": replay.local_url(SPLUNKD),
                "username": "ace4",
                "timezone": "GMT",
                "request_timeout_seconds": 10,
            },
        })),
        secrets: Secrets::new().with("ai_splunk", ace_sdk::Secret::new("ace4-fake-password")),
        connections: ace_sdk::Connections::new(),
    }
}

fn request(query: &str) -> AiQueryRequest {
    let end = Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap();
    AiQueryRequest {
        query: query.to_owned(),
        start_time: Some(end - TimeDelta::hours(1)),
        end_time: Some(end),
        limit: None,
        timeout_seconds: None,
        extras: Map::new(),
    }
}

#[tokio::test]
async fn the_api_is_off_unless_the_overlay_turns_it_on() {
    let test_db = TestDb::new().await;
    let types = builtin_types();
    // nothing, or a section that doesn't say enabled, is no surface, and builds no backend: this
    // one's credential isn't there and nothing asks for it
    for text in [
        "",
        "ai_api: {}",
        "secrets: {t: 'env:NOT_SET'}\n\
         ai_api: {backends: {splunk: {type: splunk, enabled: true, secrets: [t], \
         settings: {splunk: {host: h, timezone: GMT}}}}}",
    ] {
        let overlay = Overlay::from_yaml(text).expect("parses");
        assert!(!overlay.ai_api.enabled);
        let surface = surface(&types, &overlay, test_db.db().clone(), &no_env).expect("checks");
        assert!(surface.is_none(), "{text}");
    }
    let overlay = Overlay::from_yaml("ai_api: {enabled: true}").expect("parses");
    let on = surface(&types, &overlay, test_db.db().clone(), &no_env)
        .expect("checks")
        .expect("on");
    assert!(on.backend_names().is_empty());
}

#[tokio::test]
async fn a_backend_s_entry_takes_ace3_s_defaults() {
    let test_db = TestDb::new().await;
    let overlay = Overlay::from_yaml(
        "ai_api:\n  enabled: true\n  export_limits: {max_concurrency: 3}\n  backends:\n    \
         fake: {type: fake, enabled: true}\n    \
         tuned: {type: fake, enabled: true, limits: {max_concurrency: 4, requests_per_minute: 30, \
         hourly_budget: 400, max_window: '180:00:00:00'}}\n",
    )
    .expect("parses");
    let surface = surface(&builtin_types(), &overlay, test_db.db().clone(), &no_env)
        .expect("checks")
        .expect("on");
    let fake = surface.backend("fake").expect("built");
    assert_eq!(fake.limits, AiLimits::default());
    assert_eq!(
        (fake.limits.max_concurrency, fake.limits.default_limit),
        (2, 1000)
    );
    assert_eq!(fake.limits.max_window(), "90:00:00:00");
    let tuned = &surface.backend("tuned").expect("built").limits;
    assert_eq!(
        (
            tuned.max_concurrency,
            tuned.requests_per_minute,
            tuned.hourly_budget,
            tuned.max_window_seconds,
            tuned.max_limit
        ),
        (4, 30, 400, 180 * 86_400, 5000)
    );

    // limits that can't be used stop the server, and say which
    for (text, names) in [
        (
            "ai_api: {search_limits: {max_concurrency: 0}}",
            "search_limits",
        ),
        (
            "ai_api: {export_limits: {max_window: soon}}",
            "export_limits",
        ),
        (
            "ai_api: {backends: {b: {type: fake, limits: {default_limit: 9, max_limit: 5}}}}",
            "backends.b.limits",
        ),
        (
            "ai_api: {backends: {b: {type: fake, limits: {max_query_timeout: 86400}}}}",
            "backends.b.limits",
        ),
    ] {
        let overlay = Overlay::from_yaml(text).expect("parses");
        let error =
            surface_error(&overlay, test_db.db().clone()).unwrap_or_else(|| panic!("{text}"));
        assert!(error.contains(names), "{error}");
    }
}

fn surface_error(overlay: &Overlay, db: ace_core::Db) -> Option<String> {
    surface(&builtin_types(), overlay, db, &no_env).err()
}

#[tokio::test]
async fn only_enabled_backends_are_built() {
    let test_db = TestDb::new().await;
    let overlay = Overlay::from_yaml(
        "ai_api:\n  enabled: true\n  rate_limit_fail_open: true\n  backends:\n    \
         fake: {type: fake, enabled: true}\n    \
         fake_unwindowed: {type: fake_unwindowed, enabled: true}\n    \
         off: {type: fake}\n",
    )
    .expect("parses");
    let surface = surface(&builtin_types(), &overlay, test_db.db().clone(), &no_env)
        .expect("checks")
        .expect("on");
    assert_eq!(surface.backend_names(), ["fake", "fake_unwindowed"]);
    assert!(surface.backend("fake").expect("built").backend.windowed());
    assert!(
        !surface
            .backend("fake_unwindowed")
            .expect("built")
            .backend
            .windowed()
    );
    assert!(surface.backend("off").is_none());
    assert!(surface.backend("does_not_exist").is_none());

    // a name that can't be a permission's minor, or that is a route's own, can't be a backend's
    for (name, reason) in [
        ("Fake", "lowercase"),
        ("a b", "permission part"),
        ("alert", "route's own permission"),
        ("export", "route's own permission"),
    ] {
        let overlay = Overlay::from_yaml(&format!(
            "ai_api: {{enabled: true, backends: {{'{name}': {{type: fake, enabled: true}}}}}}"
        ))
        .expect("parses");
        let error = surface_error(&overlay, test_db.db().clone()).expect("refused");
        assert!(error.contains(reason), "{name}: {error}");
    }
    // the fakes take no settings
    let overlay = Overlay::from_yaml(
        "ai_api: {enabled: true, backends: {fake: {type: fake, enabled: true, settings: {a: 1}}}}",
    )
    .expect("parses");
    assert!(
        surface_error(&overlay, test_db.db().clone())
            .expect("refused")
            .contains("takes no settings")
    );
}

#[tokio::test]
async fn a_type_the_binary_lacks_parses_and_then_stops_the_server() {
    let test_db = TestDb::new().await;
    let overlay =
        Overlay::from_yaml("ai_api: {backends: {bogus: {type: does_not_exist, enabled: true}}}")
            .expect("the overlay parses: it names a type, it doesn't load one");
    assert_eq!(overlay.ai_api.backends["bogus"].kind, "does_not_exist");
    let error = surface_error(&overlay, test_db.db().clone()).expect("refused");
    assert!(
        error.contains("backends.bogus: this binary has no backend type \"does_not_exist\"")
            && error.contains("fake, fake_unwindowed, splunk"),
        "{error}"
    );

    // a site's binary adds its own type, and may replace a built-in's
    let app = crate::App::new()
        .ai_backend_type("does_not_exist", |_| {
            Ok(Arc::new(FakeBackend::new()) as Arc<dyn AiQueryBackend>)
        })
        .ai_backend_type("splunk", |_| Err("replaced".to_owned()));
    let overlay = Overlay::from_yaml(
        "ai_api: {enabled: true, backends: {bogus: {type: does_not_exist, enabled: true}}}",
    )
    .expect("parses");
    let built = surface(
        &app.ai_backend_types(),
        &overlay,
        test_db.db().clone(),
        &no_env,
    )
    .expect("checks")
    .expect("on");
    assert_eq!(built.backend_names(), ["bogus"]);
    let overlay =
        Overlay::from_yaml("ai_api: {enabled: true, backends: {s: {type: splunk, enabled: true}}}")
            .expect("parses");
    let error = surface(
        &app.ai_backend_types(),
        &overlay,
        test_db.db().clone(),
        &no_env,
    )
    .expect_err("the site's type is the one built");
    assert_eq!(error, "backends.s: replaced");
}

/// ace3's `validate_startup`: a backend whose credential can't be read stops the server, with a reason
/// that names the setting and never a value.
#[tokio::test]
async fn a_backend_without_its_credential_stops_the_server() {
    let test_db = TestDb::new().await;
    let entry = |secrets: &str, username: &str| {
        format!(
            "secrets: {{ai_splunk: 'env:AI_SPLUNK_PASSWORD', other: 'env:AI_SPLUNK_PASSWORD'}}\n\
             ai_api:\n  enabled: true\n  backends:\n    splunk:\n      type: splunk\n      \
             enabled: true\n      secrets: {secrets}\n      settings:\n        \
             splunk: {{host: splunk.example.com, timezone: GMT{username}}}\n"
        )
    };
    let build = |text: &str, env: &dyn Fn(&str) -> Option<String>| {
        let overlay = Overlay::from_yaml(text).expect("parses");
        surface(&builtin_types(), &overlay, test_db.db().clone(), env)
    };
    // no secret named, and one named that isn't set
    let error = build(&entry("[]", ""), &env).expect_err("no token");
    assert!(
        error.starts_with("backends.splunk: splunk token is not set"),
        "{error}"
    );
    let error = build(&entry("[ai_splunk]", ", username: ace4"), &no_env).expect_err("not set");
    assert!(
        error.starts_with("backends.splunk: splunk password is not set"),
        "{error}"
    );
    let error = build(&entry("[ai_splunk, other]", ""), &env).expect_err("two");
    assert!(error.contains("takes one secret"), "{error}");
    // no error says what a secret holds
    assert!(!error.contains("ace4-fake-password"));
    // with it, the backend is built, and nothing prints the credential
    let surface = build(&entry("[ai_splunk]", ""), &env)
        .expect("builds")
        .expect("on");
    let shown = format!("{surface:?}");
    assert!(
        shown.contains("SplunkBackend") && !shown.contains("ace4-fake-password"),
        "{shown}"
    );

    // a secret the overlay's secrets: doesn't name is refused when the overlay is read
    let error =
        Overlay::from_yaml("ai_api: {backends: {splunk: {type: splunk, secrets: [nowhere]}}}")
            .expect_err("refused")
            .to_string();
    assert!(
        error.contains("ai_api.backends.splunk.secrets") && error.contains("\"nowhere\""),
        "{error}"
    );
}

#[tokio::test]
async fn a_backend_gets_only_the_secrets_it_lists() {
    let test_db = TestDb::new().await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = seen.clone();
    let app = crate::App::new().ai_backend_type("probe", move |setup| {
        let names: Vec<String> = setup
            .secrets
            .names()
            .into_iter()
            .map(str::to_owned)
            .collect();
        record.lock().unwrap().push((setup.name.clone(), names));
        Ok(Arc::new(FakeBackend::new()) as Arc<dyn AiQueryBackend>)
    });
    let overlay = Overlay::from_yaml(
        "secrets: {mine: 'env:AI_SPLUNK_PASSWORD', theirs: 'env:AI_SPLUNK_PASSWORD'}\n\
         ai_api: {enabled: true, backends: {\n  \
         one: {type: probe, enabled: true, secrets: [mine]},\n  \
         two: {type: probe, enabled: true}}}\n",
    )
    .expect("parses");
    surface(
        &app.ai_backend_types(),
        &overlay,
        test_db.db().clone(),
        &env,
    )
    .expect("builds")
    .expect("on");
    assert_eq!(
        *seen.lock().unwrap(),
        [
            ("one".to_owned(), vec!["mine".to_owned()]),
            ("two".to_owned(), vec![])
        ]
    );
}

#[tokio::test]
async fn the_splunk_backend_reads_its_settings() {
    let replay = splunkd().await;
    let backend = SplunkBackend::new(&setup(&replay)).expect("builds");
    assert_eq!(backend.auto_append, "| fields *");
    assert_eq!(backend.host, "splunk.example.com");
    let described = backend.describe();
    assert_eq!(described["query_language"], "SPL");
    assert!(
        described["notes"]
            .as_str()
            .unwrap()
            .contains("'| fields *'")
    );
    assert!(backend.windowed() && backend.extras_schema().is_none());

    for (settings, reason) in [
        (json!(null), "settings:"),
        (
            json!({"splunk": {"host": "h", "timezone": "GMT"}, "extra": 1}),
            "unknown field",
        ),
        (
            json!({"splunk": {"host": "h", "timezone": "Nowhere/None"}}),
            "timezone",
        ),
    ] {
        let error = SplunkBackend::new(&AiBackendSetup {
            settings: Some(settings),
            ..setup(&replay)
        })
        .expect_err("refused");
        assert!(error.contains(reason), "{error}");
    }
}

#[tokio::test]
async fn the_splunk_backend_refuses_what_ace3_s_does() {
    let replay = splunkd().await;
    let backend = SplunkBackend::new(&setup(&replay)).expect("builds");
    let limits = AiLimits::default();
    let refused = |request: AiQueryRequest| backend.validate(&request, &limits).unwrap_err();

    assert_eq!(refused(request("  ")), "query must not be empty");
    let good = request("search index=main");
    assert_eq!(
        refused(AiQueryRequest {
            start_time: good.end_time,
            end_time: good.start_time,
            ..good.clone()
        }),
        "start_time must be before end_time"
    );
    // one day past the widest window
    let too_wide = TimeDelta::seconds(limits.max_window_seconds) + TimeDelta::days(1);
    assert_eq!(
        refused(AiQueryRequest {
            start_time: good.end_time.map(|end| end - too_wide),
            ..good.clone()
        }),
        "query window exceeds the maximum of 90:00:00:00 (DD:HH:MM:SS)"
    );
    assert_eq!(
        refused(AiQueryRequest {
            limit: Some(limits.max_limit + 1),
            ..good.clone()
        }),
        "limit exceeds the maximum of 5000"
    );
    assert_eq!(backend.validate(&good, &limits), Ok(()));
}

#[tokio::test]
async fn a_query_is_one_search_with_its_window_and_fields() {
    let replay = splunkd().await;
    let backend = SplunkBackend::new(&setup(&replay))
        .expect("builds")
        .with_poll(Duration::from_millis(10));
    let limits = AiLimits::default();
    let asked = AiQueryRequest {
        limit: Some(50),
        timeout_seconds: Some(60),
        ..request("search index=main")
    };
    let result = backend.execute(&asked, &limits).await.expect("answers");
    assert!(!result.rows.is_empty());
    assert!(!result.truncated && result.truncation_reason.is_none());
    assert_eq!(
        (result.window_start, result.window_end),
        (asked.start_time, asked.end_time)
    );
    let link = result.meta["search_link"].as_str().expect("a link");
    assert!(link.starts_with("https://splunk.example.com"), "{link}");

    // the job: the window in front of the query in the instance's timezone, the fields kept, the
    // limit as its count, and the window again as its range
    let submitted = |replay: &HttpReplay| -> Vec<String> {
        replay
            .requests()
            .into_iter()
            .filter(|r| r.method == "POST" && r.url.ends_with("/search/v2/jobs/"))
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect()
    };
    let jobs = submitted(&replay);
    assert_eq!(jobs.len(), 1, "one search for one query");
    let form: std::collections::BTreeMap<String, String> = jobs[0]
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.replace('+', " ")))
        .collect();
    assert_eq!(
        form["search"],
        "search earliest%3D01%2F01%2F2026%3A23%3A00%3A00 latest%3D01%2F02%2F2026%3A00%3A00%3A00 \
         index%3Dmain %7C fields %2A"
    );
    assert_eq!(form["max_count"], "50");
    assert_eq!(form["exec_mode"], "normal");
    assert_eq!(form["earliest_time"], "2026-01-01T23%3A00%3A00%2B00%3A00");
    assert_eq!(form["latest_time"], "2026-01-02T00%3A00%3A00%2B00%3A00");
    assert!(replay.unmatched().is_empty(), "{:?}", replay.unmatched());

    // with no limit of its own a request takes the backend's default, and a generating command gets
    // no `search` and no window in front
    let replay = splunkd().await;
    let backend = SplunkBackend::new(&setup(&replay))
        .expect("builds")
        .with_poll(Duration::from_millis(10));
    backend
        .execute(&request("| tstats count where index=main"), &limits)
        .await
        .expect("answers");
    let jobs = submitted(&replay);
    assert!(jobs[0].contains("max_count=1000"), "{}", jobs[0]);
    assert!(
        jobs[0].starts_with("search=%7C+tstats+count"),
        "{}",
        jobs[0]
    );
}

#[tokio::test]
async fn rows_at_the_limit_are_truncated_and_say_so() {
    let replay = splunkd().await;
    let backend = SplunkBackend::new(&setup(&replay))
        .expect("builds")
        .with_poll(Duration::from_millis(10));
    let limits = AiLimits::default();
    let all = backend
        .execute(&request("search index=main"), &limits)
        .await
        .expect("answers");
    let rows = u32::try_from(all.rows.len()).unwrap();

    let replay = splunkd().await;
    let backend = SplunkBackend::new(&setup(&replay))
        .expect("builds")
        .with_poll(Duration::from_millis(10));
    let result = backend
        .execute(
            &AiQueryRequest {
                limit: Some(rows),
                ..request("search index=main")
            },
            &limits,
        )
        .await
        .expect("answers");
    assert!(result.truncated);
    assert_eq!(result.truncation_reason.as_deref(), Some("limit"));
}

#[test]
fn a_failed_search_maps_as_ace3_s() {
    let status = |error: SearchError| match backend_error(error) {
        AiQueryError::Backend { status, reason } => (status, reason),
        other => panic!("{other:?}"),
    };
    // a 401 from Splunk isn't the caller's key failing
    assert_eq!(
        status(SearchError::Failed(
            "HTTP 401 Unauthorized -- call not properly authenticated".to_owned()
        )),
        (502, "splunk authentication failure".to_owned())
    );
    let (code, reason) = status(SearchError::TimedOut {
        phase: "run",
        budget: Duration::from_secs(60),
    });
    assert_eq!(code, 504);
    assert!(reason.contains("exceeded its run budget"), "{reason}");
    for other in [
        SearchError::Failed("HTTP 500 Internal Server Error".to_owned()),
        SearchError::Unavailable("connection refused".to_owned()),
    ] {
        assert_eq!(status(other).0, 502);
    }
}

/// A splunkd that has nothing recorded for the search answers 404: the backend's failure, a 502.
#[tokio::test]
async fn a_splunk_that_refuses_is_a_502() {
    let replay = splunkd().await;
    let mut wrong = setup(&replay);
    wrong.settings = Some(json!({
        "splunk": {
            "host": "splunk.example.com",
            "base_url": replay.local_url("https://127.0.0.1:9999"),
            "username": "ace4",
            "timezone": "GMT",
            "request_timeout_seconds": 10,
        },
    }));
    let backend = SplunkBackend::new(&wrong)
        .expect("builds")
        .with_poll(Duration::from_millis(10));
    let error = backend
        .execute(&request("search index=main"), &AiLimits::default())
        .await
        .expect_err("fails");
    match error {
        AiQueryError::Backend { status, reason } => {
            assert_eq!(status, 502);
            assert!(!reason.contains("ace4-fake-password"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
}
