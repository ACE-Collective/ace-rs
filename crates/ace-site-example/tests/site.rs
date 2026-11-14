//! PLAN.md 2.31's Done check: a site's binaries, built through ace-app from the open-source pools
//! plus one module and one observable type of the site's own, run a submission. The site's
//! `ace serve` runs on a test database and the stack's bucket, and the site's network pool runs
//! as its own contained process with only the lease API's URL and its token, as in Compose. The
//! submission goes to the JSON API's listener with a key the site's `ace user create-key` made
//! (PLAN.md 5.5).
//!
//! The ticket lookup's result on the submitted fqdn adds an `example_ticket` observable. The
//! core checks the result against the type's schema, which lists the site's type, stores the
//! observable under it, and queues the ticket lookup on it, which only works if the pool reads
//! the site's type off the leased task. The root completes. `ace schema export` from the site's
//! binary writes the site's analysis type, with the site's type among the observable types.
//! Needs the stack's postgres and bucket services.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ace_core::testing::TestDb;
use serde_json::{Value, json};
use uuid::Uuid;

const POOL_TOKEN: &str = "ace4-site-test-lookups-token";
const BOUNDARY: &str = "ace4-site-test-boundary";

/// A process of the site's, killed when dropped, whose stderr goes to a file.
struct Process {
    child: Child,
    log: std::path::PathBuf,
}

impl Process {
    fn start(mut command: Command, log: &Path) -> Process {
        let file = std::fs::File::create(log).expect("a log file");
        let child = command
            .stdout(Stdio::null())
            .stderr(file)
            .spawn()
            .expect("the process starts");
        Process {
            child,
            log: log.to_owned(),
        }
    }

    /// Stops the process with SIGTERM, waits up to 30 seconds, and returns its log.
    fn stop(&mut self) -> String {
        let pid = i32::try_from(self.child.id()).unwrap_or_default();
        // SAFETY: kill takes integers only; the pid is this child's, not yet reaped
        unsafe { libc::kill(pid, libc::SIGTERM) };
        let started = Instant::now();
        while matches!(self.child.try_wait(), Ok(None))
            && started.elapsed() < Duration::from_secs(30)
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            eprintln!("killing {}: {e}", self.log.display());
        }
        if let Err(e) = self.child.wait() {
            eprintln!("reaping {}: {e}", self.log.display());
        }
    }
}

/// The dev container's database URL with the test's database in place of its own.
fn database_url(name: &str) -> String {
    let url = std::env::var("ACE4_DATABASE_URL").expect("ACE4_DATABASE_URL");
    let (server, _) = url.rsplit_once('/').expect("a database in the URL");
    format!("{server}/{name}")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
        .port()
}

/// Waits until `check` returns something, or fails the test after `within`.
async fn wait_for<T, F: std::future::Future<Output = Option<T>>>(
    what: &str,
    within: Duration,
    mut check: impl FnMut() -> F,
) -> T {
    let started = Instant::now();
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(started.elapsed() < within, "{what} within {within:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// PLAN.md 5.9: the site's binary list names its analysis view, so its GUI draws the ticket lookup's
/// results with the site's template, beside the open-source views, and every module has one.
#[test]
fn the_site_binary_draws_its_results_with_its_own_view() {
    let app = ace_site_example::app();
    assert_eq!(app.modules_without_a_view(), []);
    let drawn = app.views().draw(
        "example_ticket_analysis",
        1,
        &json!({"tickets": ["TICKET-<b>.example.com"]}),
    );
    assert_eq!(drawn.fallback, None);
    let html = drawn.html.as_str();
    assert!(html.contains("<h3>Tickets</h3>"), "{html}");
    assert!(
        html.contains("<li>TICKET-&#60;b&#62;.example.com</li>"),
        "{html}"
    );
    // the open-source views are still there
    assert!(app.views().has("email_analysis", 1));

    // and its observable action joins the open-source ones, on its own type only
    let names: Vec<&str> = app.actions().names().collect();
    assert_eq!(
        names,
        ["file_download_as_zip", "add_comment", "example_open_ticket"]
    );
    let ticket = |kind: &str| ace_service::AlertObservable {
        id: 7,
        kind: kind.to_owned(),
        value: "TICKET-a b/<c>".to_owned(),
        time: None,
        tags: Vec::new(),
        directives: Vec::new(),
        exclude_modules: Vec::new(),
        redirection: None,
        display_type: None,
        display_value: None,
        ignored: false,
        files: Vec::new(),
        relationships: Vec::new(),
        results: Vec::new(),
        detections: Vec::new(),
    };
    let links = app.actions().links(Uuid::nil(), &ticket("example_ticket"));
    let hrefs: Vec<&str> = links.iter().map(|l| l.href.as_str()).collect();
    assert_eq!(
        hrefs,
        [
            "/alerts/00000000-0000-0000-0000-000000000000/observables/7/comment",
            "https://tickets.example.com/ticket/TICKET-a%20b%2F%3Cc%3E",
        ]
    );
    assert_eq!(app.actions().links(Uuid::nil(), &ticket("fqdn")).len(), 1);
}

#[test]
fn the_site_binary_exports_its_types_schemas() {
    let dir = tempfile::tempdir().expect("a directory");
    let output = Command::new(env!("CARGO_BIN_EXE_example-ace"))
        .args(["schema", "export"])
        .arg(dir.path())
        .output()
        .expect("ace runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(dir.path().join("example_ticket_analysis.v1.schema.json"))
        .expect("the site's analysis type has a schema");
    let schema: Value = serde_json::from_str(&text).expect("JSON");
    let kinds = schema["$defs"]["ObservableKind"]["enum"]
        .as_array()
        .expect("the observable types");
    assert!(kinds.contains(&json!("example_ticket")), "{kinds:?}");
    assert!(kinds.contains(&json!("fqdn")));
    // the open-source modules' types are there too
    assert!(dir.path().join("rdap_analysis.v1.schema.json").exists());
}

/// PLAN.md 5.4's first admin, through a site's own binary, so the command comes with `ace-app` and a site
/// lists nothing for it. `ACE4_LOG=trace`, so that what isn't in the log isn't there at any level.
#[tokio::test]
async fn an_operator_makes_the_first_admin_with_the_sites_binary() {
    use std::io::Write;

    let test_db = TestDb::new().await;
    let url = database_url(test_db.name());
    let ace = |args: &[&str], stdin: Option<&str>| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_example-ace"))
            .args(["user", "create-first"])
            .args(args)
            .env("ACE4_DATABASE_URL", &url)
            .env("ACE4_LOG", "trace")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("ace runs");
        let mut pipe = child.stdin.take().expect("a pipe");
        if let Some(text) = stdin {
            pipe.write_all(text.as_bytes()).expect("writes");
        }
        drop(pipe);
        let output = child.wait_with_output().expect("ace ends");
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let service = ace_service::Service::new(
        test_db.db().clone(),
        ace_core::orchestrator::Orchestrator::new(
            ace_core::eligibility::Catalog::new([]),
            ace_core::modes::Modes::ace3(),
        ),
    );

    // A generated password, printed once on standard output.
    let (code, stdout, stderr) = ace(&["Root"], None);
    assert_eq!(code, Some(0), "{stderr}");
    let password = stdout
        .lines()
        .find_map(|line| line.strip_prefix("password (shown once): "))
        .expect("the password");
    assert_eq!(password.len(), 48, "{stdout}");
    assert!(stderr.contains("service.users"), "it logged: {stderr}");
    assert!(!stderr.contains(password), "the log holds the password");
    assert!(!stderr.contains("$argon2id$"), "the log holds the hash");
    let session = service
        .login("root", ace_service::Password::new(password), None)
        .await
        .expect("the printed password logs in");
    assert!(
        service
            .allowed(&session.actor, &ace_service::ALERT_WRITE)
            .await
            .expect("checks"),
        "it holds everything"
    );

    // A user exists, so a second is refused, with no password printed and nobody added.
    let (code, stdout, stderr) = ace(&["other"], None);
    assert_eq!(code, Some(1), "{stderr}");
    assert_eq!(stdout, "");
    assert!(stderr.contains("needs forcing"), "{stderr}");
    assert!(
        service
            .login("other", ace_service::Password::new(password), None)
            .await
            .is_err()
    );

    // Forced, from standard input, with the password in neither output.
    let chosen = "an operator's chosen passphrase";
    let (code, stdout, stderr) = ace(
        &["rescue", "--force", "--password-stdin"],
        Some(&format!("{chosen}\n")),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(stdout, "created user rescue\n");
    assert!(!stderr.contains(chosen), "the log holds the password");
    service
        .login("rescue", ace_service::Password::new(chosen), None)
        .await
        .expect("the chosen password logs in");

    // Too short, and nothing is made.
    let (code, _, stderr) = ace(&["weak", "--force", "--password-stdin"], Some("short\n"));
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("at least"), "{stderr}");

    // There's no way to put a password on the command line.
    let (code, _, stderr) = ace(&["third", "--password", "on-the-command-line"], None);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!stderr.contains("created"), "{stderr}");
}

/// `ace schema check` (PLAN.md 4.2) says what the core would, for an author with no pool running.
#[test]
fn the_site_binary_checks_a_result_against_its_types_schema() {
    let dir = tempfile::tempdir().expect("a directory");
    let check = |name: &str, result: &Value| {
        let path = dir.path().join(name);
        std::fs::write(&path, result.to_string()).expect("writes the result");
        let output = Command::new(env!("CARGO_BIN_EXE_example-ace"))
            .args(["schema", "check"])
            .arg(&path)
            .output()
            .expect("ace runs");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        (output.status.code(), stdout)
    };
    let (code, stdout) = check(
        "wrong.json",
        &json!({
            "analysis_type": "rdap_analysis",
            "schema_version": 1,
            "details": {"not_a_field": 1},
            "summary": 3,
        }),
    );
    assert_eq!(code, Some(1), "{stdout}");
    assert!(
        stdout.contains("/details/not_a_field: unknown field"),
        "{stdout}"
    );
    assert!(stdout.contains("/summary: "), "{stdout}");
    let (code, stdout) = check(
        "right.json",
        &json!({
            "analysis_type": "example_ticket_analysis",
            "schema_version": 1,
            "details": {"tickets": ["T-1"]},
        }),
    );
    assert_eq!(code, Some(0), "{stdout}");
    let (code, stdout) = check(
        "unknown.json",
        &json!({"analysis_type": "no_such_type", "schema_version": 1, "details": {}}),
    );
    assert_eq!(code, Some(1), "{stdout}");
    assert!(
        stdout.contains("unknown analysis type no_such_type"),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_site_module_adds_an_observable_of_the_sites_type() {
    let test_db = TestDb::new().await;
    let db = test_db.db().pool().clone();
    let dir = tempfile::tempdir().expect("a directory");
    let port = free_port();
    let api = format!("http://127.0.0.1:{port}");
    let web_port = free_port();
    let web = format!("http://127.0.0.1:{web_port}");
    let made = Command::new(env!("CARGO_BIN_EXE_example-ace"))
        .args([
            "user",
            "create-key",
            "site-test",
            "--grant",
            "alert:create",
            "--grant",
            "observable:read",
        ])
        .env("ACE4_DATABASE_URL", database_url(test_db.name()))
        .output()
        .expect("runs");
    let stdout = String::from_utf8_lossy(&made.stdout);
    assert!(
        made.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let token = stdout
        .lines()
        .find_map(|line| line.strip_prefix("token (shown once): "))
        .expect("the token")
        .to_owned();

    let mut serve = Command::new(env!("CARGO_BIN_EXE_example-ace"));
    serve
        .arg("serve")
        .env("ACE4_DATABASE_URL", database_url(test_db.name()))
        .env("ACE4_API_LISTEN", format!("127.0.0.1:{port}"))
        .env("ACE4_CACHE_DIR", dir.path().join("cache"))
        .env("ACE4_POOL_TOKEN_LOOKUPS", POOL_TOKEN)
        .env("ACE4_WEB_LISTEN", format!("127.0.0.1:{web_port}"))
        .env("ACE4_LOG", "info")
        // the site's own pool list, and nothing else of the dev container's
        .env_remove("ACE4_POOLS")
        .env_remove("ACE4_OVERLAY")
        .env_remove("ACE4_SIGNATURES_REPO")
        .env_remove("ACE4_OTLP_ENDPOINT");
    let mut core = Process::start(serve, &dir.path().join("ace.log"));
    let http = reqwest::Client::new();
    wait_for("the site's ace serves", Duration::from_secs(60), || {
        let request = http.get(format!("{api}/healthz")).send();
        async move { request.await.ok().filter(|r| r.status().is_success()) }
    })
    .await;

    // The JSON API lists the site's type beside the open-source ones (PLAN.md 5.6's observable_types).
    let types: Value = http
        .get(format!("{web}/api/observables/v1/types"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("answered")
        .error_for_status()
        .expect("listed")
        .json()
        .await
        .expect("JSON");
    let types = types["types"].as_array().expect("types");
    let ticket = types
        .iter()
        .find(|t| t["name"] == "example_ticket")
        .expect("the site's type is listed");
    assert_eq!(
        *ticket,
        json!({
            "name": "example_ticket",
            "parent": null,
            "deprecated": false,
            "default_display_type": "Ticket",
            "description": "a ticket in the example site's ticket system",
        })
    );
    assert!(types.iter().any(|t| t["name"] == "fqdn"));

    let mut lookups = Command::new(env!("CARGO_BIN_EXE_example-lookups"));
    lookups
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("ACE4_API_URL", &api)
        .env("ACE4_POOL_TOKEN", POOL_TOKEN)
        .env("ACE4_HEALTH_FILE", dir.path().join("health"))
        .env("ACE4_LOG", "info");
    let mut pool = Process::start(lookups, &dir.path().join("lookups.log"));

    // RDAP and DNS would look example.com up on the internet, so the submission leaves them out,
    // and the newly registered domains module, which would read the core's empty list, the
    // IDNA module, a parser this test has no pool for, and the two that read what analysts flagged
    // and tagged, which would find nothing
    let analysis = json!({
        "description": "a site's own module and type",
        "analysis_mode": "analysis",
        "observables": [
            {"type": "fqdn", "value": "example.com",
             "exclude_modules": ["rdap_analyzer", "fqdn_analyzer", "nrd_analyzer", "idna_analyzer",
                                 "observable_detection", "user_defined_tagging"]},
        ],
    });
    let body = format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"analysis\"\r\n\r\n{analysis}\r\n--{BOUNDARY}--\r\n"
    );
    let response = http
        .post(format!("{web}/api/analysis/v1/submit"))
        .bearer_auth(&token)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body)
        .send()
        .await
        .expect("the submission is answered");
    assert_eq!(response.status(), 201, "{:?}", response.text().await);
    let submitted: Value = response.json().await.expect("JSON");
    let root: Uuid = submitted["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .expect("the root's uuid");
    assert_eq!(
        submitted["queued"].as_array().map(Vec::len),
        Some(1),
        "the ticket lookup on the fqdn: {submitted}"
    );

    wait_for("the root completes", Duration::from_secs(60), || {
        let db = db.clone();
        async move {
            let done: Option<bool> = sqlx::query_scalar(
                "SELECT pass > 0 AND completed_pass = pass FROM analysis.roots WHERE id = $1",
            )
            .bind(root)
            .fetch_optional(&db)
            .await
            .expect("reads the root");
            done.filter(|done| *done)
        }
    })
    .await;
    let pool_log = pool.stop();
    let core_log = core.stop();

    let tasks: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT t.module, o.type, o.value, t.state::text FROM queue.tasks t
         JOIN analysis.observables o ON o.id = t.observable_id
         WHERE t.root_id = $1 ORDER BY t.id",
    )
    .bind(root)
    .fetch_all(&db)
    .await
    .expect("lists tasks");
    let expected = |kind: &str, value: &str| {
        (
            "example_ticket_lookup".to_owned(),
            kind.to_owned(),
            value.to_owned(),
            "done".to_owned(),
        )
    };
    assert_eq!(
        tasks,
        [
            expected("fqdn", "example.com"),
            expected("example_ticket", "TICKET-example.com"),
        ],
        "pool:\n{pool_log}\ncore:\n{core_log}"
    );

    let results: Vec<(String, String, String, Value)> = sqlx::query_as(
        "SELECT o.type, o.value, r.analysis_type, r.details FROM analysis.results r
         JOIN analysis.observables o ON o.id = r.observable_id
         WHERE r.root_id = $1 ORDER BY r.id",
    )
    .bind(root)
    .fetch_all(&db)
    .await
    .expect("lists results");
    assert_eq!(
        results,
        [
            (
                "fqdn".to_owned(),
                "example.com".to_owned(),
                "example_ticket_analysis".to_owned(),
                json!({"tickets": ["TICKET-example.com"]}),
            ),
            (
                "example_ticket".to_owned(),
                "TICKET-example.com".to_owned(),
                "example_ticket_analysis".to_owned(),
                json!({"tickets": ["TICKET-example.com"]}),
            ),
        ]
    );
    assert!(
        pool_log.contains("contained"),
        "the site's pool ran contained:\n{pool_log}"
    );
}

/// PLAN.md 7.10 batch 3, ace3's test_child.py `test_the_sandboxed_scan_cannot_read_saq_home`: a validation's
/// scan, `ace yara replay --contained` as `ace serve` runs it, reads only its validation's directory. A rule
/// file including a file outside it is left out with the include's error, and the rest of the namespace
/// still matches; the same replay uncontained reads the include. Through a site's binary, so the command
/// comes with `ace-app`.
#[test]
fn a_contained_replay_reads_only_its_validation() {
    let work = tempfile::Builder::new()
        .prefix("svswork")
        .tempdir_in("/tmp")
        .expect("a directory");
    let outside = tempfile::tempdir().expect("a directory");
    let secret = outside.path().join("secret.yar");
    std::fs::write(&secret, "rule secret { condition: true }\n").expect("writes");
    let namespace = work.path().join("base/tree/yara/acme");
    std::fs::create_dir_all(&namespace).expect("makes it");
    let steal = namespace.join("steal.yar");
    std::fs::write(
        &steal,
        format!(
            "include \"{}\"\nrule x {{ strings: $a = \"evil\" condition: $a }}\n",
            secret.display()
        ),
    )
    .expect("writes");
    let plain = namespace.join("plain.yar");
    std::fs::write(
        &plain,
        "rule plain { strings: $a = \"evil\" condition: $a }\n",
    )
    .expect("writes");
    let unit = work.path().join("u/0/files/x.bin");
    std::fs::create_dir_all(unit.parent().unwrap()).expect("makes it");
    std::fs::write(&unit, "some evil text\n").expect("writes");
    let side = work.path().join("base");
    let job = json!({
        "version": 1,
        "tree_root": work.path().join("base/tree"),
        "file_timeout": 10,
        "namespaces": [{"name": "acme", "directory": namespace, "files": [plain, steal]}],
        "units": [{"id": 0, "path": unit, "meta_tags": []}],
    });
    std::fs::write(side.join("job.json"), job.to_string()).expect("writes the job");
    let replay = |contained: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_example-ace"));
        command.args(["yara", "replay"]);
        if contained {
            command
                .args(["--contained", "--read"])
                .arg(work.path())
                .args(["--cpu-seconds", "60", "--memory-mb", "4096"]);
        }
        let output = command
            .arg(&side)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .expect("ace runs");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: Value =
            serde_json::from_slice(&std::fs::read(side.join("result.json")).expect("a result"))
                .expect("JSON");
        let stolen = result["files"]
            .as_array()
            .expect("files")
            .iter()
            .find(|f| f["path"].as_str().unwrap().ends_with("steal.yar"))
            .expect("the stealing file")["error"]
            .clone();
        let mut matched: Vec<String> = result["units"]["0"]["matches"]
            .as_array()
            .expect("matches")
            .iter()
            .map(|m| m["rule"].as_str().unwrap().to_owned())
            .collect();
        matched.sort();
        (stolen, matched)
    };

    let (error, matched) = replay(true);
    let error = error.as_str().expect("left out");
    assert!(
        error.contains("include") && error.contains("secret.yar"),
        "{error}"
    );
    assert_eq!(matched, ["plain"]);

    // uncontained, the include is read
    let (error, matched) = replay(false);
    assert_eq!(error, Value::Null);
    assert_eq!(matched, ["plain", "secret", "x"]);
}

/// An alert as a router reads it, with these tags.
fn routed_alert(tags: &[&str]) -> ace_service::routing::Alert {
    ace_service::routing::Alert {
        root: Uuid::new_v4(),
        description: "an alert".to_owned(),
        pass: 1,
        queue: ace_service::DEFAULT_QUEUE.to_owned(),
        disposition: None,
        alerted_at: chrono::Utc::now(),
        detections: Vec::new(),
        tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
        last_change: None,
    }
}

/// PLAN.md 7.13, ace3's `test_the_shipped_configuration_loads`: with no overlay, the open-source binary routes
/// with SVS's marker router (7.10 batch 7a) ahead of the built-in one, as ace3's `saq.default.yaml` does.
#[test]
fn the_shipped_routers_are_the_marker_router_and_the_built_in_one() {
    let routers = ace::app()
        .alert_routers(&ace_sdk::Overlay::default())
        .expect("loads");
    assert_eq!(
        routers.names(),
        [("svs_marker", 100), ("detection_queue", 500)]
    );
}

/// PLAN.md 7.13, ace3's `TestExampleIntegration`: the example router is loaded the way an overlay entry
/// loads it, routes an alert with its tag, and does nothing to one without; settings it doesn't know stop
/// startup.
#[tokio::test]
async fn the_example_router_loads_and_routes_only_tagged_alerts() {
    let entry = |extra: &str| {
        format!(
            "alert_routers:\n  example_tag_router:\n    type: example_tag\n    priority: 400\n    settings:\n      tag: example_route\n      queue: example\n{extra}"
        )
    };
    let overlay = ace_sdk::Overlay::from_yaml(&entry("")).expect("parses");
    let routers = ace_site_example::app()
        .alert_routers(&overlay)
        .expect("loads");
    assert_eq!(
        routers.names(),
        [("example_tag_router", 400), ("detection_queue", 500)]
    );
    let test_db = TestDb::new().await;
    let mut tx = test_db.db().begin().await.expect("begins");
    let stage = ace_service::routing::Stage::Alerted;
    assert_eq!(
        routers
            .decide(&routed_alert(&[]), stage, &mut tx)
            .await
            .expect("decides"),
        None
    );
    let decision = routers
        .decide(&routed_alert(&["example_route"]), stage, &mut tx)
        .await
        .expect("decides")
        .expect("a decision");
    assert_eq!(
        (decision.queue.as_str(), decision.router.as_str()),
        ("example", "example_tag_router")
    );
    let typo = ace_sdk::Overlay::from_yaml(&entry("      colour: red\n")).expect("parses");
    let error = ace_site_example::app()
        .alert_routers(&typo)
        .expect_err("refused");
    assert!(
        error.contains("example_tag_router") && error.contains("colour"),
        "{error}"
    );
}
