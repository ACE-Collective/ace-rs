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

/// PLAN.md decision 25: the site's binary lists its file role beside ace3's, and a result naming it
/// reads once the binary's list is installed, while one naming a role no binary lists doesn't.
#[test]
fn the_site_binary_lists_its_file_roles() {
    let roles = ace_site_example::app().roles().expect("a valid list");
    assert!(roles.contains(&ace_site_example::TICKET_EXPORT));
    assert!(roles.contains(&ace_results::FileRole::EMAIL_ATTACHMENT));
    let duplicate = ace_site_example::app().file_roles(&[ace_results::FileRole::EMAIL]);
    assert!(duplicate.roles().is_err());
    ace_results::install_roles(ace_site_example::FILE_ROLES).expect("installs");
    let read: ace_results::FileRole =
        serde_json::from_value(json!("example.ticket_export")).expect("the site's role reads");
    assert_eq!(read, ace_site_example::TICKET_EXPORT);
    assert!(serde_json::from_value::<ace_results::FileRole>(json!("example.nothing")).is_err());
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
        file_type: None,
        relationships: Vec::new(),
        results: Vec::new(),
        failed: Some(Vec::new()),
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

/// The owner's UI direction of 2026-11-15: the site's binary list names its alert summary, so its GUI
/// draws the top of a ticket alert's page with the site's template, as an ace3 integration adds an
/// alert template for its alert type, beside the open-source summaries.
#[test]
fn the_site_binary_draws_its_alert_type_s_summary() {
    let app = ace_site_example::app();
    let summaries = app.alert_summaries();
    assert_eq!(
        summaries.types().collect::<Vec<_>>(),
        ["example - ticket", "hunter", "mailbox"],
        "the site's beside the open-source ones"
    );
    // a type is the site's when it is the registered one, or starts with it and ` - `
    assert_eq!(
        summaries.chosen("example - ticket - vip"),
        Some("example - ticket")
    );
    assert_eq!(summaries.chosen("example - tickets"), None);
    assert_eq!(summaries.chosen("hunter - splunk"), Some("hunter"));

    let at = chrono::Utc::now();
    let tree = |origin: serde_json::Value, ticket: Option<&str>| ace_service::AlertTree {
        alert: ace_service::Alert {
            summary: ace_service::AlertSummary {
                id: Uuid::nil(),
                title: "a ticket alert".to_owned(),
                analysis_mode: "correlation".to_owned(),
                event_time: None,
                event_time_source: "unset".to_owned(),
                created_at: at,
                alerted_at: at,
                disposition: None,
                dispositioned_at: None,
                dispositioned_by: None,
                submitted_by: None,
                analysis: ace_service::AnalysisState::Complete,
                queue: "default".to_owned(),
                tags: Vec::new(),
                svs: None,
                owner: None,
                owned_at: None,
            },
            observables: 1,
            files: 0,
            detections: 0,
        },
        observables: ticket
            .map(|value| ace_service::AlertObservable {
                id: 1,
                kind: "example_ticket".to_owned(),
                value: value.to_owned(),
                time: None,
                tags: Vec::new(),
                directives: Vec::new(),
                exclude_modules: Vec::new(),
                redirection: None,
                display_type: None,
                display_value: None,
                ignored: false,
                files: Vec::new(),
                file_type: None,
                relationships: Vec::new(),
                results: Vec::new(),
                failed: Some(Vec::new()),
                detections: Vec::new(),
            })
            .into_iter()
            .collect(),
        top: vec![1],
        additions: Vec::new(),
        root_detections: Vec::new(),
        truncated: false,
        origin,
    };
    let draw = |tree: &ace_service::AlertTree| {
        let alert_type = tree.alert_type().unwrap_or_default().to_owned();
        summaries.draw(&ace_gui::SummaryInput {
            alert_type: &alert_type,
            origin: &tree.origin,
            tree,
            remediation: None,
        })
    };
    let ticket = tree(
        json!({"alert_type": "example - ticket - vip", "details": {"ticket_queue": "<b>SOC</b> tier 2"}}),
        Some("TICKET-<i>7</i>"),
    );
    let drawn = draw(&ticket).expect("the site's summary");
    assert_eq!(drawn.alert_type, "example - ticket");
    let html = drawn.html.as_str();
    assert!(
        html.contains("<dt>Ticket queue</dt><dd>&#60;b&#62;SOC&#60;/b&#62; tier 2</dd>")
            && html.contains("<dt>Ticket</dt><dd>TICKET-&#60;i&#62;7&#60;/i&#62;</dd>"),
        "{html}"
    );
    // an alert of the type that names no ticket queue, and an alert of another type, have the page's
    // default: the site's summary says nothing of them
    assert!(draw(&tree(json!({"alert_type": "example - ticket"}), None)).is_none());
    assert!(
        draw(&tree(
            json!({"alert_type": "manual", "details": {"ticket_queue": "q"}}),
            None
        ))
        .is_none()
    );
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

/// The site builds on ace4's list (`ace::app()`) and adds to two of its pools, so it holds what ace4's
/// does: its cacheable modules, hunt types, script command types and action handlers, and the site's
/// collector besides.
#[test]
fn the_site_s_list_is_ace4_s_with_its_own_added() {
    let (ace4, site) = (ace::app(), ace_site_example::app());
    assert_eq!(site.cacheable_modules(), ace4.cacheable_modules());
    assert_eq!(site.hunt_script_names(), ace4.hunt_script_names());
    let kinds = |app: &ace_app::App| -> Vec<String> {
        app.hunt_types()
            .iter()
            .map(|k| k.name().to_owned())
            .collect()
    };
    assert_eq!(kinds(&site), kinds(&ace4));
    let handlers = |app: &ace_app::App| -> Vec<String> {
        app.action_catalog()
            .expect("a catalog")
            .iter()
            .map(|spec| spec.pool_entry())
            .collect()
    };
    assert_eq!(handlers(&site), handlers(&ace4));
    assert_eq!(site.collector_names(), ["example"]);
    assert!(ace4.collector_names().is_empty(), "ace4 ships no collector");
    assert_eq!(site.modules_without_a_view(), []);
}

/// A site's module in one mode (`App::module_in_mode`) is eligible in that mode and in no other, and
/// one in a group (`App::module_in_group`) in every mode that runs the group, as ace3 builds a mode
/// from its groups' modules and its `enabled_modules`.
#[test]
fn a_site_s_module_in_a_mode_is_eligible_there_alone() {
    use ace_core::eligibility::{Facts, Ineligible, check};
    let modes = ace_site_example::app().modes();
    let eligible_in = |manifest: ace_sdk::Manifest, kind: ace_results::ObservableKind| {
        let component = ace_sdk::Component::of(manifest);
        let facts = Facts {
            kind,
            directives: &[],
            exclude_modules: &[],
            limit_modules: &[],
        };
        let mut eligible = Vec::new();
        for mode in modes.mode_names() {
            match check(
                &component,
                facts,
                &modes.modules_in(mode),
                &Default::default(),
            ) {
                Ok(()) => eligible.push(mode.to_owned()),
                Err(Ineligible::NotInMode) => {}
                Err(other) => panic!("{} in {mode}: {other:?}", component.key),
            }
        }
        eligible
    };
    assert_eq!(
        eligible_in(
            ace_sdk::Manifest::parser::<ace_site_example::TicketFile>(),
            ace_results::ObservableKind::File
        ),
        ["correlation"]
    );
    assert_eq!(
        eligible_in(
            ace_sdk::Manifest::lookup::<ace_site_example::TicketLookup>(),
            ace_results::ObservableKind::Fqdn
        ),
        ["analysis", "cli", "correlation"]
    );
}

/// PLAN.md 6.1: `ace collect example` runs the site's collector as a process of the site's binary. It
/// reads its own section and its one secret, submits each ticket file once as `collector:example`, which
/// holds `alert:create` through the class `collector`, answers a file that comes back with the root it
/// made (and deletes it), skips Finder's `.DS_Store`, logs a metrics event for each submission, and stops
/// on SIGTERM with exit code 0.
#[tokio::test]
async fn a_site_s_collector_submits_each_item_once_and_stops() {
    let test_db = TestDb::new().await;
    let db = test_db.db().pool().clone();
    let dir = tempfile::tempdir().expect("a directory");
    let source = dir.path().join("source");
    std::fs::create_dir(&source).expect("the source");
    std::fs::write(source.join("a.ticket"), "TICKET-1\n").expect("written");
    std::fs::write(source.join("b.ticket"), "TICKET-2\n").expect("written");
    std::fs::write(source.join(".DS_Store"), "finder").expect("written");
    let overlay = dir.path().join("overlay.yaml");
    std::fs::write(
        &overlay,
        format!(
            "collectors:\n  example:\n    poll_seconds: 1\n    settings:\n      directory: {}\n\
             secrets:\n  example_collector_token: env:EXAMPLE_COLLECTOR_TOKEN\n  \
             other_token: env:OTHER_TOKEN\n",
            source.display()
        ),
    )
    .expect("the overlay");
    let mut collect = Command::new(env!("CARGO_BIN_EXE_example-ace"));
    collect
        .args(["collect", "example"])
        .env("ACE4_DATABASE_URL", database_url(test_db.name()))
        .env("ACE4_OVERLAY", &overlay)
        .env("EXAMPLE_COLLECTOR_TOKEN", "a-source-credential")
        .env("OTHER_TOKEN", "another-process-credential")
        .env("ACE4_LOG", "info")
        .env_remove("ACE4_OTLP_ENDPOINT");
    let mut process = Process::start(collect, &dir.path().join("collect.log"));
    let roots = || {
        let db = db.clone();
        async move {
            sqlx::query_as::<_, (String, Value, Value)>(
                "SELECT description, submitted_by::jsonb, origin FROM analysis.roots
                 ORDER BY description",
            )
            .fetch_all(&db)
            .await
            .expect("the roots")
        }
    };
    wait_for("both files submitted", Duration::from_secs(60), || {
        let roots = roots();
        let source = source.clone();
        async move {
            (roots.await.len() == 2
                && !source.join("a.ticket").exists()
                && !source.join("b.ticket").exists())
            .then_some(())
        }
    })
    .await;
    // the source offers a.ticket again
    std::fs::write(source.join("a.ticket"), "TICKET-1\n").expect("written");
    wait_for(
        "the redelivered file taken",
        Duration::from_secs(60),
        || {
            let source = source.clone();
            async move { (!source.join("a.ticket").exists()).then_some(()) }
        },
    )
    .await;
    let log = process.stop();
    let status = process.child.try_wait().expect("waited");
    assert!(status.is_some_and(|s| s.success()), "{status:?}\n{log}");
    // without the terminal's colours
    let mut plain = String::with_capacity(log.len());
    let mut rest = log.as_str();
    while let Some(at) = rest.find('\u{1b}') {
        plain.push_str(&rest[..at]);
        rest = rest[at..].split_once('m').map_or("", |(_, after)| after);
    }
    plain.push_str(rest);
    let log = plain;

    let by = json!({"kind": "internal", "id": "collector:example"});
    let origin = |name: &str| {
        (
            format!("Example ticket file {name}"),
            by.clone(),
            json!({
                "alert_type": "example - ticket",
                "tool": "example collector",
                "details": {"ticket_queue": "triage"},
            }),
        )
    };
    assert_eq!(
        roots().await,
        [origin("a.ticket"), origin("b.ticket")],
        "{log}"
    );
    assert!(
        source.join(".DS_Store").exists(),
        "a dot file isn't an item"
    );
    let keys: i64 = sqlx::query_scalar("SELECT count(*) FROM collection.submitted_keys")
        .fetch_one(&db)
        .await
        .expect("counted");
    assert_eq!(keys, 2);
    let metrics: Vec<&str> = log
        .lines()
        .filter_map(|line| {
            line.split_once("METRICS (collector): ")
                .map(|(_, json)| json)
        })
        .collect();
    let outcomes: Vec<String> = metrics
        .iter()
        .map(|json| {
            // the line's fields follow the event's JSON
            serde_json::Deserializer::from_str(json)
                .into_iter::<Value>()
                .next()
                .expect("an event")
                .expect("JSON")["outcome"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    assert_eq!(outcomes, ["submitted", "submitted", "duplicate"], "{log}");
    assert!(
        log.contains(r#"secrets=["example_collector_token"]"#),
        "it resolves its own secret and no other: {log}"
    );
    assert!(!log.contains("a-source-credential"), "{log}");
    assert!(!log.contains("another-process-credential"), "{log}");
    assert!(log.contains("collection ended"), "{log}");
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
    // IDNA and apex domain modules, parsers this test has no pool for, and the two that read what
    // analysts flagged and tagged, which would find nothing
    let analysis = json!({
        "description": "a site's own module and type",
        "analysis_mode": "analysis",
        "observables": [
            {"type": "fqdn", "value": "example.com",
             "exclude_modules": ["rdap_analyzer", "fqdn_analyzer", "nrd_analyzer", "idna_analyzer",
                                 "apex_domain_analyzer", "observable_detection",
                                 "user_defined_tagging"]},
            // a ticket the site's ticket system doesn't know, so the lookup says it failed
            {"type": "example_ticket", "value": "LEGACY-7",
             "exclude_modules": ["observable_detection", "user_defined_tagging"]},
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
        Some(2),
        "the ticket lookup on the fqdn and on the ticket: {submitted}"
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
    // the lookup that failed ran to its end too: its task is done, not failed
    assert_eq!(
        tasks,
        [
            expected("fqdn", "example.com"),
            expected("example_ticket", "LEGACY-7"),
            expected("example_ticket", "TICKET-example.com"),
        ],
        "pool:\n{pool_log}\ncore:\n{core_log}"
    );

    // a site's module marks its result failed as any module does (`ResultEnvelope::with_error`),
    // and the core stores the reason beside the result
    let failed: Vec<(String, Option<String>, Value)> = sqlx::query_as(
        "SELECT o.value, r.error, r.details FROM analysis.results r
         JOIN analysis.observables o ON o.id = r.observable_id
         WHERE r.root_id = $1 AND r.error IS NOT NULL",
    )
    .bind(root)
    .fetch_all(&db)
    .await
    .expect("lists the failed results");
    assert_eq!(
        failed,
        [(
            "LEGACY-7".to_owned(),
            Some(
                "the ticket system has no ticket LEGACY-7: its tickets start with TICKET-"
                    .to_owned()
            ),
            json!({"tickets": []}),
        )]
    );

    let results: Vec<(String, String, String, Value)> = sqlx::query_as(
        "SELECT o.type, o.value, r.analysis_type, r.details FROM analysis.results r
         JOIN analysis.observables o ON o.id = r.observable_id
         WHERE r.root_id = $1 AND r.error IS NULL ORDER BY r.id",
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
/// scan, `ace yara replay --contained` as `ace serve` runs it, reads only its validation's directory. ace3's
/// case shows it with a rule file that includes a file outside. Here no include leaves its signature
/// directory, contained or not (`ace_yara::include`), so that file is left out both times with the
/// include's error and the outside file is never compiled in; what shows the containment is a unit whose
/// file is outside the validation, which the contained replay can't open and the same replay uncontained
/// scans. Through a site's binary, so the command comes with `ace-app`.
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
    let outside_unit = outside.path().join("x.bin");
    std::fs::write(&outside_unit, "more evil text outside\n").expect("writes");
    let side = work.path().join("base");
    let job = json!({
        "version": 1,
        "tree_root": work.path().join("base/tree"),
        "file_timeout": 10,
        "namespaces": [{"name": "acme", "directory": namespace, "files": [plain, steal]}],
        "units": [
            {"id": 0, "path": unit, "meta_tags": []},
            {"id": 1, "path": outside_unit, "meta_tags": []},
        ],
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
        let outside = &result["units"]["1"];
        let outside = (
            outside["matches"].as_array().expect("matches").len(),
            outside["errors"].as_array().expect("errors").len(),
        );
        (stolen, matched, outside)
    };

    let (error, matched, outside_unit) = replay(true);
    let error = error.as_str().expect("left out");
    assert!(
        error.contains("include") && error.contains("secret.yar") && error.contains("absolute"),
        "{error}"
    );
    assert_eq!(matched, ["plain"]);
    assert_eq!(outside_unit, (0, 1), "the file outside can't be opened");

    // uncontained, the include is refused the same, and the file outside is scanned
    let (again, matched, outside_unit) = replay(false);
    assert_eq!(again.as_str(), Some(error));
    assert_eq!(matched, ["plain"]);
    assert_eq!(outside_unit, (1, 0));
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

/// PLAN.md 7.10 batch 8: every binary runs SVS's marker router, not only the open-source one. A binary
/// built from `App::new()` with nothing added has it, so a test run's alerts never stay in the queue
/// analysts triage for want of a line in a site's list; and its name is taken, so a router the binary
/// adds, or one its overlay configures, can't be called `svs_marker`.
#[test]
fn a_binary_built_from_app_new_runs_the_marker_router() {
    let bare = ace_app::App::new()
        .alert_routers(&ace_sdk::Overlay::default())
        .expect("loads");
    assert_eq!(
        bare.names(),
        [("svs_marker", 100), ("detection_queue", 500)]
    );

    let router = || -> std::sync::Arc<dyn ace_service::routing::Router> {
        std::sync::Arc::new(
            ace_site_example::ExampleTagRouter::new(&json!({"tag": "t", "queue": "q"}))
                .expect("builds"),
        )
    };
    let error = ace_app::App::new()
        .alert_router("svs_marker", 50, router())
        .alert_routers(&ace_sdk::Overlay::default())
        .expect_err("the name is the marker router's");
    assert_eq!(
        error,
        "an alert router named \"svs_marker\" is there already"
    );
    // the built-in one's name is refused too, as before
    let error = ace_app::App::new()
        .alert_router("detection_queue", 50, router())
        .alert_routers(&ace_sdk::Overlay::default())
        .expect_err("the name is a built-in's");
    assert_eq!(
        error,
        "\"detection_queue\" is the name of a built-in router"
    );
    // and an overlay's entry can't take it either
    let overlay = ace_sdk::Overlay::from_yaml(
        "alert_routers:\n  svs_marker:\n    type: example_tag\n    priority: 50\n    settings:\n      \
         tag: t\n      queue: q\n",
    )
    .expect("parses");
    let error = ace_site_example::app()
        .alert_routers(&overlay)
        .expect_err("the name is the marker router's");
    assert_eq!(
        error,
        "alert_routers.svs_marker: an alert router named \"svs_marker\" is there already"
    );
    // a site's own router runs beside it
    let beside = ace_app::App::new()
        .alert_router("site_first", 50, router())
        .alert_routers(&ace_sdk::Overlay::default())
        .expect("loads");
    assert_eq!(
        beside.names(),
        [
            ("site_first", 50),
            ("svs_marker", 100),
            ("detection_queue", 500)
        ]
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
        [
            ("svs_marker", 100),
            ("example_tag_router", 400),
            ("detection_queue", 500)
        ]
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

/// The site's parser pool binary with `overlay` as its site overlay, run as the pool's supervisor
/// with no lease API to reach: its exit code and what it wrote on stderr.
fn parser_pool_start(overlay: &str) -> (Option<i32>, String) {
    let dir = tempfile::tempdir().expect("a directory");
    let overlay_at = dir.path().join("overlay.yaml");
    std::fs::write(&overlay_at, overlay).expect("writes the overlay");
    let output = Command::new(env!("CARGO_BIN_EXE_example-parsers"))
        .env_clear()
        .env("ACE4_OVERLAY", &overlay_at)
        .env("ACE4_RULESET_DIR", dir.path().join("rulesets"))
        .output()
        .expect("the pool runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// PLAN.md 2.23, for a site's parser pool: the pool checks its overlay and builds every module
/// when it starts, so a bad setting for any module, the site's own or an open-source one, stops
/// it then with the module's name. A task process builds only its task's module from the block
/// that passed here, so this is the one place the check happens. The pool is run with no lease
/// API: a refused overlay ends it before it looks for one, and an overlay it takes ends it there.
#[test]
fn a_site_s_parser_pool_refuses_a_bad_setting_when_it_starts() {
    let refused = [
        // a key the site's module hasn't (ace3 #858)
        (
            "modules:\n  example_ticket_file:\n    settings:\n      prefx: CASE-\n",
            "setup failed: the overlay's modules.example_ticket_file.settings: unknown settings key prefx",
        ),
        // a value of the wrong type
        (
            "modules:\n  example_ticket_file:\n    settings:\n      prefix: [CASE-]\n",
            "setup failed: the overlay's modules.example_ticket_file.settings: invalid setting prefix",
        ),
        // the site's module's init refuses its settings
        (
            "modules:\n  example_ticket_file:\n    settings:\n      prefix: ''\n",
            "setup failed: module example_ticket_file: prefix must not be empty",
        ),
        // and so does an instance of it
        (
            "modules:\n  example_ticket_file:\n    instances:\n      case_tickets:\n        settings:\n          prefix: ''\n",
            "setup failed: module example_ticket_file: prefix must not be empty",
        ),
        // an open-source module's key
        (
            "modules:\n  email_analyzer:\n    settings:\n      no_such_key: 1\n",
            "setup failed: the overlay's modules.email_analyzer.settings: unknown settings key no_such_key",
        ),
        // an open-source module's init: a network that isn't one
        (
            "modules:\n  network_identifier:\n    settings:\n      networks:\n        - cidr: nonsense\n          name: office\n",
            "setup failed: module network_identifier: network \"nonsense\" isn't a range",
        ),
        // a module that is off by default, turned on without what it needs
        (
            "modules:\n  ssdeep: {}\n",
            "setup failed: module ssdeep: ssdeep needs ssdeep_hashes",
        ),
        // an instance of a module with a name the overlay may not give it
        (
            "modules:\n  example_ticket_file:\n    instances:\n      email_analyzer: {}\n",
            "setup failed: the overlay's instance email_analyzer of example_ticket_file has a module's or another instance's name",
        ),
        // a key the overlay itself hasn't
        ("module: {}\n", "setup failed: the overlay doesn't parse"),
    ];
    for (overlay, error) in refused {
        let (code, stderr) = parser_pool_start(overlay);
        assert_eq!(code, Some(2), "{overlay}\n{stderr}");
        assert!(stderr.contains(error), "{overlay}\n{stderr}");
    }
    // what the pool takes: no overlay sections, a site module's settings and an instance of it,
    // a section for a module the binary no longer has (#901, #916) and another pool's module's
    let taken = [
        "",
        "modules:\n  example_ticket_file:\n    instances:\n      case_tickets:\n        settings:\n          prefix: CASE-\n      ticket_tickets: {}\n",
        "modules:\n  a_module_removed_last_year:\n    settings:\n      anything: 1\n  example_ticket_lookup:\n    settings:\n      no_such_key: 1\n",
    ];
    for overlay in taken {
        let (code, stderr) = parser_pool_start(overlay);
        assert!(!stderr.contains("setup failed"), "{overlay}\n{stderr}");
        // it got as far as the lease API it wasn't given
        assert_eq!(code, Some(2), "{overlay}\n{stderr}");
        assert!(stderr.contains("ACE4_API_URL"), "{overlay}\n{stderr}");
    }
}

/// A task of the component `key`, made of `module`, on a file holding `bytes`: the request a
/// parser pool's supervisor writes its task process, here written by hand.
fn task_request(
    dir: &Path,
    module: &str,
    key: &str,
    settings: Option<Value>,
    bytes: &[u8],
) -> ace_pool::supervisor::TaskRequest {
    let (input, outputs) = (dir.join("input"), dir.join("outputs"));
    std::fs::write(&input, bytes).expect("writes the input");
    std::fs::create_dir_all(&outputs).expect("an output directory");
    // the module doesn't check the hash, and nothing downloads the file
    let sha256 = "0".repeat(64);
    let task = serde_json::from_value(json!({
        "id": 1,
        "root": "00000000-0000-0000-0000-000000000000",
        "module": key,
        "attempts": 1,
        "lease_expires_at": "2030-01-01T00:00:00Z",
        "lease_seconds": 30.0,
        "observable": {
            "type": "file",
            "value": sha256,
            "file": {
                "path": "notes.txt",
                "sha256": sha256,
                "size": bytes.len(),
                "facts": {"description": "ASCII text", "mime": "text/plain",
                          "is_ole_file": false, "is_rtf_file": false, "has_pdf_marker": false,
                          "is_pe_file": false, "is_zip_file": false, "is_jar_file": false,
                          "is_x509": false, "is_lnk_file": false, "is_email_file": false,
                          "is_pcap_file": false, "has_onenote_header": false,
                          "is_java_class_file": false, "has_xml_marker": false,
                          "is_eps_file": false, "is_encoded_script": false,
                          "has_har_header": false, "is_image": false},
                "download": {"url": "http://unused.invalid/"},
            },
        },
    }))
    .expect("a leased task");
    let manifest = ace_sdk::Manifest::parser::<ace_site_example::TicketFile>();
    ace_pool::supervisor::TaskRequest {
        task,
        module: module.to_owned(),
        settings,
        profile: ace_pool::SandboxProfile::for_manifest(&manifest)
            .allow_read(&input)
            .allow_write(&outputs),
        input: Some(input),
        email_parts: Vec::new(),
        tree_files: None,
        outputs,
        tools: None,
        scan_output: None,
    }
}

/// Runs the site's parser pool binary as a task process on `request`, with an empty environment
/// as the supervisor starts it: its exit code, its stdout and its stderr.
fn task_process(request: &ace_pool::supervisor::TaskRequest) -> (Option<i32>, Vec<u8>, String) {
    use std::io::Write;
    let mut child = Command::new(env!("CARGO_BIN_EXE_example-parsers"))
        .arg("task")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the task process starts");
    child
        .stdin
        .take()
        .expect("its stdin")
        .write_all(&serde_json::to_vec(request).expect("the request"))
        .expect("writes the request");
    let output = child.wait_with_output().expect("the task process ends");
    (
        output.status.code(),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// A site's parser runs in a task process that builds it alone, from the settings its request
/// carries: the request names the module, and the process is given no overlay and no ruleset
/// directory, so it has nothing to build the pool's other modules from as the pool configured
/// them. It is contained before it reads the file. A module whose `init` fails on the settings it
/// is sent fails the task's setup, with its name, and a module the binary hasn't is refused.
#[test]
fn a_site_s_parser_is_built_alone_in_its_task_process() {
    let dir = tempfile::tempdir().expect("a directory");
    let module = "example_ticket_file";
    let text = b"see TICKET-42 and CASE-9, then TICKET-7 and TICKET-42 again";
    // the task's end as JSON: this process hasn't the site's observable types, which the
    // result's new observables are of
    let end = |stdout: &[u8]| serde_json::from_slice::<Value>(stdout).expect("a task's end");

    // on its defaults, as itself
    let (code, stdout, stderr) =
        task_process(&task_request(dir.path(), module, module, None, text));
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.contains("contained: Contained"), "{stderr}");
    let done = end(&stdout);
    assert_eq!(done["outcome"], "done", "{done}");
    assert_eq!(
        done["result"]["details"]["tickets"],
        json!(["TICKET-42", "TICKET-7"])
    );
    // the result adds each ticket as an observable of the site's type
    assert_eq!(done["result"]["observables"][0]["type"], "example_ticket");

    // as an instance, with the instance's settings
    let settings = Some(json!({"prefix": "CASE-"}));
    let (code, stdout, stderr) = task_process(&task_request(
        dir.path(),
        module,
        "case_tickets",
        settings,
        text,
    ));
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(
        end(&stdout)["result"]["details"]["tickets"],
        json!(["CASE-9"])
    );

    // a file that names no ticket is declined
    let (code, stdout, stderr) = task_process(&task_request(
        dir.path(),
        module,
        module,
        None,
        b"nothing here",
    ));
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(end(&stdout)["outcome"], "skipped");

    // what the module declares it takes: the pool checks it before `analyze`, so a file the
    // settings skip is declined though it names tickets, and an empty one is
    let skip = Some(json!({"skip_extensions": [".TXT", ".txt"]}));
    let (code, stdout, stderr) =
        task_process(&task_request(dir.path(), module, module, skip, text));
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(end(&stdout)["outcome"], "skipped", "{stderr}");
    let (code, stdout, stderr) = task_process(&task_request(dir.path(), module, module, None, b""));
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(end(&stdout)["outcome"], "skipped", "{stderr}");
    // and the core reads the same declaration from the overlay's settings, as data
    let overlay = ace_sdk::Overlay::from_yaml(
        "modules:\n  example_ticket_file:\n    settings:\n      skip_extensions: [.bin]\n",
    )
    .expect("parses");
    let components = overlay
        .components(&[ace_sdk::Manifest::parser::<ace_site_example::TicketFile>()])
        .expect("builds");
    let takes = &components[0].takes;
    assert_eq!(
        takes.describe()[1]["when"],
        json!({"not": {"extension": {"test": {"one_of": [".bin"]}, "case": "lower"}}})
    );
    let facts = |path: &'static str| ace_sdk::takes::Facts {
        kind: ace_results::ObservableKind::File,
        directives: &[],
        relationships: &[],
        redirected: false,
        added_by: &[],
        at_root: false,
        mode: None,
        file: Some(ace_sdk::takes::FileFacts {
            path,
            size: Some(10),
            facts: None,
            role: None,
            yara_meta: Some(&[]),
        }),
        results: Box::leak(Box::default()),
    };
    assert_eq!(
        takes.check(&facts("dir/a.BIN")),
        Err("its extension is one the settings skip")
    );
    assert_eq!(takes.check(&facts("a.bin/notes.txt")), Ok(()));

    // settings its init refuses fail the setup, exit 10, before anything is contained or run
    let settings = Some(json!({"prefix": ""}));
    let (code, stdout, stderr) =
        task_process(&task_request(dir.path(), module, module, settings, text));
    assert_eq!(code, Some(10), "{stderr}");
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("setup failed: module example_ticket_file: prefix must not be empty"),
        "{stderr}"
    );
    assert!(!stderr.contains("contained"), "{stderr}");

    // a module this pool hasn't: the site's lookup is the network pool's
    let (code, _, stderr) = task_process(&task_request(
        dir.path(),
        "example_ticket_lookup",
        "example_ticket_lookup",
        None,
        text,
    ));
    assert_eq!(code, Some(10), "{stderr}");
    assert!(
        stderr.contains("setup failed: this pool doesn't run example_ticket_lookup"),
        "{stderr}"
    );
}

/// The site's overlay with its ticket system named once as a shared connection
/// (`ace_sdk::connections`), bound to the ticket lookup's slot, and a secret no component uses.
const TICKET_CONNECTION: &str = "\
connections:
  tickets:
    type: example_ticket_system
    settings:
      url: https://tickets.site.example
      request_timeout_seconds: 5
    secrets:
      token: ticket_token
modules:
  example_ticket_lookup:
    connections:
      tickets: tickets
secrets:
  ticket_token: env:ACE4_TEST_TICKET_TOKEN
  other_token: env:ACE4_TEST_OTHER_TOKEN
";

/// A shared connection: the site's binary checks it against the site's connection type, the ticket
/// lookup gets its settings under its slot's name and its secret by role and no other secret, and a
/// cached result's key holds the connection's identity (its URL) and not its timeout.
#[test]
fn a_site_s_shared_connection_is_named_once_and_bound_by_its_lookup() {
    let app = ace_site_example::app();
    assert_eq!(app.check_overlay(&ace_sdk::Overlay::default()), Ok(()));
    let overlay = ace_sdk::Overlay::from_yaml(TICKET_CONNECTION).expect("loads");
    assert_eq!(app.check_overlay(&overlay), Ok(()));
    assert!(
        app.connection_kinds()
            .iter()
            .any(|kind| kind.name == "example_ticket_system")
    );
    let manifests = [ace_sdk::Manifest::lookup::<ace_site_example::TicketLookup>()];
    let components = overlay.components(&manifests).expect("components");
    let lookup = &components[0];
    assert_eq!(
        lookup.settings,
        Some(
            json!({"tickets": {"url": "https://tickets.site.example", "request_timeout_seconds": 5}})
        )
    );
    assert_eq!(lookup.own_settings(), None);
    let env = |name: &str| match name {
        "ACE4_TEST_TICKET_TOKEN" => Some("ticket-value".to_owned()),
        "ACE4_TEST_OTHER_TOKEN" => Some("other-value".to_owned()),
        _ => None,
    };
    // the process resolves the connection's secret and not the one nothing names (PLAN.md 2.24)
    let secrets = ace_pool::secrets::resolve_components("lookups", &components, &overlay, &env);
    assert_eq!(secrets.names(), ["ticket_token"]);
    let connections = ace_sdk::Connections::resolve(&lookup.connections, &secrets);
    assert_eq!(
        connections.secret("tickets", "token").map(|s| s.expose()),
        Some("ticket-value")
    );
    let settings = connections
        .settings::<ace_site_example::TicketSystem>("tickets")
        .expect("its settings");
    assert_eq!(settings.request_timeout_seconds, 5);
    // a module built from the component reads them as its own settings' `tickets`
    let built: ace_site_example::TicketSettings =
        ace_sdk::load_settings(lookup.settings.as_ref()).expect("loads");
    assert_eq!(built.tickets.url, "https://tickets.site.example");
    assert_eq!(built.prefix, "TICKET-");

    // an instance takes its module's bindings, and binds a slot of its own over one
    let instances = TICKET_CONNECTION
    .replace(
        "    connections:\n      tickets: tickets\n",
        "    connections:\n      tickets: tickets\n    instances:\n      site_a: {}\n      site_b:\n        connections:\n          tickets: tickets_b\n",
    )
    .replace(
        "modules:\n",
        "  tickets_b:\n    type: example_ticket_system\n    settings: {url: https://b.site.example}\nmodules:\n",
    );
    let overlay = ace_sdk::Overlay::from_yaml(&instances).expect("loads");
    let urls: Vec<(String, String)> = overlay
        .components(&manifests)
        .expect("components")
        .iter()
        .map(|c| {
            (
                c.key.clone(),
                c.settings.as_ref().expect("settings")["tickets"]["url"]
                    .as_str()
                    .expect("a url")
                    .to_owned(),
            )
        })
        .collect();
    assert_eq!(
        urls,
        [
            (
                "site_a".to_owned(),
                "https://tickets.site.example".to_owned()
            ),
            ("site_b".to_owned(), "https://b.site.example".to_owned()),
        ]
    );

    // the cache key: the URL is in it, the timeout isn't, and the module's own settings are
    let mut cached = manifests[0];
    cached.cache = Some(ace_sdk::cache::Cache::new(1, Duration::from_secs(3600)));
    let key = |yaml: &str| {
        let component = ace_sdk::Overlay::from_yaml(yaml)
            .expect("loads")
            .components(&[cached])
            .expect("components")
            .remove(0);
        ace_core::cache::key(&component, "fqdn", "a.example", &Default::default()).expect("a key")
    };
    let base = key(TICKET_CONNECTION);
    assert_eq!(
        base,
        key(&TICKET_CONNECTION.replace("request_timeout_seconds: 5", "request_timeout_seconds: 60")),
        "a timeout doesn't change what is found"
    );
    assert_ne!(
        base,
        key(&TICKET_CONNECTION.replace("tickets.site.example", "other.site.example")),
        "another ticket system may answer otherwise"
    );
    assert_ne!(
        base,
        key(&TICKET_CONNECTION.replace(
            "    connections:\n      tickets: tickets\n",
            "    connections:\n      tickets: tickets\n    settings:\n      prefix: CASE-\n",
        )),
        "the module's own settings are in it"
    );
}

/// What the overlay may not say of a shared connection, each refused with its path: by any process
/// that reads the overlay (a name no connection has, a secret `secrets:` hasn't), by the site's `ace`
/// (a type no component takes), and by whatever binds it (a setting or a role its type hasn't, a slot
/// its component hasn't, the slot's settings written in the module's own block).
#[test]
fn a_shared_connection_the_overlay_can_t_use_is_refused_with_its_path() {
    let app = ace_site_example::app();
    let manifests = [ace_sdk::Manifest::lookup::<ace_site_example::TicketLookup>()];
    let refusal = |yaml: &str| -> String {
        let overlay = match ace_sdk::Overlay::from_yaml(yaml) {
            Ok(overlay) => overlay,
            Err(e) => return e.to_string(),
        };
        if let Err(e) = overlay.components(&manifests) {
            // a pool refuses it when it builds its modules, and the site's `ace` before that
            let checked = app
                .check_overlay(&overlay)
                .expect_err("the binary refuses it too");
            return format!("{e}\n{checked}");
        }
        app.check_overlay(&overlay).expect_err("refused")
    };
    let cases = [
        (
            TICKET_CONNECTION.replace("      tickets: tickets\n", "      tickets: ticket\n"),
            "the overlay's modules.example_ticket_lookup.connections.tickets: \"ticket\" isn't a connection in connections:",
        ),
        (
            TICKET_CONNECTION.replace("token: ticket_token", "token: tiket_token"),
            "the overlay's connections.tickets.secrets.token: \"tiket_token\" isn't a secret in secrets:",
        ),
        (
            TICKET_CONNECTION.replace("type: example_ticket_system", "type: example_tickets"),
            "the overlay's connections.tickets.type: no component of this binary takes a connection of type \"example_tickets\"",
        ),
        (
            TICKET_CONNECTION.replace("request_timeout_seconds: 5", "request_timeout: 5"),
            "the overlay's connections.tickets.settings: unknown settings key request_timeout",
        ),
        (
            TICKET_CONNECTION.replace("token: ticket_token", "password: ticket_token"),
            "the overlay's connections.tickets.secrets.password: a connection of type example_ticket_system has no secret \"password\"",
        ),
        (
            TICKET_CONNECTION.replace("      tickets: tickets\n", "      ticket_system: tickets\n"),
            "the overlay's modules.example_ticket_lookup.connections.ticket_system: this has no slot \"ticket_system\"; its slots are [\"tickets\"]",
        ),
        (
            TICKET_CONNECTION.replace(
                "    connections:\n      tickets: tickets\n",
                "    settings:\n      tickets:\n        url: https://elsewhere.example\n",
            ),
            "the overlay's modules.example_ticket_lookup.settings.tickets: the settings of the slot tickets come from the connection",
        ),
    ];
    for (yaml, error) in cases {
        let refused = refusal(&yaml);
        assert!(refused.contains(error), "{yaml}\n{refused}");
    }
}

/// PLAN.md 2.24 for a shared connection: the site's network pool binary resolves the secret of the
/// connection its lookup binds, and not a secret no component of it names, and its startup log lists
/// only the one; a connection the pool can't use stops it with the path.
#[test]
fn a_site_s_network_pool_holds_only_its_connections_secrets() {
    let start = |overlay: &str| {
        let dir = tempfile::tempdir().expect("a directory");
        let overlay_at = dir.path().join("overlay.yaml");
        std::fs::write(&overlay_at, overlay).expect("writes the overlay");
        let output = Command::new(env!("CARGO_BIN_EXE_example-lookups"))
            .env_clear()
            .env("ACE4_OVERLAY", &overlay_at)
            .env("ACE4_TEST_TICKET_TOKEN", "ticket-value")
            .env("ACE4_TEST_OTHER_TOKEN", "other-value")
            .output()
            .expect("the pool runs");
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let (code, stderr) = start(TICKET_CONNECTION);
    assert_eq!(code, Some(2), "{stderr}");
    // it got past its modules to the lease API it wasn't given
    assert!(stderr.contains("ACE4_API_URL"), "{stderr}");
    assert!(stderr.contains("ticket_token"), "{stderr}");
    assert!(!stderr.contains("other_token"), "{stderr}");
    assert!(!stderr.contains("ticket-value"), "{stderr}");
    let (code, stderr) =
        start(&TICKET_CONNECTION.replace("request_timeout_seconds: 5", "timeout: 5"));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains(
            "setup failed: the overlay's connections.tickets.settings: unknown settings key timeout"
        ),
        "{stderr}"
    );
}

/// A site's module that reads the root's event time (`Module::READS_EVENT_TIME`) and where its
/// observable came from, as a search around the alert would, and says what it read.
mod around_the_alert {
    use ace_results::{AnalysisType, ObservableKind};
    use ace_sdk::{Lookup, Module, ModuleError, Outcome, TaskContext};

    #[derive(
        Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
    )]
    pub struct LineStats {
        pub note: String,
    }

    impl AnalysisType for LineStats {
        const NAME: &'static str = "site_around_the_alert";
        const VERSION: u32 = 1;
        const MODULE: &'static str = "site_around_the_alert";
    }

    pub struct AroundTheAlert;

    impl Module for AroundTheAlert {
        const NAME: &'static str = "site_around_the_alert";
        const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
        const READS_EVENT_TIME: bool = true;
        const READS_ADDED_BY: bool = true;
        type Output = LineStats;
        type Settings = ();
        fn init(_: &()) -> Result<Self, ModuleError> {
            Ok(AroundTheAlert)
        }
    }

    impl Lookup for AroundTheAlert {
        const TCP_PORTS: &'static [u16] = &[];
        async fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<LineStats>, ModuleError> {
            Ok(Outcome::Skipped(format!(
                "{:?} {:?} at the root {}",
                ctx.event_time().map(|t| t.to_rfc3339()),
                ctx.event_time_source(),
                ctx.at_root()
            )))
        }
    }
}

/// A site's module reads the root's event time and whether its observable came with the
/// submission, as the testkit gives them, which is as the lease does.
#[tokio::test]
async fn a_site_module_reads_the_root_s_event_time_through_the_testkit() {
    use around_the_alert::AroundTheAlert;
    let when = chrono::DateTime::parse_from_rfc3339("2026-11-18T09:30:00Z")
        .expect("a time")
        .to_utc();
    let harness = ace_testkit::Harness::<AroundTheAlert>::new()
        .expect("a harness")
        .event_time(when)
        .at_root(true);
    let observable = harness.observable(ace_results::ObservableKind::Fqdn, "a.example");
    let outcome = harness.run_lookup(observable).await.expect("runs");
    assert_eq!(
        outcome,
        ace_sdk::Outcome::Skipped(
            "Some(\"2026-11-18T09:30:00+00:00\") Some(Event) at the root true".to_owned()
        )
    );
}
