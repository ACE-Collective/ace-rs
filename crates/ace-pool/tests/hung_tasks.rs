//! PLAN.md 2.19's Done check: the supervisor kills a task process at its deadline and writes a
//! failed-task row with the error and the input hashes.

mod common;

use std::time::{Duration, Instant};

use ace_pool::testing;

use common::{Core, PoolProcess, enqueue, root_with_bytes, test_pool, wait_until_idle};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_infinite_loop_is_killed_at_its_deadline_and_its_row_names_its_inputs() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_spin"],
        Duration::from_secs(30),
    )
    .await;
    // a root in event mode queues nothing by itself
    let (root, sha256) = root_with_bytes(&core, "event", b"spin on this", "spin.bin").await;
    enqueue(&core, root, &sha256.to_hex(), "test_spin").await;

    let started = Instant::now();
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &["parsers", "--task-user", "ace4-task", "--concurrency", "1"],
    ));
    wait_until_idle(&core, root, Duration::from_secs(30)).await;
    let took = started.elapsed();
    let stderr = pool.stop();
    println!("ended after {took:?}");

    let (state, error, inputs): (String, Option<String>, Vec<String>) = sqlx::query_as(
        "SELECT state::text, error, input_hashes FROM queue.tasks WHERE root_id = $1",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the task's row");
    assert_eq!(state, "failed", "{stderr}");
    assert_eq!(
        error.as_deref(),
        Some("the task process ran past its deadline of 2s and was killed")
    );
    assert_eq!(inputs, [sha256.to_hex()]);
    // it spun on its input before the deadline, and the kill came at the deadline, not later
    assert!(stderr.contains("test_spin: spinning on"), "{stderr}");
    assert!(took < Duration::from_secs(10), "{took:?}");
}

// PLAN.md 5.12's Done check: a command an analyst starts from the GUI runs as a task, contained, and ends
// at its deadline whatever happens to the session that started it or to the API (#973).

/// A command's row, as these tests read it.
#[derive(Debug, Clone)]
struct CommandRow {
    state: String,
    exit_code: Option<i32>,
    error: Option<String>,
    output: String,
    output_truncated: bool,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    deadline_at: Option<chrono::DateTime<chrono::Utc>>,
    finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn command_row(core: &Core, id: i64) -> CommandRow {
    let (state, exit_code, error, output, output_truncated, started_at, deadline_at, finished_at) =
        sqlx::query_as(
            "SELECT state::text, exit_code, error, output, output_truncated, started_at, deadline_at,
                    finished_at
             FROM queue.commands WHERE id = $1",
        )
        .bind(id)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the command's row");
    CommandRow {
        state,
        exit_code,
        error,
        output,
        output_truncated,
        started_at,
        deadline_at,
        finished_at,
    }
}

/// Waits up to `within` for the command's row to satisfy `done`.
async fn wait_for_command(
    core: &Core,
    id: i64,
    within: Duration,
    done: impl Fn(&CommandRow) -> bool,
) -> CommandRow {
    let started = Instant::now();
    loop {
        let row = command_row(core, id).await;
        if done(&row) {
            return row;
        }
        assert!(started.elapsed() < within, "after {within:?}: {row:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The pid a `sleep` test command printed first.
fn pid_in(output: &str) -> i32 {
    output
        .lines()
        .find_map(|line| line.strip_prefix("pid "))
        .and_then(|pid| pid.trim().parse().ok())
        .expect("the command printed its pid")
}

/// True while a process with this pid runs. A reaped process has no `/proc` entry, and a zombie isn't
/// running.
fn alive(pid: i32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        !stat
            .rsplit(')')
            .next()
            .unwrap_or("")
            .trim_start()
            .starts_with('Z')
    })
}

/// The service and GUI on the core's database, served over TCP as `ace serve` serves them.
struct Gui {
    service: ace_service::Service,
    url: String,
    http: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Gui {
    fn drop(&mut self) {
        self.task.abort();
    }
}

const PASSWORD: &str = "correct horse battery staple";

impl Gui {
    async fn start(core: &Core) -> Gui {
        let service =
            ace_service::Service::new(core.test_db.db().clone(), core.orchestrator.clone());
        let router = ace_gui::Gui::new(service.clone(), ace_service::Transport::Plain).router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds");
        let url = format!("http://{}", listener.local_addr().expect("an address"));
        let task = tokio::spawn(async move {
            let served = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
            if let Err(e) = served {
                eprintln!("the GUI stopped: {e}");
            }
        });
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a client");
        Gui {
            service,
            url,
            http,
            task,
        }
    }

    /// An analyst who may use the CLI page.
    async fn analyst(&self, name: &str) -> ace_service::Actor {
        let bootstrap = ace_service::Actor::Internal {
            id: ace_service::Component::new("bootstrap").expect("a name"),
        };
        let id = self
            .service
            .create_user(
                &bootstrap,
                &ace_service::Username::new(name).expect("a name"),
                ace_service::Password::new(PASSWORD),
                &ace_service::Profile::default(),
            )
            .await
            .expect("makes a user");
        for (major, minor) in [("admin", "read"), ("cli", "execute")] {
            self.service
                .grant(
                    &bootstrap,
                    &ace_service::Holder::User(id),
                    &ace_service::PermissionPattern::new(major, minor).expect("a pattern"),
                    ace_service::Effect::Allow,
                )
                .await
                .expect("grants");
        }
        ace_service::Actor::User {
            id,
            name: name.to_owned(),
        }
    }

    /// A form post from this site's own page, with the session's cookie.
    async fn post(&self, path: &str, cookie: &str, form: &[(&str, &str)]) -> reqwest::Response {
        self.http
            .post(format!("{}{path}", self.url))
            .header("origin", &self.url)
            .header("cookie", cookie)
            .form(form)
            .send()
            .await
            .expect("answered")
    }

    async fn get(&self, path: &str, cookie: &str) -> reqwest::Response {
        self.http
            .get(format!("{}{path}", self.url))
            .header("cookie", cookie)
            .send()
            .await
            .expect("answered")
    }

    /// Signs in through the login form and returns the session's cookie.
    async fn sign_in(&self, name: &str) -> String {
        let response = self
            .http
            .post(format!("{}/login", self.url))
            .header("origin", &self.url)
            .form(&[("username", name), ("password", PASSWORD)])
            .send()
            .await
            .expect("answered");
        assert_eq!(response.status(), 303, "signs in");
        let set = response.headers()["set-cookie"].to_str().expect("text");
        set.split(';').next().expect("a cookie").to_owned()
    }
}

/// The test pool as a parser pool's supervisor that runs GUI commands, one at a time unless `concurrency`.
fn command_pool(core: &Core) -> PoolProcess {
    PoolProcess::start(test_pool(
        core,
        &[
            "parsers",
            "--task-user",
            "ace4-task",
            "--concurrency",
            "1",
            "--commands",
        ],
    ))
}

/// PLAN.md 5.12's Done check: an analyst starts a command from the CLI page, signs out, and the command
/// runs on to its deadline, no earlier and no later, and its row says it was killed there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_the_session_leaves_a_command_bounded_by_its_deadline() {
    let core = Core::start(testing::test_manifests(), &[], Duration::from_secs(30)).await;
    let gui = Gui::start(&core).await;
    gui.analyst("alice").await;
    let cookie = gui.sign_in("alice").await;
    let mut pool = command_pool(&core);

    let response = gui
        .post(
            "/admin/cli",
            &cookie,
            &[("command", "ace sleep forever"), ("timeout_seconds", "4")],
        )
        .await;
    assert_eq!(response.status(), 303, "starts it");
    let location = response.headers()["location"].to_str().expect("text");
    let id: i64 = location
        .strip_prefix("/admin/cli/")
        .and_then(|id| id.parse().ok())
        .expect("the run's page");
    let running = wait_for_command(&core, id, Duration::from_secs(20), |row| {
        row.state == "running" && row.output.contains("pid ")
    })
    .await;
    let pid = pid_in(&running.output);
    assert!(alive(pid));

    // the session closes: the page's cookie no longer opens anything
    let response = gui.post("/logout", &cookie, &[]).await;
    assert_eq!(response.status(), 303, "signs out");
    let response = gui.get(&format!("/admin/cli/{id}"), &cookie).await;
    assert_eq!(response.status(), 303, "the session is gone");
    assert!(
        response.headers()["location"]
            .to_str()
            .expect("text")
            .starts_with("/login")
    );

    // it runs on until its deadline, not earlier
    let deadline = running.deadline_at.expect("a deadline");
    let started_at = running.started_at.expect("a start");
    assert_eq!(deadline - started_at, chrono::Duration::seconds(4));
    let before = (deadline - chrono::Utc::now() - chrono::Duration::milliseconds(700))
        .to_std()
        .expect("the deadline is ahead");
    tokio::time::sleep(before).await;
    assert_eq!(command_row(&core, id).await.state, "running");
    assert!(alive(pid), "still running just before its deadline");

    // and ends at it, not later
    let ended = wait_for_command(&core, id, Duration::from_secs(10), |row| {
        row.state != "running"
    })
    .await;
    let stderr = pool.terminate(Duration::from_secs(20));
    assert_eq!(ended.state, "timed_out", "{stderr}");
    assert_eq!(
        ended.error.as_deref(),
        Some("killed at its deadline, 4 seconds after it started")
    );
    let finished = ended.finished_at.expect("finished");
    let late = finished - deadline;
    println!("the row ended {late} after the deadline");
    assert!(
        late >= chrono::Duration::zero() && late < chrono::Duration::milliseconds(1500),
        "ended {late} after its deadline"
    );
    assert!(!alive(pid), "the process is gone");
    assert!(ended.output.starts_with(&format!("pid {pid}\n")));
}

/// A command still ends at its deadline while the API is down: the supervisor kills it on its own clock,
/// and the row says so once a new API takes the end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_command_doesnt_outlive_its_deadline_when_the_api_restarts() {
    let core = Core::start(testing::test_manifests(), &[], Duration::from_secs(30)).await;
    let gui = Gui::start(&core).await;
    let analyst = gui.analyst("bob").await;
    let mut pool = command_pool(&core);
    let id = gui
        .service
        .start_command(&analyst, "sleep forever", Some(4))
        .await
        .expect("starts")
        .run
        .id;
    let running = wait_for_command(&core, id, Duration::from_secs(20), |row| {
        row.state == "running" && row.output.contains("pid ")
    })
    .await;
    let pid = pid_in(&running.output);
    let deadline = running.deadline_at.expect("a deadline");

    core.stop_api().await;
    // past the deadline with no API: the process is gone all the same
    let past = (deadline - chrono::Utc::now() + chrono::Duration::milliseconds(1500))
        .to_std()
        .expect("the deadline is ahead");
    tokio::time::sleep(past).await;
    assert!(!alive(pid), "killed at its deadline while the API was down");
    assert_eq!(
        command_row(&core, id).await.state,
        "running",
        "nothing could say so yet"
    );

    core.start_api().await;
    let ended = wait_for_command(&core, id, Duration::from_secs(10), |row| {
        row.state != "running"
    })
    .await;
    let stderr = pool.terminate(Duration::from_secs(20));
    assert_eq!(ended.state, "timed_out", "{stderr}");
    assert_eq!(
        ended.error.as_deref(),
        Some("killed at its deadline, 4 seconds after it started")
    );
    assert!(ended.finished_at.expect("finished") > deadline);
}

/// A command's process is contained like a task's, and what it writes is kept in order, bounded, with
/// NUL as U+FFFD; its exit code is its row's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_command_runs_contained_and_its_output_is_bounded() {
    let core = Core::start(testing::test_manifests(), &[], Duration::from_secs(30)).await;
    let gui = Gui::start(&core).await;
    let analyst = gui.analyst("carol").await;
    let mut pool = command_pool(&core);
    let mut ids = Vec::new();
    for line in [
        "fork",
        "open /etc/hostname",
        "flood 1500000",
        "nul",
        "both",
        "exit 3",
    ] {
        let detail = gui
            .service
            .start_command(&analyst, line, Some(30))
            .await
            .expect("starts");
        ids.push((line, detail.run.id));
    }
    let mut rows = Vec::new();
    for (line, id) in &ids {
        let row = wait_for_command(&core, *id, Duration::from_secs(60), |row| {
            row.state != "running" && row.state != "queued"
        })
        .await;
        rows.push((*line, row));
    }
    let stderr = pool.terminate(Duration::from_secs(20));
    let row = |line: &str| &rows.iter().find(|(l, _)| *l == line).expect("ran").1;

    let fork = row("fork");
    assert_eq!(fork.state, "failed", "{stderr}");
    assert_eq!(
        fork.error.as_deref(),
        Some("the command was killed by SIGSYS (a blocked system call)")
    );
    assert_eq!(fork.output, "starting a process\n");

    let open = row("open /etc/hostname");
    assert_eq!(
        (open.state.as_str(), open.exit_code),
        ("completed", Some(1))
    );
    assert!(
        open.output
            .starts_with("can't open /etc/hostname: Permission denied"),
        "{}",
        open.output
    );

    let flood = row("flood 1500000");
    assert_eq!(
        (flood.state.as_str(), flood.exit_code),
        ("completed", Some(0))
    );
    assert!(flood.output_truncated);
    assert_eq!(flood.output.len(), 1 << 20);

    let nul = row("nul");
    assert_eq!(nul.output, "a\u{fffd}b\n");
    assert_eq!(row("both").output, "out 1\nerr 1\nout 2\n");
    let exit = row("exit 3");
    assert_eq!(
        (exit.state.as_str(), exit.exit_code),
        ("completed", Some(3))
    );
}

/// A cancel kills a running command within a report or two, and a pool that stops kills its commands
/// and ends them as abandoned, never to run again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_or_a_stopping_pool_kills_a_command() {
    let core = Core::start(testing::test_manifests(), &[], Duration::from_secs(30)).await;
    let gui = Gui::start(&core).await;
    let analyst = gui.analyst("dave").await;
    let mut pool = command_pool(&core);

    let id = gui
        .service
        .start_command(&analyst, "sleep forever", Some(120))
        .await
        .expect("starts")
        .run
        .id;
    let running = wait_for_command(&core, id, Duration::from_secs(20), |row| {
        row.output.contains("pid ")
    })
    .await;
    let pid = pid_in(&running.output);
    let asked = Instant::now();
    gui.service
        .cancel_command(&analyst, id)
        .await
        .expect("cancels");
    let cancelled = wait_for_command(&core, id, Duration::from_secs(10), |row| {
        row.state != "running"
    })
    .await;
    println!("cancelled after {:?}", asked.elapsed());
    assert_eq!(cancelled.state, "cancelled");
    assert_eq!(cancelled.error.as_deref(), Some("cancelled while it ran"));
    assert!(!alive(pid));

    let id = gui
        .service
        .start_command(&analyst, "sleep forever", Some(120))
        .await
        .expect("starts")
        .run
        .id;
    let running = wait_for_command(&core, id, Duration::from_secs(20), |row| {
        row.output.contains("pid ")
    })
    .await;
    let pid = pid_in(&running.output);
    let stderr = pool.terminate(Duration::from_secs(20));
    let abandoned = command_row(&core, id).await;
    assert_eq!(abandoned.state, "abandoned", "{stderr}");
    assert_eq!(
        abandoned.error.as_deref(),
        Some("its pool stopped while it ran, and killed it")
    );
    assert!(!alive(pid));
}

// PLAN.md 7.5 batch 10: a task whose tool is stopped, killed or refused ends with the reason in its
// result, not a hang. `test_runs_tool` runs the containment test task as its tool, with the arguments
// its input holds, through the supervisor's sandbox runner, as the task's user.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_task_whose_tool_is_stopped_or_refused_ends_with_the_reason() {
    let core = Core::start(
        testing::test_manifests(),
        &["test_runs_tool"],
        Duration::from_secs(30),
    )
    .await;
    let tool = format!("test-tool={}", env!("CARGO_BIN_EXE_containment-test-task"));
    let cases: &[(&str, &str)] = &[
        ("--uncontained\nthread", "exited 0; stdout \"a thread ran\""),
        ("--uncontained\nfork", "stopped: Process"),
        ("--uncontained\nexec", "stopped: Program"),
        ("--uncontained\nsleep\n60", "stopped: Timeout"),
        ("--uncontained\nprint-mb\n80", "stopped: Output"),
        ("--uncontained\nread\n/etc/passwd", "exited 4"),
        ("--uncontained\nread\n{input}", "exited 0; stdout \"read "),
        ("--uncontained\nkeep", "kept [\"out\"]"),
    ];
    let mut roots = Vec::new();
    for (i, (args, _)) in cases.iter().enumerate() {
        let (root, sha256) =
            root_with_bytes(&core, "event", args.as_bytes(), &format!("case-{i}")).await;
        enqueue(&core, root, &sha256.to_hex(), "test_runs_tool").await;
        roots.push(root);
    }
    let started = Instant::now();
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &[
            "parsers",
            "--task-user",
            "ace4-task",
            "--concurrency",
            "4",
            "--tool",
            &tool,
        ],
    ));
    for root in &roots {
        wait_until_idle(&core, *root, Duration::from_secs(60)).await;
    }
    let stderr = pool.stop();
    println!("ended after {:?}", started.elapsed());
    for (root, (args, wanted)) in roots.iter().zip(cases) {
        let note: Option<String> =
            sqlx::query_scalar("SELECT details->>'note' FROM analysis.results WHERE root_id = $1")
                .bind(root)
                .fetch_optional(core.test_db.db().pool())
                .await
                .expect("the result");
        let (state, error) = common::task_of(&core, *root, "test_runs_tool").await;
        println!("{args:?}: {state} {error:?} {note:?}");
        assert_eq!(state, "done", "{args:?}: {error:?}\n{stderr}");
        let note = note.unwrap_or_default();
        assert!(
            note.contains(wanted),
            "{args:?}: {wanted} in {note}\n{stderr}"
        );
    }
}

// PLAN.md 7.5 batch 10: OpenCV, which the ocr and qrcode modules run in the task, runs on the task's
// one thread under containment, and tesseract, zbarimg and Ghostscript in the runner, as the pool's
// task user. A blank image is a clean negative for qrcode, after zbarimg, OpenCV's decoder and the
// inverted scan; a small screenshot is scaled, sharpened and denoised for ocr.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sandbox_modules_run_opencv_contained() {
    let manifests = vec![
        ace_sdk::Manifest::parser::<ace_mod_sandbox::QrCodeAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::OcrAnalyzer>(),
    ];
    let core = Core::start(manifests, &["qrcode", "ocr"], Duration::from_secs(30)).await;
    let images = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/ace3/dumps/fixtures/images");
    let blank = std::fs::read(images.join("blank.png")).expect("the fixture");
    let text = std::fs::read(images.join("text_small.png")).expect("the fixture");
    let (qr_root, qr_sha) = root_with_bytes(&core, "event", &blank, "blank.png").await;
    enqueue(&core, qr_root, &qr_sha.to_hex(), "qrcode").await;
    let (ocr_root, ocr_sha) =
        common::root_with_file(&core, "event", &text, "text_small.png", &["ocr"]).await;
    enqueue(&core, ocr_root, &ocr_sha.to_hex(), "ocr").await;
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &["parsers", "--task-user", "ace4-task", "--concurrency", "2"],
    ));
    for root in [qr_root, ocr_root] {
        wait_until_idle(&core, root, Duration::from_secs(120)).await;
    }
    let stderr = pool.stop();
    for (root, module) in [(qr_root, "qrcode"), (ocr_root, "ocr")] {
        let (state, error) = common::task_of(&core, root, module).await;
        assert_eq!(state, "done", "{module}: {error:?}\n{stderr}");
    }
    let ocr: Option<bool> = sqlx::query_scalar(
        "SELECT (details->>'ocr')::bool FROM analysis.results WHERE root_id = $1",
    )
    .bind(ocr_root)
    .fetch_optional(core.test_db.db().pool())
    .await
    .expect("the result");
    assert_eq!(ocr, Some(true), "{stderr}");
}

// PLAN.md 7.5 batch 11: the unpackers and decompilers through a pool, their tools run by the runner as
// the pool's task user, who must reach each tool's files (the containment tests run them as root).
// Each module makes a result with a file on its sample: CFR's source, upx's unpacked file, unautoit's
// script, de4dot's cleaned assembly and ilspycmd's IL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_executable_modules_run_their_tools_as_the_task_user() {
    let runs = [
        (
            "java_class_decompiler",
            "ace3/executables/VxUGJsAplRNavewkjKujp.class",
        ),
        ("upx", "ace3/executables/cmd-upx.exe"),
        ("autoit", "ace3/executables/hello_autoit.exe"),
        ("de4dot", "ace4/executables/emitted_methods.exe"),
        ("ilspy", "ace4/executables/hello_dotnet.dll"),
    ];
    let manifests = vec![
        ace_sdk::Manifest::parser::<ace_mod_sandbox::JavaClassDecompiler>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::UpxAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::AutoItAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::De4dotAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::IlspyAnalyzer>(),
    ];
    let modules: Vec<&str> = runs.iter().map(|(module, _)| *module).collect();
    let core = Core::start(manifests, &modules, Duration::from_secs(30)).await;
    let samples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples");
    let mut roots = Vec::new();
    for (module, sample) in runs {
        let bytes = std::fs::read(samples.join(sample)).expect("the sample");
        let name = sample.rsplit('/').next().expect("a name");
        let (root, sha256) = root_with_bytes(&core, "event", &bytes, name).await;
        enqueue(&core, root, &sha256.to_hex(), module).await;
        roots.push((root, module));
    }
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &["parsers", "--task-user", "ace4-task", "--concurrency", "2"],
    ));
    for (root, _) in &roots {
        wait_until_idle(&core, *root, Duration::from_secs(180)).await;
    }
    let stderr = pool.stop();
    for (root, module) in roots {
        let (state, error) = common::task_of(&core, root, module).await;
        assert_eq!(state, "done", "{module}: {error:?}\n{stderr}");
        // the sample and the file its result added
        let files: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM analysis.observables WHERE root_id = $1 AND type = 'file'",
        )
        .bind(root)
        .fetch_one(core.test_db.db().pool())
        .await
        .expect("the count");
        assert_eq!(files, 2, "{module}\n{stderr}");
    }
}

/// PLAN.md 7.5 batch 12: dmg2img and 7z as the task's user, under the runner: dmg_analyzer turns a
/// DMG into its image and lists it, and the CVE module, queued on the image it added, as the core
/// queues it in a mode, lists it again and extracts the script in its app bundle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_macos_image_modules_run_their_tools_as_the_task_user() {
    let manifests = vec![
        ace_sdk::Manifest::parser::<ace_mod_sandbox::DmgAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::Cve202130657Analyzer>(),
    ];
    let modules = ["dmg_analyzer", "cve_2021_30657_analyzer"];
    let core = Core::start(manifests, &modules, Duration::from_secs(30)).await;
    let samples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples");
    let bytes = std::fs::read(samples.join("ace4/macos/script_app.dmg")).expect("the sample");
    let (root, sha256) = root_with_bytes(&core, "event", &bytes, "script_app.dmg").await;
    enqueue(&core, root, &sha256.to_hex(), "dmg_analyzer").await;
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &["parsers", "--task-user", "ace4-task", "--concurrency", "2"],
    ));
    wait_until_idle(&core, root, Duration::from_secs(180)).await;
    let image: String = sqlx::query_scalar(
        "SELECT value FROM analysis.observables WHERE root_id = $1 AND type = 'file' AND value <> $2",
    )
    .bind(root)
    .bind(sha256.to_hex())
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the image");
    enqueue(&core, root, &image, "cve_2021_30657_analyzer").await;
    wait_until_idle(&core, root, Duration::from_secs(180)).await;
    let stderr = pool.stop();
    let states: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT module, state::text, error FROM queue.tasks WHERE root_id = $1 ORDER BY module",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("the tasks");
    assert_eq!(states.len(), 2, "{states:?}\n{stderr}");
    for (module, state, error) in &states {
        assert_eq!(state, "done", "{module}: {error:?}\n{stderr}");
    }
    let results: Vec<(String, String)> = sqlx::query_as(
        "SELECT analysis_type, details::text FROM analysis.results WHERE root_id = $1
         ORDER BY analysis_type",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("the results");
    assert_eq!(results.len(), 2, "{results:?}\n{stderr}");
    assert_eq!(results[0].0, "cve_2021_30657_analysis");
    assert!(
        results[0].1.contains(r#""Payload": "text/x-shellscript""#),
        "{results:?}"
    );
    assert!(
        results[1]
            .1
            .contains("Installer/Payload.app/Contents/MacOS/Payload"),
        "{results:?}"
    );
    // the DMG, its image and the script
    let files: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM analysis.observables WHERE root_id = $1 AND type = 'file'",
    )
    .bind(root)
    .fetch_one(core.test_db.db().pool())
    .await
    .expect("the count");
    assert_eq!(files, 3, "{stderr}");
}

/// PLAN.md 7.5 batch 13: tshark and capinfos as the task's user, under the runner: pcap_analyzer
/// dissects ace3's TLS capture and stores what it carves, and pcap_files and pcap_tls, queued on it
/// as the core queues them in a mode, add the payload and the certificate with no upload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pcap_modules_run_tshark_as_the_task_user() {
    let manifests = vec![
        ace_sdk::Manifest::parser::<ace_mod_pcap::PcapAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_pcap::PcapFiles>(),
        ace_sdk::Manifest::parser::<ace_mod_pcap::PcapTls>(),
    ];
    let modules = ["pcap_analyzer", "pcap_files", "pcap_tls"];
    let core = Core::start(manifests, &modules, Duration::from_secs(30)).await;
    let samples = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples");
    let bytes = std::fs::read(samples.join("ace3/pcap/http_tls.pcapng")).expect("the sample");
    let (root, sha256) = root_with_bytes(&core, "event", &bytes, "http_tls.pcapng").await;
    enqueue(&core, root, &sha256.to_hex(), "pcap_analyzer").await;
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &["parsers", "--task-user", "ace4-task", "--concurrency", "2"],
    ));
    wait_until_idle(&core, root, Duration::from_secs(180)).await;
    for module in ["pcap_files", "pcap_tls"] {
        enqueue(&core, root, &sha256.to_hex(), module).await;
    }
    wait_until_idle(&core, root, Duration::from_secs(180)).await;
    let stderr = pool.stop();
    let states: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT module, state::text, error FROM queue.tasks WHERE root_id = $1 ORDER BY module",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("the tasks");
    assert_eq!(states.len(), 3, "{states:?}\n{stderr}");
    for (module, state, error) in &states {
        assert_eq!(state, "done", "{module}: {error:?}\n{stderr}");
    }
    let summaries: Vec<(String, String)> = sqlx::query_as(
        "SELECT module, summary FROM analysis.results WHERE root_id = $1 ORDER BY module",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("the results");
    assert_eq!(
        summaries,
        [
            (
                "pcap_analyzer".to_owned(),
                "PCAP Analysis: 41 packets, 3 flows, 2 TLS sessions".to_owned()
            ),
            (
                "pcap_files".to_owned(),
                "PCAP Files: 1 files (1 file)".to_owned()
            ),
            (
                "pcap_tls".to_owned(),
                "PCAP TLS: 2 entries (1 file, 2 fqdn, 2 ja4)".to_owned()
            ),
        ],
        "{stderr}"
    );
    let files: Vec<(String, i64)> = sqlx::query_as(
        "SELECT f.path, s.size FROM analysis.files f
         JOIN analysis.observables o ON o.root_id = f.root_id AND o.id = f.observable_id
         JOIN store.objects s ON s.pool = 'alert_files' AND s.sha256 = o.value
         WHERE f.root_id = $1 ORDER BY f.path",
    )
    .bind(root)
    .fetch_all(core.test_db.db().pool())
    .await
    .expect("the files");
    assert_eq!(
        files,
        [
            ("http_tls.pcapng".to_owned(), 11652),
            (
                "http_tls.pcapng.pcap_objects/certificates/46601b3e65dc50aef3998a71b5ccdbd0f5fc1aa13488ed38349b3abe15543fad.der".to_owned(),
                848
            ),
            ("http_tls.pcapng.pcap_objects/http/payload.txt".to_owned(), 36),
        ]
    );
}

/// docs/measurements/sandbox-modules.md, executables.md and pdf-link-text.md: crafted files through the sandbox modules,
/// contained, as the pool runs them. `ACE4_CRAFTED` names a directory of them, and a file goes to the
/// module its name starts with, or to batch 10's five when none; each line printed is a module, a
/// file, how its task ended, how long it took and the result's details.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, run by hand"]
async fn crafted_files_through_the_sandbox_modules() {
    let dir = std::path::PathBuf::from(std::env::var("ACE4_CRAFTED").expect("ACE4_CRAFTED"));
    let batch_10 = ["qrcode", "ocr", "pdftotext", "exif", "pdf_analyzer"];
    let batch_11 = ["java_class_decompiler", "upx", "autoit", "de4dot", "ilspy"];
    let mut modules = batch_10.to_vec();
    modules.extend(batch_11);
    let manifests = vec![
        ace_sdk::Manifest::parser::<ace_mod_sandbox::QrCodeAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::OcrAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::PdfTextAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::ExifAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_pdf::PdfAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::JavaClassDecompiler>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::UpxAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::AutoItAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::De4dotAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::IlspyAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::DmgAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_sandbox::Cve202130657Analyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_pcap::PcapAnalyzer>(),
        ace_sdk::Manifest::parser::<ace_mod_pcap::PcapHttp>(),
        ace_sdk::Manifest::parser::<ace_mod_pcap::PcapFiles>(),
        ace_sdk::Manifest::parser::<ace_mod_pcap::PcapDns>(),
        ace_sdk::Manifest::parser::<ace_mod_pcap::PcapTls>(),
        ace_mod_pdf::links::MANIFEST,
    ];
    modules.extend(["dmg_analyzer", "cve_2021_30657_analyzer"]);
    // docs/measurements/pdf-link-text.md
    modules.push("pdf_link_text");
    let pcap_modules = [
        "pcap_analyzer",
        "pcap_http",
        "pcap_files",
        "pcap_dns",
        "pcap_tls",
    ];
    modules.extend(pcap_modules);
    let core = Core::start(manifests, &modules, Duration::from_secs(30)).await;
    let mut pool = PoolProcess::start(test_pool(
        &core,
        &["parsers", "--task-user", "ace4-task", "--concurrency", "1"],
    ));
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("the directory")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .into_string()
                .expect("a name")
        })
        .collect();
    names.sort();
    for name in &names {
        let bytes = std::fs::read(dir.join(name)).expect("the file");
        // batch 13's: pcap_analyzer on the capture, then the categories on its index
        if name.starts_with("pcap_") {
            let (root, sha256) = common::root_with_file(&core, "event", &bytes, name, &[]).await;
            for step in [&pcap_modules[..1], &pcap_modules[1..]] {
                for module in step {
                    enqueue(&core, root, &sha256.to_hex(), module).await;
                }
                let started = Instant::now();
                wait_until_idle(&core, root, Duration::from_secs(900)).await;
                println!(
                    "{name}: {:?} idle in {:.1} s",
                    step,
                    started.elapsed().as_secs_f64()
                );
            }
            for module in pcap_modules {
                let (state, error) = common::task_of(&core, root, module).await;
                let result: Option<(String, String)> = sqlx::query_as(
                    "SELECT coalesce(summary, ''), left(details::text, 400) FROM analysis.results
                     WHERE root_id = $1 AND module = $2",
                )
                .bind(root)
                .bind(module)
                .fetch_optional(core.test_db.db().pool())
                .await
                .expect("the result");
                println!("{module} {name}: {state}; {error:?}; {result:?}");
            }
            let files: i64 =
                sqlx::query_scalar("SELECT count(*) FROM analysis.files WHERE root_id = $1")
                    .bind(root)
                    .fetch_one(core.test_db.db().pool())
                    .await
                    .expect("counts");
            println!("{name}: {files} files in the alert");
            continue;
        }
        // batch 12's: dmg_analyzer on the DMG, then the CVE module on the image it added
        if name.starts_with("dmg_analyzer") || name.starts_with("cve_2021_30657_analyzer") {
            let (root, sha256) = common::root_with_file(&core, "event", &bytes, name, &[]).await;
            for module in ["dmg_analyzer", "cve_2021_30657_analyzer"] {
                let image: Option<String> = sqlx::query_scalar(
                    "SELECT value FROM analysis.observables
                     WHERE root_id = $1 AND type = 'file' AND value <> $2",
                )
                .bind(root)
                .bind(sha256.to_hex())
                .fetch_optional(core.test_db.db().pool())
                .await
                .expect("the image");
                let target = match (module, image) {
                    ("dmg_analyzer", _) => sha256.to_hex(),
                    (_, Some(image)) => image,
                    (_, None) => break,
                };
                enqueue(&core, root, &target, module).await;
                let started = Instant::now();
                wait_until_idle(&core, root, Duration::from_secs(600)).await;
                let (state, error) = common::task_of(&core, root, module).await;
                let result: Option<(String, String)> = sqlx::query_as(
                    "SELECT coalesce(summary, ''), left(details::text, 600) FROM analysis.results
                     WHERE root_id = $1 AND module = $2",
                )
                .bind(root)
                .bind(module)
                .fetch_optional(core.test_db.db().pool())
                .await
                .expect("the result");
                println!(
                    "{module} {name}: {state} in {:.1} s; {error:?}; {result:?}",
                    started.elapsed().as_secs_f64()
                );
            }
            continue;
        }
        let own = batch_11.iter().chain(&["pdf_link_text"]);
        let mine: Vec<&str> = match own.into_iter().find(|m| name.starts_with(*m)) {
            Some(module) => vec![*module],
            None => batch_10.to_vec(),
        };
        for module in mine {
            if module == "ocr" && !name.ends_with(".png") {
                continue;
            }
            let (root, sha256) =
                common::root_with_file(&core, "event", &bytes, name, &["ocr"]).await;
            enqueue(&core, root, &sha256.to_hex(), module).await;
            let started = Instant::now();
            wait_until_idle(&core, root, Duration::from_secs(600)).await;
            let (state, error) = common::task_of(&core, root, module).await;
            let result: Option<(String, String)> = sqlx::query_as(
                "SELECT coalesce(summary, ''), left(details::text, 600) FROM analysis.results
                 WHERE root_id = $1",
            )
            .bind(root)
            .fetch_optional(core.test_db.db().pool())
            .await
            .expect("the result");
            println!(
                "{module} {name}: {state} in {:.1} s; {error:?}; {result:?}",
                started.elapsed().as_secs_f64()
            );
        }
    }
    pool.stop();
}
