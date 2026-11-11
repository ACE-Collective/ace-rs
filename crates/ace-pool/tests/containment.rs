//! PLAN.md 2.18's Done check: test tasks that fork, exec, open a file outside their allowed
//! paths, connect to a port that isn't allowed, or allocate past the limit are each stopped, and
//! a task process reports one thread.
//!
//! Each test runs `containment-test-task`, which contains itself and then tries one thing. Most
//! tests first run it with `--uncontained`, to show that the action works without containment,
//! so a refusal comes from containment and not from a missing file or a closed port.

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const TASK: &str = env!("CARGO_BIN_EXE_containment-test-task");

/// Longer than any test task should take. A task still running then is killed and fails its test.
const DEADLINE: Duration = Duration::from_secs(60);

struct Run {
    args: Vec<String>,
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl Run {
    fn assert_done(&self) {
        assert!(self.status.success(), "{self}");
    }

    fn assert_killed_by(&self, signal: i32) {
        assert_eq!(self.status.signal(), Some(signal), "{self}");
    }

    /// The action failed with EACCES, which is how Landlock refuses an open or a connect.
    fn assert_refused(&self) {
        assert_eq!(self.status.code(), Some(4), "{self}");
        assert!(
            self.stderr.contains("Permission denied (os error 13)"),
            "{self}"
        );
    }
}

impl std::fmt::Display for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "containment-test-task {}\n{}\nstdout: {}\nstderr: {}",
            self.args.join(" "),
            self.status,
            self.stdout.trim_end(),
            self.stderr.trim_end()
        )
    }
}

fn start(args: &[&str]) -> Child {
    Command::new(TASK)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting the test task")
}

/// Runs the test task to its end. Its output is a few lines, so it can't fill a pipe.
fn run(args: &[&str]) -> Run {
    let mut child = start(args);
    drop(child.stdin.take());
    let started = Instant::now();
    while child.try_wait().expect("polling the test task").is_none() {
        if started.elapsed() > DEADLINE {
            child.kill().expect("killing the test task");
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("reading the test task");
    let run = Run {
        args: args.iter().map(|a| a.to_string()).collect(),
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    println!("{run}\n");
    run
}

fn path(path: &Path) -> &str {
    path.to_str().expect("temporary paths are UTF-8")
}

#[test]
fn fork_kills_the_task() {
    run(&["--uncontained", "fork"]).assert_done();
    run(&["fork"]).assert_killed_by(libc::SIGSYS);
}

#[test]
fn exec_kills_the_task() {
    // uncontained, the process becomes /bin/true and exits 0
    run(&["--uncontained", "exec"]).assert_done();
    run(&["exec"]).assert_killed_by(libc::SIGSYS);
}

#[test]
fn starting_a_thread_kills_the_task() {
    run(&["--uncontained", "thread"]).assert_done();
    run(&["thread"]).assert_killed_by(libc::SIGSYS);
}

#[test]
fn spawning_a_process_kills_the_task() {
    run(&["--uncontained", "spawn"]).assert_done();
    run(&["spawn"]).assert_killed_by(libc::SIGSYS);
}

#[test]
fn opening_a_file_outside_the_allowed_paths_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let allowed = dir.path().join("allowed");
    fs::create_dir(&allowed).unwrap();
    let inside = allowed.join("inside.txt");
    let outside = dir.path().join("outside.txt");
    fs::write(&inside, "inside").unwrap();
    fs::write(&outside, "outside").unwrap();

    let read = ["--read", path(&allowed), "read"];
    run(&[&read[..], &[path(&inside)]].concat()).assert_done();
    run(&["--uncontained", "read", path(&outside)]).assert_done();
    run(&[&read[..], &[path(&outside)]].concat()).assert_refused();
    // /proc and /etc are paths like any other
    run(&[&read[..], &["/proc/self/status"]].concat()).assert_refused();
    run(&[&read[..], &["/etc/passwd"]].concat()).assert_refused();
}

#[test]
fn writing_outside_the_write_paths_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let readable = dir.path().join("readable");
    let writable = dir.path().join("writable");
    fs::create_dir(&readable).unwrap();
    fs::create_dir(&writable).unwrap();
    let paths = [
        "--read",
        path(&readable),
        "--write",
        path(&writable),
        "write",
    ];

    let output = writable.join("output.txt");
    run(&[&paths[..], &[path(&output)]].concat()).assert_done();
    assert_eq!(
        fs::read_to_string(&output).unwrap(),
        "written by a test task\n"
    );

    let elsewhere = dir.path().join("elsewhere.txt");
    run(&["--uncontained", "write", path(&elsewhere)]).assert_done();
    fs::remove_file(&elsewhere).unwrap();
    run(&[&paths[..], &[path(&elsewhere)]].concat()).assert_refused();
    run(&[&paths[..], &[path(&readable.join("output.txt"))]].concat()).assert_refused();
    assert!(!elsewhere.exists());
}

#[test]
fn connecting_to_a_port_not_allowed_is_refused() {
    let allowed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let other_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let allowed = allowed_listener.local_addr().unwrap().port().to_string();
    let other = other_listener.local_addr().unwrap().port().to_string();

    run(&["--port", &allowed, "connect", &allowed]).assert_done();
    run(&["--uncontained", "connect", &other]).assert_done();
    run(&["--port", &allowed, "connect", &other]).assert_refused();
}

/// Landlock's signal scope (ABI 6): a task can't kill its supervisor or another task.
#[test]
fn signalling_the_parent_is_refused() {
    run(&["--uncontained", "signal-parent"]).assert_done();
    let refused = run(&["signal-parent"]);
    assert_eq!(refused.status.code(), Some(4), "{refused}");
    assert!(
        refused
            .stderr
            .contains("Operation not permitted (os error 1)"),
        "{refused}"
    );
}

#[test]
fn allocating_past_the_limit_aborts_the_task() {
    run(&["--uncontained", "allocate", "512"]).assert_done();
    run(&["--memory-mb", "256", "allocate", "64"]).assert_done();
    let past = run(&["--memory-mb", "256", "allocate", "512"]);
    past.assert_killed_by(libc::SIGABRT);
    assert!(
        past.stderr
            .contains("memory allocation of 536870912 bytes failed"),
        "{past}"
    );
}

#[test]
fn running_past_the_cpu_limit_kills_the_task() {
    run(&["--cpu-seconds", "5", "cpu", "1"]).assert_done();
    run(&["--cpu-seconds", "1", "cpu", "30"]).assert_killed_by(libc::SIGXCPU);
}

/// The PIDs whose parent is `pid`, from every process's status in /proc.
fn children_of(pid: u32) -> Vec<u32> {
    let parent = format!("PPid:\t{pid}");
    fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter(|child| {
            fs::read_to_string(format!("/proc/{child}/status"))
                .is_ok_and(|status| status.lines().any(|line| line == parent))
        })
        .collect()
}

#[test]
fn a_contained_task_runs_one_thread_and_dies_whole_when_killed() {
    let mut task = start(&["wait"]);
    let pid = task.id();
    let mut stdout = BufReader::new(task.stdout.take().unwrap());
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    assert!(line.starts_with("contained"), "{line}");

    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let threads = status.lines().find(|l| l.starts_with("Threads:")).unwrap();
    println!("test task {pid}: {threads}");
    assert_eq!(threads, "Threads:\t1");
    assert!(children_of(pid).is_empty(), "test task {pid} has children");

    task.kill().unwrap();
    assert_eq!(task.wait().unwrap().signal(), Some(libc::SIGKILL));
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[test]
fn containment_refuses_a_process_that_already_runs_threads() {
    let refused = run(&["--thread-before", "nothing"]);
    assert_eq!(refused.status.code(), Some(3), "{refused}");
    assert!(refused.stderr.contains("runs 2 threads"), "{refused}");
}

/// Landlock filters TCP only, so a contained task can still send UDP, DNS included. This pins the
/// gap down, so the change that closes it has to change this test.
#[test]
fn udp_is_not_contained() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let port = receiver.local_addr().unwrap().port().to_string();

    run(&["udp", &port]).assert_done();
    let mut datagram = [0; 64];
    let (length, _) = receiver.recv_from(&mut datagram).unwrap();
    assert_eq!(&datagram[..length], b"from a test task");
}

// PLAN.md 7.5 batch 10: the sandbox runner (`ace_pool::tools`). Each test runs this file's test task
// as a tool: `containment-test-task tool` contains itself and execs `containment-test-task
// --uncontained ACTION`, as a pool's `tool` mode execs a program, so every refusal is the runner's.
mod runner {
    use std::collections::BTreeMap;
    use std::fs;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use ace_pool::tools::{Keeping, Ran, ToolExec, ToolTable, execute_keeping};
    use ace_sdk::tools::{
        Keep, OPEN_FILES_LIMIT, SANDBOX_TOOLS, ToolRun, ToolStatus, ToolStop, environment,
    };

    use super::TASK;

    /// A task's directory with a working directory for one run, as a pool lays them out.
    struct Dirs {
        dir: tempfile::TempDir,
    }

    impl Dirs {
        fn new() -> Dirs {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir(dir.path().join("runs")).unwrap();
            fs::create_dir(dir.path().join("runs/1")).unwrap();
            Dirs { dir }
        }

        fn task(&self) -> &Path {
            self.dir.path()
        }

        fn workdir(&self) -> PathBuf {
            self.dir.path().join("runs/1")
        }

        fn kept(&self) -> PathBuf {
            self.dir.path().join("results/1")
        }
    }

    /// What to run: `tool`'s program with `args`, reading `task_reads` of the task's directory.
    fn exec(dirs: &Dirs, tool: &str, args: &[&str], task_reads: &[&str]) -> ToolExec {
        let table = if tool == "test-task" {
            ToolTable::resolve(&[ace_pool::testing::test_tool(
                "test-task".into(),
                TASK.into(),
            )])
        } else {
            ToolTable::resolve(SANDBOX_TOOLS)
        }
        .expect("the tools resolve");
        let tool = table.get(tool).expect("the tool");
        let mut argv = vec![tool.spec.program.to_owned()];
        argv.extend(tool.spec.args.iter().map(|a| a.to_string()));
        argv.extend(args.iter().map(|a| a.to_string()));
        // the environment the supervisor gives it, with what its spec adds
        let env = environment(
            &tool.spec,
            &ToolRun::new(tool.spec.name, args.iter().copied()),
            &dirs.workdir(),
        )
        .expect("the environment");
        ToolExec {
            program: PathBuf::from(tool.spec.program),
            argv,
            env,
            workdir: dirs.workdir(),
            task_dir: dirs.task().to_owned(),
            task_reads: task_reads.iter().map(PathBuf::from).collect(),
            reads: tool.reads.clone(),
            executes: tool.executes.clone(),
            address_space_bytes: tool.spec.memory_bytes,
            cpu_seconds: 60,
            file_size_bytes: tool.spec.file_size_bytes,
            open_files: OPEN_FILES_LIMIT,
        }
    }

    fn test_task(dirs: &Dirs, action: &[&str]) -> ToolExec {
        let mut args = vec!["--uncontained"];
        args.extend_from_slice(action);
        exec(dirs, "test-task", &args, &[])
    }

    async fn run(exec: &ToolExec, timeout: Duration, keep: Option<(&Keep, &Path)>) -> Ran {
        let keep = keep.map(|(keep, into)| Keeping {
            keep,
            staged: &[],
            into,
            when_stopped: false,
        });
        let ran = execute_keeping(Path::new(TASK), &[], None, exec, timeout, keep)
            .await
            .expect("the tool starts");
        println!(
            "{:?}: {:?}\nstdout: {}\nstderr: {}\n",
            exec.argv,
            ran.status,
            String::from_utf8_lossy(&ran.stdout[..ran.stdout.len().min(2000)]),
            String::from_utf8_lossy(&ran.stderr[..ran.stderr.len().min(2000)])
        );
        ran
    }

    fn stdout(ran: &Ran) -> String {
        String::from_utf8_lossy(&ran.stdout).trim().to_owned()
    }

    /// The tool failed with EACCES: Landlock's refusal of an open or a connect, or the tool
    /// filter's of a socket.
    fn assert_refused(ran: &Ran) {
        assert_eq!(ran.status, ToolStatus::Exited(4));
        let stderr = String::from_utf8_lossy(&ran.stderr);
        assert!(
            stderr.contains("Permission denied (os error 13)"),
            "{stderr}"
        );
    }

    const SECOND: Duration = Duration::from_secs(1);
    const LONG: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn a_tool_may_start_threads() {
        let dirs = Dirs::new();
        let ran = run(&test_task(&dirs, &["thread"]), LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        assert_eq!(stdout(&ran), "a thread ran");
    }

    #[tokio::test]
    async fn a_tool_that_forks_is_killed() {
        let dirs = Dirs::new();
        let ran = run(&test_task(&dirs, &["fork"]), LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Stopped(ToolStop::Process));
    }

    #[tokio::test]
    async fn a_tool_that_spawns_a_process_is_killed() {
        let dirs = Dirs::new();
        let ran = run(&test_task(&dirs, &["spawn"]), LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Stopped(ToolStop::Process));
    }

    #[tokio::test]
    async fn a_tool_that_execs_again_is_killed() {
        let dirs = Dirs::new();
        let started = Instant::now();
        let ran = run(&test_task(&dirs, &["exec"]), LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Stopped(ToolStop::Program));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn a_tool_can_open_no_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let dirs = Dirs::new();
        assert_refused(&run(&test_task(&dirs, &["socket", &port]), LONG, None).await);
        // UDP too, which a parser's task can still send
        assert_refused(&run(&test_task(&dirs, &["udp", &port]), LONG, None).await);
    }

    #[tokio::test]
    async fn a_tool_writes_only_its_working_directory() {
        let dirs = Dirs::new();
        let inside = dirs.workdir().join("inside.txt");
        let ran = run(
            &test_task(&dirs, &["write", inside.to_str().unwrap()]),
            LONG,
            None,
        )
        .await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let outside = dirs.task().join("outside.txt");
        assert_refused(
            &run(
                &test_task(&dirs, &["write", outside.to_str().unwrap()]),
                LONG,
                None,
            )
            .await,
        );
        assert!(!outside.exists());
    }

    #[tokio::test]
    async fn a_tool_reads_only_what_it_was_given() {
        let dirs = Dirs::new();
        fs::write(dirs.task().join("given"), "given").unwrap();
        fs::write(dirs.task().join("other"), "other").unwrap();
        let given = dirs.task().join("given");
        let mut exec = test_task(&dirs, &["read", given.to_str().unwrap()]);
        exec.task_reads = vec![PathBuf::from("given")];
        assert_eq!(run(&exec, LONG, None).await.status, ToolStatus::Exited(0));
        let other = dirs.task().join("other");
        let mut exec = test_task(&dirs, &["read", other.to_str().unwrap()]);
        exec.task_reads = vec![PathBuf::from("given")];
        assert_refused(&run(&exec, LONG, None).await);
        for path in ["/etc/passwd", "/proc/self/status"] {
            assert_refused(&run(&test_task(&dirs, &["read", path]), LONG, None).await);
        }
    }

    #[tokio::test]
    async fn a_task_file_is_opened_with_no_symlink_followed() {
        let dirs = Dirs::new();
        std::os::unix::fs::symlink("/etc/passwd", dirs.task().join("link")).unwrap();
        let mut exec = test_task(&dirs, &["read", "/etc/passwd"]);
        exec.task_reads = vec![PathBuf::from("link")];
        let refused = execute_keeping(Path::new(TASK), &[], None, &exec, LONG, None).await;
        let why = refused.err().expect("the runner refuses the link");
        assert!(why.contains("the task's link"), "{why}");
    }

    #[tokio::test]
    async fn a_tool_past_its_memory_limit_is_refused_the_memory() {
        let dirs = Dirs::new();
        let mut exec = test_task(&dirs, &["allocate", "512"]);
        exec.address_space_bytes = 256 * 1024 * 1024;
        let ran = run(&exec, LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Signaled(libc::SIGABRT));
        assert!(
            String::from_utf8_lossy(&ran.stderr)
                .contains("memory allocation of 536870912 bytes failed")
        );
    }

    #[tokio::test]
    async fn a_tool_past_its_cpu_limit_is_killed() {
        let dirs = Dirs::new();
        let mut exec = test_task(&dirs, &["cpu", "30"]);
        exec.cpu_seconds = 1;
        let ran = run(&exec, LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Signaled(libc::SIGXCPU));
    }

    #[tokio::test]
    async fn a_tool_that_writes_a_file_past_its_limit_is_stopped() {
        let dirs = Dirs::new();
        let mut exec = test_task(&dirs, &["write-mb", "8"]);
        exec.file_size_bytes = 1024 * 1024;
        let keep = Keep::Named(vec!["big".into()]);
        let ran = run(&exec, LONG, Some((&keep, &dirs.kept()))).await;
        assert_eq!(ran.status, ToolStatus::Stopped(ToolStop::FileSize));
        assert_eq!(ran.kept, None);
    }

    #[tokio::test]
    async fn a_tool_past_its_open_files_is_refused_more() {
        let dirs = Dirs::new();
        let mut exec = test_task(&dirs, &["open-files", "100"]);
        exec.open_files = 32;
        let ran = run(&exec, LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Exited(4));
        assert!(String::from_utf8_lossy(&ran.stderr).contains("Too many open files"));
    }

    #[tokio::test]
    async fn a_tool_that_writes_too_much_output_is_stopped() {
        let dirs = Dirs::new();
        let ran = run(&test_task(&dirs, &["print-mb", "80"]), LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Stopped(ToolStop::Output));
        assert_eq!(ran.stdout.len() as u64, ace_sdk::tools::MAX_OUTPUT_BYTES);
    }

    #[tokio::test]
    async fn a_tool_past_its_timeout_is_killed() {
        let dirs = Dirs::new();
        let started = Instant::now();
        let ran = run(&test_task(&dirs, &["sleep", "60"]), SECOND, None).await;
        assert_eq!(ran.status, ToolStatus::Stopped(ToolStop::Timeout));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn only_plain_files_are_kept() {
        let dirs = Dirs::new();
        let ran = run(
            &test_task(&dirs, &["keep"]),
            LONG,
            Some((&Keep::All, &dirs.kept())),
        )
        .await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let kept = ran.kept.expect("what it kept");
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["out"]);
        assert_eq!(fs::read_to_string(&kept["out"]).unwrap(), "kept\n");
    }

    /// A run keeps at most `MAX_KEPT_FILES` files, the first by name, and its answer lists them
    /// (7.5 batch 13: tshark exporting 20,000 objects); the rest go with the working directory.
    #[tokio::test]
    async fn a_run_keeps_at_most_max_kept_files() {
        use ace_sdk::tools::MAX_KEPT_FILES;
        let dirs = Dirs::new();
        let ran = run(
            &test_task(&dirs, &["keep-many"]),
            LONG,
            Some((&Keep::Tree, &dirs.kept())),
        )
        .await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let kept = ran.kept.expect("what it kept");
        assert_eq!(kept.len(), MAX_KEPT_FILES);
        assert_eq!(kept.keys().next().map(String::as_str), Some("many/000000"));
        assert!(!kept.contains_key(&format!("many/{MAX_KEPT_FILES:06}")));
        // the answer that names them all fits its frame
        let answer = ace_pool::tools::ToolAnswer::Ran {
            status: ran.status,
            stdout: dirs.kept().join("stdout"),
            stderr: dirs.kept().join("stderr"),
            outputs: kept,
        };
        let mut bytes = Vec::new();
        assert!(
            ace_pool::tools::write_frame(&mut bytes, &answer).is_err(),
            "past MAX_FRAME"
        );
        let json = serde_json::to_vec(&answer).unwrap();
        assert!(
            json.len() > ace_pool::tools::MAX_FRAME
                && json.len() < ace_pool::tools::MAX_ANSWER_FRAME
        );
        let mut framed = (json.len() as u32).to_be_bytes().to_vec();
        framed.extend(&json);
        let back: ace_pool::tools::ToolAnswer = ace_pool::tools::read_frame_up_to(
            &mut framed.as_slice(),
            ace_pool::tools::MAX_ANSWER_FRAME,
        )
        .unwrap();
        assert_eq!(back, answer);
    }

    /// The most threads a process named `name` had while `work` ran.
    async fn most_threads_of<T>(
        name: &str,
        work: impl std::future::Future<Output = T>,
    ) -> (T, usize) {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watcher = {
            let (stop, name) = (stop.clone(), name.to_owned());
            std::thread::spawn(move || {
                let mut most = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    for entry in fs::read_dir("/proc").unwrap().flatten() {
                        let status =
                            fs::read_to_string(entry.path().join("status")).unwrap_or_default();
                        if status.lines().next() == Some(&format!("Name:\t{name}")[..]) {
                            let threads = status
                                .lines()
                                .find_map(|l| l.strip_prefix("Threads:"))
                                .and_then(|n| n.trim().parse().ok())
                                .unwrap_or(0);
                            most = most.max(threads);
                        }
                    }
                }
                most
            })
        };
        let result = work.await;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        (result, watcher.join().unwrap())
    }

    /// tesseract and zbarimg start OpenMP threads (docs/modules.md, *External tools*), and run
    /// under the runner as they run outside it. The page is the sample with a QR code, which
    /// Ghostscript renders, contained too.
    #[tokio::test]
    async fn tesseract_and_zbarimg_run_their_threads_under_the_runner() {
        let dirs = Dirs::new();
        let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../samples/ace3/pdf/sample_pdf_with_qr_code.pdf");
        fs::copy(&sample, dirs.task().join("input.pdf")).unwrap();
        let input = dirs.task().join("input.pdf");
        let render = exec(
            &dirs,
            "gs",
            &[
                "-sDEVICE=pngalpha",
                "-o",
                "page-%d.png",
                "-r144",
                input.to_str().unwrap(),
            ],
            &["input.pdf"],
        );
        let ran = run(&render, LONG, Some((&Keep::All, &dirs.kept()))).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let pages: BTreeMap<String, PathBuf> = ran.kept.unwrap();
        assert!(pages.contains_key("page-1.png"), "{pages:?}");
        // the pages, where the next runs can read them
        let mut readable = Vec::new();
        for (name, path) in &pages {
            fs::rename(path, dirs.task().join(name)).unwrap();
            readable.push(name.clone());
        }
        let reads: Vec<&str> = readable.iter().map(String::as_str).collect();

        let mut codes = Vec::new();
        let mut zbar_threads = 0;
        for page in &readable {
            fs::create_dir_all(dirs.workdir()).unwrap();
            let path = dirs.task().join(page);
            let scan = exec(
                &dirs,
                "zbarimg",
                &["-q", "--raw", "--nodbus", path.to_str().unwrap()],
                &reads,
            );
            let (ran, threads) = most_threads_of("zbarimg", run(&scan, LONG, None)).await;
            zbar_threads = zbar_threads.max(threads);
            assert!(
                matches!(ran.status, ToolStatus::Exited(0 | 4)),
                "{:?}",
                ran.status
            );
            codes.push(stdout(&ran));
            // the same run outside the runner
            let plain = std::process::Command::new("zbarimg")
                .args(["-q", "--raw", "--nodbus", path.to_str().unwrap()])
                .output()
                .unwrap();
            assert_eq!(ran.stdout, plain.stdout);
        }
        assert!(codes.iter().any(|c| c.contains("http")), "{codes:?}");

        fs::create_dir_all(dirs.workdir()).unwrap();
        let page = dirs.task().join(&readable[0]);
        let ocr = exec(
            &dirs,
            "tesseract",
            &[page.to_str().unwrap(), "stdout", "--oem", "1", "--psm", "3"],
            &reads,
        );
        let (ran, tesseract_threads) = most_threads_of("tesseract", run(&ocr, LONG, None)).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let plain = std::process::Command::new("tesseract")
            .args([page.to_str().unwrap(), "stdout", "--oem", "1", "--psm", "3"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert_eq!(ran.stdout, plain.stdout);
        assert!(!ran.stdout.is_empty());
        println!("most threads: zbarimg {zbar_threads}, tesseract {tesseract_threads}");
        assert!(
            zbar_threads > 1 && tesseract_threads > 1,
            "zbarimg {zbar_threads}, tesseract {tesseract_threads}"
        );
    }

    /// ExifTool, Perl with the modules it loads for OOXML, OpenDocument and an AES-256 PDF, prints
    /// the same under the runner as plain, but for the copy's own times.
    #[tokio::test]
    async fn exiftool_reads_what_it_reads_plain() {
        let samples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples");
        for sample in [
            "ace3/office/doc.docx",
            "ace3/office/demo.odt",
            "ace3/pdf/ComplaintApril_424256637.pdf",
        ] {
            let dirs = Dirs::new();
            let name = Path::new(sample).file_name().unwrap().to_str().unwrap();
            fs::copy(samples.join(sample), dirs.workdir().join(name)).unwrap();
            let exiftool = exec(&dirs, "exiftool", &["-j", "-G", "-n", name], &[]);
            let ran = run(&exiftool, LONG, None).await;
            assert_eq!(ran.status, ToolStatus::Exited(0), "{sample}");
            let plain = std::process::Command::new("exiftool")
                .args(["-j", "-G", "-n", name])
                .current_dir(dirs.workdir())
                .output()
                .unwrap();
            let strip = |bytes: &[u8]| {
                let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                for key in [
                    "File:FileAccessDate",
                    "File:FileInodeChangeDate",
                    "File:FileModifyDate",
                ] {
                    value[0].as_object_mut().unwrap().remove(key);
                }
                value
            };
            assert_eq!(strip(&ran.stdout), strip(&plain.stdout), "{sample}");
        }
    }

    // ---- PLAN.md 7.5 batch 11: the executable tools ----

    fn samples() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples")
    }

    /// ace3's .NET sample, an Obfuscar-protected assembly, which ace3's tests keep hex-encoded as
    /// tools/ace3/dumps/fixtures/executables does, written into the task's directory.
    fn dotnet_sample(dirs: &Dirs) -> PathBuf {
        let hex = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tools/ace3/dumps/fixtures/executables/6346eea9dff4eac53113fc2ba3b8a497.hex",
        ))
        .unwrap();
        let digits: Vec<u8> = hex.bytes().filter(u8::is_ascii_hexdigit).collect();
        let bytes: Vec<u8> = digits
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let path = dirs.task().join("sample.exe");
        fs::write(&path, bytes).unwrap();
        path
    }

    /// The same program outside the runner, with the environment the runner gives it, in a fresh
    /// directory as its working directory.
    fn plain(tool: &str, args: &[&str]) -> (std::process::Output, tempfile::TempDir) {
        let spec = ace_sdk::tools::find(SANDBOX_TOOLS, tool).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut command = std::process::Command::new(spec.program);
        command
            .args(spec.args)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("HOME", dir.path())
            .env("TMPDIR", dir.path())
            .envs(spec.env.iter().copied())
            .current_dir(dir.path());
        (command.output().unwrap(), dir)
    }

    /// CFR on the JVM, 7.3's 29 threads, decompiles ace3's class to the same source under the
    /// runner as outside it.
    #[tokio::test]
    async fn cfr_runs_the_jvms_threads_under_the_runner() {
        let dirs = Dirs::new();
        let class = dirs.task().join("Sample.class");
        fs::copy(
            samples().join("ace3/executables/VxUGJsAplRNavewkjKujp.class"),
            &class,
        )
        .unwrap();
        let cfr = exec(&dirs, "cfr", &[class.to_str().unwrap()], &["Sample.class"]);
        let (ran, threads) = most_threads_of("java", run(&cfr, LONG, None)).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let (plain, _dir) = plain("cfr", &[class.to_str().unwrap()]);
        assert_eq!(ran.stdout, plain.stdout);
        assert!(stdout(&ran).contains("public final class VxUGJsAplRNavewkjKujp"));
        println!("most threads: java {threads}");
        assert!(threads > 1, "java {threads}");
    }

    /// upx tests and unpacks ace3's packed cmd.exe under the runner, and keeps the same file.
    #[tokio::test]
    async fn upx_tests_and_unpacks_under_the_runner() {
        let dirs = Dirs::new();
        let packed = dirs.task().join("cmd-upx.exe");
        fs::copy(samples().join("ace3/executables/cmd-upx.exe"), &packed).unwrap();
        let input = packed.to_str().unwrap();
        let test = exec(&dirs, "upx", &["-t", input], &["cmd-upx.exe"]);
        let ran = run(&test, LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        assert!(stdout(&ran).contains("[OK]"), "{}", stdout(&ran));
        let unpack = exec(
            &dirs,
            "upx",
            &["-d", "-ounpacked.exe", input],
            &["cmd-upx.exe"],
        );
        let keep = Keep::Named(vec!["unpacked.exe".into()]);
        let ran = run(&unpack, LONG, Some((&keep, &dirs.kept()))).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let kept = ran.kept.unwrap();
        let (plain, dir) = plain("upx", &["-d", "-ounpacked.exe", input]);
        assert!(plain.status.success());
        assert_eq!(ran.stdout, plain.stdout);
        assert_eq!(
            fs::read(&kept["unpacked.exe"]).unwrap(),
            fs::read(dir.path().join("unpacked.exe")).unwrap()
        );
    }

    /// 7.5 batch 12: dmg2img converts a DMG, and 7z, which loads 7z.so and 7zip-rar's codec by
    /// dlopen, lists the image and extracts a member of its HFS+ volume, under the runner as
    /// outside it; `7z i` names the codec it loaded, so the runner read the Codecs directory.
    #[tokio::test]
    async fn dmg2img_and_7z_convert_list_and_extract_under_the_runner() {
        let dirs = Dirs::new();
        let dmg = dirs.task().join("script_app.dmg");
        fs::copy(samples().join("ace4/macos/script_app.dmg"), &dmg).unwrap();
        let input = dmg.to_str().unwrap();
        let convert = exec(&dirs, "dmg2img", &[input, "image.img"], &["script_app.dmg"]);
        let keep = Keep::Named(vec!["image.img".into()]);
        let ran = run(&convert, LONG, Some((&keep, &dirs.kept()))).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let (plain_convert, dir) = plain("dmg2img", &[input, "image.img"]);
        assert_eq!(ran.stderr, plain_convert.stderr);
        let image = fs::read(&ran.kept.unwrap()["image.img"]).unwrap();
        assert_eq!(image, fs::read(dir.path().join("image.img")).unwrap());

        let dirs = Dirs::new();
        let img = dirs.task().join("script_app.img");
        fs::write(&img, &image).unwrap();
        let input = img.to_str().unwrap();
        let ran = run(
            &exec(&dirs, "7z", &["l", input], &["script_app.img"]),
            LONG,
            None,
        )
        .await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        assert_eq!(
            but_open_max(&ran.stdout),
            but_open_max(&plain("7z", &["l", input]).0.stdout)
        );
        assert!(stdout(&ran).contains("Installer/Payload.app/Contents/MacOS/Payload"));
        let member = "Installer/Payload.app/Contents/MacOS/Payload";
        let extract = exec(
            &dirs,
            "7z",
            &["x", "-o.", input, member],
            &["script_app.img"],
        );
        let ran = run(&extract, LONG, Some((&Keep::Tree, &dirs.kept()))).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let (plain_extract, dir) = plain("7z", &["x", "-o.", input, member]);
        assert!(plain_extract.status.success());
        assert_eq!(
            fs::read(&ran.kept.unwrap()[member]).unwrap(),
            fs::read(dir.path().join(member)).unwrap()
        );

        let dirs = Dirs::new();
        let ran = run(&exec(&dirs, "7z", &["i"], &[]), LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        assert_eq!(
            but_open_max(&ran.stdout),
            but_open_max(&plain("7z", &["i"]).0.stdout)
        );
        assert!(stdout(&ran).contains("/usr/lib/7zip/Codecs/Rar.so"));
    }

    /// 7z's output without the banner's `OPEN_MAX`, which is the runner's `RLIMIT_NOFILE` (1,024, as
    /// ace3's sandbox sets it) and the container's outside it.
    fn but_open_max(stdout: &[u8]) -> String {
        String::from_utf8_lossy(stdout)
            .lines()
            .filter(|line| !line.contains("OPEN_MAX:"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// unautoit, Go's 4 or 5 threads, lists and extracts ace3's AutoIt executable under the runner
    /// as outside it. Its threads are counted on ace3's larger script, which it takes long enough to
    /// decompile for the count to see them: the small one's runs end in milliseconds.
    #[tokio::test]
    async fn unautoit_lists_and_extracts_under_the_runner() {
        let dirs = Dirs::new();
        let exe = dirs.task().join("hello_autoit.exe");
        fs::copy(samples().join("ace3/executables/hello_autoit.exe"), &exe).unwrap();
        let input = exe.to_str().unwrap();
        let list = exec(&dirs, "unautoit", &["list", input], &["hello_autoit.exe"]);
        let ran = run(&list, LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let (plain_list, _dir) = plain("unautoit", &["list", input]);
        assert_eq!(ran.stdout, plain_list.stdout);
        let extract = exec(
            &dirs,
            "unautoit",
            &["extract-all", "--output-dir", "out", input],
            &["hello_autoit.exe"],
        );
        let ran = run(&extract, LONG, Some((&Keep::Tree, &dirs.kept()))).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let kept = ran.kept.unwrap();
        let (_, dir) = plain("unautoit", &["extract-all", "--output-dir", "out", input]);
        assert_eq!(
            fs::read(&kept["out/script_1.au3"]).unwrap(),
            fs::read(dir.path().join("out/script_1.au3")).unwrap()
        );
        let script = dirs.task().join("UGtZgHHT.au3");
        fs::copy(samples().join("ace3/executables/UGtZgHHT.au3"), &script).unwrap();
        let extract = exec(
            &dirs,
            "unautoit",
            &[
                "extract-all",
                "--output-dir",
                "big",
                script.to_str().unwrap(),
            ],
            &["UGtZgHHT.au3"],
        );
        let (ran, threads) = most_threads_of("unautoit", run(&extract, LONG, None)).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        println!("most threads: unautoit {threads}");
        assert!(threads > 1, "unautoit {threads}");
    }

    /// de4dot, self-contained .NET, detects and cleans ace3's Obfuscar sample under the runner, with
    /// .NET's threads, and writes the assembly it writes outside it.
    #[tokio::test]
    async fn de4dot_detects_and_cleans_under_the_runner() {
        let dirs = Dirs::new();
        let sample = dotnet_sample(&dirs);
        let input = sample.to_str().unwrap();
        let detect = exec(&dirs, "de4dot", &["-d", input], &["sample.exe"]);
        let (ran, threads) = most_threads_of("de4dot", run(&detect, LONG, None)).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        assert!(
            stdout(&ran).contains("Detected Obfuscar"),
            "{}",
            stdout(&ran)
        );
        let clean = exec(
            &dirs,
            "de4dot",
            &[input, "-o", "deobfuscated"],
            &["sample.exe"],
        );
        let keep = Keep::Named(vec!["deobfuscated".into()]);
        let ran = run(&clean, LONG, Some((&keep, &dirs.kept()))).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let kept = ran.kept.unwrap();
        let (plain, dir) = plain("de4dot", &[input, "-o", "deobfuscated"]);
        assert!(plain.status.success());
        assert_eq!(
            fs::read(&kept["deobfuscated"]).unwrap(),
            fs::read(dir.path().join("deobfuscated")).unwrap()
        );
        println!("most threads: de4dot {threads}");
        assert!(threads > 1, "de4dot {threads}");
    }

    /// ilspycmd, on the shared .NET runtime, writes the sample's IL under the runner as outside it.
    #[tokio::test]
    async fn ilspycmd_writes_il_under_the_runner() {
        let dirs = Dirs::new();
        let sample = dotnet_sample(&dirs);
        let input = sample.to_str().unwrap();
        let args = ["-il", "--disable-updatecheck", "-o", ".", input];
        let ilspy = exec(&dirs, "ilspycmd", &args, &["sample.exe"]);
        let keep = Keep::Named(vec!["sample.il".into()]);
        let (ran, threads) =
            most_threads_of("ilspycmd", run(&ilspy, LONG, Some((&keep, &dirs.kept())))).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let kept = ran.kept.unwrap();
        let (plain, dir) = plain("ilspycmd", &args);
        assert!(plain.status.success());
        let il = fs::read(&kept["sample.il"]).unwrap();
        assert_eq!(il, fs::read(dir.path().join("sample.il")).unwrap());
        assert!(il.len() > 1_000_000, "{} bytes", il.len());
        println!("most threads: ilspycmd {threads}");
        assert!(threads > 1, "ilspycmd {threads}");
    }

    // ---- PLAN.md 7.5 batch 13: tshark and capinfos ----

    /// tshark's field run as pcap_analyzer makes it, with ace3's key log and its object export.
    const TSHARK_FIELDS: &[&str] = &[
        "-n",
        "-r",
        "input.pcapng",
        "-T",
        "json",
        "-Y",
        "frame.number <= 50000 && (dns || tls.handshake || http.request || http.response)",
        "-e",
        "frame.number",
        "-e",
        "ip.src",
        "-e",
        "tcp.stream",
        "-e",
        "tls.handshake.type",
        "-e",
        "tls.handshake.extensions_server_name",
        "-e",
        "tls.handshake.ja4",
        "-e",
        "tls.handshake.random",
        "-e",
        "tls.handshake.certificate",
        "-e",
        "http.request.full_uri",
        "--export-objects",
        "http,objects/http",
        "-o",
        "tls.keylog_file:sslkeylog.txt",
    ];

    /// The capture and key log ace3's tests decrypt, in the run's working directory, where the
    /// module's runs read them.
    fn capture_in(dir: &Path) {
        for (from, to) in [
            ("ace3/pcap/http_tls.pcapng", "input.pcapng"),
            ("ace3/pcap/sslkeylog.txt", "sslkeylog.txt"),
        ] {
            fs::copy(samples().join(from), dir.join(to)).unwrap();
        }
    }

    /// tshark dissects, decrypts with a key log and exports objects with its threads under the
    /// runner as outside it: the same JSON, and the same objects, the payload of each TLS session
    /// among them. capinfos gives the same summary. Neither starts a process (7.3's strace).
    #[tokio::test]
    async fn tshark_and_capinfos_read_a_capture_under_the_runner() {
        let dirs = Dirs::new();
        capture_in(&dirs.workdir());
        let tshark = exec(&dirs, "tshark", TSHARK_FIELDS, &[]);
        let keep = Keep::Tree;
        let (ran, threads) =
            most_threads_of("tshark", run(&tshark, LONG, Some((&keep, &dirs.kept())))).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        // outside the runner, with the same environment
        let dir = tempfile::tempdir().unwrap();
        capture_in(dir.path());
        let plain_run = std::process::Command::new("/usr/bin/tshark")
            .args(TSHARK_FIELDS)
            .env_clear()
            .envs(tshark.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(plain_run.status.success());
        assert_eq!(ran.stdout, plain_run.stdout);
        let kept = ran.kept.unwrap();
        for name in [
            "objects/http/payload.txt",
            "objects/http/secret12.txt",
            "objects/http/secret13.txt",
        ] {
            assert_eq!(
                fs::read(&kept[name]).unwrap(),
                fs::read(dir.path().join(name)).unwrap(),
                "{name}"
            );
        }
        println!("most threads: tshark {threads}");
        assert!(threads > 1, "tshark {threads}");
        let dirs = Dirs::new();
        capture_in(&dirs.workdir());
        let args = ["-M", "-S", "input.pcapng"];
        let ran = run(&exec(&dirs, "capinfos", &args, &[]), LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let dir = tempfile::tempdir().unwrap();
        capture_in(dir.path());
        let plain_run = std::process::Command::new("/usr/bin/capinfos")
            .args(args)
            .env_clear()
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert_eq!(ran.stdout, plain_run.stdout);
        assert!(
            stdout(&ran).contains("Number of packets:   41"),
            "{}",
            stdout(&ran)
        );
    }

    /// `exec` under the runner as `nobody`, as a pool runs a tool as its task's user: tshark runs no
    /// Lua at all as root. The task's directories are opened to it first.
    async fn run_as_nobody(dirs: &Dirs, exec: &ToolExec) -> Ran {
        use std::os::unix::fs::PermissionsExt;
        fn open_up(path: &Path) {
            let mode = if path.is_dir() { 0o777 } else { 0o644 };
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            if path.is_dir() {
                for entry in fs::read_dir(path).unwrap().flatten() {
                    open_up(&entry.path());
                }
            }
        }
        open_up(dirs.task());
        let ran = execute_keeping(Path::new(TASK), &[], Some((65534, 65534)), exec, LONG, None)
            .await
            .expect("the tool starts");
        println!(
            "{:?} as nobody: {:?}\nstdout: {}\nstderr: {}\n",
            exec.argv,
            ran.status,
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        ran
    }

    /// tshark loads no Lua script and no personal configuration from its working directory, which
    /// the runner otherwise gives a tool as its home: one run can't leave one there for a later run
    /// to load, and nothing staged there is read as configuration. With the home the runner gives
    /// other tools, the same files are loaded and run, so it's the spec's `HOME` and
    /// `WIRESHARK_CONFIG_DIR` that keep them out.
    #[tokio::test]
    async fn tshark_reads_no_lua_or_configuration_from_a_home() {
        let plant = |dirs: &Dirs| {
            let workdir = dirs.workdir();
            capture_in(&workdir);
            fs::create_dir_all(workdir.join(".local/lib/wireshark/plugins")).unwrap();
            fs::write(
                workdir.join(".local/lib/wireshark/plugins/planted.lua"),
                "print(\"planted plugin ran\")\n",
            )
            .unwrap();
            fs::create_dir_all(workdir.join(".config/wireshark")).unwrap();
            fs::write(
                workdir.join(".config/wireshark/init.lua"),
                "print(\"planted init ran\")\n",
            )
            .unwrap();
        };
        let dirs = Dirs::new();
        plant(&dirs);
        let args = ["-n", "-r", "input.pcapng", "-c", "1"];
        let ran = run_as_nobody(&dirs, &exec(&dirs, "tshark", &args, &[])).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        let out = format!("{}{}", stdout(&ran), String::from_utf8_lossy(&ran.stderr));
        assert!(!out.contains("planted"), "{out}");
        assert!(!out.contains("Lua"), "{out}");
        // the control: the runner's usual home, the working directory
        let dirs = Dirs::new();
        plant(&dirs);
        let mut exec = exec(&dirs, "tshark", &args, &[]);
        let workdir = dirs.workdir().display().to_string();
        for (name, value) in &mut exec.env {
            if name == "HOME" {
                *value = workdir.clone();
            }
        }
        exec.env.retain(|(name, _)| name != "WIRESHARK_CONFIG_DIR");
        let ran = run_as_nobody(&dirs, &exec).await;
        let out = stdout(&ran);
        assert!(out.contains("planted plugin ran"), "{out}");
        assert!(out.contains("planted init ran"), "{out}");
    }

    /// tshark asked to capture, or to list interfaces, runs dumpcap or the extcap helpers, which the
    /// runner kills it for: a pcap module only reads a file, and nothing else is let through.
    #[tokio::test]
    async fn tshark_is_stopped_when_it_would_capture() {
        for args in [&["-n", "-i", "lo", "-c", "1"][..], &["-D"][..]] {
            let dirs = Dirs::new();
            let ran = run(&exec(&dirs, "tshark", args, &[]), LONG, None).await;
            assert!(
                matches!(
                    ran.status,
                    ToolStatus::Stopped(ToolStop::Program | ToolStop::Process)
                ),
                "{args:?}: {:?}",
                ran.status
            );
        }
    }

    /// The one read the .NET tools needed beyond 7.3's: OpenSSL. An assembly whose references carry
    /// public keys, as System.Reflection.Emit writes them, has de4dot (dnlib) hash each to its token,
    /// and .NET hashes with OpenSSL, which it loads by dlopen: `openat` of `libssl.so.3` and
    /// `libcrypto.so.3`, `O_RDONLY|O_CLOEXEC`. Without those two in de4dot's reads Landlock refuses
    /// them and the runtime aborts, `No usable version of libssl was found`; with them it detects.
    /// OpenSSL's `openssl.cnf`, which it also opens, stays unreadable, and it does without.
    #[tokio::test]
    async fn de4dot_reads_openssl_to_hash_a_public_key() {
        let dirs = Dirs::new();
        let sample = dirs.task().join("emitted.exe");
        fs::copy(
            samples().join("ace4/executables/emitted_methods.exe"),
            &sample,
        )
        .unwrap();
        let mut detect = exec(
            &dirs,
            "de4dot",
            &["-d", sample.to_str().unwrap()],
            &["emitted.exe"],
        );
        let ran = run(&detect, LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Exited(0));
        assert!(
            stdout(&ran).contains("Detected Unknown Obfuscator"),
            "{}",
            stdout(&ran)
        );
        let openssl = |p: &PathBuf| {
            let name = p.file_name().unwrap().to_string_lossy();
            name.starts_with("libssl.so") || name.starts_with("libcrypto.so")
        };
        // the spec's two, and libcrypto again as libssl's own need
        assert!(detect.reads.iter().filter(|p| openssl(p)).count() >= 2);
        detect.reads.retain(|p| !openssl(p));
        let ran = run(&detect, LONG, None).await;
        assert_eq!(ran.status, ToolStatus::Signaled(6));
        assert!(
            String::from_utf8_lossy(&ran.stderr).contains("No usable version of libssl was found")
        );
    }

    /// docs/measurements/sandbox-runner.md: what the runner adds to a tool's run, the test task doing
    /// nothing, contained through the runner and plain, 21 runs each.
    #[tokio::test]
    #[ignore = "a measurement, run by hand"]
    async fn the_runners_cost() {
        let dirs = Dirs::new();
        let exec = test_task(&dirs, &["nothing"]);
        let mut contained = Vec::new();
        let mut plain = Vec::new();
        for _ in 0..21 {
            let started = Instant::now();
            let ran = execute_keeping(Path::new(TASK), &[], None, &exec, LONG, None)
                .await
                .expect("runs");
            contained.push(started.elapsed());
            assert_eq!(ran.status, ToolStatus::Exited(0));
            let started = Instant::now();
            let status = std::process::Command::new(TASK)
                .args(["--uncontained", "nothing"])
                .output()
                .expect("runs")
                .status;
            plain.push(started.elapsed());
            assert!(status.success());
        }
        for (name, mut times) in [("contained", contained), ("plain", plain)] {
            times.sort();
            println!(
                "{name}: median {:?}, range {:?} to {:?}",
                times[10], times[0], times[20]
            );
        }
    }
}
