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
        FILE_SIZE_LIMIT, Keep, OPEN_FILES_LIMIT, SANDBOX_TOOLS, ToolStatus, ToolStop,
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
        argv.extend(args.iter().map(|a| a.to_string()));
        ToolExec {
            program: PathBuf::from(tool.spec.program),
            argv,
            env: vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LANG".into(), "C.UTF-8".into()),
                ("HOME".into(), dirs.workdir().display().to_string()),
                ("TMPDIR".into(), dirs.workdir().display().to_string()),
            ],
            workdir: dirs.workdir(),
            task_dir: dirs.task().to_owned(),
            task_reads: task_reads.iter().map(PathBuf::from).collect(),
            reads: tool.reads.clone(),
            executes: tool.executes.clone(),
            address_space_bytes: tool.spec.memory_bytes,
            cpu_seconds: 60,
            file_size_bytes: FILE_SIZE_LIMIT,
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
