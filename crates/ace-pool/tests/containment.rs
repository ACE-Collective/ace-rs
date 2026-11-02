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
