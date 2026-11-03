//! The task supervisor (PLAN.md 2.17): a parser pool runs each task in a process of its own.
//!
//! The supervisor leases tasks like any worker. For each one it downloads the input into the
//! task's directory and starts a task process by exec, never fork (#982): the pool's own
//! binary again, with the `task` mode, as a non-root user with no capabilities and an empty
//! environment. It writes the task on the process's stdin and reads how the task ended from its
//! stdout. The task process contains itself (`contain`) before the module touches its input,
//! so it runs one thread, can't start a thread or a process, reads only its input and writes
//! only its output directory.
//!
//! The task process's exit code says which side failed (#847): 0 and 20 put the task's end on
//! stdout (20 when the module failed), 10 is a setup failure before the module ran, 101 is a
//! panic, and a signal is a crash or a limit, such as SIGSYS for a blocked call or SIGXCPU for
//! the CPU-time limit. A task process still running at its module's deadline is killed and its
//! task fails; the task's row keeps its error and the hashes of its inputs (PLAN.md 2.19).

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ace_sdk::LocalFileStore;
use ace_sdk::wire::{LeasedTask, TaskEnd};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::client::{ClientError, LeaseClient};
use crate::containment::SandboxProfile;
use crate::modules::Modules;
use crate::pool::{PoolStats, Runner, SHUTDOWN_GRACE, lease_loop};
use crate::run::{LeaseKeeper, TaskDir, fetch_input, finish};

/// The task's end is on stdout.
pub const EXIT_DONE: i32 = 0;
/// The task process couldn't set up: no usable request, an unknown module, or containment
/// failed. The module never ran.
pub const EXIT_SETUP: i32 = 10;
/// The module failed; its `TaskEnd::Failed` is on stdout.
pub const EXIT_MODULE: i32 = 20;
/// Rust's exit code after a panic.
pub const EXIT_PANIC: i32 = 101;

/// How long the supervisor waits for a finished task process's pipes to close.
const PIPE_TIMEOUT: Duration = Duration::from_secs(5);

/// What the supervisor writes on a task process's stdin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRequest {
    pub task: LeasedTask,
    /// The input's bytes, for a file task.
    pub input: Option<PathBuf>,
    /// Where the module writes its files.
    pub outputs: PathBuf,
    /// What the task process may touch once it contains itself.
    pub profile: SandboxProfile,
}

/// How a supervisor starts task processes.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// The binary a task process runs, usually the pool's own.
    pub program: PathBuf,
    /// Its arguments, such as `task` and the pool's settings.
    pub args: Vec<String>,
    /// The (uid, gid) task processes run as. None runs them as the supervisor's own user,
    /// which keeps its capabilities, so only tests should leave it out.
    pub user: Option<(u32, u32)>,
    /// How many task processes run at once.
    pub concurrency: usize,
    /// Files and directories every task may read besides its input.
    pub read_paths: Vec<PathBuf>,
}

/// The uid and gid of a user, by name.
pub fn user_ids(name: &str) -> Option<(u32, u32)> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut entry: libc::passwd = unsafe_zeroed_passwd();
    let mut buffer = vec![0 as libc::c_char; 4096];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r writes `entry`, whose strings point into `buffer`; both outlive the
    // call, and only the integer ids are read from it after.
    let status = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    (status == 0 && !found.is_null()).then_some((entry.pw_uid, entry.pw_gid))
}

fn unsafe_zeroed_passwd() -> libc::passwd {
    // SAFETY: passwd is plain data, pointers and integers, for which all zeroes is valid.
    unsafe { std::mem::zeroed() }
}

/// A parser pool's supervisor.
pub struct Supervisor {
    client: LeaseClient,
    modules: Arc<Modules>,
    config: SupervisorConfig,
    lease_wait: Duration,
    grace: Duration,
}

impl Supervisor {
    pub fn new(client: LeaseClient, modules: Arc<Modules>, config: SupervisorConfig) -> Self {
        Supervisor {
            client,
            modules,
            config,
            lease_wait: Duration::from_secs(10),
            grace: SHUTDOWN_GRACE,
        }
    }

    pub fn lease_wait(mut self, wait: Duration) -> Self {
        self.lease_wait = wait;
        self
    }

    /// How long shutdown waits for task processes, which it kills, before it gives their
    /// leases back.
    pub fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Leases tasks and runs each in a task process, up to the concurrency limit, until `stop`
    /// fires; then kills the running ones and gives their tasks back (`lease_loop`).
    pub async fn run(&self, stop: CancellationToken) -> PoolStats {
        let (client, modules, config) = (
            self.client.clone(),
            self.modules.clone(),
            self.config.clone(),
        );
        let run: Runner = Arc::new(move |task, shutdown| {
            let (client, modules, config) = (client.clone(), modules.clone(), config.clone());
            Box::pin(async move {
                let id = task.id;
                match run_task_process(&client, &modules, &config, task, &shutdown).await {
                    Ok(_) => true,
                    Err(e) => {
                        tracing::error!(task = id, "the task's end wasn't sent: {e}");
                        false
                    }
                }
            })
        });
        lease_loop(
            &self.client,
            self.config.concurrency,
            self.lease_wait,
            self.grace,
            stop,
            run,
        )
        .await
    }
}

/// Runs one leased task in a task process and sends its end. `shutdown` kills the process, and
/// the task then goes back to the queue.
pub async fn run_task_process(
    client: &LeaseClient,
    modules: &Modules,
    config: &SupervisorConfig,
    task: LeasedTask,
    shutdown: &CancellationToken,
) -> Result<TaskEnd, ClientError> {
    let Some(parser) = modules.parser(&task.module) else {
        let end = TaskEnd::Failed {
            error: format!("this pool doesn't run {}", task.module),
        };
        client.end(task.id, &end).await?;
        return Ok(end);
    };
    let manifest = parser.manifest();
    let keeper = LeaseKeeper::start(client, &task, shutdown);
    let dir = TaskDir::new()?;
    let input = fetch_input(client, &task, &dir).await?;
    open_to_task_user(&dir, input.as_deref(), config.user)?;

    let mut profile = SandboxProfile::for_manifest(&manifest).allow_write(dir.outputs());
    if let Some(input) = &input {
        profile = profile.allow_read(input);
    }
    for path in &config.read_paths {
        profile = profile.allow_read(path);
    }
    let request = TaskRequest {
        task: task.clone(),
        input,
        outputs: dir.outputs(),
        profile,
    };
    let end = match run_process(config, &request, keeper.token(), manifest.resources.timeout).await
    {
        Ok(end) => end,
        Err(e) => TaskEnd::Failed {
            error: format!("the task process didn't run: {e}"),
        },
    };
    drop(keeper);
    let outputs = LocalFileStore::new(dir.outputs())?;
    finish(client, &task, &outputs, &end, shutdown).await?;
    Ok(end)
}

/// Lets the task's user read the task's directory and input and write its outputs.
fn open_to_task_user(
    dir: &TaskDir,
    input: Option<&std::path::Path>,
    user: Option<(u32, u32)>,
) -> std::io::Result<()> {
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))?;
    if let Some(input) = input {
        std::fs::set_permissions(input, std::fs::Permissions::from_mode(0o644))?;
    }
    if let Some((uid, gid)) = user {
        std::os::unix::fs::chown(dir.outputs(), Some(uid), Some(gid))?;
    }
    Ok(())
}

/// Starts the task process, hands it the request and reads how the task ended. Cancelling
/// `cancel` kills it, and so does running past `deadline` (PLAN.md 2.19), which fails the task;
/// the task's row keeps its input hashes for replay.
async fn run_process(
    config: &SupervisorConfig,
    request: &TaskRequest,
    cancel: &CancellationToken,
    deadline: Duration,
) -> std::io::Result<TaskEnd> {
    let mut command = tokio::process::Command::new(&config.program);
    command
        .args(&config.args)
        // the task gets nothing from the supervisor's environment, its token included
        .env_clear()
        .env("ACE4_LOG", std::env::var("ACE4_LOG").unwrap_or_default())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some((uid, gid)) = config.user {
        // std drops the supplementary groups when it sets the uid as root
        command.uid(uid).gid(gid);
    }
    let mut child = command.spawn()?;
    let (Some(mut stdin), Some(mut stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(std::io::Error::other("the task process has no pipes"));
    };
    let id = request.task.id;
    let bytes = serde_json::to_vec(request).map_err(std::io::Error::other)?;
    let writer = tokio::spawn(async move {
        stdin.write_all(&bytes).await?;
        stdin.shutdown().await
    });
    let reader = tokio::spawn(async move {
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).await.map(|_| out)
    });
    let errors = tokio::spawn(async move {
        let mut err = Vec::new();
        stderr.read_to_end(&mut err).await.map(|_| err)
    });
    // one thread and no children, so a kill ends all of it
    enum Ended {
        Exited(ExitStatus),
        Cancelled,
        PastDeadline,
    }
    let ended = tokio::select! {
        status = child.wait() => Ended::Exited(status?),
        () = cancel.cancelled() => {
            child.kill().await?;
            Ended::Cancelled
        }
        () = tokio::time::sleep(deadline) => {
            child.kill().await?;
            tracing::error!(task = id, ?deadline, "killed the task process at its deadline");
            Ended::PastDeadline
        }
    };
    // a task process that died early may never have read its request
    if let Ok(Ok(Err(e))) = tokio::time::timeout(PIPE_TIMEOUT, writer).await {
        tracing::debug!("writing the task's request: {e}");
    }
    // the process can't have children, so its pipes close when it dies and these end too;
    // the timeouts only make that bound explicit
    let stdout = tokio::time::timeout(PIPE_TIMEOUT, reader)
        .await
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)??;
    let stderr = tokio::time::timeout(PIPE_TIMEOUT, errors)
        .await
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)??;
    let stderr = String::from_utf8_lossy(&stderr);
    for line in stderr.lines() {
        tracing::info!(task = id, "task process: {line}");
    }
    Ok(match ended {
        Ended::Exited(status) => end_of(status, &stdout, &stderr),
        Ended::Cancelled => TaskEnd::Cancelled,
        Ended::PastDeadline => TaskEnd::Failed {
            error: format!(
                "the task process ran past its deadline of {} and was killed",
                seconds(deadline)
            ),
        },
    })
}

fn seconds(duration: Duration) -> String {
    format!("{}s", duration.as_secs_f64())
}

/// How a task ended, from its process's exit status and output.
pub fn end_of(status: ExitStatus, stdout: &[u8], stderr: &str) -> TaskEnd {
    let tail = || last_lines(stderr, 5);
    match status.code() {
        Some(EXIT_DONE | EXIT_MODULE) => {
            serde_json::from_slice(stdout).unwrap_or_else(|e| TaskEnd::Failed {
                error: format!("the task process's reply doesn't read ({e}): {}", tail()),
            })
        }
        Some(EXIT_SETUP) => TaskEnd::Failed {
            error: format!("the task process couldn't set up: {}", tail()),
        },
        Some(EXIT_PANIC) => TaskEnd::Failed {
            error: format!("the module panicked: {}", panic_message(stderr)),
        },
        Some(code) => TaskEnd::Failed {
            error: format!("the task process exited {code}: {}", tail()),
        },
        None => {
            let signal = status.signal().unwrap_or_default();
            TaskEnd::Failed {
                error: format!(
                    "the task process was killed by {}: {}",
                    signal_name(signal),
                    tail()
                ),
            }
        }
    }
}

/// The message of the panic a task process printed: the line after `panicked at`.
fn panic_message(stderr: &str) -> String {
    let mut lines = stderr.lines();
    while let Some(line) = lines.next() {
        if line.contains("panicked at") {
            return lines.next().unwrap_or("").trim().to_owned();
        }
    }
    last_lines(stderr, 3)
}

fn last_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    let tail = lines[start..].join(" | ");
    tail.chars().take(2000).collect()
}

pub fn signal_name(signal: i32) -> String {
    match signal {
        libc::SIGKILL => "SIGKILL".to_owned(),
        libc::SIGSYS => "SIGSYS (a blocked system call)".to_owned(),
        libc::SIGXCPU => "SIGXCPU (the CPU-time limit)".to_owned(),
        libc::SIGABRT => "SIGABRT".to_owned(),
        libc::SIGSEGV => "SIGSEGV".to_owned(),
        other => format!("signal {other}"),
    }
}
