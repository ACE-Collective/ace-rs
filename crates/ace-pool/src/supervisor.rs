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
//! The supervisor holds every module of its pool, built when the pool started, which is where a
//! setting that doesn't load or a module that doesn't build stops the pool (PLAN.md 2.23). A task
//! process builds one: the request names the task's module and carries the settings block the
//! supervisor built it from, so the process reads no overlay and builds no other module
//! (`crate::task_process`).
//!
//! A task whose module runs tools (PLAN.md 7.3) gets a Unix socket as its descriptor 3, on which
//! the supervisor runs them for it in the sandbox runner (`crate::tools`), and two more
//! directories: `scratch`, which it may write, for the files it hands a tool, and `results`, which
//! it may read, where each run's output lands.
//!
//! The supervisor reaps each task process itself (`crate::reap`), and the task's end carries the
//! user and system CPU of the process and of the tools it had run (PLAN.md 3.6), with the time of
//! its module's `analyze`, which the process wrote with its end.
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
use crate::commands::{CommandConfig, run_commands};
use crate::containment::SandboxProfile;
use crate::modules::{Modules, ModulesHandle, TimedEnd};
use crate::pool::{PoolStats, Runner, SHUTDOWN_GRACE, lease_loop};
use crate::reap::{CpuTally, OwnedChild};
use crate::run::{
    LeaseKeeper, TaskDir, fetch_email_parts, fetch_input, fetch_scan_output, fetch_tree_files,
    finish,
};
use crate::tools::{ToolDirs, ToolHost, ToolTable};

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
    /// The module the task's component is made of: its own name, where `task.module` is the
    /// component's, which is an instance's name for a named instance. The task process builds
    /// this module and no other of its pool.
    pub module: String,
    /// The component's settings block, as the supervisor read it from the site overlay and
    /// checked it when the pool started. None runs on the module's defaults.
    #[serde(default)]
    pub settings: Option<serde_json::Value>,
    /// The input's bytes, for a file task.
    pub input: Option<PathBuf>,
    /// The body parts of the email that carried the task's file, for a module that reads it.
    #[serde(default)]
    pub email_parts: Vec<ace_sdk::EmailBodyPart>,
    /// The directory of the tree's files the module reads, for a module that reads them.
    #[serde(default)]
    pub tree_files: Option<PathBuf>,
    /// Where the module writes its files.
    pub outputs: PathBuf,
    /// What the task process may touch once it contains itself.
    pub profile: SandboxProfile,
    /// For a module that runs tools: its scratch directory. The supervisor serves its runs on
    /// `TOOL_FD`.
    #[serde(default)]
    pub tools: Option<PathBuf>,
    /// The output archive of the task's latest scan (PLAN.md 7.7).
    #[serde(default)]
    pub scan_output: Option<PathBuf>,
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
    /// The tools the pool's image carries, resolved (PLAN.md 7.3). A parser pool without tools
    /// never starts the `tool` mode.
    pub tools: Arc<ToolTable>,
    /// The arguments of the binary's `tool` mode, before `tool` itself.
    pub tool_args: Vec<String>,
    /// What each cacheable module's results depend on in this image, read when the pool started
    /// (`crate::cache`), sent with each of its results.
    pub cache_probes: Arc<crate::cache::Probes>,
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
    modules: ModulesHandle,
    config: SupervisorConfig,
    commands: Option<CommandConfig>,
    lease_wait: Duration,
    grace: Duration,
}

impl Supervisor {
    pub fn new(client: LeaseClient, modules: ModulesHandle, config: SupervisorConfig) -> Self {
        Supervisor {
            client,
            modules,
            config,
            commands: None,
            lease_wait: Duration::from_secs(10),
            grace: SHUTDOWN_GRACE,
        }
    }

    /// Also leases GUI commands and runs each in a contained process (`crate::commands`, PLAN.md 5.12).
    pub fn with_commands(mut self, commands: CommandConfig) -> Self {
        self.commands = Some(commands);
        self
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
    /// fires; then kills the running ones and gives their tasks back (`lease_loop`). With commands, it
    /// leases and runs those beside the tasks, and ends the running ones as abandoned at the stop.
    pub async fn run(&self, stop: CancellationToken) -> PoolStats {
        let commands = self.commands.clone().map(|config| {
            let (client, stop, wait) = (self.client.clone(), stop.clone(), self.lease_wait);
            tokio::spawn(async move { run_commands(&client, &config, wait, stop).await })
        });
        let stats = self.run_tasks(stop).await;
        if let Some(commands) = commands {
            match commands.await {
                Ok(ran) => tracing::info!(commands = ran, "stopped running commands"),
                Err(e) => tracing::error!("the command loop failed: {e}"),
            }
        }
        stats
    }

    async fn run_tasks(&self, stop: CancellationToken) -> PoolStats {
        let (client, modules, config) = (
            self.client.clone(),
            self.modules.clone(),
            self.config.clone(),
        );
        let run: Runner = Arc::new(move |task, shutdown| {
            // the modules as they are when the task starts
            let (client, modules, config) = (client.clone(), modules.now(), config.clone());
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
    let email_parts = fetch_email_parts(client, &task, dir.path()).await?;
    let tree_files = fetch_tree_files(client, &task, dir.path()).await?;
    let scan_output = fetch_scan_output(client, &task, dir.path()).await?;

    let mut profile = SandboxProfile::for_manifest(&manifest).allow_write(dir.outputs());
    let tool_dirs = if manifest.tools.is_empty() {
        None
    } else {
        let dirs = ToolDirs::create(dir.path(), config.user)?;
        profile = profile.allow_write(&dirs.scratch).allow_read(&dirs.results);
        Some(dirs)
    };
    if let Some(input) = &input {
        profile = profile.allow_read(input);
    }
    for part in &email_parts {
        profile = profile.allow_read(&part.path);
    }
    if let Some(files) = &tree_files {
        profile = profile.allow_read(files);
    }
    if let Some(output) = &scan_output {
        profile = profile.allow_read(output);
    }
    for path in &config.read_paths {
        profile = profile.allow_read(path);
    }
    let request = TaskRequest {
        task: task.clone(),
        module: manifest.name.to_owned(),
        settings: parser.settings().cloned(),
        input,
        email_parts,
        tree_files,
        outputs: dir.outputs(),
        profile,
        tools: tool_dirs.as_ref().map(|dirs| dirs.scratch.clone()),
        scan_output,
    };
    let deadline = manifest.resources.timeout;
    let tool_cpu = CpuTally::default();
    let host = match tool_dirs {
        Some(dirs) => {
            let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
            ours.set_nonblocking(true)?;
            let host = ToolHost {
                table: config.tools.clone(),
                declared: manifest.tools,
                dirs,
                user: config.user,
                program: config.program.clone(),
                args: config.tool_args.clone(),
                deadline: std::time::Instant::now() + deadline,
                cpu: tool_cpu.clone(),
            };
            let socket = tokio::net::UnixStream::from_std(ours)?;
            let serving = tokio::spawn(async move { host.serve(socket).await });
            Some((serving, theirs))
        }
        None => None,
    };
    let (serving, socket) = match host {
        Some((serving, socket)) => (Some(serving), Some(socket)),
        None => (None, None),
    };
    let ran = run_process(config, &request, keeper.token(), deadline, socket).await;
    if let Some(serving) = serving {
        // the task process is gone, so its socket is closed; a run still going is killed, and
        // the abort has dropped it once the await returns, so the tally knows it was cut off
        serving.abort();
        if let Err(e) = serving.await
            && !e.is_cancelled()
        {
            tracing::warn!("serving the task's tools: {e}");
        }
    }
    let mut timed = match ran {
        Ok(Finished { mut end, cpu, wall }) => {
            // the tools' runs are over: the task process is gone, and a run still going was
            // dropped with the serving above, which left the tools' CPU unknown
            end.cost.cpu_seconds = task_cpu(&task, cpu, tool_cpu.total());
            end.cost.analyze_seconds = analyze_within(&task, end.cost.analyze_seconds, wall);
            end
        }
        Err(e) => TimedEnd::untimed(TaskEnd::Failed {
            error: format!("the task process didn't run: {e}"),
        }),
    };
    crate::cache::attach(&mut timed.end, &task.module, &config.cache_probes);
    let outputs = LocalFileStore::new(dir.outputs())?;
    // the lease stays kept until the end lands: a result's uploads can outlast it
    finish(client, &task, &outputs, &timed, shutdown).await?;
    drop(keeper);
    Ok(timed.end)
}

/// The task's CPU in seconds: its process's and its tools', or None when either couldn't be read,
/// which is logged with the task's identifiers, since the end then goes without it.
pub fn task_cpu(
    task: &LeasedTask,
    process: std::io::Result<Duration>,
    tools: Result<Duration, String>,
) -> Option<f64> {
    let why = match (process, tools) {
        (Ok(process), Ok(tools)) => return Some((process + tools).as_secs_f64()),
        (Err(e), _) => format!("its process's rusage: {e}"),
        (_, Err(e)) => format!("a tool's rusage: {e}"),
    };
    tracing::warn!(
        task = task.id,
        root = %task.root,
        module = %task.module,
        observable = %task.observable.value,
        "the task's CPU couldn't be read, so its end goes without it: {why}"
    );
    None
}

/// The `analyze` time the task process wrote, if it is no more than the process's own wall time,
/// which this measured. The process may be a hostile file's, and a time it couldn't have taken is
/// dropped, logged with the task's identifiers.
pub fn analyze_within(task: &LeasedTask, analyze: Option<f64>, wall: Duration) -> Option<f64> {
    let analyze = analyze?;
    if analyze >= 0.0 && analyze <= wall.as_secs_f64() {
        return Some(analyze);
    }
    tracing::warn!(
        task = task.id,
        root = %task.root,
        module = %task.module,
        observable = %task.observable.value,
        analyze_seconds = analyze,
        wall_seconds = wall.as_secs_f64(),
        "the task process's analyze time is more than it ran for, so its end goes without it"
    );
    None
}

/// Lets the task's user read the task's directory and input and write its outputs.
pub(crate) fn open_to_task_user(
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

/// How a task process ended: the task's end, with its `analyze` time when the process wrote one,
/// the process's CPU, or why it couldn't be read, and how long it ran, from its start to its reap.
struct Finished {
    end: TimedEnd,
    cpu: std::io::Result<Duration>,
    wall: Duration,
}

/// Starts the task process, hands it the request and reads how the task ended. Cancelling
/// `cancel` kills it, and so does running past `deadline` (PLAN.md 2.19), which fails the task;
/// the task's row keeps its input hashes for replay. The process is reaped here, killed or not,
/// for its CPU.
async fn run_process(
    config: &SupervisorConfig,
    request: &TaskRequest,
    cancel: &CancellationToken,
    deadline: Duration,
    tools: Option<std::os::unix::net::UnixStream>,
) -> std::io::Result<Finished> {
    // std's, which this reaps itself (`crate::reap`): tokio's would reap it without its rusage
    let mut command = std::process::Command::new(&config.program);
    command
        .args(&config.args)
        // the task gets nothing from the supervisor's environment, its token included
        .env_clear()
        .env(
            "ACE_RS_LOG",
            std::env::var("ACE_RS_LOG").unwrap_or_default(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some((uid, gid)) = config.user {
        // std drops the supplementary groups when it sets the uid as root
        std::os::unix::process::CommandExt::uid(&mut command, uid);
        std::os::unix::process::CommandExt::gid(&mut command, gid);
    }
    if let Some(socket) = &tools {
        // only this task process gets the socket
        crate::tools::pass_as_tool_fd(&mut command, socket);
    }
    let started = std::time::Instant::now();
    let mut spawned = command.spawn()?;
    // killed and reaped if this returns early or is dropped, as tokio's kill_on_drop did
    let mut child = OwnedChild::new(&spawned)?;
    drop(tools);
    let (Some(stdin), Some(stdout), Some(stderr)) = (
        spawned.stdin.take(),
        spawned.stdout.take(),
        spawned.stderr.take(),
    ) else {
        return Err(std::io::Error::other("the task process has no pipes"));
    };
    let mut stdin = tokio::process::ChildStdin::from_std(stdin)?;
    let mut stdout = tokio::process::ChildStdout::from_std(stdout)?;
    let mut stderr = tokio::process::ChildStderr::from_std(stderr)?;
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
    // a wait is cancel-safe (`OwnedChild::wait`): one the kill cut short starts again below, and
    // the killed process ends, so it is bounded
    let (ended, reaped) = tokio::select! {
        reaped = child.wait() => {
            let reaped = reaped?;
            (Ended::Exited(reaped.status), reaped)
        }
        () = cancel.cancelled() => {
            child.kill()?;
            (Ended::Cancelled, child.wait().await?)
        }
        () = tokio::time::sleep(deadline) => {
            child.kill()?;
            tracing::error!(task = id, ?deadline, "killed the task process at its deadline");
            (Ended::PastDeadline, child.wait().await?)
        }
    };
    let wall = started.elapsed();
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
    let end = match ended {
        Ended::Exited(status) => end_of(status, &stdout, &stderr),
        Ended::Cancelled => TimedEnd::untimed(TaskEnd::Cancelled),
        Ended::PastDeadline => TimedEnd::untimed(TaskEnd::Failed {
            error: format!(
                "the task process ran past its deadline of {} and was killed",
                seconds(deadline)
            ),
        }),
    };
    Ok(Finished {
        end,
        cpu: reaped.cpu,
        wall,
    })
}

fn seconds(duration: Duration) -> String {
    format!("{}s", duration.as_secs_f64())
}

/// How a task ended, from its process's exit status and output: the end the process wrote, with
/// its `analyze` time, or a failure with no time, since the module didn't answer.
pub fn end_of(status: ExitStatus, stdout: &[u8], stderr: &str) -> TimedEnd {
    let tail = || last_lines(stderr, 5);
    let failed = |error: String| TimedEnd::untimed(TaskEnd::Failed { error });
    match status.code() {
        Some(EXIT_DONE | EXIT_MODULE) => match serde_json::from_slice(stdout) {
            Ok(end) => end,
            Err(e) => failed(format!(
                "the task process's reply doesn't read ({e}): {}",
                tail()
            )),
        },
        Some(EXIT_SETUP) => failed(format!("the task process couldn't set up: {}", tail())),
        Some(EXIT_PANIC) => failed(format!("the module panicked: {}", panic_message(stderr))),
        Some(code) => failed(format!("the task process exited {code}: {}", tail())),
        None => {
            let signal = status.signal().unwrap_or_default();
            failed(format!(
                "the task process was killed by {}: {}",
                signal_name(signal),
                tail()
            ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use ace_results::ObservableKind;
    use ace_sdk::wire::TaskObservable;
    use std::sync::Mutex;

    fn task() -> LeasedTask {
        LeasedTask {
            id: 41,
            root: uuid::Uuid::from_u128(7),
            module: "pdf_analyzer".to_owned(),
            attempts: 1,
            lease_expires_at: chrono::Utc::now(),
            lease_seconds: 1.0,
            observable: TaskObservable {
                kind: ObservableKind::File,
                value: "invoice.pdf".to_owned(),
                time: None,
                directives: Vec::new(),
                file: None,
                redirection: None,
                relationships: Vec::new(),
            },
            delayed: None,
            input_hashes: Vec::new(),
            carrying_email: None,
            emails_pending: false,
            yara_rules_below: Vec::new(),
            lists: Vec::new(),
            dependency_results: Default::default(),
            dependency_errors: Default::default(),
            observables_below: Vec::new(),
            added_by: Vec::new(),
            related_tags: Vec::new(),
            tree: None,
            scan: None,
            gate: Default::default(),
            at_root: false,
            event_time: None,
        }
    }

    /// What `f` logs, as text.
    fn logged(f: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("the buffer").extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = buffer.0.lock().expect("the buffer").clone();
        String::from_utf8(bytes).expect("UTF-8")
    }

    /// PLAN.md 3.6: a task's CPU is its process's and its tools', and when either couldn't be read
    /// the end goes without it, null rather than a number that leaves part out, and the log says
    /// which task and why.
    #[test]
    fn a_tasks_cpu_is_its_processs_and_its_tools_or_none_logged_when_one_isnt_read() {
        let task = task();
        let mut cpu = None;
        let quiet = logged(|| {
            cpu = task_cpu(
                &task,
                Ok(Duration::from_millis(1500)),
                Ok(Duration::from_millis(500)),
            );
        });
        assert_eq!(cpu, Some(2.0));
        assert!(quiet.is_empty(), "{quiet}");

        let process = std::io::Error::from_raw_os_error(libc::ECHILD);
        let log = logged(|| cpu = task_cpu(&task, Err(process), Ok(Duration::ZERO)));
        assert_eq!(cpu, None);
        for wanted in [
            "WARN",
            "task=41",
            "root=00000000-0000-0000-0000-000000000007",
            "module=pdf_analyzer",
            "observable=invoice.pdf",
            "its process's rusage",
        ] {
            assert!(log.contains(wanted), "{wanted} in {log}");
        }

        let log = logged(|| {
            cpu = task_cpu(
                &task,
                Ok(Duration::from_secs(1)),
                Err("No child processes (os error 10)".to_owned()),
            );
        });
        assert_eq!(cpu, None, "a tool's CPU unread leaves the sum unknown");
        assert!(log.contains("a tool's rusage"), "{log}");
    }

    /// A task process may be a hostile file's, so the `analyze` time it wrote is kept only when it
    /// fits in the time the process ran, and one that doesn't is dropped with a WARN naming the task.
    #[test]
    fn an_analyze_time_longer_than_the_process_ran_is_dropped_and_logged() {
        let task = task();
        let wall = Duration::from_secs(2);
        let mut kept = None;
        let quiet = logged(|| kept = analyze_within(&task, Some(1.5), wall));
        assert_eq!(kept, Some(1.5));
        assert!(quiet.is_empty(), "{quiet}");
        assert_eq!(analyze_within(&task, None, wall), None);
        for sent in [2.5, f64::MAX, f64::NAN, -1.0] {
            let log = logged(|| kept = analyze_within(&task, Some(sent), wall));
            assert_eq!(kept, None, "{sent}");
            for wanted in [
                "WARN",
                "task=41",
                "root=00000000-0000-0000-0000-000000000007",
                "module=pdf_analyzer",
                "observable=invoice.pdf",
                "wall_seconds=2",
            ] {
                assert!(log.contains(wanted), "{sent}: {wanted} in {log}");
            }
        }
    }

    /// A task process that wrote its end has its `analyze` time; one that died before has none.
    #[test]
    fn a_processs_end_keeps_the_analyze_time_it_wrote() {
        let written = TimedEnd {
            cost: ace_sdk::wire::RunCost {
                analyze_seconds: Some(0.75),
                cpu_seconds: None,
            },
            end: TaskEnd::Cancelled,
        };
        let stdout = serde_json::to_vec(&written).expect("serializes");
        assert_eq!(end_of(ExitStatus::from_raw(0), &stdout, ""), written);
        let panicked = end_of(ExitStatus::from_raw(EXIT_PANIC << 8), b"", "");
        assert_eq!(panicked.cost, ace_sdk::wire::RunCost::default());
        assert!(
            matches!(panicked.end, TaskEnd::Failed { .. }),
            "{panicked:?}"
        );
    }
}
