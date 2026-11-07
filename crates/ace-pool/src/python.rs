//! The Python pool's supervisor (PLAN.md 4.1, DESIGN.md's *Modules and pools*).
//!
//! The supervisor is this crate's Rust, and a worker is a Python process that only runs modules.
//! The supervisor leases tasks with the lease API's client, keeps their leases, downloads their
//! inputs, enforces their deadlines and sends their ends, exactly as a parser pool does, so none of
//! that is written twice and a worker stuck inside a C library can't stop a renewal. It keeps one
//! worker per concurrency slot, and each worker runs tasks one after another, because importing
//! these libraries is too slow to repeat per task.
//!
//! A worker starts by exec, never fork (#982): the pool's binary again, in its `python-worker`
//! mode, as a non-root user with an empty environment, so it holds no token at all. That process
//! contains itself (`contain_before_exec`) and execs Python, which keeps the PID. Python imports
//! only the modules it's told to, says it's ready, and then reads one request a line on stdin and
//! writes one `TaskEnd` a line on stdout (`python/worker.py`).
//!
//! # Recycling
//!
//! After each task, and while the worker sits idle, the supervisor reads `RssAnon` from
//! `/proc/<pid>/status`: the worker's anonymous resident memory, which is what a long-lived Python
//! heap grows. It's the private memory ace3's figures count, except for a few MB of a library's
//! file-backed private pages, and unlike `smaps_rollup` reading it takes no ptrace permission.
//! A worker at its task count or past its memory limit is replaced: it gets EOF on stdin and
//! exits, and a new worker starts at once, so the next task doesn't wait for the imports.
//!
//! A worker that dies, breaks the protocol, passes its deadline or is stopped for a cancelled task
//! is replaced too. It has no children, so killing its PID ends all of it (#981).
//!
//! # A hung worker
//!
//! At a task's deadline, and only there, the supervisor runs `py-spy dump` on the worker before the
//! kill, and the failed row keeps the stacks, or the reason there are none (`stacks`). A cancelled
//! task's worker, a lost lease's and one stopping at shutdown aren't hung, so they're killed with
//! no dump, and a cancellation that arrives during a dump ends it.
//!
//! One worker's tasks share a process until it's recycled, so a hostile file that takes over a
//! worker can affect that worker's later tasks, though it can't reach the token, the network or
//! another slot's files. `ACE4_PYTHON_MAX_TASKS=1` gives every task a new process.
//!
//! # Results
//!
//! The core checks a result's details against the schema, as it does a Rust module's (PLAN.md 4.2).
//! A Rust module can't get the result's own fields wrong, but a Python one can, and then the reply
//! doesn't read as a `TaskEnd` and never reaches the core. So the supervisor runs the same check on
//! such a reply, and the failed task's row names the field just as the core's would.

mod stacks;

use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ace_results::{AnalysisTypeInfo, ResultValidator};
use ace_sdk::LocalFileStore;
use ace_sdk::wire::{LeasedTask, TaskEnd};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::client::{ClientError, LeaseClient};
use crate::containment::{SandboxProfile, contain_before_exec};
use crate::modules::{Modules, PythonModule};
use crate::pool::{PoolStats, Runner, SHUTDOWN_GRACE, lease_loop};
use crate::run::{LeaseKeeper, TaskDir, fetch_input, finish};
use crate::supervisor::{EXIT_SETUP, open_to_task_user, signal_name};

use stacks::StackDumper;
pub use stacks::{DUMP_TIMEOUT, MAX_STACKS};

/// How long a worker may take to start: its imports, on a machine that may be busy.
const START_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a recycled worker has to exit after EOF, before it's killed.
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the supervisor waits before leasing again after a replacement didn't start.
const START_FAILED_PAUSE: Duration = Duration::from_secs(1);
/// How many of a worker's last stderr lines a failed task's error quotes.
const STDERR_LINES: usize = 5;

/// When a worker is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecycleLimits {
    /// The most tasks one worker runs.
    pub max_tasks: u64,
    /// The private memory, in bytes, at which a worker is replaced after its task.
    pub max_private_bytes: u64,
}

impl RecycleLimits {
    /// Why a worker that has run `tasks` tasks and holds `private_bytes` should go, if it should.
    fn reason(&self, tasks: u64, private_bytes: u64) -> Option<&'static str> {
        if private_bytes >= self.max_private_bytes {
            Some("memory limit")
        } else if tasks >= self.max_tasks {
            Some("task count")
        } else {
            None
        }
    }
}

/// How a supervisor starts its workers.
#[derive(Debug, Clone)]
pub struct PythonConfig {
    /// The binary a worker starts as, usually the pool's own, and the arguments that put it in its
    /// `python-worker` mode. The worker's spec follows them.
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The Python interpreter.
    pub python: PathBuf,
    /// The directory holding `worker.py` and the `ace4_python` package.
    pub source: PathBuf,
    /// The (uid, gid) workers run as. None runs them as the supervisor's own user, which keeps its
    /// capabilities, so only tests should leave it out.
    pub user: Option<(u32, u32)>,
    /// How many workers run, each one task at a time.
    pub concurrency: usize,
    pub limits: RecycleLimits,
    /// The py-spy binary, which a worker can't read or run, so outside its Landlock paths.
    pub py_spy: PathBuf,
    /// How long a hung worker's dump may take; see `DUMP_TIMEOUT`.
    pub dump_timeout: Duration,
}

/// What a worker's `python-worker` process contains itself with and then runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSpec {
    pub profile: SandboxProfile,
    pub exec_paths: Vec<PathBuf>,
    /// The interpreter and its arguments.
    pub command: Vec<String>,
}

/// The `python-worker` mode: contains this process and becomes Python. It returns only on a
/// failure, with the exit code that says so.
pub fn exec_worker(spec: &str) -> ExitCode {
    let setup_failed = |why: String| {
        eprintln!("setup failed: {why}");
        ExitCode::from(u8::try_from(EXIT_SETUP).unwrap_or(u8::MAX))
    };
    let spec: WorkerSpec = match serde_json::from_str(spec) {
        Ok(spec) => spec,
        Err(e) => return setup_failed(format!("the worker's spec doesn't read: {e}")),
    };
    allow_the_supervisors_children_to_read_this_process();
    if let Err(e) = contain_before_exec(&spec.profile, &spec.exec_paths) {
        return setup_failed(format!("containment: {e}"));
    }
    let Some((program, args)) = spec.command.split_first() else {
        return setup_failed("the worker's spec has no command".to_owned());
    };
    let error = std::process::Command::new(program).args(args).exec();
    setup_failed(format!("running {program}: {error}"))
}

/// Names the supervisor to Yama (`stacks`' module docs), so py-spy, its child, may read this process
/// at `ptrace_scope` 1. It lasts through the exec. Other workers are the supervisor's children too,
/// but Landlock still refuses them. A kernel without Yama answers EINVAL and has nothing to allow.
fn allow_the_supervisors_children_to_read_this_process() {
    // SAFETY: getppid and PR_SET_PTRACER take and return integers only
    let declared = unsafe {
        let supervisor = libc::c_ulong::try_from(libc::getppid()).unwrap_or_default();
        libc::prctl(libc::PR_SET_PTRACER, supervisor, 0_u64, 0_u64, 0_u64)
    };
    if declared != 0 {
        eprintln!(
            "PR_SET_PTRACER: {}, so py-spy may not read this worker",
            std::io::Error::last_os_error()
        );
    }
}

/// The worker's private memory in bytes: `RssAnon` in its `/proc/<pid>/status`.
pub fn private_bytes(pid: u32) -> std::io::Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("RssAnon:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|kb| kb.trim().parse::<u64>().ok())
        .map(|kb| kb * 1024)
        .ok_or_else(|| std::io::Error::other(format!("/proc/{pid}/status has no RssAnon line")))
}

/// What a worker says once its imports are done.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    ready: bool,
}

/// What the supervisor writes on a worker's stdin for one task.
#[derive(Debug, Serialize)]
struct WorkerRequest<'a> {
    task: &'a LeasedTask,
    /// The module's name, which is the task's unless the task is an instance's.
    module: &'static str,
    analysis_type: &'static str,
    schema_version: u32,
    settings: Option<&'a Value>,
    input: Option<&'a Path>,
    outputs: &'a Path,
}

/// A running worker, between tasks or on one.
struct Worker {
    child: Child,
    pid: u32,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
    tasks: u64,
}

impl Worker {
    /// Starts a worker and waits for its imports.
    async fn start(starter: &Starter) -> std::io::Result<Worker> {
        let config = &starter.config;
        let mut command = tokio::process::Command::new(&config.program);
        command
            .args(&config.args)
            .arg(&starter.spec)
            // the worker gets nothing from the supervisor's environment, its token included
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some((uid, gid)) = config.user {
            // std drops the supplementary groups when it sets the uid as root
            command.uid(uid).gid(gid);
        }
        let mut child = command.spawn()?;
        let pid = child
            .id()
            .ok_or_else(|| std::io::Error::other("the worker has no PID"))?;
        let (Some(stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            return Err(std::io::Error::other("the worker has no pipes"));
        };
        let stderr_tail: Arc<Mutex<VecDeque<String>>> = Arc::default();
        tokio::spawn(log_stderr(pid, stderr, stderr_tail.clone()));
        let mut worker = Worker {
            child,
            pid,
            stdin,
            stdout: BufReader::new(stdout),
            stderr_tail,
            tasks: 0,
        };
        let mut line = String::new();
        let read = tokio::time::timeout(START_TIMEOUT, worker.stdout.read_line(&mut line));
        let ready = match read.await {
            Ok(Ok(0)) => Err("it exited before it was ready".to_owned()),
            Ok(Ok(_)) => serde_json::from_str::<Ready>(&line)
                .map_err(|e| format!("it said {line:?}: {e}"))
                .and_then(|r| {
                    r.ready
                        .then_some(())
                        .ok_or_else(|| "it said it wasn't ready".to_owned())
                }),
            Ok(Err(e)) => Err(format!("reading from it: {e}")),
            Err(_) => Err(format!("it wasn't ready within {START_TIMEOUT:?}")),
        };
        match ready {
            Ok(()) => {
                tracing::info!(pid, "a Python worker is ready");
                Ok(worker)
            }
            Err(why) => {
                // its pipe closes before the last of its stderr is read
                let status = tokio::time::timeout(EXIT_TIMEOUT, worker.child.wait()).await;
                if status.is_err()
                    && let Err(e) = worker.child.kill().await
                {
                    tracing::warn!(pid, "killing a worker that didn't start: {e}");
                }
                Err(std::io::Error::other(format!(
                    "the Python worker didn't start, {why}: {}",
                    worker.stderr()
                )))
            }
        }
    }

    fn stderr(&self) -> String {
        lock(&self.stderr_tail)
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// Runs one task to its end and says whether the worker can take another.
    async fn run(
        &mut self,
        request: &WorkerRequest<'_>,
        output: AnalysisTypeInfo,
        cancel: &CancellationToken,
        deadline: Duration,
        dumper: &StackDumper,
    ) -> (TaskEnd, Option<&'static str>) {
        const BROKEN: Option<&str> = Some("it broke the protocol");
        let mut bytes = match serde_json::to_vec(request) {
            Ok(bytes) => bytes,
            Err(e) => {
                let error = format!("the task's request doesn't serialize: {e}");
                return (TaskEnd::Failed { error }, None);
            }
        };
        bytes.push(b'\n');
        self.tasks += 1;
        let mut line = String::new();
        let exchange = async {
            self.stdin.write_all(&bytes).await?;
            self.stdin.flush().await?;
            self.stdout.read_line(&mut line).await
        };
        let answered = tokio::select! {
            read = exchange => read,
            () = cancel.cancelled() => return (TaskEnd::Cancelled, Some("the task stopped")),
            () = tokio::time::sleep(deadline) => {
                tracing::error!(pid = self.pid, ?deadline, "a task ran past its deadline");
                let error = format!(
                    "the Python worker ran past the task's deadline of {}s and was killed",
                    deadline.as_secs_f64(),
                );
                let dump = tokio::select! {
                    dump = dumper.dump(self.pid) => dump,
                    () = cancel.cancelled() => {
                        return (TaskEnd::Cancelled, Some("the task stopped"));
                    }
                };
                let end = match dump {
                    Ok(stacks) => TaskEnd::Hung { error, stacks },
                    Err(why) => {
                        tracing::warn!(pid = self.pid, "no stacks from a hung worker: {why}");
                        let error = format!("{error}; no stack could be taken: {why}");
                        TaskEnd::Failed { error }
                    }
                };
                return (end, Some("it passed a deadline"));
            }
        };
        match answered {
            Ok(n) if n > 0 => match serde_json::from_str::<TaskEnd>(&line) {
                // only this supervisor's account of a worker it killed says this
                Ok(TaskEnd::Hung { .. }) => {
                    let error = "the Python worker said it had hung, which it can't know";
                    let error = error.to_owned();
                    (TaskEnd::Failed { error }, BROKEN)
                }
                Ok(end) => (end, None),
                Err(e) => match failed_fields(output, &line) {
                    // the module's result was wrong, and the worker is fine
                    Some(error) => (TaskEnd::Failed { error }, None),
                    None => {
                        let error = format!("the Python worker's reply doesn't read: {e}");
                        (TaskEnd::Failed { error }, BROKEN)
                    }
                },
            },
            // EOF or a broken pipe: it died
            _ => {
                let error = self.how_it_died().await;
                (TaskEnd::Failed { error }, Some("it died"))
            }
        }
    }

    /// What a failed task's error says about a worker whose pipes closed.
    async fn how_it_died(&mut self) -> String {
        let status = match tokio::time::timeout(EXIT_TIMEOUT, self.child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(e)) => return format!("the Python worker stopped answering: {e}"),
            Err(_) => return "the Python worker closed its pipes and kept running".to_owned(),
        };
        let how = match (status.code(), status.signal()) {
            (Some(code), _) => format!("exited {code}"),
            (None, Some(signal)) => format!("was killed by {}", signal_name(signal)),
            (None, None) => "stopped".to_owned(),
        };
        match self.stderr() {
            stderr if stderr.is_empty() => format!("the Python worker {how}"),
            stderr => format!("the Python worker {how}: {stderr}"),
        }
    }

    /// Lets the worker go: EOF on stdin, then a kill if it hasn't exited in time.
    fn retire(self) {
        let Worker {
            mut child,
            pid,
            stdin,
            ..
        } = self;
        drop(stdin);
        tokio::spawn(async move {
            match tokio::time::timeout(EXIT_TIMEOUT, child.wait()).await {
                Ok(Ok(status)) => tracing::debug!(pid, ?status, "a recycled worker exited"),
                Ok(Err(e)) => tracing::warn!(pid, "waiting for a recycled worker: {e}"),
                Err(_) => {
                    tracing::warn!(pid, "a recycled worker didn't exit; killing it");
                    if let Err(e) = child.kill().await {
                        tracing::warn!(pid, "killing a recycled worker: {e}");
                    }
                }
            }
        });
    }

    async fn kill(mut self) {
        if matches!(self.child.try_wait(), Ok(None))
            && let Err(e) = self.child.kill().await
        {
            tracing::warn!(pid = self.pid, "killing a worker: {e}");
        }
    }
}

/// What the result's schema says about a reply that didn't read as a `TaskEnd`, if it holds a
/// result that fails it.
fn failed_fields(output: AnalysisTypeInfo, reply: &str) -> Option<String> {
    let reply: Value = serde_json::from_str(reply).ok()?;
    let result = reply.get("result")?;
    let validator = ResultValidator::new(&output.schema()).ok()?;
    validator.validate(result).err().map(|e| e.to_string())
}

/// Logs a worker's stderr and keeps its last lines for a failed task's error.
async fn log_stderr(
    pid: u32,
    stderr: tokio::process::ChildStderr,
    tail: Arc<Mutex<VecDeque<String>>>,
) {
    let mut lines = BufReader::new(stderr).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                tracing::info!(pid, "python worker: {line}");
                let mut tail = lock(&tail);
                if tail.len() == STDERR_LINES {
                    tail.pop_front();
                }
                tail.push_back(line.chars().take(500).collect());
            }
            Ok(None) => return,
            Err(e) => {
                tracing::debug!(pid, "reading a worker's stderr: {e}");
                return;
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Everything starting a worker takes, cheap to share with the task that starts a replacement.
struct Starter {
    config: PythonConfig,
    /// The worker's spec as JSON. It allows the slot directory, so each slot has its own.
    spec: String,
}

/// A slot's worker: up and idle, or starting.
enum Held {
    Ready(Box<Worker>),
    Starting(JoinHandle<std::io::Result<Worker>>),
}

/// One concurrency slot: its directory, the only place its workers may write, and its worker,
/// which is out of the slot while it runs a task.
struct Slot {
    dir: tempfile::TempDir,
    starter: Arc<Starter>,
    worker: Option<Held>,
}

impl Slot {
    fn new(config: &PythonConfig, names: &[&str], address_space: u64) -> std::io::Result<Slot> {
        let dir = tempfile::Builder::new().prefix("ace4-python-").tempdir()?;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))?;
        let spec = worker_spec(config, names, dir.path(), address_space)?;
        let starter = Arc::new(Starter {
            config: config.clone(),
            spec: serde_json::to_string(&spec).map_err(std::io::Error::other)?,
        });
        let mut slot = Slot {
            dir,
            starter,
            worker: None,
        };
        slot.replace();
        Ok(slot)
    }

    /// The slot's worker, once it's up. On an error a new one is already starting.
    async fn take(&mut self) -> std::io::Result<Worker> {
        let taken = match self.worker.take() {
            Some(Held::Ready(worker)) => Ok(*worker),
            Some(Held::Starting(starting)) => starting
                .await
                .map_err(std::io::Error::other)
                .and_then(|started| started),
            None => Worker::start(&self.starter).await,
        };
        if taken.is_err() {
            self.replace();
        }
        taken
    }

    fn give_back(&mut self, worker: Worker) {
        self.worker = Some(Held::Ready(Box::new(worker)));
    }

    /// Starts a new worker for the slot, without waiting for it.
    fn replace(&mut self) {
        let starter = self.starter.clone();
        self.worker = Some(Held::Starting(tokio::spawn(async move {
            Worker::start(&starter).await
        })));
    }
}

/// What a worker may touch and what it runs.
fn worker_spec(
    config: &PythonConfig,
    names: &[&str],
    slot: &Path,
    address_space: u64,
) -> std::io::Result<WorkerSpec> {
    // Landlock looks at the file itself, past the symlinks a python3 usually is
    let interpreter = std::fs::canonicalize(&config.python)?;
    let worker = config.source.join("worker.py");
    let mut command = vec![
        config.python.display().to_string(),
        // ignore the environment and the user's site directory, add nothing to sys.path from the
        // current directory, and write no .pyc files
        "-I".to_owned(),
        "-B".to_owned(),
        worker.display().to_string(),
    ];
    command.extend(names.iter().map(|name| (*name).to_owned()));
    let profile = SandboxProfile {
        // the interpreter, its libraries and the worker's code, and the loader's cache
        read_paths: vec!["/usr".into(), config.source.clone()],
        write_paths: vec![slot.to_owned()],
        tcp_ports: Vec::new(),
        address_space_bytes: address_space,
        cpu_seconds: 0,
    }
    .allow_read_if_exists("/etc/ld.so.cache");
    Ok(WorkerSpec {
        profile,
        // the loader is under /usr/lib, wherever /lib points
        exec_paths: vec![interpreter, "/usr/lib".into()],
        command,
    })
}

/// The Python pool's supervisor.
pub struct PythonPool {
    client: LeaseClient,
    modules: Arc<Modules>,
    config: PythonConfig,
    lease_wait: Duration,
    grace: Duration,
}

impl PythonPool {
    pub fn new(client: LeaseClient, modules: Arc<Modules>, config: PythonConfig) -> PythonPool {
        PythonPool {
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

    /// Starts a worker per slot, waits for all of them, and then leases and runs tasks until
    /// `stop` fires. It leases nothing until a worker is up, so a broken image fails here rather
    /// than failing every task it can lease.
    pub async fn run(&self, stop: CancellationToken) -> std::io::Result<PoolStats> {
        let names = self.modules.python_names();
        let manifests = self.modules.manifests();
        let address_space = manifests
            .iter()
            .map(|m| m.resources.memory_mb)
            .max()
            .unwrap_or(ace_sdk::Resources::DEFAULT.memory_mb)
            .saturating_mul(1024 * 1024);
        let mut slots = Vec::new();
        for _ in 0..self.config.concurrency.max(1) {
            let mut slot = Slot::new(&self.config, &names, address_space)?;
            let worker = slot.take().await?;
            slot.give_back(worker);
            slots.push(slot);
        }
        tracing::info!(workers = slots.len(), modules = ?names, "the Python pool is leasing");
        let slots = Arc::new(Mutex::new(slots));
        let (client, modules, limits) = (
            self.client.clone(),
            self.modules.clone(),
            self.config.limits,
        );
        let run: Runner = Arc::new(move |task, shutdown| {
            let (client, modules, slots) = (client.clone(), modules.clone(), slots.clone());
            Box::pin(async move {
                let id = task.id;
                let slot = lock(&slots).pop();
                let Some(mut slot) = slot else {
                    tracing::error!(task = id, "no free worker slot; giving the task back");
                    return client.release(id).await.is_ok();
                };
                let ended = run_task(&client, &modules, limits, &mut slot, task, &shutdown).await;
                lock(&slots).push(slot);
                match ended {
                    Ok(()) => true,
                    Err(e) => {
                        tracing::error!(task = id, "the task's end wasn't sent: {e}");
                        false
                    }
                }
            })
        });
        Ok(lease_loop(
            &self.client,
            self.config.concurrency.max(1),
            self.lease_wait,
            self.grace,
            stop,
            run,
        )
        .await)
    }
}

/// Runs one leased task on the slot's worker, sends its end, and recycles the worker if it should
/// go.
async fn run_task(
    client: &LeaseClient,
    modules: &Modules,
    limits: RecycleLimits,
    slot: &mut Slot,
    task: LeasedTask,
    shutdown: &CancellationToken,
) -> Result<(), ClientError> {
    let Some(module) = modules.python(&task.module) else {
        let end = TaskEnd::Failed {
            error: format!("this pool doesn't run {}", task.module),
        };
        return client.end(task.id, &end).await;
    };
    let keeper = LeaseKeeper::start(client, &task, shutdown);
    let mut worker = match slot.take().await {
        Ok(worker) => worker,
        Err(e) => {
            // not the task's fault, so it doesn't count as an attempt
            tracing::error!(
                task = task.id,
                "no worker for the task; giving it back: {e}"
            );
            tokio::time::sleep(START_FAILED_PAUSE).await;
            drop(keeper);
            return client.release(task.id).await;
        }
    };
    let dir = TaskDir::new_in(slot.dir.path())?;
    let config = &slot.starter.config;
    let outcome = fetch_and_run(client, config, module, &mut worker, &task, &dir, &keeper).await;
    let (end, broken) = match outcome {
        Ok(outcome) => outcome,
        Err(e) => {
            slot.give_back(worker);
            return Err(e);
        }
    };
    settle(slot, worker, broken, limits).await;
    let outputs = LocalFileStore::new(dir.outputs())?;
    // the lease stays kept until the end lands: a result's uploads can outlast it
    let sent = finish(client, &task, &outputs, &end, shutdown).await;
    drop(keeper);
    sent
}

async fn fetch_and_run(
    client: &LeaseClient,
    config: &PythonConfig,
    module: &PythonModule,
    worker: &mut Worker,
    task: &LeasedTask,
    dir: &TaskDir,
    keeper: &LeaseKeeper,
) -> Result<(TaskEnd, Option<&'static str>), ClientError> {
    let input = fetch_input(client, task, dir).await?;
    open_to_task_user(dir, input.as_deref(), config.user)?;
    let dumper = StackDumper {
        program: config.py_spy.clone(),
        user: config.user,
        timeout: config.dump_timeout,
    };
    let manifest = module.manifest;
    let outputs = dir.outputs();
    let request = WorkerRequest {
        task,
        module: manifest.name,
        analysis_type: manifest.output.name,
        schema_version: manifest.output.version,
        settings: module.settings.as_ref(),
        input: input.as_deref(),
        outputs: &outputs,
    };
    Ok(worker
        .run(
            &request,
            manifest.output,
            keeper.token(),
            manifest.resources.timeout,
            &dumper,
        )
        .await)
}

/// Puts the slot right after a task: the worker back if it stays, or a replacement starting.
async fn settle(
    slot: &mut Slot,
    worker: Worker,
    broken: Option<&'static str>,
    limits: RecycleLimits,
) {
    let pid = worker.pid;
    if let Some(why) = broken {
        tracing::info!(pid, why, tasks = worker.tasks, "replacing a Python worker");
        worker.kill().await;
        slot.replace();
        return;
    }
    let private = match private_bytes(pid) {
        Ok(private) => private,
        Err(e) => {
            tracing::warn!(pid, "reading a worker's memory: {e}; replacing it");
            worker.kill().await;
            slot.replace();
            return;
        }
    };
    match limits.reason(worker.tasks, private) {
        None => slot.give_back(worker),
        Some(reason) => {
            tracing::info!(
                pid,
                reason,
                tasks = worker.tasks,
                private_mb = private / (1024 * 1024),
                "recycling a Python worker"
            );
            worker.retire();
            slot.replace();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: RecycleLimits = RecycleLimits {
        max_tasks: 3,
        max_private_bytes: 1000,
    };

    #[test]
    fn a_worker_goes_at_its_task_count_or_its_memory_limit() {
        assert_eq!(LIMITS.reason(2, 999), None);
        assert_eq!(LIMITS.reason(3, 999), Some("task count"));
        assert_eq!(LIMITS.reason(1, 1000), Some("memory limit"));
        // memory is the one worth knowing when both are true
        assert_eq!(LIMITS.reason(3, 1000), Some("memory limit"));
    }

    #[test]
    fn private_memory_is_read_from_proc_and_grows_with_the_heap() {
        let pid = std::process::id();
        let before = private_bytes(pid).expect("this process's memory");
        let held = vec![1u8; 64 * 1024 * 1024];
        std::hint::black_box(&held);
        let after = private_bytes(pid).expect("this process's memory");
        assert!(after >= before + 32 * 1024 * 1024, "{before} to {after}");
    }
}
