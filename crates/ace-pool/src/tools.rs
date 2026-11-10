//! The sandbox runner (PLAN.md 7.3, 7.5 batch 10; docs/modules.md's *External tools*): a parser's
//! contained task process asks its supervisor to run a program, and the supervisor runs it as a
//! contained process of its own.
//!
//! # Who does what
//!
//! A module declares its tools by name (`Module::TOOLS`) and runs one with `TaskContext::run_tool`.
//! The pool knows its image's tools (`ace_sdk::tools::ToolSpec`), and resolves each at start-up to
//! absolute paths: the program, its interpreter if it's a script, the dynamic loader, the libraries
//! they need by `DT_NEEDED` (`libraries`), and the data each reads (`ToolTable::resolve`). A task can
//! name only a tool, never a path to run.
//!
//! The supervisor starts a task process whose module declares tools with one end of a Unix socket
//! as its descriptor 3 (`TOOL_FD`), opened before the task process contains itself, and serves its
//! requests (`ToolHost::serve`). For each, it checks the tool is one the module declares and the
//! pool has, that every file the request reads is the task's own (its input, the email body and
//! tree files it was given, its outputs, its scratch directory and what earlier runs kept), that the
//! variables it sets are ones the tool allows, and that the task hasn't run `MAX_RUNS` tools. It
//! makes an empty working directory, owned by the task's user, and execs the pool's binary in its
//! `tool` mode as that user, never forking it from itself (#982). That process reads what to run
//! (`ToolExec`) on stdin, opens every path it may touch, contains itself (`contain_tool`), hands the
//! tool filter's listener to the supervisor over its own descriptor 3, and execs the tool. The
//! supervisor lets that first exec through the listener and kills the tool at any other, reads its
//! stdout and stderr up to `MAX_OUTPUT_BYTES` each, kills it at its timeout or past that output,
//! and when it has ended moves what it kept into the task's results directory and answers.
//!
//! # The protocol on descriptor 3
//!
//! Each message is a frame: a 4-byte big-endian length, at most `MAX_FRAME`, then that many bytes of
//! JSON. The task process writes a request, an `ace_sdk::tools::ToolRun`:
//!
//! ```text
//! {"tool": "pdftotext", "args": ["/tmp/ace4-task-x/input", "output.txt"],
//!  "reads": ["/tmp/ace4-task-x/input"], "keep": {"named": ["output.txt"]}, "env": [],
//!  "timeout": {"secs": 5, "nanos": 0}}
//! ```
//!
//! and blocks until the supervisor answers with one `ToolAnswer`:
//!
//! - `{"ran": {"status": ..., "stdout": PATH, "stderr": PATH, "outputs": {NAME: PATH}}}`: the tool
//!   ran. `status` is `{"exited": CODE}`, `{"signaled": SIGNAL}` or `{"stopped": REASON}`, REASON
//!   one of `timeout`, `output`, `file_size`, `process` and `program` (`ToolStop`). The paths are in
//!   the task's results directory, which it may read: what the tool wrote to stdout and stderr, and
//!   each file it kept. A stopped run keeps none.
//! - `{"refused": WHY}`: the request isn't one this module may make, such as a tool it didn't
//!   declare or a path outside the task. The task fails.
//! - `{"failed": WHY}`: the tool couldn't start, which is the node's fault. The task fails.
//!
//! The supervisor answers one request at a time, in order. The socket closes when the task process
//! ends; a run still going then is killed.
//!
//! Between the supervisor and a `tool` process, descriptor 3 carries one message the other way: the
//! listener's descriptor in an `SCM_RIGHTS` message with the byte `L`, or text saying why containing
//! failed. The descriptor is close-on-exec after that, so the supervisor reads end-of-file when the
//! tool's exec succeeds, and text when it fails.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ace_sdk::tools::{
    FILE_SIZE_LIMIT, Keep, MAX_OUTPUT_BYTES, MAX_RUNS, OPEN_FILES_LIMIT, ToolError, ToolOutput,
    ToolRun, ToolRunner, ToolSpec, ToolStatus, ToolStop, check_keep, collect_outputs, environment,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::containment::{ToolProfile, contain_tool};

/// The task process's descriptor for its supervisor's tools, and a `tool` process's for its
/// supervisor.
pub const TOOL_FD: RawFd = 3;
/// The largest frame either side sends.
pub const MAX_FRAME: usize = 1 << 20;
/// How long the supervisor waits for a `tool` process to contain itself.
const SETUP_TIMEOUT: Duration = Duration::from_secs(30);
/// The exit code of a `tool` process that couldn't contain itself or exec.
pub const EXIT_TOOL_SETUP: i32 = 125;

/// The supervisor's answer to a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAnswer {
    Ran {
        status: ToolStatus,
        stdout: PathBuf,
        stderr: PathBuf,
        outputs: BTreeMap<String, PathBuf>,
    },
    Refused(String),
    Failed(String),
}

/// Writes one frame.
pub fn write_frame<T: Serialize>(to: &mut impl Write, message: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(message).map_err(io::Error::other)?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::other("the message is too large to send"));
    }
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    to.write_all(&length.to_be_bytes())?;
    to.write_all(&bytes)?;
    to.flush()
}

/// Reads one frame.
pub fn read_frame<T: for<'de> Deserialize<'de>>(from: &mut impl Read) -> io::Result<T> {
    let mut length = [0u8; 4];
    from.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::other(format!("a frame of {length} bytes")));
    }
    let mut bytes = vec![0u8; length];
    from.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

async fn write_frame_async<T: Serialize>(
    to: &mut (impl AsyncWrite + Unpin),
    message: &T,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(message).map_err(io::Error::other)?;
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    to.write_all(&length.to_be_bytes()).await?;
    to.write_all(&bytes).await?;
    to.flush().await
}

/// Reads one frame, or None at the end of the stream.
async fn read_frame_async<T: for<'de> Deserialize<'de>>(
    from: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<T>> {
    let mut length = [0u8; 4];
    match from.read_exact(&mut length).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::other(format!("a frame of {length} bytes")));
    }
    let mut bytes = vec![0u8; length];
    from.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(io::Error::other)
}

// ---------------------------------------------------------------------------------------------
// The task process's side

/// The task process's runner: requests to its supervisor on `TOOL_FD`.
pub struct SocketRunner {
    stream: Mutex<UnixStream>,
    scratch: PathBuf,
}

impl SocketRunner {
    /// Takes `TOOL_FD`, which must be a socket, before the task process contains itself.
    pub fn from_fd(scratch: PathBuf) -> io::Result<SocketRunner> {
        let mut stat: libc::stat = unsafe_zeroed();
        // SAFETY: fstat writes one stat struct, which lives for the call.
        if unsafe { libc::fstat(TOOL_FD, &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            return Err(io::Error::other("descriptor 3 isn't a socket"));
        }
        // SAFETY: the supervisor gave this process the descriptor for this use only.
        let stream = unsafe { UnixStream::from_raw_fd(TOOL_FD) };
        Ok(SocketRunner {
            stream: Mutex::new(stream),
            scratch,
        })
    }
}

fn unsafe_zeroed<T>() -> T {
    // SAFETY: used only for plain C structs, for which all zeroes is valid.
    unsafe { std::mem::zeroed() }
}

impl ToolRunner for SocketRunner {
    fn scratch(&self) -> &Path {
        &self.scratch
    }

    fn run(&self, run: &ToolRun) -> Result<ToolOutput, ToolError> {
        let io_error = |source| ToolError::Io {
            tool: run.tool.clone(),
            source,
        };
        let mut stream = self
            .stream
            .lock()
            .map_err(|_| io_error(io::Error::other("the tool socket is poisoned")))?;
        write_frame(&mut *stream, run).map_err(io_error)?;
        let answer: ToolAnswer = read_frame(&mut *stream).map_err(io_error)?;
        match answer {
            ToolAnswer::Ran {
                status,
                stdout,
                stderr,
                outputs,
            } => Ok(ToolOutput {
                status,
                stdout: fs::read(&stdout).map_err(io_error)?,
                stderr: fs::read(&stderr).map_err(io_error)?,
                outputs,
            }),
            ToolAnswer::Refused(why) => Err(ToolError::Refused(why)),
            ToolAnswer::Failed(reason) => Err(ToolError::Start {
                tool: run.tool.clone(),
                reason,
            }),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The pool's tools

/// A tool with the paths its spec resolves to on this machine.
#[derive(Debug, Clone)]
pub struct ResolvedTool {
    pub spec: ToolSpec,
    /// What it may run: the program, its interpreter and the dynamic loader.
    pub executes: Vec<PathBuf>,
    /// What it may read: the libraries they need and the spec's data that exists here.
    pub reads: Vec<PathBuf>,
}

/// The tools a pool runs, resolved once when it starts.
#[derive(Debug, Clone, Default)]
pub struct ToolTable {
    tools: Vec<ResolvedTool>,
}

/// Files every tool may read: the dynamic loader's cache, the time zone, the C locale, glibc's
/// character set modules and the random devices.
const COMMON_READS: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/usr/lib/locale/C.utf8",
    GCONV,
    "/dev/urandom",
    "/dev/random",
    "/dev/zero",
];

#[cfg(target_arch = "aarch64")]
const GCONV: &str = "/usr/lib/aarch64-linux-gnu/gconv";
#[cfg(not(target_arch = "aarch64"))]
const GCONV: &str = "/usr/lib/x86_64-linux-gnu/gconv";

impl ToolTable {
    /// Resolves each spec: its program and interpreter must exist here, and so must every library
    /// they need. A spec's data that doesn't exist is left out, as ace3's sandbox leaves out an
    /// `/etc` file a system lacks.
    pub fn resolve(specs: &[ToolSpec]) -> Result<ToolTable, String> {
        let mut tools = Vec::new();
        for spec in specs {
            tools.push(resolve(spec).map_err(|e| format!("tool {}: {e}", spec.name))?);
        }
        Ok(ToolTable { tools })
    }

    pub fn get(&self, name: &str) -> Option<&ResolvedTool> {
        self.tools.iter().find(|tool| tool.spec.name == name)
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.tools.iter().map(|tool| tool.spec.name).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

fn resolve(spec: &ToolSpec) -> Result<ResolvedTool, String> {
    let program = fs::canonicalize(spec.program).map_err(|e| format!("{}: {e}", spec.program))?;
    let mut executes = vec![program.clone()];
    let mut binaries = vec![program];
    if let Some(interpreter) = spec.interpreter {
        let interpreter =
            fs::canonicalize(interpreter).map_err(|e| format!("{interpreter}: {e}"))?;
        executes.push(interpreter.clone());
        binaries.push(interpreter);
    }
    let mut reads = Vec::new();
    for path in COMMON_READS.iter().chain(spec.reads) {
        if Path::new(path).exists() {
            reads.push(PathBuf::from(path));
        }
    }
    // the libraries of the program, its interpreter, and the modules in its data it may load
    let mut modules = Vec::new();
    for path in spec.reads {
        collect_shared_objects(Path::new(path), &mut modules);
    }
    let mut loaders = Vec::new();
    let libraries = libraries(binaries.iter().chain(&modules), &mut loaders)?;
    for loader in loaders {
        if !executes.contains(&loader) {
            executes.push(loader);
        }
    }
    reads.extend(libraries);
    Ok(ResolvedTool {
        spec: *spec,
        executes,
        reads,
    })
}

/// The `.so` files beneath `path`, such as ImageMagick's coders, which a tool loads at run time.
fn collect_shared_objects(path: &Path, into: &mut Vec<PathBuf>) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                collect_shared_objects(&entry.path(), into);
            }
        }
    } else if meta.is_file()
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".so") || n.contains(".so."))
    {
        into.push(path.to_owned());
    }
}

/// The library directories the dynamic loader searches here.
fn library_dirs() -> Vec<PathBuf> {
    let triplet = if cfg!(target_arch = "aarch64") {
        "aarch64-linux-gnu"
    } else {
        "x86_64-linux-gnu"
    };
    [
        format!("/lib/{triplet}"),
        format!("/usr/lib/{triplet}"),
        "/lib".to_owned(),
        "/usr/lib".to_owned(),
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect()
}

/// Every library `binaries` need by `DT_NEEDED`, transitively, by its real path; and the dynamic
/// loaders they name, into `loaders`.
fn libraries<'a>(
    binaries: impl Iterator<Item = &'a PathBuf>,
    loaders: &mut Vec<PathBuf>,
) -> Result<Vec<PathBuf>, String> {
    let dirs = library_dirs();
    let mut found: Vec<PathBuf> = Vec::new();
    let mut queue: Vec<PathBuf> = binaries.cloned().collect();
    while let Some(binary) = queue.pop() {
        let Some(elf) = Elf::read(&binary).map_err(|e| format!("{}: {e}", binary.display()))?
        else {
            continue;
        };
        if let Some(interpreter) = elf.interpreter {
            let interpreter = fs::canonicalize(&interpreter)
                .map_err(|e| format!("{}: {e}", interpreter.display()))?;
            if !loaders.contains(&interpreter) {
                loaders.push(interpreter);
            }
        }
        let origin = binary.parent().unwrap_or(Path::new("/")).to_owned();
        let mut search: Vec<PathBuf> = elf
            .runpaths
            .iter()
            .flat_map(|paths| paths.split(':'))
            .map(|p| PathBuf::from(p.replace("$ORIGIN", &origin.display().to_string())))
            .collect();
        search.extend(dirs.iter().cloned());
        for name in elf.needed {
            let path = search
                .iter()
                .map(|dir| dir.join(&name))
                .find(|path| path.exists())
                .ok_or_else(|| format!("{} needs {name}, which isn't here", binary.display()))?;
            let path = fs::canonicalize(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            if !found.contains(&path) {
                found.push(path.clone());
                queue.push(path);
            }
        }
    }
    Ok(found)
}

/// What the dynamic loader reads of a 64-bit little-endian ELF file.
struct Elf {
    interpreter: Option<PathBuf>,
    needed: Vec<String>,
    runpaths: Vec<String>,
}

impl Elf {
    /// None for a file that isn't such an ELF file, such as a script.
    fn read(path: &Path) -> io::Result<Option<Elf>> {
        let data = fs::read(path)?;
        if data.len() < 64 || &data[..4] != b"\x7fELF" || data[4] != 2 || data[5] != 1 {
            return Ok(None);
        }
        let bad = || io::Error::other("a malformed ELF file");
        let u16_at = |at: usize| -> io::Result<u16> {
            Ok(u16::from_le_bytes(
                data.get(at..at + 2)
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?,
            ))
        };
        let u32_at = |at: usize| -> io::Result<u32> {
            Ok(u32::from_le_bytes(
                data.get(at..at + 4)
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?,
            ))
        };
        let u64_at = |at: usize| -> io::Result<u64> {
            Ok(u64::from_le_bytes(
                data.get(at..at + 8)
                    .ok_or_else(bad)?
                    .try_into()
                    .map_err(|_| bad())?,
            ))
        };
        let usize_at =
            |at: usize| -> io::Result<usize> { usize::try_from(u64_at(at)?).map_err(|_| bad()) };
        let phoff = usize_at(0x20)?;
        let phentsize = usize::from(u16_at(0x36)?);
        let phnum = usize::from(u16_at(0x38)?);
        let mut interpreter = None;
        let mut dynamic = None;
        let mut loads = Vec::new();
        for i in 0..phnum {
            let at = phoff + i * phentsize;
            let kind = u32_at(at)?;
            let offset = usize_at(at + 8)?;
            let vaddr = u64_at(at + 16)?;
            let filesz = usize_at(at + 32)?;
            match kind {
                1 => loads.push((vaddr, offset, filesz)),
                2 => dynamic = Some((offset, filesz)),
                3 => {
                    let bytes = data.get(offset..offset + filesz).ok_or_else(bad)?;
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    interpreter = Some(PathBuf::from(
                        String::from_utf8_lossy(&bytes[..end]).into_owned(),
                    ));
                }
                _ => {}
            }
        }
        let mut needed_offsets = Vec::new();
        let mut runpath_offsets = Vec::new();
        let mut strtab = None;
        if let Some((offset, size)) = dynamic {
            for i in 0..size / 16 {
                let at = offset + i * 16;
                let tag = u64_at(at)?;
                let value = u64_at(at + 8)?;
                match tag {
                    0 => break,
                    1 => needed_offsets.push(value),
                    5 => strtab = Some(value),
                    15 | 29 => runpath_offsets.push(value),
                    _ => {}
                }
            }
        }
        let mut needed = Vec::new();
        let mut runpaths = Vec::new();
        if let Some(strtab) = strtab {
            let base = loads
                .iter()
                .find(|&&(vaddr, _, filesz)| strtab >= vaddr && strtab < vaddr + filesz as u64)
                .map(|&(vaddr, offset, _)| offset + (strtab - vaddr) as usize)
                .ok_or_else(bad)?;
            let string = |offset: u64| -> io::Result<String> {
                let start = base + usize::try_from(offset).map_err(|_| bad())?;
                let bytes = data.get(start..).ok_or_else(bad)?;
                let end = bytes.iter().position(|&b| b == 0).ok_or_else(bad)?;
                Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
            };
            for offset in needed_offsets {
                needed.push(string(offset)?);
            }
            for offset in runpath_offsets {
                runpaths.push(string(offset)?);
            }
        }
        Ok(Some(Elf {
            interpreter,
            needed,
            runpaths,
        }))
    }
}

// ---------------------------------------------------------------------------------------------
// The supervisor's side

/// The directories of a task that runs tools, inside its task directory.
#[derive(Debug, Clone)]
pub struct ToolDirs {
    /// The task's directory: every path a request reads is beneath it.
    pub task: PathBuf,
    /// Where the module puts files for its tools, which the task process may write.
    pub scratch: PathBuf,
    /// Where the supervisor puts what each run gave back, which the task process may read.
    pub results: PathBuf,
    /// Where each run's working directory is, which the task process can't touch.
    pub runs: PathBuf,
}

impl ToolDirs {
    /// Makes them in `task`: scratch for `user` to write, the others the supervisor's.
    pub fn create(task: &Path, user: Option<(u32, u32)>) -> io::Result<ToolDirs> {
        let dirs = ToolDirs {
            task: task.to_owned(),
            scratch: task.join("scratch"),
            results: task.join("results"),
            runs: task.join("runs"),
        };
        for dir in [&dirs.scratch, &dirs.results, &dirs.runs] {
            fs::create_dir(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755))?;
        }
        if let Some((uid, gid)) = user {
            std::os::unix::fs::chown(&dirs.scratch, Some(uid), Some(gid))?;
        }
        Ok(dirs)
    }
}

/// What a `tool` process reads on stdin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolExec {
    pub program: PathBuf,
    /// The arguments, the program's path first.
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    /// Its working directory, the one it may write.
    pub workdir: PathBuf,
    /// The task's directory, beneath which `task_reads` are opened with no symlinks followed.
    pub task_dir: PathBuf,
    /// The task's files it reads, relative to `task_dir`.
    pub task_reads: Vec<PathBuf>,
    /// The pool's files it reads: its libraries and data.
    pub reads: Vec<PathBuf>,
    /// What it may run.
    pub executes: Vec<PathBuf>,
    pub address_space_bytes: u64,
    pub cpu_seconds: u64,
    pub file_size_bytes: u64,
    pub open_files: u64,
}

/// Runs the tools of one task process for its supervisor.
pub struct ToolHost {
    pub table: Arc<ToolTable>,
    /// The tools the task's module declares.
    pub declared: &'static [&'static str],
    pub dirs: ToolDirs,
    /// The task's user, whom the tool runs as.
    pub user: Option<(u32, u32)>,
    /// The binary whose `tool` mode contains and execs a tool, and its arguments up to the mode.
    pub program: PathBuf,
    pub args: Vec<String>,
    /// No run goes past the task's own deadline.
    pub deadline: Instant,
}

impl ToolHost {
    /// Serves the task's requests until it closes its end.
    pub async fn serve(&self, mut socket: tokio::net::UnixStream) {
        let mut runs = 0u32;
        loop {
            let run: ToolRun = match read_frame_async(&mut socket).await {
                Ok(Some(run)) => run,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!("the task's tool request doesn't read: {e}");
                    return;
                }
            };
            runs += 1;
            let answer = self.answer(&run, runs).await;
            if let ToolAnswer::Refused(why) | ToolAnswer::Failed(why) = &answer {
                tracing::warn!(tool = %run.tool, "a tool didn't run: {why}");
            }
            if let Err(e) = write_frame_async(&mut socket, &answer).await {
                tracing::warn!("answering the task's tool request: {e}");
                return;
            }
        }
    }

    async fn answer(&self, run: &ToolRun, n: u32) -> ToolAnswer {
        match self.check(run, n) {
            Err(why) => ToolAnswer::Refused(why),
            Ok((tool, task_reads)) => match self.run(run, n, tool, task_reads).await {
                Ok(answer) => answer,
                Err(why) => ToolAnswer::Failed(why),
            },
        }
    }

    /// The tool and the task's files the request reads, relative to the task directory, or why it
    /// is refused.
    fn check<'t>(
        &'t self,
        run: &ToolRun,
        n: u32,
    ) -> Result<(&'t ResolvedTool, Vec<PathBuf>), String> {
        if !self.declared.contains(&run.tool.as_str()) {
            return Err(ToolError::Undeclared(run.tool.clone()).to_string());
        }
        let tool = self
            .table
            .get(&run.tool)
            .ok_or_else(|| ToolError::Unknown(run.tool.clone()).to_string())?;
        if n > MAX_RUNS {
            return Err(ToolError::TooMany.to_string());
        }
        check_keep(run).map_err(|e| e.to_string())?;
        environment(&tool.spec, run, Path::new("/")).map_err(|e| e.to_string())?;
        let mut task_reads = Vec::new();
        for path in &run.reads {
            task_reads.push(self.task_path(path)?);
        }
        for staged in &run.stage {
            self.task_path(&staged.from)?;
        }
        Ok((tool, task_reads))
    }

    /// `path` relative to the task directory, if it's a plain path beneath it and not in a run's
    /// working directory.
    fn task_path(&self, path: &Path) -> Result<PathBuf, String> {
        let refuse = || format!("{} isn't one of the task's files", path.display());
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        {
            return Err(refuse());
        }
        let relative = path.strip_prefix(&self.dirs.task).map_err(|_| refuse())?;
        if relative.as_os_str().is_empty() || path.starts_with(&self.dirs.runs) {
            return Err(refuse());
        }
        Ok(relative.to_owned())
    }

    async fn run(
        &self,
        run: &ToolRun,
        n: u32,
        tool: &ResolvedTool,
        task_reads: Vec<PathBuf>,
    ) -> Result<ToolAnswer, String> {
        let workdir = self.dirs.runs.join(n.to_string());
        let results = self.dirs.results.join(n.to_string());
        fs::create_dir(&workdir).map_err(|e| format!("its working directory: {e}"))?;
        fs::set_permissions(&workdir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("its working directory: {e}"))?;
        if let Some((uid, gid)) = self.user {
            std::os::unix::fs::chown(&workdir, Some(uid), Some(gid))
                .map_err(|e| format!("its working directory: {e}"))?;
        }
        fs::create_dir(&results).map_err(|e| format!("its results directory: {e}"))?;
        fs::set_permissions(&results, fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("its results directory: {e}"))?;
        // the files it's given in its working directory, copied without following a symlink, since
        // the task could have made one
        let task_dir = open_path(&self.dirs.task)?;
        for staged in &run.stage {
            let relative = self.task_path(&staged.from)?;
            let source = open_beneath_with(&task_dir, &relative, libc::O_RDONLY)?;
            let mut source = fs::File::from(source);
            let target = workdir.join(&staged.name);
            let mut copy = fs::File::create(&target).map_err(|e| format!("staging: {e}"))?;
            io::copy(&mut source, &mut copy).map_err(|e| format!("staging: {e}"))?;
            if let Some((uid, gid)) = self.user {
                std::os::unix::fs::chown(&target, Some(uid), Some(gid))
                    .map_err(|e| format!("staging: {e}"))?;
            }
        }
        let timeout = run
            .timeout
            .min(self.deadline.saturating_duration_since(Instant::now()));
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as u64);
        let env = environment(&tool.spec, run, &workdir).map_err(|e| e.to_string())?;
        let mut argv = vec![tool.spec.program.to_owned()];
        argv.extend(run.args.iter().cloned());
        let exec = ToolExec {
            program: PathBuf::from(tool.spec.program),
            argv,
            env,
            workdir: workdir.clone(),
            task_dir: self.dirs.task.clone(),
            task_reads,
            reads: tool.reads.clone(),
            executes: tool.executes.clone(),
            address_space_bytes: tool.spec.memory_bytes,
            // ace3 gives a tool its timeout times the cores: the limit counts every thread
            cpu_seconds: timeout.as_secs().max(1).saturating_mul(cpus),
            file_size_bytes: FILE_SIZE_LIMIT,
            open_files: OPEN_FILES_LIMIT,
        };
        let outputs = results.join("outputs");
        let staged: Vec<String> = run.stage.iter().map(|s| s.name.clone()).collect();
        let keeping = Keeping {
            keep: &run.keep,
            staged: &staged,
            into: &outputs,
            when_stopped: run.keep_stopped,
        };
        let ran = execute_keeping(
            &self.program,
            &self.args,
            self.user,
            &exec,
            timeout,
            Some(keeping),
        )
        .await;
        if let Err(e) = fs::remove_dir_all(&workdir) {
            tracing::warn!("removing a tool's working directory: {e}");
        }
        let ran = ran?;
        let stdout = results.join("stdout");
        let stderr = results.join("stderr");
        fs::write(&stdout, &ran.stdout).map_err(|e| format!("keeping its stdout: {e}"))?;
        fs::write(&stderr, &ran.stderr).map_err(|e| format!("keeping its stderr: {e}"))?;
        Ok(ToolAnswer::Ran {
            status: ran.status,
            stdout,
            stderr,
            outputs: ran
                .kept
                .map(|kept| kept.into_iter().collect())
                .unwrap_or_default(),
        })
    }
}

/// How one contained run went.
pub struct Ran {
    pub status: ToolStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// What it kept, by name, when it ran to its end and something was to be kept.
    pub kept: Option<BTreeMap<String, PathBuf>>,
}

/// What to keep from a run's working directory, and where to.
#[derive(Debug, Clone, Copy)]
pub struct Keeping<'a> {
    pub keep: &'a Keep,
    /// The names staged there, which aren't kept.
    pub staged: &'a [String],
    pub into: &'a Path,
    /// Keep them from a stopped run too.
    pub when_stopped: bool,
}

/// Starts `program`'s `tool` mode as `user`, has it contain itself and exec `exec`'s tool, and
/// waits for the tool, killing it at `timeout`, at too much output or at a second exec. When it
/// ran to its end, or `keeping` says so anyway, what that names is moved from its working directory.
/// An `Err` is a tool that couldn't start.
pub async fn execute_keeping(
    program: &Path,
    args: &[String],
    user: Option<(u32, u32)>,
    exec: &ToolExec,
    timeout: Duration,
    keep: Option<Keeping<'_>>,
) -> Result<Ran, String> {
    let (ours, theirs) = UnixStream::pair().map_err(|e| format!("a socket: {e}"))?;
    let theirs_fd = theirs.as_raw_fd();
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .arg("tool")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some((uid, gid)) = user {
        command.uid(uid).gid(gid);
    }
    // SAFETY: dup2 is async-signal-safe, and the closure touches nothing else.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(theirs_fd, TOOL_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("the tool runner: {e}"))?;
    drop(theirs);
    let pid = child
        .id()
        .and_then(|pid| libc::pid_t::try_from(pid).ok())
        .ok_or("the tool runner has no pid")?;
    let (Some(mut stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err("the tool runner has no pipes".to_owned());
    };
    let request = serde_json::to_vec(exec).map_err(|e| e.to_string())?;
    stdin
        .write_all(&request)
        .await
        .map_err(|e| format!("writing to the tool runner: {e}"))?;
    drop(stdin);

    // the listener, or why the runner couldn't contain itself
    let handshake = tokio::task::spawn_blocking(move || receive_listener(ours))
        .await
        .map_err(|e| e.to_string())?;
    let (listener, ours) = match handshake {
        Ok(pair) => pair,
        Err(why) => {
            child.kill().await.ok();
            return Err(why);
        }
    };
    let done = Arc::new(AtomicBool::new(false));
    let second = Arc::new(AtomicBool::new(false));
    let watcher = {
        let (done, second) = (done.clone(), second.clone());
        std::thread::spawn(move || watch_execs(&listener, pid, &done, &second))
    };
    // end-of-file once the exec succeeds; text if it failed
    let exec_failed = tokio::task::spawn_blocking(move || exec_outcome(ours))
        .await
        .map_err(|e| e.to_string())?;

    let over = Arc::new(AtomicBool::new(false));
    let out = tokio::spawn(read_capped(stdout, over.clone()));
    let err = tokio::spawn(read_capped(stderr, over.clone()));
    let killed_for_output = {
        let over = over.clone();
        async move {
            while !over.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    };
    enum Ended {
        Exited(std::process::ExitStatus),
        Timeout,
        Output,
    }
    let ended = tokio::select! {
        status = child.wait() => Ended::Exited(status.map_err(|e| e.to_string())?),
        () = tokio::time::sleep(timeout) => Ended::Timeout,
        () = killed_for_output => Ended::Output,
    };
    if !matches!(ended, Ended::Exited(_)) {
        child.kill().await.ok();
    }
    done.store(true, Ordering::Relaxed);
    if watcher.join().is_err() {
        tracing::warn!("the exec watcher panicked");
    }
    let stdout = out.await.map_err(|e| e.to_string())?;
    let stderr = err.await.map_err(|e| e.to_string())?;
    if let Some(why) = exec_failed {
        return Err(why);
    }
    let status = if second.load(Ordering::Relaxed) {
        ToolStatus::Stopped(ToolStop::Program)
    } else {
        match ended {
            Ended::Timeout => ToolStatus::Stopped(ToolStop::Timeout),
            Ended::Output => ToolStatus::Stopped(ToolStop::Output),
            Ended::Exited(_) if over.load(Ordering::Relaxed) => {
                ToolStatus::Stopped(ToolStop::Output)
            }
            Ended::Exited(status) => match (status.code(), status.signal()) {
                (Some(code), _) => ToolStatus::Exited(code),
                (None, Some(libc::SIGSYS)) => ToolStatus::Stopped(ToolStop::Process),
                (None, Some(libc::SIGXFSZ)) => ToolStatus::Stopped(ToolStop::FileSize),
                (None, Some(signal)) => ToolStatus::Signaled(signal),
                (None, None) => ToolStatus::Exited(-1),
            },
        }
    };
    let kept = match keep {
        None => None,
        Some(keeping) if matches!(status, ToolStatus::Stopped(_)) && !keeping.when_stopped => None,
        Some(keeping) => Some(
            collect_outputs(&exec.workdir, keeping.keep, keeping.staged, keeping.into)
                .map_err(|e| format!("keeping its outputs: {e}"))?,
        ),
    };
    Ok(Ran {
        status,
        stdout,
        stderr,
        kept,
    })
}

/// Reads a pipe up to `MAX_OUTPUT_BYTES`, and sets `over` when there was more.
async fn read_capped<R: AsyncRead + Unpin>(pipe: R, over: Arc<AtomicBool>) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut limited = pipe.take(MAX_OUTPUT_BYTES + 1);
    limited.read_to_end(&mut bytes).await.ok();
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        over.store(true, Ordering::Relaxed);
        bytes.truncate(MAX_OUTPUT_BYTES as usize);
    }
    bytes
}

/// Receives the tool filter's listener on `socket`, or the runner's reason for failing.
fn receive_listener(socket: UnixStream) -> Result<(OwnedFd, UnixStream), String> {
    socket
        .set_read_timeout(Some(SETUP_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut byte = [0u8; 1];
    let mut space = [0u8; 64];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe_zeroed();
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = space.as_mut_ptr().cast();
    message.msg_controllen = space.len() as _;
    // SAFETY: the message's buffers live for the call.
    let received =
        unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(format!(
            "the tool runner didn't contain itself: {}",
            io::Error::last_os_error()
        ));
    }
    if received == 1 && byte[0] == b'L' {
        // SAFETY: the control buffer is the one the kernel filled, of the length it set.
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if !header.is_null() {
            // SAFETY: a non-null header points into `space`.
            let header_ref = unsafe { &*header };
            if header_ref.cmsg_level == libc::SOL_SOCKET && header_ref.cmsg_type == libc::SCM_RIGHTS
            {
                // SAFETY: an SCM_RIGHTS message's data is the descriptors it carries.
                let fd =
                    unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>()) };
                // SAFETY: the kernel gave this process the descriptor.
                return Ok((unsafe { OwnedFd::from_raw_fd(fd) }, socket));
            }
        }
        return Err("the tool runner sent no listener".to_owned());
    }
    // text: why it failed
    let mut text = byte[..usize::try_from(received).unwrap_or(0)].to_vec();
    let mut rest = &socket;
    rest.read_to_end(&mut text).ok();
    let text = String::from_utf8_lossy(&text).trim().to_owned();
    Err(if text.is_empty() {
        "the tool runner ended before containing itself".to_owned()
    } else {
        text
    })
}

/// None when the exec succeeded, or the runner's reason when it didn't.
fn exec_outcome(socket: UnixStream) -> Option<String> {
    socket.set_read_timeout(Some(SETUP_TIMEOUT)).ok();
    let mut text = Vec::new();
    let mut socket = socket;
    socket.read_to_end(&mut text).ok();
    let text = String::from_utf8_lossy(&text).trim().to_owned();
    (!text.is_empty()).then_some(text)
}

/// Answers the tool's execs on `listener` until `done`: the first goes ahead, and any other kills
/// the tool.
fn watch_execs(listener: &OwnedFd, pid: libc::pid_t, done: &AtomicBool, second: &AtomicBool) {
    let mut execs = 0u32;
    while !done.load(Ordering::Relaxed) {
        let mut poll = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll reads and writes one pollfd, which lives for the call.
        let ready = unsafe { libc::poll(&mut poll, 1, 50) };
        if ready <= 0 || poll.revents & libc::POLLIN == 0 {
            if poll.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return;
            }
            continue;
        }
        let mut notification: libc::seccomp_notif = unsafe_zeroed();
        // SAFETY: the kernel fills one seccomp_notif, zeroed as it requires.
        if unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_RECV,
                &mut notification,
            )
        } != 0
        {
            continue;
        }
        execs += 1;
        let mut response: libc::seccomp_notif_resp = unsafe_zeroed();
        response.id = notification.id;
        if execs == 1 {
            response.flags = libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32;
        } else {
            second.store(true, Ordering::Relaxed);
            // SAFETY: kill takes two integers.
            unsafe { libc::kill(pid, libc::SIGKILL) };
            response.error = -libc::EPERM;
        }
        // SAFETY: the kernel reads one seccomp_notif_resp, which lives for the call.
        unsafe {
            libc::ioctl(
                listener.as_raw_fd(),
                libc::SECCOMP_IOCTL_NOTIF_SEND,
                &mut response,
            )
        };
    }
}

// ---------------------------------------------------------------------------------------------
// The `tool` mode

/// The pool binary's `tool` mode: reads a `ToolExec` on stdin, contains itself, hands the
/// supervisor the tool filter's listener on `TOOL_FD`, and execs the tool. It returns only when
/// something failed, having said what on `TOOL_FD`.
pub fn tool_main() -> ExitCode {
    // SAFETY: the supervisor gave this process the descriptor for this use only.
    let mut supervisor = unsafe { UnixStream::from_raw_fd(TOOL_FD) };
    let why = match contain_and_exec(&mut supervisor) {
        Ok(never) => match never {},
        Err(why) => why,
    };
    supervisor.write_all(why.as_bytes()).ok();
    ExitCode::from(u8::try_from(EXIT_TOOL_SETUP).unwrap_or(u8::MAX))
}

enum Never {}

fn contain_and_exec(supervisor: &mut UnixStream) -> Result<Never, String> {
    let mut bytes = Vec::new();
    io::stdin()
        .read_to_end(&mut bytes)
        .map_err(|e| format!("reading what to run: {e}"))?;
    let exec: ToolExec =
        serde_json::from_slice(&bytes).map_err(|e| format!("what to run doesn't read: {e}"))?;
    // the tool reads nothing on stdin
    let null = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| format!("/dev/null: {e}"))?;
    // SAFETY: dup2 takes two descriptors this process holds.
    if unsafe { libc::dup2(null.as_raw_fd(), 0) } < 0 {
        return Err(format!("stdin: {}", io::Error::last_os_error()));
    }
    let mut profile = ToolProfile {
        address_space_bytes: exec.address_space_bytes,
        cpu_seconds: exec.cpu_seconds,
        file_size_bytes: exec.file_size_bytes,
        open_files: exec.open_files,
        ..ToolProfile::default()
    };
    profile
        .read_write_files
        .push(open_path(Path::new("/dev/null"))?);
    profile.writes.push(open_path(&exec.workdir)?);
    for path in &exec.reads {
        profile.reads.push(open_path(path)?);
    }
    for path in &exec.executes {
        profile.executes.push(open_path(path)?);
    }
    let task_dir = open_path(&exec.task_dir)?;
    for path in &exec.task_reads {
        profile.reads.push(open_beneath(&task_dir, path)?);
    }
    let argv = c_strings(&exec.argv)?;
    let env = c_strings(
        &exec
            .env
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>(),
    )?;
    let program = c_string(&exec.program.display().to_string())?;
    std::env::set_current_dir(&exec.workdir).map_err(|e| format!("its working directory: {e}"))?;

    let (_contained, listener) = contain_tool(&profile).map_err(|e| format!("containment: {e}"))?;
    send_listener(supervisor, &listener)?;
    drop(listener);
    // the supervisor reads end-of-file at a successful exec
    // SAFETY: fcntl takes integers.
    if unsafe { libc::fcntl(TOOL_FD, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(format!("{}", io::Error::last_os_error()));
    }
    let argv_pointers: Vec<*const libc::c_char> = argv
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env_pointers: Vec<*const libc::c_char> = env
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // SAFETY: both arrays are null-terminated arrays of C strings that live for the call.
    unsafe {
        libc::execve(
            program.as_ptr(),
            argv_pointers.as_ptr(),
            env_pointers.as_ptr(),
        )
    };
    Err(format!(
        "exec {}: {}",
        exec.program.display(),
        io::Error::last_os_error()
    ))
}

fn c_string(text: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(text).map_err(|_| format!("{text:?} holds a NUL"))
}

fn c_strings(texts: &[String]) -> Result<Vec<std::ffi::CString>, String> {
    texts.iter().map(|t| c_string(t)).collect()
}

/// `path` opened for a Landlock rule.
fn open_path(path: &Path) -> Result<OwnedFd, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags_path()
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(OwnedFd::from(file))
}

/// `relative` opened beneath `dir` with no symlink followed on the way, for a Landlock rule. A
/// task can write some of its directory, so a path it names can't be trusted to stay inside it any
/// other way.
fn open_beneath(dir: &OwnedFd, relative: &Path) -> Result<OwnedFd, String> {
    open_beneath_with(dir, relative, libc::O_PATH)
}

/// `open_beneath` with `flags`, such as `O_RDONLY` to read the file.
fn open_beneath_with(dir: &OwnedFd, relative: &Path, flags: i32) -> Result<OwnedFd, String> {
    let path = c_string(&relative.display().to_string())?;
    let mut how: libc::open_how = unsafe_zeroed();
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: openat2 reads the path and one open_how, which live for the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            path.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(format!(
            "the task's {}: {}",
            relative.display(),
            io::Error::last_os_error()
        ));
    }
    let fd = RawFd::try_from(fd).map_err(|e| e.to_string())?;
    // SAFETY: openat2 returned a new descriptor, which nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opening with `O_PATH`, which needs no read permission and opens directories too.
trait PathOpen {
    fn custom_flags_path(&mut self) -> &mut Self;
}

impl PathOpen for fs::OpenOptions {
    fn custom_flags_path(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.custom_flags(libc::O_PATH | libc::O_CLOEXEC)
    }
}

fn send_listener(supervisor: &UnixStream, listener: &OwnedFd) -> Result<(), String> {
    let mut byte = *b"L";
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // SAFETY: CMSG_SPACE is arithmetic.
    let space_len = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut space = vec![0u8; space_len];
    let mut message: libc::msghdr = unsafe_zeroed();
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = space.as_mut_ptr().cast();
    message.msg_controllen = space_len as _;
    // SAFETY: the header and data point into `space`, which is CMSG_SPACE long.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(header).cast::<RawFd>(),
            listener.as_raw_fd(),
        );
    }
    // SAFETY: the message's buffers live for the call.
    if unsafe { libc::sendmsg(supervisor.as_raw_fd(), &message, 0) } != 1 {
        return Err(format!(
            "sending the listener: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_refuse_a_huge_length() {
        let mut buffer = Vec::new();
        let run = ToolRun::new("pdftotext", ["a", "b"]);
        write_frame(&mut buffer, &run).unwrap();
        let back: ToolRun = read_frame(&mut buffer.as_slice()).unwrap();
        assert_eq!(back, run);
        let mut huge = (u32::MAX).to_be_bytes().to_vec();
        huge.extend_from_slice(b"{}");
        assert!(read_frame::<ToolRun>(&mut huge.as_slice()).is_err());
    }

    #[test]
    fn a_binarys_libraries_are_its_needed_ones_transitively() {
        let mut loaders = Vec::new();
        let ls = fs::canonicalize("/bin/ls").unwrap();
        let found = libraries(std::iter::once(&ls), &mut loaders).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n.starts_with("libc.so")), "{names:?}");
        assert_eq!(loaders.len(), 1, "{loaders:?}");
        assert!(
            loaders[0].to_string_lossy().contains("ld-linux"),
            "{loaders:?}"
        );
    }

    #[test]
    fn a_request_reads_only_plain_paths_in_its_task() {
        let host = ToolHost {
            table: Arc::new(ToolTable::default()),
            declared: &[],
            dirs: ToolDirs {
                task: PathBuf::from("/tmp/task"),
                scratch: PathBuf::from("/tmp/task/scratch"),
                results: PathBuf::from("/tmp/task/results"),
                runs: PathBuf::from("/tmp/task/runs"),
            },
            user: None,
            program: PathBuf::new(),
            args: Vec::new(),
            deadline: Instant::now(),
        };
        assert_eq!(
            host.task_path(Path::new("/tmp/task/input")).unwrap(),
            PathBuf::from("input")
        );
        for bad in [
            "/tmp/task/../etc/passwd",
            "/etc/passwd",
            "/tmp/task",
            "/tmp/task/runs/1/x",
            "input",
        ] {
            assert!(host.task_path(Path::new(bad)).is_err(), "{bad}");
        }
    }
}
