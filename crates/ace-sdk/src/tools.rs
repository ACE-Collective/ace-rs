//! The programs a module runs on its task's files (PLAN.md 7.3, 7.5 batch 10), such as tesseract or
//! Ghostscript: what a module asks for, what it gets back, and the programs the sandbox pool's image
//! carries.
//!
//! A module names the tools it runs in `Module::TOOLS`, by name, and runs one with
//! `TaskContext::run_tool`. It can't name a program: the pool maps each name to an absolute path in
//! its image (`ToolSpec`, `SANDBOX_TOOLS`), and refuses a tool its module didn't declare. A parser's
//! task process is contained and can't exec, so in a pool the run is its supervisor's: it starts the
//! tool as a contained process of its own, which may start threads but not processes
//! (`ace_pool::tools` has how, and the protocol). `LocalRunner` runs a tool as a plain child process,
//! for module tests and for replaying a task in a process of its own.
//!
//! What a run sees, as ace3's `run_sandboxed_tool` gives it: an empty working directory, which is
//! its current directory, `HOME` and `TMPDIR`, and the only place it may write; the files the
//! request names, which must be the task's own; an environment of `PATH`, `LANG`, `HOME` and
//! `TMPDIR`, with what the tool's spec adds and the variables the spec lets a request set. A run
//! ends with the tool's exit, or is stopped (`ToolStop`): at its timeout, when it writes more than
//! `MAX_OUTPUT_BYTES` to stdout or to stderr, writes a file past the size limit, or tries to start
//! another program or process. What it left in its working directory is kept only when the request
//! names it, or asks for everything, and only as a plain file with one link; nothing is kept from a
//! stopped run.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The most a tool may write to stdout, and to stderr: ace3's `tool_sandbox.max_output_bytes`.
pub const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
/// The largest file a tool may write: ace3's `tool_sandbox.file_size_limit` (`RLIMIT_FSIZE`).
pub const FILE_SIZE_LIMIT: u64 = 1024 * 1024 * 1024;
/// A tool's address-space limit by default: ace3's `tool_sandbox.memory_limit` (`RLIMIT_AS`).
pub const MEMORY_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
/// The most files a tool may have open: ace3's `open_files_limit` (`RLIMIT_NOFILE`).
pub const OPEN_FILES_LIMIT: u64 = 1024;
/// How many tools one task may run.
pub const MAX_RUNS: u32 = 64;
/// How much of a tool's stderr ace3's sandbox keeps: its end (`STDERR_TAIL_BYTES`).
pub const STDERR_TAIL_BYTES: usize = 16 * 1024;
/// How much of the task's time a run leaves, as ace3's `TOOL_TIMEOUT_MARGIN_SECONDS`.
pub const TIMEOUT_MARGIN: Duration = Duration::from_secs(5);

/// A program the pool's image carries, under the name modules declare it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolSpec {
    pub name: &'static str,
    /// Its absolute path in the image.
    pub program: &'static str,
    /// For a script, the interpreter its first line names, which the kernel runs too.
    pub interpreter: Option<&'static str>,
    /// Arguments it always gets before the request's, such as the JVM's options and CFR's jar,
    /// which make `java` the CFR tool.
    pub args: &'static [&'static str],
    /// The files and directories it reads besides its own libraries, such as its data.
    pub reads: &'static [&'static str],
    /// Variables it always gets, besides `PATH`, `LANG`, `HOME` and `TMPDIR`.
    pub env: &'static [(&'static str, &'static str)],
    /// Variables a request may set, such as tesseract's `OMP_THREAD_LIMIT`.
    pub request_env: &'static [&'static str],
    /// Its address-space limit.
    pub memory_bytes: u64,
}

impl ToolSpec {
    const fn new(name: &'static str, program: &'static str) -> ToolSpec {
        ToolSpec {
            name,
            program,
            interpreter: None,
            args: &[],
            reads: &[],
            env: &[],
            request_env: &[],
            memory_bytes: MEMORY_LIMIT,
        }
    }
}

/// The tools of the sandbox pool's image (`docker/ace4/Dockerfile`), at ace3's versions
/// (`docs/modules.md`, *External tools*). What each reads besides its libraries is what it opened
/// under strace on the samples, with the directories those paths' symlinks lead to; the runner adds
/// the dynamic loader's cache, the time zone, the C locale, glibc's character set modules and the
/// random devices for every tool (`ace_pool::tools`).
pub const SANDBOX_TOOLS: &[ToolSpec] = &[
    ToolSpec {
        reads: &["/usr/share/tesseract-ocr", "/sys/devices/system/cpu"],
        request_env: &["OMP_THREAD_LIMIT"],
        ..ToolSpec::new("tesseract", "/usr/bin/tesseract")
    },
    ToolSpec {
        reads: &[
            "/etc/ImageMagick-7",
            "/usr/share/ImageMagick-7",
            IMAGEMAGICK_MODULES,
            "/sys/devices/system/cpu",
        ],
        ..ToolSpec::new("zbarimg", "/usr/bin/zbarimg")
    },
    ToolSpec {
        interpreter: Some("/usr/bin/perl"),
        // the arch-dependent modules too, Compress::Raw::Zlib and Digest::MD5 among them, which
        // ExifTool's OOXML, OpenDocument and encrypted PDF support loads
        reads: &[
            "/usr/share/perl5",
            "/usr/share/perl",
            PERL_LIBRARIES,
            PERL_BASE,
            PERL_ARCH,
        ],
        ..ToolSpec::new("exiftool", "/usr/bin/exiftool")
    },
    ToolSpec {
        reads: POPPLER,
        ..ToolSpec::new("pdftotext", "/usr/bin/pdftotext")
    },
    ToolSpec {
        reads: POPPLER,
        ..ToolSpec::new("pdfinfo", "/usr/bin/pdfinfo")
    },
    ToolSpec {
        reads: &[
            "/usr/share/ghostscript",
            "/var/lib/ghostscript",
            "/etc/ghostscript",
            "/etc/paperspecs",
            // what the Resource directory's links lead to: poppler's CMaps, the URW fonts, the
            // ICC profiles
            "/usr/share/poppler",
            "/usr/share/fonts",
            "/usr/share/color/icc",
            "/etc/fonts",
            "/usr/share/fontconfig",
            "/var/cache/fontconfig",
        ],
        ..ToolSpec::new("gs", "/usr/bin/gs")
    },
    ToolSpec::new("unace", "/usr/bin/unace"),
    // CFR 0.151 on OpenJDK 21, with ace3's options (java.py's JVM_OPTIONS): the JVM reserves more
    // address space than the memory limit unless told how much heap and class space to reserve.
    // Its configuration is in /etc, where the JDK's conf directory links.
    ToolSpec {
        args: &[
            "-Xmx1g",
            "-XX:CompressedClassSpaceSize=128m",
            "-XX:ReservedCodeCacheSize=128m",
            "-XX:-UsePerfData",
            "-jar",
            CFR_JAR,
        ],
        reads: &[JVM, "/etc/java-21-openjdk", CFR_JAR],
        ..ToolSpec::new("cfr", "/usr/bin/java")
    },
    ToolSpec::new("upx", "/usr/bin/upx"),
    ToolSpec::new("unautoit", "/usr/local/bin/unautoit"),
    // de4dotEx, self-contained, and ilspycmd on the shared runtime, with ace3's DOTNET_ENV and
    // DOTNET_MEMORY_LIMIT (dotnet.py): the GC reserves 256 GB of address space without a heap limit
    // and a region range, and the runtime still reserves about 5 GB to use a few hundred MB, so the
    // heap limit is what bounds its memory. CoreCLR won't start without its own /proc/<pid>, its
    // maps and cgroup, which ace3 makes readable as /proc/self; that rule is the tool's own
    // directory, opened by the tool process that execs it. de4dot loads ICU, and OpenSSL by dlopen
    // to hash a reference's public key to its token (a test in ace-pool's containment.rs); ilspycmd
    // runs with invariant globalization and was never seen to hash.
    ToolSpec {
        reads: &[
            "/opt/de4dotEx",
            "/proc/self",
            ICU_UC,
            ICU_I18N,
            ICU_DATA,
            LIBSSL,
            LIBCRYPTO,
        ],
        env: DOTNET_ENV,
        memory_bytes: DOTNET_MEMORY_LIMIT,
        ..ToolSpec::new("de4dot", "/opt/de4dotEx/de4dot")
    },
    ToolSpec {
        reads: &["/opt/dotnet", "/usr/share/dotnet", "/proc/self"],
        env: DOTNET_ENV,
        memory_bytes: DOTNET_MEMORY_LIMIT,
        ..ToolSpec::new("ilspycmd", "/opt/dotnet/ilspycmd")
    },
    // batch 12's: dmg2img, and 7-Zip's 7z itself, which /usr/bin/7z is a shell script to exec, and
    // which loads its formats from 7z.so beside it and the codecs in Codecs/, 7zip-rar's, by dlopen
    ToolSpec::new("dmg2img", "/usr/bin/dmg2img"),
    ToolSpec {
        reads: &[
            "/usr/lib/7zip/7z.so",
            "/usr/lib/7zip/Codecs",
            "/sys/devices/system/cpu",
        ],
        ..ToolSpec::new("7z", "/usr/lib/7zip/7z")
    },
];

/// Where the sandbox image keeps CFR's jar.
pub const CFR_JAR: &str = "/usr/local/share/java/cfr-0.151.jar";
const DOTNET_ENV: &[(&str, &str)] = &[
    ("DOTNET_GCHeapHardLimit", "0x40000000"),
    ("DOTNET_GCRegionRange", "0x80000000"),
];
const DOTNET_MEMORY_LIMIT: u64 = 12 * 1024 * 1024 * 1024;

const POPPLER: &[&str] = &[
    "/usr/share/poppler",
    "/etc/fonts",
    "/usr/share/fontconfig",
    "/usr/share/fonts",
    "/var/cache/fontconfig",
];

#[cfg(target_arch = "aarch64")]
const JVM: &str = "/usr/lib/jvm/java-21-openjdk-arm64";
#[cfg(not(target_arch = "aarch64"))]
const JVM: &str = "/usr/lib/jvm/java-21-openjdk-amd64";
#[cfg(target_arch = "aarch64")]
const ICU_UC: &str = "/usr/lib/aarch64-linux-gnu/libicuuc.so.76";
#[cfg(not(target_arch = "aarch64"))]
const ICU_UC: &str = "/usr/lib/x86_64-linux-gnu/libicuuc.so.76";
#[cfg(target_arch = "aarch64")]
const ICU_I18N: &str = "/usr/lib/aarch64-linux-gnu/libicui18n.so.76";
#[cfg(not(target_arch = "aarch64"))]
const ICU_I18N: &str = "/usr/lib/x86_64-linux-gnu/libicui18n.so.76";
#[cfg(target_arch = "aarch64")]
const ICU_DATA: &str = "/usr/lib/aarch64-linux-gnu/libicudata.so.76";
#[cfg(not(target_arch = "aarch64"))]
const ICU_DATA: &str = "/usr/lib/x86_64-linux-gnu/libicudata.so.76";
#[cfg(target_arch = "aarch64")]
const LIBSSL: &str = "/usr/lib/aarch64-linux-gnu/libssl.so.3";
#[cfg(not(target_arch = "aarch64"))]
const LIBSSL: &str = "/usr/lib/x86_64-linux-gnu/libssl.so.3";
#[cfg(target_arch = "aarch64")]
const LIBCRYPTO: &str = "/usr/lib/aarch64-linux-gnu/libcrypto.so.3";
#[cfg(not(target_arch = "aarch64"))]
const LIBCRYPTO: &str = "/usr/lib/x86_64-linux-gnu/libcrypto.so.3";
#[cfg(target_arch = "aarch64")]
const IMAGEMAGICK_MODULES: &str = "/usr/lib/aarch64-linux-gnu/ImageMagick-7.1.1";
#[cfg(not(target_arch = "aarch64"))]
const IMAGEMAGICK_MODULES: &str = "/usr/lib/x86_64-linux-gnu/ImageMagick-7.1.1";
#[cfg(target_arch = "aarch64")]
const PERL_LIBRARIES: &str = "/usr/lib/aarch64-linux-gnu/perl5";
#[cfg(not(target_arch = "aarch64"))]
const PERL_LIBRARIES: &str = "/usr/lib/x86_64-linux-gnu/perl5";
#[cfg(target_arch = "aarch64")]
const PERL_ARCH: &str = "/usr/lib/aarch64-linux-gnu/perl";
#[cfg(not(target_arch = "aarch64"))]
const PERL_ARCH: &str = "/usr/lib/x86_64-linux-gnu/perl";
#[cfg(target_arch = "aarch64")]
const PERL_BASE: &str = "/usr/lib/aarch64-linux-gnu/perl-base";
#[cfg(not(target_arch = "aarch64"))]
const PERL_BASE: &str = "/usr/lib/x86_64-linux-gnu/perl-base";

/// The spec named `name` in `tools`.
pub fn find<'a>(tools: &'a [ToolSpec], name: &str) -> Option<&'a ToolSpec> {
    tools.iter().find(|tool| tool.name == name)
}

/// Which files a run keeps from its working directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Keep {
    /// These names, each a plain name in the working directory.
    Named(Vec<String>),
    /// Every plain file at the top of the working directory, as Ghostscript's pages.
    All,
    /// Every plain file beneath the working directory, by its path in it, as an archive's members,
    /// but the files the run staged there.
    Tree,
}

/// A file of the task's that the runner copies into the working directory before the tool starts,
/// as ace3 copies an ACE archive into a directory of its own for unace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Staged {
    pub from: PathBuf,
    /// A plain name in the working directory.
    pub name: String,
}

/// What a module asks to run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRun {
    /// A tool the module declares.
    pub tool: String,
    /// Its arguments. A path in them is the module's to make absolute; a plain name is relative to
    /// the working directory.
    pub args: Vec<String>,
    /// The task's own files and directories the tool reads: its input, its scratch directory
    /// (`TaskContext::scratch_dir`) and what earlier runs kept.
    pub reads: Vec<PathBuf>,
    /// What to keep from the working directory.
    pub keep: Keep,
    /// Also keep it when the run is stopped, as ace3 keeps what an extractor wrote before its
    /// timeout.
    #[serde(default)]
    pub keep_stopped: bool,
    /// The task's files copied into the working directory first.
    #[serde(default)]
    pub stage: Vec<Staged>,
    /// Variables to set, of those the tool's spec allows.
    pub env: Vec<(String, String)>,
    /// How long it may run. `TaskContext::run_tool` cuts it to the task's time left.
    pub timeout: Duration,
}

impl ToolRun {
    pub fn new(tool: &str, args: impl IntoIterator<Item = impl Into<String>>) -> ToolRun {
        ToolRun {
            tool: tool.to_owned(),
            args: args.into_iter().map(Into::into).collect(),
            reads: Vec::new(),
            keep: Keep::Named(Vec::new()),
            keep_stopped: false,
            stage: Vec::new(),
            env: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Copies the task's file `from` into the working directory as `name` before the tool starts.
    pub fn stage(mut self, from: impl Into<PathBuf>, name: &str) -> ToolRun {
        self.stage.push(Staged {
            from: from.into(),
            name: name.to_owned(),
        });
        self
    }

    pub fn keep_tree(mut self) -> ToolRun {
        self.keep = Keep::Tree;
        self
    }

    pub fn keep_stopped(mut self) -> ToolRun {
        self.keep_stopped = true;
        self
    }

    pub fn read(mut self, path: impl Into<PathBuf>) -> ToolRun {
        self.reads.push(path.into());
        self
    }

    pub fn keep(mut self, name: &str) -> ToolRun {
        if let Keep::Named(names) = &mut self.keep {
            names.push(name.to_owned());
        }
        self
    }

    pub fn keep_all(mut self) -> ToolRun {
        self.keep = Keep::All;
        self
    }

    pub fn env(mut self, name: &str, value: &str) -> ToolRun {
        self.env.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> ToolRun {
        self.timeout = timeout;
        self
    }
}

/// Why a run was stopped before the tool ended on its own. ace3's `run_sandboxed_tool` returns
/// nothing for these: a timeout, too much output, a file past the size limit. The last two are
/// ace4's: ace3's sandbox lets a tool start processes and programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStop {
    /// It ran past its timeout and was killed.
    Timeout,
    /// It wrote more than `MAX_OUTPUT_BYTES` to stdout or to stderr and was killed.
    Output,
    /// It wrote a file past `FILE_SIZE_LIMIT` and died of SIGXFSZ.
    FileSize,
    /// It tried to start a process, and the tool filter killed it with SIGSYS.
    Process,
    /// It tried to run another program, and was killed.
    Program,
}

impl ToolStop {
    pub fn describe(self) -> &'static str {
        match self {
            ToolStop::Timeout => "it ran past its timeout",
            ToolStop::Output => "it wrote more output than allowed",
            ToolStop::FileSize => "it wrote a file larger than allowed",
            ToolStop::Process => "it tried to start a process",
            ToolStop::Program => "it tried to run another program",
        }
    }
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    /// It exited with this code.
    Exited(i32),
    /// A signal killed it, such as SIGXCPU at the CPU-time limit or SIGSEGV.
    Signaled(i32),
    /// It was stopped.
    Stopped(ToolStop),
}

/// What a run gave back.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolOutput {
    pub status: ToolStatus,
    /// What it wrote, up to `MAX_OUTPUT_BYTES` each.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The files kept, by their names in its working directory, at paths the task reads. None from
    /// a stopped run.
    pub outputs: BTreeMap<String, PathBuf>,
}

impl ToolOutput {
    /// Its exit status as ace3's sandbox reports it, the launcher's: the code, or 128 plus the
    /// signal. None when it was stopped, when ace3's `run_sandboxed_tool` returns nothing.
    pub fn returncode(&self) -> Option<i32> {
        match self.status {
            ToolStatus::Exited(code) => Some(code),
            ToolStatus::Signaled(signal) => Some(128 + signal),
            ToolStatus::Stopped(_) => None,
        }
    }

    pub fn stopped(&self) -> Option<ToolStop> {
        match self.status {
            ToolStatus::Stopped(stop) => Some(stop),
            _ => None,
        }
    }

    /// stdout as text, as ace3's sandbox gives it: UTF-8 with invalid bytes replaced.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// The end of stderr as text, as ace3's sandbox gives it: its last `STDERR_TAIL_BYTES`, as
    /// UTF-8 with invalid bytes replaced.
    pub fn stderr_text(&self) -> String {
        let start = self.stderr.len().saturating_sub(STDERR_TAIL_BYTES);
        String::from_utf8_lossy(&self.stderr[start..]).into_owned()
    }

    /// The path of a file it kept.
    pub fn output(&self, name: &str) -> Option<&Path> {
        self.outputs.get(name).map(PathBuf::as_path)
    }
}

/// Why a run couldn't happen. Each is the node's or the module's fault, not the file's, so the task
/// fails.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("tool {0:?} isn't declared in the module's TOOLS")]
    Undeclared(String),
    #[error("this pool has no tool {0:?}")]
    Unknown(String),
    #[error("this task has no tool runner")]
    NoRunner,
    #[error("the task ran its {MAX_RUNS} tools")]
    TooMany,
    #[error("the request is refused: {0}")]
    Refused(String),
    #[error("{tool} couldn't start: {reason}")]
    Start { tool: String, reason: String },
    #[error("running {tool}: {source}")]
    Io {
        tool: String,
        #[source]
        source: io::Error,
    },
}

/// What runs a task's tools: the supervisor through the task's socket in a pool, or `LocalRunner`.
pub trait ToolRunner: Send + Sync {
    /// The task's scratch directory, where a module puts the files it hands to a tool.
    fn scratch(&self) -> &Path;

    fn run(&self, run: &ToolRun) -> Result<ToolOutput, ToolError>;
}

/// The variables a run gets: ace3's four, the spec's own and the request's allowed ones.
pub fn environment(
    spec: &ToolSpec,
    run: &ToolRun,
    workdir: &Path,
) -> Result<Vec<(String, String)>, ToolError> {
    let workdir = workdir.display().to_string();
    let mut env = vec![
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("HOME".to_owned(), workdir.clone()),
        ("TMPDIR".to_owned(), workdir),
    ];
    env.extend(
        spec.env
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    for (name, value) in &run.env {
        if !spec.request_env.contains(&name.as_str()) {
            return Err(ToolError::Refused(format!(
                "{} may not set {name}",
                spec.name
            )));
        }
        env.retain(|(n, _)| n != name);
        env.push((name.clone(), value.clone()));
    }
    Ok(env)
}

/// A plain name in a directory: not empty, `.` or `..`, with no `/` or NUL.
pub fn is_plain_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0')
}

/// Checks the names a request keeps and stages: plain names, no directories.
pub fn check_keep(run: &ToolRun) -> Result<(), ToolError> {
    if let Keep::Named(names) = &run.keep
        && let Some(name) = names.iter().find(|n| !is_plain_name(n))
    {
        return Err(ToolError::Refused(format!("can't keep {name:?}")));
    }
    if let Some(staged) = run.stage.iter().find(|s| !is_plain_name(&s.name)) {
        return Err(ToolError::Refused(format!("can't stage {:?}", staged.name)));
    }
    Ok(())
}

/// The longest path a system call takes, with its NUL (Linux's `PATH_MAX`).
const PATH_MAX: usize = 4096;

/// Moves what a run kept out of `workdir` into `into`: each plain file with one link that `keep`
/// names, as ace3's `_keep_tool_output` takes them, but none of `staged`, and none whose path, there
/// or in `into`, is too long for a system call, which ace3 can't open either. Anything else is left
/// behind. A kept file is made readable (0644), as ace3 normalizes what an extractor wrote, since the
/// tool may have given it any mode.
pub fn collect_outputs(
    workdir: &Path,
    keep: &Keep,
    staged: &[String],
    into: &Path,
) -> io::Result<BTreeMap<String, PathBuf>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let names: Vec<String> = match keep {
        Keep::Named(names) => names.clone(),
        Keep::All => {
            let mut names = Vec::new();
            for entry in fs::read_dir(workdir)? {
                if let Some(name) = entry?.file_name().to_str() {
                    names.push(name.to_owned());
                }
            }
            names.sort();
            names
        }
        Keep::Tree => {
            let mut names = Vec::new();
            walk(workdir, "", &mut names)?;
            names.sort();
            names
        }
    };
    let mut kept = BTreeMap::new();
    for name in names {
        if staged.contains(&name) {
            continue;
        }
        let path = workdir.join(&name);
        let to = into.join(&name);
        if path.as_os_str().len() >= PATH_MAX || to.as_os_str().len() >= PATH_MAX {
            tracing::warn!(
                bytes = name.len(),
                "a tool's output has a path too long to keep"
            );
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.file_type().is_file() || meta.nlink() != 1 {
            tracing::warn!(output = %name, "a tool's output isn't a plain file, so it isn't kept");
            continue;
        }
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&path, &to)?;
        fs::set_permissions(&to, fs::Permissions::from_mode(0o644))?;
        kept.insert(name, to);
    }
    Ok(kept)
}

/// The paths of the files and other non-directories beneath `dir`, relative to it, without
/// following a symlink. Names that aren't UTF-8 are left out.
fn walk(dir: &Path, prefix: &str, into: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        // a tool can make paths no system call takes, by a directory at a time: 7z extracting a
        // member of a folder cycle, 1,024 folders deep; nothing below one is kept
        if entry.path().as_os_str().len() >= PATH_MAX {
            continue;
        }
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if entry.file_type()?.is_dir() {
            walk(&entry.path(), &relative, into)?;
        } else {
            into.push(relative);
        }
    }
    Ok(())
}

/// Runs tools as plain child processes, with no containment: for module tests and for replaying a
/// task (`ace task replay`), which already runs uncontained. The tools are the ones `tools` lists,
/// such as `SANDBOX_TOOLS`, at their paths, with each run's working directory and environment as a
/// pool gives them, its timeout and its output limit.
pub struct LocalRunner {
    tools: Vec<ToolSpec>,
    declared: Vec<&'static str>,
    dir: tempfile::TempDir,
    scratch: PathBuf,
    runs: AtomicU32,
}

impl LocalRunner {
    pub fn new(tools: &[ToolSpec], declared: &[&'static str]) -> io::Result<LocalRunner> {
        let dir = tempfile::Builder::new().prefix("ace4-tools-").tempdir()?;
        let scratch = dir.path().join("scratch");
        fs::create_dir(&scratch)?;
        Ok(LocalRunner {
            tools: tools.to_vec(),
            declared: declared.to_vec(),
            dir,
            scratch,
            runs: AtomicU32::new(0),
        })
    }
}

impl ToolRunner for LocalRunner {
    fn scratch(&self) -> &Path {
        &self.scratch
    }

    fn run(&self, run: &ToolRun) -> Result<ToolOutput, ToolError> {
        if !self.declared.contains(&run.tool.as_str()) {
            return Err(ToolError::Undeclared(run.tool.clone()));
        }
        let spec =
            find(&self.tools, &run.tool).ok_or_else(|| ToolError::Unknown(run.tool.clone()))?;
        check_keep(run)?;
        let n = self.runs.fetch_add(1, Ordering::Relaxed) + 1;
        if n > MAX_RUNS {
            return Err(ToolError::TooMany);
        }
        let io_error = |source| ToolError::Io {
            tool: run.tool.clone(),
            source,
        };
        let workdir = self.dir.path().join(format!("run-{n}"));
        fs::create_dir(&workdir).map_err(io_error)?;
        for staged in &run.stage {
            fs::copy(&staged.from, workdir.join(&staged.name)).map_err(io_error)?;
        }
        let env = environment(spec, run, &workdir)?;
        let mut child = Command::new(spec.program)
            .args(spec.args)
            .args(&run.args)
            .env_clear()
            .envs(env)
            .current_dir(&workdir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| ToolError::Start {
                tool: run.tool.clone(),
                reason: e.to_string(),
            })?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            return Err(io_error(io::Error::other("no pipes")));
        };
        let over = Arc::new(AtomicBool::new(false));
        let out = {
            let over = over.clone();
            std::thread::spawn(move || read_capped(stdout, &over))
        };
        let err = {
            let over = over.clone();
            std::thread::spawn(move || read_capped(stderr, &over))
        };
        let started = Instant::now();
        let ended = loop {
            if let Some(status) = child.try_wait().map_err(io_error)? {
                break Some(status);
            }
            if over.load(Ordering::Relaxed) || started.elapsed() > run.timeout {
                child.kill().ok();
                child.wait().ok();
                break None;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let stdout = out.join().unwrap_or_default();
        let stderr = err.join().unwrap_or_default();
        use std::os::unix::process::ExitStatusExt;
        let status = match ended {
            _ if over.load(Ordering::Relaxed) => ToolStatus::Stopped(ToolStop::Output),
            None => ToolStatus::Stopped(ToolStop::Timeout),
            Some(status) => match (status.code(), status.signal()) {
                (Some(code), _) => ToolStatus::Exited(code),
                (None, Some(SIGXFSZ)) => ToolStatus::Stopped(ToolStop::FileSize),
                (None, Some(signal)) => ToolStatus::Signaled(signal),
                (None, None) => ToolStatus::Exited(-1),
            },
        };
        let staged: Vec<String> = run.stage.iter().map(|s| s.name.clone()).collect();
        let outputs = match status {
            ToolStatus::Stopped(_) if !run.keep_stopped => BTreeMap::new(),
            _ => collect_outputs(
                &workdir,
                &run.keep,
                &staged,
                &self.dir.path().join(format!("kept-{n}")),
            )
            .map_err(io_error)?,
        };
        fs::remove_dir_all(&workdir).ok();
        Ok(ToolOutput {
            status,
            stdout,
            stderr,
            outputs,
        })
    }
}

/// SIGXFSZ, on the architectures the pools run on.
const SIGXFSZ: i32 = 25;

/// Reads a pipe up to `MAX_OUTPUT_BYTES`, and sets `over` when it held more.
fn read_capped(mut pipe: impl Read, over: &AtomicBool) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut limited = (&mut pipe).take(MAX_OUTPUT_BYTES + 1);
    limited.read_to_end(&mut bytes).ok();
    if bytes.len() as u64 > MAX_OUTPUT_BYTES {
        over.store(true, Ordering::Relaxed);
        bytes.truncate(MAX_OUTPUT_BYTES as usize);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_sets_only_the_variables_its_tool_allows() {
        let spec = find(SANDBOX_TOOLS, "tesseract").unwrap();
        let run = ToolRun::new("tesseract", ["a"]).env("OMP_THREAD_LIMIT", "1");
        let env = environment(spec, &run, Path::new("/w")).unwrap();
        assert!(env.contains(&("OMP_THREAD_LIMIT".to_owned(), "1".to_owned())));
        assert!(env.contains(&("HOME".to_owned(), "/w".to_owned())));
        let run = ToolRun::new("tesseract", ["a"]).env("LD_PRELOAD", "/x.so");
        assert!(matches!(
            environment(spec, &run, Path::new("/w")),
            Err(ToolError::Refused(_))
        ));
    }

    #[test]
    fn a_run_keeps_and_stages_only_plain_names() {
        for bad in ["", ".", "..", "a/b", "../x"] {
            assert!(
                check_keep(&ToolRun::new("t", ["a"]).keep(bad)).is_err(),
                "{bad}"
            );
            assert!(
                check_keep(&ToolRun::new("t", ["a"]).stage("/x", bad)).is_err(),
                "{bad}"
            );
        }
        assert!(check_keep(&ToolRun::new("t", ["a"]).keep("output.txt")).is_ok());
    }

    #[test]
    fn only_plain_files_with_one_link_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("plain"), "x").unwrap();
        fs::write(work.join("linked"), "y").unwrap();
        fs::hard_link(work.join("linked"), dir.path().join("other")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", work.join("symlink")).unwrap();
        fs::create_dir(work.join("dir")).unwrap();
        fs::write(work.join("dir/inner"), "z").unwrap();
        fs::write(work.join("staged"), "s").unwrap();
        let kept = collect_outputs(
            &work,
            &Keep::All,
            &["staged".to_owned()],
            &dir.path().join("kept"),
        )
        .unwrap();
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["plain"]);
        let kept = collect_outputs(
            &work,
            &Keep::Named(vec!["missing".to_owned(), "symlink".to_owned()]),
            &[],
            &dir.path().join("kept"),
        )
        .unwrap();
        assert!(kept.is_empty());
        let kept = collect_outputs(
            &work,
            &Keep::Tree,
            &["staged".to_owned()],
            &dir.path().join("tree"),
        )
        .unwrap();
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["dir/inner"]);
        assert_eq!(
            fs::read_to_string(dir.path().join("tree/dir/inner")).unwrap(),
            "z"
        );
    }

    #[test]
    fn a_tree_too_deep_for_a_system_call_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("work");
        fs::create_dir(&work).unwrap();
        fs::write(work.join("shallow"), "x").unwrap();
        // 20 folders of 250 characters, made a folder at a time below the last, as 7z makes them,
        // each by the short path its descriptor has in /proc
        use std::os::fd::AsRawFd;
        let name = "d".repeat(250);
        let mut folder = fs::File::open(&work).unwrap();
        for _ in 0..20 {
            let below = format!("/proc/self/fd/{}/{name}", folder.as_raw_fd());
            fs::create_dir(&below).unwrap();
            folder = fs::File::open(&below).unwrap();
        }
        fs::write(format!("/proc/self/fd/{}/leaf", folder.as_raw_fd()), "deep").unwrap();
        let kept = collect_outputs(&work, &Keep::Tree, &[], &dir.path().join("tree")).unwrap();
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["shallow"]);
    }

    #[test]
    fn returncodes_are_the_launchers() {
        let output = |status| ToolOutput {
            status,
            stdout: Vec::new(),
            stderr: Vec::new(),
            outputs: BTreeMap::new(),
        };
        assert_eq!(output(ToolStatus::Exited(3)).returncode(), Some(3));
        assert_eq!(output(ToolStatus::Signaled(24)).returncode(), Some(152));
        assert_eq!(
            output(ToolStatus::Stopped(ToolStop::Timeout)).returncode(),
            None
        );
    }

    #[test]
    fn text_is_utf8_with_errors_replaced_and_stderr_its_end() {
        let output = ToolOutput {
            status: ToolStatus::Exited(0),
            stdout: b"a\r\nb\xff".to_vec(),
            stderr: [vec![b'x'; STDERR_TAIL_BYTES], b"end".to_vec()].concat(),
            outputs: BTreeMap::new(),
        };
        assert_eq!(output.stdout_text(), "a\r\nb\u{fffd}");
        let stderr = output.stderr_text();
        assert_eq!(stderr.len(), STDERR_TAIL_BYTES);
        assert!(stderr.ends_with("xend"));
    }
}
