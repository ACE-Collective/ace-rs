//! Containment of a hostile task (PLAN.md 2.18, DESIGN.md's "Containing hostile tasks").
//!
//! A parser's task process calls `contain` on itself once its setup is done and before the module
//! touches its input. `contain` takes a `SandboxProfile` and, in this order:
//!
//! 1. Checks that the process runs one thread. Before Landlock ABI 8 (Linux 7.0) Landlock
//!    restricts only the thread that applies it, so a thread started earlier would escape the
//!    rules. Containment refuses such a process instead.
//! 2. Sets rlimits: the address space (`RLIMIT_AS`), CPU time (`RLIMIT_CPU`: SIGXCPU at the limit
//!    and SIGKILL a second later) and core files (`RLIMIT_CORE` 0, so a killed task writes none).
//! 3. Sets `no_new_privs`, which Landlock and seccomp both need without `CAP_SYS_ADMIN`.
//! 4. Applies Landlock rules. The task may read beneath its read paths, read and write beneath
//!    its write paths and connect to its TCP ports. Every other open, file change, TCP connect and
//!    TCP bind is refused, mostly with EACCES. Where the kernel has ABI 6, the task also can't
//!    signal a process outside its Landlock domain or connect to an abstract Unix socket made
//!    outside it.
//! 5. Installs a seccomp filter that kills the process when it calls fork, vfork, clone, clone3,
//!    execve, execveat or io_uring_setup.
//!
//! After that the process can't start a thread or a process. It stays one thread with no
//! children, so killing its PID ends all of it (#981).
//!
//! `contain_tool` is the variant for a tool the sandbox runner runs (PLAN.md 7.3, `crate::tools`):
//! `contain_before_exec`, which 4.13 removed, brought back with a filter that lets threads through.
//! The pool's binary, exec'd as the task's user in its `tool` mode and running one thread, contains
//! itself and then execs the tool, and all of it holds through that exec and for every thread the
//! tool starts. It sets the CPU-time, file-size, open-file and core-file limits and `no_new_privs`,
//! and no address-space limit: the supervisor bounds the memory a tool uses instead, which a runtime
//! reserving gigabytes it never touches doesn't reach (`crate::tools`, *Memory*); Landlock lets the tool read only what its profile names (the program and its
//! libraries, its data, and the task's files the request names), write only its working directory,
//! run only the program, its interpreter and the dynamic loader, and connect to no TCP port; and the
//! tool filter (`seccomp::install_tool_filter`) allows a thread, kills a new process, refuses a socket
//! that isn't `AF_UNIX`, and hands every exec to the supervisor through its listener, which lets only
//! the first through.
//!
//! `contain_pool` is the variant for an async pool's process (PLAN.md 2.16), which runs many
//! lookups at once on tokio's threads. It applies the same Landlock rules and the address-space
//! and core-file limits, before the runtime starts any thread, so every thread the runtime
//! starts later inherits them. It leaves out the seccomp filter, because tokio needs to start
//! threads, and the CPU-time limit, which would count the whole life of a process that serves
//! for days.
//!
//! How a test task sees each forbidden action:
//!
//! - fork, exec or a new thread: the process dies of SIGSYS.
//! - opening a file outside its paths, or connecting to a TCP port it isn't allowed: the call
//!   fails with EACCES.
//! - allocating past the address-space limit: the allocation fails, and Rust's allocator aborts
//!   the process (SIGABRT, "memory allocation of N bytes failed").
//! - running past the CPU-time limit: SIGXCPU.
//!
//! # Libraries that start threads
//!
//! A library that starts a thread after `contain` kills the task with SIGSYS. Known ones:
//! unrar built with `RAR_SMP` (as unrar_sys builds it) on a RAR 5 archive, yara-x's heartbeat
//! thread when a scan has a timeout, and tokio's multi-thread runtime and `spawn_blocking`, which
//! `tokio::fs` and DNS lookups use. Threads started before `contain` make it fail instead.
//!
//! # What containment does not cover
//!
//! - UDP, and so DNS: Landlock filters TCP only. A contained task can send datagrams anywhere
//!   its container's network reaches. `getaddrinfo` fails, because Landlock refuses
//!   `/etc/hosts` and `/etc/resolv.conf`, but a query sent straight to a resolver's address
//!   gets out.
//! - `listen` on a TCP socket that was never bound. The kernel gives it an ephemeral port
//!   without a bind call, so the task can accept connections.
//! - Raw and packet sockets, when the process keeps `CAP_NET_RAW`, which Docker grants a root
//!   process by default. Run task processes as a user without capabilities.
//! - Connecting to a pathname Unix socket. Landlock ABI 9 (Linux 7.1) adds a right for it.
//! - Metadata: `stat` and `readlink` work on any path, so a task can learn which files exist.
//!   Opening or listing anything outside its paths, `/proc`, `/sys` and `/dev` included, is
//!   refused.
//! - File descriptors that were open before `contain`, such as stdin and stdout. Landlock checks
//!   a file when it is opened.
//! - Calls on other processes of the same user that Landlock has no hook for, such as
//!   `prlimit64`, `setpriority` and `sched_setaffinity`. Running each task as its own user
//!   closes these.

use std::fs;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use ace_sdk::{Manifest, Resources, Sandbox};
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, LandlockStatus, NetPort,
    PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
    Scope,
};

mod seccomp;

/// The Landlock ABI containment can't do without: ABI 4 (Linux 6.7) is the first with TCP port
/// rules. On an older kernel `contain` fails.
const REQUIRED_LANDLOCK_ABI: ABI = ABI::V4;

/// The newest Landlock ABI whose rights containment asks for, on kernels that have them: device
/// ioctls (ABI 5) and the signal and abstract Unix socket scopes (ABI 6). ABI 7 adds only audit
/// logging. It is the ABI of the kernel the tests ran on (Linux 6.18). Raise it on purpose, after
/// testing on a kernel that has the new ABI.
const TARGET_LANDLOCK_ABI: ABI = ABI::V7;

/// What a contained task may touch.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxProfile {
    /// Files and directories the task may read, with everything beneath them.
    pub read_paths: Vec<PathBuf>,
    /// Files and directories the task may read, write, create, rename and remove things beneath.
    pub write_paths: Vec<PathBuf>,
    /// TCP ports the task may connect to, on any address. It may bind none.
    pub tcp_ports: Vec<u16>,
    /// The address-space limit in bytes (`RLIMIT_AS`). It counts every mapping, including the
    /// binary, its libraries and its thread stack, not only the heap.
    pub address_space_bytes: u64,
    /// The CPU-time limit in seconds (`RLIMIT_CPU`), counted from the start of the process.
    pub cpu_seconds: u64,
}

impl SandboxProfile {
    /// The limits in `resources` and the TCP ports `sandbox` allows, with no paths yet. The
    /// supervisor adds the task's own paths, such as its input file and its output directory.
    pub fn new(resources: Resources, sandbox: Sandbox) -> Self {
        let tcp_ports = match sandbox {
            Sandbox::Contained => Vec::new(),
            Sandbox::Network { tcp_ports } => tcp_ports.to_vec(),
        };
        SandboxProfile {
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            tcp_ports,
            address_space_bytes: resources.memory_mb.saturating_mul(1024 * 1024),
            cpu_seconds: resources.cpu_seconds,
        }
    }

    /// The profile a module's manifest asks for. A lookup's memory limit is its pool's, not a
    /// process's (see `Resources::memory_mb`), so 2.16 decides what applies to an async pool.
    pub fn for_manifest(manifest: &Manifest) -> Self {
        SandboxProfile::new(manifest.resources, manifest.sandbox)
    }

    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.read_paths.push(path.into());
        self
    }

    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.write_paths.push(path.into());
        self
    }

    /// Allows reading `path` if it exists, for files a process may need on one system and not
    /// another, such as `/etc/gai.conf`.
    pub fn allow_read_if_exists(self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if path.exists() {
            self.allow_read(path)
        } else {
            self
        }
    }

    pub fn allow_port(mut self, port: u16) -> Self {
        if !self.tcp_ports.contains(&port) {
            self.tcp_ports.push(port);
        }
        self
    }
}

/// What `contain` enforced, for the task's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contained {
    /// The newest Landlock ABI that both the kernel and the landlock crate know.
    pub landlock_abi: ABI,
    /// False when the kernel lacks some right that `TARGET_LANDLOCK_ABI` adds over ABI 4, such as
    /// the signal scope. Everything else still applies.
    pub landlock_fully_enforced: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ContainmentError {
    #[error("containment needs a single-threaded process, and this one runs {0} threads")]
    Threads(usize),
    #[error("counting this process's threads: {0}")]
    CountThreads(io::Error),
    #[error("setting {name}: {source}")]
    Rlimit {
        name: &'static str,
        source: io::Error,
    },
    #[error("setting no_new_privs: {0}")]
    NoNewPrivs(io::Error),
    #[error("allowing {path}: {source}")]
    Path { path: PathBuf, source: io::Error },
    #[error("Landlock: {0}")]
    Landlock(#[from] RulesetError),
    #[error("Landlock: the kernel enforced none of the rules")]
    LandlockNotEnforced,
    #[error("installing the seccomp filter: {0}")]
    Seccomp(io::Error),
}

/// Contains the calling process for the rest of its life. See the module docs for what that
/// means. On an error the process may be partly contained, so it must not run the task.
pub fn contain(profile: &SandboxProfile) -> Result<Contained, ContainmentError> {
    let threads = count_threads().map_err(ContainmentError::CountThreads)?;
    if threads != 1 {
        return Err(ContainmentError::Threads(threads));
    }
    set_rlimits(profile)?;
    set_no_new_privs()?;
    let contained = restrict_files_and_ports(profile)?;
    seccomp::install().map_err(ContainmentError::Seccomp)?;
    Ok(contained)
}

/// Contains an async pool's process for the rest of its life: the single-thread check, the
/// address-space and core-file limits, `no_new_privs` and the Landlock rules, but no seccomp
/// filter and no CPU-time limit (see the module docs). Call it before starting the runtime.
pub fn contain_pool(profile: &SandboxProfile) -> Result<Contained, ContainmentError> {
    let threads = count_threads().map_err(ContainmentError::CountThreads)?;
    if threads != 1 {
        return Err(ContainmentError::Threads(threads));
    }
    let bytes = profile.address_space_bytes;
    set_rlimit(libc::RLIMIT_AS, "RLIMIT_AS", bytes, bytes)?;
    set_rlimit(libc::RLIMIT_CORE, "RLIMIT_CORE", 0, 0)?;
    set_no_new_privs()?;
    restrict_files_and_ports(profile)
}

/// What a tool may touch once `contain_tool` applies, each path already open: a descriptor holds
/// the file or directory it was opened on, whatever its path later names.
#[derive(Debug, Default)]
pub struct ToolProfile {
    /// Files and directories it may read, with everything beneath them.
    pub reads: Vec<OwnedFd>,
    /// Files it may read and write, such as `/dev/null`.
    pub read_write_files: Vec<OwnedFd>,
    /// The directory it may read, write, create and remove things beneath: its working directory.
    pub writes: Vec<OwnedFd>,
    /// The files it may run: the program, its interpreter and the dynamic loader.
    pub executes: Vec<OwnedFd>,
    /// `RLIMIT_CPU`, which counts the CPU time of every thread.
    pub cpu_seconds: u64,
    /// `RLIMIT_FSIZE`: SIGXFSZ at a write past it.
    pub file_size_bytes: u64,
    /// `RLIMIT_NOFILE`.
    pub open_files: u64,
}

/// Contains this process for the tool it execs next (see the module docs), and returns the tool
/// filter's listener, which the supervisor must hold and answer for the exec to go ahead. On an
/// error the process may be partly contained, so it must not exec the tool.
pub fn contain_tool(profile: &ToolProfile) -> Result<(Contained, OwnedFd), ContainmentError> {
    let threads = count_threads().map_err(ContainmentError::CountThreads)?;
    if threads != 1 {
        return Err(ContainmentError::Threads(threads));
    }
    let seconds = profile.cpu_seconds;
    set_rlimit(
        libc::RLIMIT_CPU,
        "RLIMIT_CPU",
        seconds,
        seconds.saturating_add(1),
    )?;
    let size = profile.file_size_bytes;
    set_rlimit(libc::RLIMIT_FSIZE, "RLIMIT_FSIZE", size, size)?;
    let files = profile.open_files;
    set_rlimit(libc::RLIMIT_NOFILE, "RLIMIT_NOFILE", files, files)?;
    set_rlimit(libc::RLIMIT_CORE, "RLIMIT_CORE", 0, 0)?;
    set_no_new_privs()?;
    let contained = restrict_tool(profile)?;
    let listener = seccomp::install_tool_filter().map_err(ContainmentError::Seccomp)?;
    Ok((contained, listener))
}

fn restrict_tool(profile: &ToolProfile) -> Result<Contained, ContainmentError> {
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED_LANDLOCK_ABI))?
        .handle_access(AccessNet::from_all(REQUIRED_LANDLOCK_ABI))?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(TARGET_LANDLOCK_ABI))?
        .scope(Scope::from_all(TARGET_LANDLOCK_ABI))?
        .create()?;
    for fd in &profile.reads {
        ruleset = ruleset.add_rule(fd_rule(fd, read_access())?)?;
    }
    for fd in &profile.read_write_files {
        ruleset = ruleset.add_rule(fd_rule(fd, AccessFs::ReadFile | AccessFs::WriteFile)?)?;
    }
    for fd in &profile.writes {
        ruleset = ruleset.add_rule(fd_rule(fd, write_access())?)?;
    }
    for fd in &profile.executes {
        ruleset = ruleset.add_rule(fd_rule(fd, AccessFs::ReadFile | AccessFs::Execute)?)?;
    }
    // no TCP port: every connect and bind is refused
    let status = ruleset.restrict_self()?;
    let landlock_abi = match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => effective_abi,
        _ => ABI::Unsupported,
    };
    match status.ruleset {
        RulesetStatus::NotEnforced => Err(ContainmentError::LandlockNotEnforced),
        enforced => Ok(Contained {
            landlock_abi,
            landlock_fully_enforced: enforced == RulesetStatus::FullyEnforced,
        }),
    }
}

/// A rule allowing `access` beneath the file or directory `fd` is open on, cut to a file's rights
/// for a file.
fn fd_rule(
    fd: &OwnedFd,
    access: BitFlags<AccessFs>,
) -> Result<PathBeneath<std::os::fd::BorrowedFd<'_>>, ContainmentError> {
    let error = |source| ContainmentError::Path {
        path: PathBuf::from(format!("descriptor {fd:?}")),
        source,
    };
    let file = fs::File::from(fd.try_clone().map_err(error)?);
    let is_dir = file.metadata().map_err(error)?.is_dir();
    let access = if is_dir {
        access
    } else {
        access & AccessFs::from_file(TARGET_LANDLOCK_ABI)
    };
    Ok(PathBeneath::new(fd.as_fd(), access))
}

/// The `Threads:` count in `/proc/self/status`.
fn count_threads() -> io::Result<usize> {
    let status = fs::read_to_string("/proc/self/status")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|count| count.trim().parse().ok())
        .ok_or_else(|| io::Error::other("/proc/self/status has no Threads line"))
}

fn set_rlimits(profile: &SandboxProfile) -> Result<(), ContainmentError> {
    let bytes = profile.address_space_bytes;
    set_rlimit(libc::RLIMIT_AS, "RLIMIT_AS", bytes, bytes)?;
    // SIGXCPU at the soft limit names the cause in the exit status. SIGKILL at the hard limit
    // ends a task that catches or ignores SIGXCPU.
    let seconds = profile.cpu_seconds;
    set_rlimit(
        libc::RLIMIT_CPU,
        "RLIMIT_CPU",
        seconds,
        seconds.saturating_add(1),
    )?;
    set_rlimit(libc::RLIMIT_CORE, "RLIMIT_CORE", 0, 0)
}

/// Sets a limit, never above the current hard limit, which only `CAP_SYS_RESOURCE` may raise.
fn set_rlimit(
    resource: libc::__rlimit_resource_t,
    name: &'static str,
    soft: u64,
    hard: u64,
) -> Result<(), ContainmentError> {
    let error = |source| ContainmentError::Rlimit { name, source };
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit struct, which lives for the call.
    if unsafe { libc::getrlimit(resource, &mut current) } != 0 {
        return Err(error(io::Error::last_os_error()));
    }
    let hard = hard.min(current.rlim_max);
    let limit = libc::rlimit {
        rlim_cur: soft.min(hard),
        rlim_max: hard,
    };
    // SAFETY: setrlimit reads one rlimit struct, which lives for the call.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(error(io::Error::last_os_error()));
    }
    Ok(())
}

fn set_no_new_privs() -> Result<(), ContainmentError> {
    let (yes, unused): (libc::c_ulong, libc::c_ulong) = (1, 0);
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, yes, unused, unused, unused) } != 0 {
        return Err(ContainmentError::NoNewPrivs(io::Error::last_os_error()));
    }
    Ok(())
}

/// What a read path allows.
fn read_access() -> BitFlags<AccessFs> {
    AccessFs::ReadFile | AccessFs::ReadDir
}

/// What a write path allows: reading, and making, changing, renaming and removing files,
/// directories and symlinks. Not running files, making device nodes, sockets or fifos, or ioctls
/// on devices.
fn write_access() -> BitFlags<AccessFs> {
    AccessFs::from_all(TARGET_LANDLOCK_ABI)
        & !(AccessFs::Execute
            | AccessFs::MakeChar
            | AccessFs::MakeBlock
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::IoctlDev)
}

fn restrict_files_and_ports(profile: &SandboxProfile) -> Result<Contained, ContainmentError> {
    // ABI 4's rights are a hard requirement. The newer ones apply where the kernel has them.
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(REQUIRED_LANDLOCK_ABI))?
        .handle_access(AccessNet::from_all(REQUIRED_LANDLOCK_ABI))?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(TARGET_LANDLOCK_ABI))?
        .scope(Scope::from_all(TARGET_LANDLOCK_ABI))?
        .create()?;
    for path in &profile.read_paths {
        ruleset = ruleset.add_rule(path_rule(path, read_access())?)?;
    }
    for path in &profile.write_paths {
        ruleset = ruleset.add_rule(path_rule(path, write_access())?)?;
    }
    for &port in &profile.tcp_ports {
        ruleset = ruleset.add_rule(NetPort::new(port, AccessNet::ConnectTcp))?;
    }
    let status = ruleset.restrict_self()?;

    let landlock_abi = match status.landlock {
        LandlockStatus::Available { effective_abi, .. } => effective_abi,
        _ => ABI::Unsupported,
    };
    match status.ruleset {
        RulesetStatus::NotEnforced => Err(ContainmentError::LandlockNotEnforced),
        enforced => Ok(Contained {
            landlock_abi,
            landlock_fully_enforced: enforced == RulesetStatus::FullyEnforced,
        }),
    }
}

/// A rule allowing `access` beneath `path`. The kernel refuses directory rights on a file, so a
/// file gets only the rights that apply to files.
fn path_rule(
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<PathBeneath<PathFd>, ContainmentError> {
    let error = |source| ContainmentError::Path {
        path: path.to_owned(),
        source,
    };
    let is_dir = fs::metadata(path).map_err(error)?.is_dir();
    let access = if is_dir {
        access
    } else {
        access & AccessFs::from_file(TARGET_LANDLOCK_ABI)
    };
    let fd = PathFd::new(path).map_err(|e| error(io::Error::other(e)))?;
    Ok(PathBeneath::new(fd, access))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn a_parser_profile_takes_its_limits_and_no_ports() {
        let resources = Resources {
            timeout: Duration::from_secs(60),
            memory_mb: 512,
            cpu_seconds: 30,
        };
        let profile = SandboxProfile::new(resources, Sandbox::Contained)
            .allow_read("/input")
            .allow_write("/output");
        assert_eq!(
            profile,
            SandboxProfile {
                read_paths: vec!["/input".into()],
                write_paths: vec!["/output".into()],
                tcp_ports: vec![],
                address_space_bytes: 512 * 1024 * 1024,
                cpu_seconds: 30,
            }
        );
    }

    #[test]
    fn a_lookup_profile_takes_its_ports() {
        let profile = SandboxProfile::new(
            Resources::DEFAULT,
            Sandbox::Network {
                tcp_ports: &[443, 8089],
            },
        );
        assert_eq!(profile.tcp_ports, [443, 8089]);
    }

    #[test]
    fn a_write_path_cannot_run_files_or_make_devices() {
        let write = write_access();
        assert!(write.contains(AccessFs::WriteFile | AccessFs::MakeReg | AccessFs::Truncate));
        for denied in [
            AccessFs::Execute,
            AccessFs::MakeChar,
            AccessFs::MakeBlock,
            AccessFs::IoctlDev,
        ] {
            assert!(!write.contains(denied), "{denied:?}");
        }
    }
}
