//! The seccomp filters: the parser's, which stops a contained task from starting a thread or a
//! process, and the tool filter (`install_tool_filter`), which lets a tool the sandbox runner execs
//! start threads but not processes.
//!
//! It is a short classic BPF program, written out here rather than built with a crate, because a
//! deny list on x86_64 also has to refuse x32 calls (see `Arch::kill_x32`), and seccompiler
//! doesn't. A blocked call kills the whole process (`SECCOMP_RET_KILL_PROCESS`), so it dies of
//! SIGSYS and the supervisor sees why. Other filters already on the process, such as Docker's,
//! still apply; the kernel takes the strictest answer.

use std::io;
use std::mem::offset_of;

use std::os::fd::{FromRawFd, OwnedFd};

use libc::{
    BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W,
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_USER_NOTIF,
    seccomp_data, sock_filter, sock_fprog,
};

/// What the filter blocks on one architecture.
struct Arch {
    /// The `AUDIT_ARCH_*` value the kernel gives this architecture's own calls. A call from any
    /// other ABI, such as 32-bit x86 through `int 0x80`, kills the process.
    audit_arch: u32,
    /// The calls that start a process or a thread, or that make the kernel start worker threads
    /// for the process (io_uring), with their numbers on this architecture.
    blocked: &'static [(&'static str, u32)],
    /// x86_64 only: kill any call with the x32 bit set. x32 calls carry the x86_64 audit arch but
    /// their own numbers, so a deny list that didn't check would let x32's execve through.
    kill_x32: bool,
    /// The numbers the tool filter reads: `clone`, `clone3`, `execve`, `execveat` and `socket`.
    tool: ToolCalls,
}

/// The calls the tool filter treats apart, by their numbers on one architecture.
struct ToolCalls {
    clone: u32,
    clone3: u32,
    execve: u32,
    execveat: u32,
    socket: u32,
    /// The calls that start a process, which kill it: `fork` and `vfork` where they exist, and
    /// `io_uring_setup`, whose worker threads would make calls the filter doesn't see.
    process: &'static [(&'static str, u32)],
}

/// `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`, from the kernel's `audit.h`.
#[cfg_attr(not(any(test, target_arch = "x86_64")), allow(dead_code))]
const X86_64: Arch = Arch {
    audit_arch: 0xc000_003e,
    blocked: &[
        ("clone", 56),
        ("fork", 57),
        ("vfork", 58),
        ("execve", 59),
        ("execveat", 322),
        ("io_uring_setup", 425),
        ("clone3", 435),
    ],
    kill_x32: true,
    tool: ToolCalls {
        clone: 56,
        clone3: 435,
        execve: 59,
        execveat: 322,
        socket: 41,
        process: &[("fork", 57), ("vfork", 58), ("io_uring_setup", 425)],
    },
};

/// `EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`. arm64 has no fork or vfork call; glibc
/// makes both with clone.
#[cfg_attr(not(any(test, target_arch = "aarch64")), allow(dead_code))]
const AARCH64: Arch = Arch {
    audit_arch: 0xc000_00b7,
    blocked: &[
        ("clone", 220),
        ("execve", 221),
        ("execveat", 281),
        ("io_uring_setup", 425),
        ("clone3", 435),
    ],
    kill_x32: false,
    tool: ToolCalls {
        clone: 220,
        clone3: 435,
        execve: 221,
        execveat: 281,
        socket: 198,
        process: &[("io_uring_setup", 425)],
    },
};

#[cfg(target_arch = "x86_64")]
const NATIVE: Arch = X86_64;
#[cfg(target_arch = "aarch64")]
const NATIVE: Arch = AARCH64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the seccomp filter knows the system call numbers of x86_64 and aarch64 only");

const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Installs the filter on the process. It must be the last step of containment: the filter stays
/// for the life of the process.
pub(super) fn install() -> io::Result<()> {
    let filter = program(&NATIVE);
    let program = sock_fprog {
        len: u16::try_from(filter.len()).expect("the filter is a few instructions long"),
        // the kernel only reads it, and the field is `*mut` because the struct is C's
        filter: filter.as_ptr().cast_mut(),
    };
    // TSYNC puts the filter on every thread, or fails naming the one that can't take it.
    // SAFETY: the kernel copies the program during the call, and `filter` outlives the call.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &program as *const sock_fprog,
        )
    };
    match result {
        0 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        thread => Err(io::Error::other(format!(
            "thread {thread} could not take the filter"
        ))),
    }
}

/// Installs the tool filter on this process, which must run one thread, and returns its listener:
/// the descriptor through which the supervisor answers each `execve` and `execveat` (see
/// `tool_program`). It must be the last step before the exec.
pub(super) fn install_tool_filter() -> io::Result<OwnedFd> {
    let filter = tool_program(&NATIVE);
    let program = sock_fprog {
        len: u16::try_from(filter.len()).expect("the filter is a few dozen instructions long"),
        filter: filter.as_ptr().cast_mut(),
    };
    // No TSYNC: the kernel refuses it with a listener, and the process has one thread.
    // SAFETY: the kernel copies the program during the call, and `filter` outlives the call.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::c_ulong::from(libc::SECCOMP_SET_MODE_FILTER),
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &program as *const sock_fprog,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(fd).map_err(io::Error::other)?;
    // SAFETY: the call returned a new descriptor, which nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `CLONE_THREAD | CLONE_VM`: a thread shares its process's memory and is one of its threads.
const THREAD_FLAGS: u32 = (libc::CLONE_THREAD | libc::CLONE_VM) as u32;

/// The tool filter. As the parser's, it kills a call from a foreign architecture or from x32. Then:
///
/// - `clone` with both `CLONE_THREAD` and `CLONE_VM` (a thread) is allowed, and any other `clone`
///   (a process) kills the tool. Its flags are the low 32 bits of its first argument on both
///   architectures, and the kernel ignores the high ones.
/// - `clone3` fails with ENOSYS: its flags are in memory seccomp can't read. glibc then falls back to
///   `clone`, for a thread and for a process.
/// - `fork`, `vfork` and `io_uring_setup` kill it.
/// - `execve` and `execveat` go to the supervisor, which lets the first through (the runner's own
///   exec of the tool) and kills the tool at any other.
/// - `socket` fails with EACCES for every family but `AF_UNIX`: a tool has no network, and Landlock
///   doesn't cover UDP.
/// - Everything else is allowed.
fn tool_program(arch: &Arch) -> Vec<sock_filter> {
    let calls = &arch.tool;
    let mut code = Assembler::default();
    code.push(load(offset_of!(seccomp_data, arch)));
    code.jump_unless(arch.audit_arch, "kill");
    code.push(load(offset_of!(seccomp_data, nr)));
    if arch.kill_x32 {
        code.jump_if_at_least(X32_SYSCALL_BIT, "kill");
    }
    code.jump_if(calls.clone, "clone");
    code.jump_if(calls.clone3, "enosys");
    code.jump_if(calls.execve, "notify");
    code.jump_if(calls.execveat, "notify");
    code.jump_if(calls.socket, "socket");
    for &(_, number) in calls.process {
        code.jump_if(number, "kill");
    }
    code.push(ret(SECCOMP_RET_ALLOW));
    code.label("clone");
    code.push(load(offset_of!(seccomp_data, args)));
    code.push(statement(BPF_ALU | BPF_AND | BPF_K, THREAD_FLAGS));
    code.jump_unless(THREAD_FLAGS, "kill");
    code.push(ret(SECCOMP_RET_ALLOW));
    code.label("socket");
    code.push(load(offset_of!(seccomp_data, args)));
    code.jump_unless(libc::AF_UNIX as u32, "eacces");
    code.push(ret(SECCOMP_RET_ALLOW));
    code.label("eacces");
    code.push(ret(SECCOMP_RET_ERRNO | libc::EACCES as u32));
    code.label("enosys");
    code.push(ret(SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
    code.label("notify");
    code.push(ret(SECCOMP_RET_USER_NOTIF));
    code.label("kill");
    code.push(ret(SECCOMP_RET_KILL_PROCESS));
    code.finish()
}

/// Builds a classic BPF program whose jumps go forward to labels.
#[derive(Default)]
struct Assembler {
    program: Vec<sock_filter>,
    /// Each jump's index, its label, and whether the label is its true branch.
    jumps: Vec<(usize, &'static str, bool)>,
    labels: Vec<(&'static str, usize)>,
}

impl Assembler {
    fn push(&mut self, instruction: sock_filter) {
        self.program.push(instruction);
    }

    /// To `label` when the accumulator equals `value`.
    fn jump_if(&mut self, value: u32, label: &'static str) {
        self.jumps.push((self.program.len(), label, true));
        self.push(jump(BPF_JEQ, value, 0, 0));
    }

    /// To `label` unless the accumulator equals `value`.
    fn jump_unless(&mut self, value: u32, label: &'static str) {
        self.jumps.push((self.program.len(), label, false));
        self.push(jump(BPF_JEQ, value, 0, 0));
    }

    /// To `label` when the accumulator is `value` or more.
    fn jump_if_at_least(&mut self, value: u32, label: &'static str) {
        self.jumps.push((self.program.len(), label, true));
        self.push(jump(BPF_JGE, value, 0, 0));
    }

    fn label(&mut self, name: &'static str) {
        self.labels.push((name, self.program.len()));
    }

    fn finish(mut self) -> Vec<sock_filter> {
        for &(at, label, when_true) in &self.jumps {
            let target = self
                .labels
                .iter()
                .find(|(name, _)| *name == label)
                .map(|&(_, index)| index)
                .expect("every jump has its label");
            let offset = u8::try_from(target - at - 1).expect("the filter is short");
            if when_true {
                self.program[at].jt = offset;
            } else {
                self.program[at].jf = offset;
            }
        }
        self.program
    }
}

/// Load the architecture, kill on a foreign one, load the call number, kill on x32 (x86_64 only)
/// or on a blocked call, and allow everything else.
fn program(arch: &Arch) -> Vec<sock_filter> {
    let calls = arch.blocked;
    let to_kill = |instructions_between: usize| {
        u8::try_from(instructions_between).expect("the filter blocks a few calls")
    };
    let blocked = calls.len();
    let mut program = vec![
        load(offset_of!(seccomp_data, arch)),
        jump(BPF_JEQ, arch.audit_arch, 1, 0),
        ret(SECCOMP_RET_KILL_PROCESS),
        load(offset_of!(seccomp_data, nr)),
    ];
    if arch.kill_x32 {
        // past the blocked calls and the allow, to the kill
        program.push(jump(BPF_JGE, X32_SYSCALL_BIT, to_kill(blocked + 1), 0));
    }
    for (index, &(_, number)) in calls.iter().enumerate() {
        // past the rest of the blocked calls and the allow, to the kill
        program.push(jump(BPF_JEQ, number, to_kill(blocked - index), 0));
    }
    program.push(ret(SECCOMP_RET_ALLOW));
    program.push(ret(SECCOMP_RET_KILL_PROCESS));
    program
}

fn load(offset: usize) -> sock_filter {
    statement(
        BPF_LD | BPF_W | BPF_ABS,
        u32::try_from(offset).expect("seccomp_data is small"),
    )
}

/// Compare the accumulator with `value` and skip `if_true` or `if_false` instructions.
fn jump(comparison: u32, value: u32, if_true: u8, if_false: u8) -> sock_filter {
    sock_filter {
        code: opcode(BPF_JMP | comparison | BPF_K),
        jt: if_true,
        jf: if_false,
        k: value,
    }
}

fn ret(action: u32) -> sock_filter {
    statement(BPF_RET | BPF_K, action)
}

fn statement(code: u32, k: u32) -> sock_filter {
    sock_filter {
        code: opcode(code),
        jt: 0,
        jf: 0,
        k,
    }
}

fn opcode(code: u32) -> u16 {
    u16::try_from(code).expect("classic BPF opcodes fit in 16 bits")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a filter the way the kernel would, for the instructions `program` uses.
    fn verdict(program: &[sock_filter], arch: u32, number: u32) -> u32 {
        verdict_with(program, arch, number, 0)
    }

    /// `verdict` for a call whose first argument's low 32 bits are `arg0`.
    fn verdict_with(program: &[sock_filter], arch: u32, number: u32, arg0: u32) -> u32 {
        let arch_offset = offset_of!(seccomp_data, arch) as u32;
        let number_offset = offset_of!(seccomp_data, nr) as u32;
        let arg_offset = offset_of!(seccomp_data, args) as u32;
        let mut accumulator = 0;
        let mut pc = 0;
        loop {
            let instruction = program[pc];
            let code = u32::from(instruction.code);
            pc += 1;
            if code == BPF_LD | BPF_W | BPF_ABS {
                accumulator = match instruction.k {
                    k if k == arch_offset => arch,
                    k if k == number_offset => number,
                    k if k == arg_offset => arg0,
                    k => panic!("load from offset {k}"),
                };
            } else if code == BPF_RET | BPF_K {
                return instruction.k;
            } else if code == BPF_ALU | BPF_AND | BPF_K {
                accumulator &= instruction.k;
            } else {
                let taken = match code {
                    c if c == BPF_JMP | BPF_JEQ | BPF_K => accumulator == instruction.k,
                    c if c == BPF_JMP | BPF_JGE | BPF_K => accumulator >= instruction.k,
                    c => panic!("instruction {c:#x}"),
                };
                pc += usize::from(if taken {
                    instruction.jt
                } else {
                    instruction.jf
                });
            }
        }
    }

    fn check(arch: &Arch, allowed: &[u32]) {
        let program = program(arch);
        for &(name, number) in arch.blocked {
            assert_eq!(
                verdict(&program, arch.audit_arch, number),
                SECCOMP_RET_KILL_PROCESS,
                "{name}"
            );
        }
        for &number in allowed {
            assert_eq!(
                verdict(&program, arch.audit_arch, number),
                SECCOMP_RET_ALLOW,
                "call {number}"
            );
        }
        // the same numbers under another ABI, here 32-bit ARM's audit arch
        for &number in allowed {
            assert_eq!(
                verdict(&program, 0x4000_0028, number),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn x86_64_blocks_new_processes_and_threads_and_allows_the_rest() {
        // read, write, mmap, openat, connect, exit_group
        check(&X86_64, &[0, 1, 9, 257, 42, 231]);
    }

    #[test]
    fn x86_64_kills_x32_calls() {
        let program = program(&X86_64);
        // x32's execve is 520, and its read is 0
        for number in [520, 0] {
            assert_eq!(
                verdict(&program, X86_64.audit_arch, X32_SYSCALL_BIT | number),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn aarch64_blocks_new_processes_and_threads_and_allows_the_rest() {
        // read, write, mmap, openat, connect, exit_group
        check(&AARCH64, &[63, 64, 222, 56, 203, 94]);
    }

    #[test]
    fn the_native_numbers_match_libc() {
        #[cfg(target_arch = "x86_64")]
        let fork = [("fork", libc::SYS_fork), ("vfork", libc::SYS_vfork)];
        #[cfg(not(target_arch = "x86_64"))]
        let fork = [];
        let expected: Vec<_> = [
            ("clone", libc::SYS_clone),
            ("execve", libc::SYS_execve),
            ("execveat", libc::SYS_execveat),
            ("io_uring_setup", libc::SYS_io_uring_setup),
            ("clone3", libc::SYS_clone3),
        ]
        .into_iter()
        .chain(fork)
        .collect();
        assert_eq!(NATIVE.blocked.len(), expected.len());
        for (name, number) in expected {
            let ours = NATIVE.blocked.iter().find(|&&(n, _)| n == name);
            assert_eq!(ours.map(|&(_, n)| i64::from(n)), Some(number), "{name}");
        }
    }

    fn check_tool_filter(arch: &Arch, allowed: &[u32]) {
        let program = tool_program(arch);
        let calls = &arch.tool;
        let run = |number, arg0| verdict_with(&program, arch.audit_arch, number, arg0);
        let thread = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u32;
        assert_eq!(run(calls.clone, thread), SECCOMP_RET_ALLOW, "a thread");
        // glibc's fork, posix_spawn's vfork-like clone, and a thread flag without shared memory
        let fork = (libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID) as u32 | 17;
        let spawn = (libc::CLONE_VM | libc::CLONE_VFORK) as u32 | 17;
        let no_vm = (libc::CLONE_THREAD | libc::CLONE_SIGHAND) as u32;
        for flags in [fork, spawn, no_vm, 0] {
            assert_eq!(
                run(calls.clone, flags),
                SECCOMP_RET_KILL_PROCESS,
                "clone {flags:#x}"
            );
        }
        assert_eq!(
            run(calls.clone3, 0),
            SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
        for number in [calls.execve, calls.execveat] {
            assert_eq!(run(number, 0), SECCOMP_RET_USER_NOTIF);
        }
        for &(name, number) in calls.process {
            assert_eq!(run(number, 0), SECCOMP_RET_KILL_PROCESS, "{name}");
        }
        assert_eq!(run(calls.socket, libc::AF_UNIX as u32), SECCOMP_RET_ALLOW);
        for family in [
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_NETLINK,
            libc::AF_PACKET,
        ] {
            assert_eq!(
                run(calls.socket, family as u32),
                SECCOMP_RET_ERRNO | libc::EACCES as u32,
                "family {family}"
            );
        }
        for &number in allowed {
            assert_eq!(run(number, 0), SECCOMP_RET_ALLOW, "call {number}");
            assert_eq!(
                verdict_with(&program, 0x4000_0028, number, 0),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn the_x86_64_tool_filter_lets_threads_through_and_kills_processes() {
        check_tool_filter(&X86_64, &[0, 1, 9, 257, 42, 231]);
        let program = tool_program(&X86_64);
        assert_eq!(
            verdict_with(&program, X86_64.audit_arch, X32_SYSCALL_BIT | 59, 0),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn the_aarch64_tool_filter_lets_threads_through_and_kills_processes() {
        check_tool_filter(&AARCH64, &[63, 64, 222, 56, 203, 94]);
    }

    #[test]
    fn the_native_tool_numbers_match_libc() {
        let calls = &NATIVE.tool;
        assert_eq!(i64::from(calls.clone), libc::SYS_clone);
        assert_eq!(i64::from(calls.clone3), libc::SYS_clone3);
        assert_eq!(i64::from(calls.execve), libc::SYS_execve);
        assert_eq!(i64::from(calls.execveat), libc::SYS_execveat);
        assert_eq!(i64::from(calls.socket), libc::SYS_socket);
    }
}
