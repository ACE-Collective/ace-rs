//! The seccomp filter that stops a contained task from starting a thread or a process.
//!
//! It is a short classic BPF program, written out here rather than built with a crate, because a
//! deny list on x86_64 also has to refuse x32 calls (see `Arch::kill_x32`), and seccompiler
//! doesn't. A blocked call kills the whole process (`SECCOMP_RET_KILL_PROCESS`), so it dies of
//! SIGSYS and the supervisor sees why. Other filters already on the process, such as Docker's,
//! still apply; the kernel takes the strictest answer.

use std::io;
use std::mem::offset_of;

use libc::{
    BPF_ABS, BPF_JEQ, BPF_JGE, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, SECCOMP_RET_ALLOW,
    SECCOMP_RET_KILL_PROCESS, seccomp_data, sock_filter, sock_fprog,
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
    install_program(program(&NATIVE))
}

/// Installs the filter without its block on `execve`, for a process that contains itself and then
/// becomes a Python worker (`contain_before_exec`). The worker's Landlock rules decide what it could
/// run, and everything else stays blocked, so it still can't start a thread or a process.
pub(super) fn install_keeping_exec() -> io::Result<()> {
    install_program(program_keeping_exec(&NATIVE))
}

fn install_program(mut filter: Vec<sock_filter>) -> io::Result<()> {
    let program = sock_fprog {
        len: u16::try_from(filter.len()).expect("the filter is a few instructions long"),
        filter: filter.as_mut_ptr(),
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

/// Load the architecture, kill on a foreign one, load the call number, kill on x32 (x86_64 only)
/// or on a blocked call, and allow everything else.
fn program(arch: &Arch) -> Vec<sock_filter> {
    program_blocking(arch, arch.blocked)
}

/// `program` with `execve` allowed.
fn program_keeping_exec(arch: &Arch) -> Vec<sock_filter> {
    let blocked: Vec<_> = arch
        .blocked
        .iter()
        .copied()
        .filter(|&(name, _)| name != "execve")
        .collect();
    program_blocking(arch, &blocked)
}

fn program_blocking(arch: &Arch, calls: &[(&'static str, u32)]) -> Vec<sock_filter> {
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
        let arch_offset = offset_of!(seccomp_data, arch) as u32;
        let number_offset = offset_of!(seccomp_data, nr) as u32;
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
                    k => panic!("load from offset {k}"),
                };
            } else if code == BPF_RET | BPF_K {
                return instruction.k;
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
    fn keeping_exec_allows_only_execve_of_the_blocked_calls() {
        for arch in [&X86_64, &AARCH64] {
            let program = program_keeping_exec(arch);
            for &(name, number) in arch.blocked {
                let expected = if name == "execve" {
                    SECCOMP_RET_ALLOW
                } else {
                    SECCOMP_RET_KILL_PROCESS
                };
                assert_eq!(
                    verdict(&program, arch.audit_arch, number),
                    expected,
                    "{name}"
                );
            }
        }
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
}
