//! Processes the pool reaps itself, for their CPU (PLAN.md 3.6): a parser's task process and a
//! tool process each run one task's work alone, so the user and system CPU the kernel reports when
//! one is reaped (`wait4`'s rusage) is that work's, the process's start and containment included.
//!
//! tokio's `Child` reaps with `waitpid`, which reports no rusage, and a process can be reaped only
//! once, so these are started as `std::process::Child`ren, which neither reap nor kill on their own,
//! and `OwnedChild` is the only thing that waits for them. It waits in two steps: `waitid` with
//! `WNOWAIT` on a blocking thread until the process has ended, which leaves it a zombie, so its pid
//! stays its own and a kill meanwhile can't reach another process; then `wait4`, which can't block on
//! a zombie, reaps it with its rusage. A child dropped before it was reaped is killed and reaped on a
//! thread of its own, as tokio's `kill_on_drop` did.
//!
//! The process may have no children of its own, which containment ensures (a task or tool process
//! can't fork), so its rusage is all the CPU its work used.

use std::io;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A child process only this reaps.
#[derive(Debug)]
pub struct OwnedChild {
    pid: libc::pid_t,
    reaped: bool,
    /// Where its CPU is added when it is reaped (`counted_in`).
    tally: Option<CpuTally>,
}

/// How a reaped process ended, and the CPU it used, or why that couldn't be read.
#[derive(Debug)]
pub struct Reaped {
    pub status: ExitStatus,
    pub cpu: io::Result<Duration>,
}

impl OwnedChild {
    /// Takes over waiting for `child`, which nothing else may wait for.
    pub fn new(child: &std::process::Child) -> io::Result<OwnedChild> {
        let pid = libc::pid_t::try_from(child.id())
            .map_err(|_| io::Error::other("a child's pid out of range"))?;
        Ok(OwnedChild {
            pid,
            reaped: false,
            tally: None,
        })
    }

    /// Adds the process's CPU to `tally` when it is reaped, wherever that is, and makes the tally
    /// unknown if it never is: a run dropped before its reap, as one cut off by its task's end, was
    /// reaped without its rusage.
    pub fn counted_in(mut self, tally: &CpuTally) -> OwnedChild {
        self.tally = Some(tally.clone());
        self
    }

    fn count(&self, cpu: Result<Duration, String>) {
        if let Some(tally) = &self.tally {
            tally.add(&cpu);
        }
    }

    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// Kills the process with SIGKILL, unless it has been reaped, when its pid may be another's by
    /// now. A process that has ended and not been reaped is a zombie, which the kill doesn't touch.
    pub fn kill(&self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        // SAFETY: kill takes two integers, and the pid is still this child's: it isn't reaped
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits for the process to end and reaps it. Cancel-safe: a wait dropped before the process
    /// ended changes nothing, and the next wait, or the drop, takes over. The wait is bounded by the
    /// process: a caller that can't wait kills it first.
    pub async fn wait(&mut self) -> io::Result<Reaped> {
        if self.reaped {
            return Err(io::Error::other("the process was already reaped"));
        }
        let pid = self.pid;
        let status = match tokio::task::spawn_blocking(move || ended(pid))
            .await
            .map_err(io::Error::other)?
        {
            Ok(status) => status,
            Err(e) => {
                // not this process's child any more: something else reaped it, and its pid may be
                // another's, so it is never killed
                if e.raw_os_error() == Some(libc::ECHILD) {
                    self.reaped = true;
                    self.count(Err(format!("process {pid} was reaped elsewhere")));
                }
                return Err(e);
            }
        };
        // no await from here on, so a dropped wait can't leave it reaped and not marked so
        let cpu = reap(pid);
        self.reaped = true;
        self.count(cpu.as_ref().copied().map_err(ToString::to_string));
        Ok(Reaped { status, cpu })
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        self.count(Err(format!(
            "process {} was stopped before it was reaped",
            self.pid
        )));
        if let Err(e) = self.kill() {
            tracing::warn!(pid = self.pid, "killing a dropped child: {e}");
        }
        let pid = self.pid;
        // SIGKILL ends it; the thread only collects it
        std::thread::spawn(move || {
            let mut status = 0;
            // SAFETY: waitpid writes the status integer
            unsafe { libc::waitpid(pid, &mut status, 0) };
        });
    }
}

/// Blocks until `pid` has ended, leaving it unreaped, and says how.
fn ended(pid: libc::pid_t) -> io::Result<ExitStatus> {
    let id = libc::id_t::try_from(pid).map_err(io::Error::other)?;
    loop {
        // SAFETY: siginfo_t is plain data, for which all zeroes is valid, and waitid writes it
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waitid writes `info`, which outlives the call
        let done =
            unsafe { libc::waitid(libc::P_PID, id, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if done == 0 {
            // SAFETY: waitid filled the SIGCHLD fields, which si_status reads
            let value = unsafe { info.si_status() };
            return Ok(status_of(info.si_code, value));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// A wait status as `waitpid` would have given it, from what `waitid` says: an exit's code, or the
/// signal that killed the process.
fn status_of(code: i32, value: i32) -> ExitStatus {
    ExitStatus::from_raw(match code {
        libc::CLD_EXITED => (value & 0xff) << 8,
        // the core-dump bit
        libc::CLD_DUMPED => (value & 0x7f) | 0x80,
        _ => value & 0x7f,
    })
}

/// Reaps `pid`, which has ended, and returns the user and system CPU it used.
pub fn reap(pid: libc::pid_t) -> io::Result<Duration> {
    let mut status = 0;
    // SAFETY: rusage is plain data, for which all zeroes is valid
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // a zombie is reaped at once, so WNOHANG can only say it wasn't one
    // SAFETY: wait4 writes the status integer and `usage`, which outlive the call
    let reaped = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, &mut usage) };
    match reaped {
        -1 => Err(io::Error::last_os_error()),
        0 => Err(io::Error::other(format!("process {pid} hadn't ended"))),
        _ => Ok(time(usage.ru_utime) + time(usage.ru_stime)),
    }
}

fn time(value: libc::timeval) -> Duration {
    Duration::from_secs(u64::try_from(value.tv_sec).unwrap_or(0))
        + Duration::from_micros(u64::try_from(value.tv_usec).unwrap_or(0))
}

/// The CPU of several processes added up, as a task's tool runs: unknown once one of them couldn't
/// be read, with the first reason why.
#[derive(Debug, Clone, Default)]
pub struct CpuTally(Arc<Mutex<Tally>>);

#[derive(Debug, Default)]
struct Tally {
    total: Duration,
    unread: Option<String>,
}

impl CpuTally {
    pub fn add(&self, cpu: &Result<Duration, String>) {
        let mut tally = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match cpu {
            Ok(cpu) => tally.total += *cpu,
            Err(why) => {
                tally.unread.get_or_insert_with(|| why.clone());
            }
        }
    }

    /// The sum, or why it isn't known.
    pub fn total(&self) -> Result<Duration, String> {
        let tally = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &tally.unread {
            Some(why) => Err(why.clone()),
            None => Ok(tally.total),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn spawn(script: &str) -> (std::process::Child, OwnedChild) {
        let child = Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::null())
            .spawn()
            .expect("sh starts");
        let owned = OwnedChild::new(&child).expect("a pid");
        (child, owned)
    }

    #[tokio::test]
    async fn a_reaped_process_says_how_it_ended_and_what_cpu_it_used() {
        // a busy loop of its own, so its CPU is more than nothing
        let (_child, mut owned) =
            spawn("i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done; exit 3");
        let reaped = owned.wait().await.expect("it ends");
        assert_eq!(reaped.status.code(), Some(3));
        let cpu = reaped.cpu.expect("its rusage reads");
        assert!(cpu > Duration::ZERO, "{cpu:?}");
        // reaped once: a second wait is an error, and a kill does nothing
        assert!(owned.wait().await.is_err());
        owned.kill().expect("a kill after the reap touches nothing");
    }

    #[tokio::test]
    async fn a_killed_process_is_reaped_with_its_signal() {
        let (_child, mut owned) = spawn("exec sleep 600");
        owned.kill().expect("it's killed");
        let reaped = owned.wait().await.expect("it ends");
        assert_eq!(reaped.status.signal(), Some(libc::SIGKILL));
        assert!(reaped.cpu.is_ok(), "{:?}", reaped.cpu);
    }

    #[tokio::test]
    async fn a_wait_dropped_before_the_end_leaves_the_process_to_the_next() {
        let (_child, mut owned) = spawn("exec sleep 600");
        let early = tokio::time::timeout(Duration::from_millis(50), owned.wait()).await;
        assert!(early.is_err(), "it was still running");
        owned.kill().expect("it's killed");
        let reaped = owned.wait().await.expect("the next wait reaps it");
        assert_eq!(reaped.status.signal(), Some(libc::SIGKILL));
    }

    #[tokio::test]
    async fn a_child_something_else_reaped_is_an_error_and_never_killed() {
        let (_child, mut owned) = spawn("exit 0");
        let mut status = 0;
        // SAFETY: waitpid writes the status integer
        assert_eq!(
            unsafe { libc::waitpid(owned.pid(), &mut status, 0) },
            owned.pid()
        );
        let lost = owned.wait().await.expect_err("it isn't ours to reap");
        assert_eq!(lost.raw_os_error(), Some(libc::ECHILD), "{lost}");
        assert!(
            owned.reaped,
            "so neither a kill nor the drop touches its pid"
        );
    }

    #[test]
    fn a_process_that_isnt_ours_has_no_rusage_to_read() {
        // pid 1 is never this test's child
        let refused = reap(1).expect_err("ECHILD");
        assert_eq!(refused.raw_os_error(), Some(libc::ECHILD), "{refused}");
    }

    #[test]
    fn a_dropped_child_is_killed_and_reaped() {
        let (_child, owned) = spawn("exec sleep 600");
        let pid = owned.pid();
        drop(owned);
        // the drop's thread reaps it; a guard against a hang, not a bound on how soon
        let gone = (0..600).any(|_| {
            // nothing signals the reap to this test, so it polls the pid, for at most 30 s
            std::thread::sleep(Duration::from_millis(50));
            // SAFETY: kill with signal 0 only asks whether the pid exists
            (unsafe { libc::kill(pid, 0) }) != 0
        });
        assert!(gone, "process {pid} is still there");
    }

    /// A counted child's CPU lands in its tally where it's reaped, before its caller can return
    /// early; one dropped unreaped, as a tool run its task's end cut off, leaves the tally unknown.
    #[tokio::test]
    async fn a_counted_child_adds_its_cpu_at_its_reap_and_one_dropped_unreaped_makes_it_unknown() {
        let tally = CpuTally::default();
        let (_child, owned) = spawn("i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done");
        let mut owned = owned.counted_in(&tally);
        let reaped = owned.wait().await.expect("it ends");
        let cpu = reaped.cpu.expect("its rusage reads");
        assert_eq!(tally.total(), Ok(cpu));
        assert!(cpu > Duration::ZERO, "{cpu:?}");

        let (_child, cut_off) = spawn("exec sleep 600");
        drop(cut_off.counted_in(&tally));
        let unknown = tally.total().expect_err("a run left out");
        assert!(unknown.contains("before it was reaped"), "{unknown}");
    }

    #[test]
    fn a_tally_is_unknown_once_one_of_its_reads_failed() {
        let tally = CpuTally::default();
        assert_eq!(tally.total(), Ok(Duration::ZERO));
        tally.add(&Ok(Duration::from_millis(300)));
        tally.add(&Ok(Duration::from_millis(200)));
        assert_eq!(tally.total(), Ok(Duration::from_millis(500)));
        tally.add(&Err("no rusage".to_owned()));
        tally.add(&Ok(Duration::from_millis(100)));
        tally.add(&Err("another".to_owned()));
        assert_eq!(tally.total(), Err("no rusage".to_owned()));
    }

    #[test]
    fn a_wait_status_is_rebuilt_from_waitids_code() {
        assert_eq!(status_of(libc::CLD_EXITED, 20).code(), Some(20));
        assert_eq!(
            status_of(libc::CLD_KILLED, libc::SIGSYS).signal(),
            Some(libc::SIGSYS)
        );
        let dumped = status_of(libc::CLD_DUMPED, libc::SIGSEGV);
        assert_eq!(dumped.signal(), Some(libc::SIGSEGV));
        assert!(dumped.core_dumped());
    }
}
