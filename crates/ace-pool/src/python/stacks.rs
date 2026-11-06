//! A hung worker's stacks (PLAN.md 4.3): `py-spy dump` on it, before the supervisor kills it.
//!
//! # Permission
//!
//! A root supervisor without `CAP_SYS_PTRACE` can't read a worker, because the kernel wants the
//! tracer's user to match or the capability. So py-spy runs as the worker's own user, which gets
//! past that check with no capability, and the Compose file adds none. Then two things decide:
//!
//! - Yama. At `kernel.yama.ptrace_scope` 1, which Rancher Desktop's kernel and many distributions
//!   set, a process may trace only its descendants, or a process that named one of its ancestors
//!   with `PR_SET_PTRACER`. A worker names the supervisor before it contains itself, so py-spy,
//!   the supervisor's child, may read it. Scopes 2 and 3 refuse without the capability or at all;
//!   the task then still fails at its deadline, and its row says what py-spy said.
//! - Landlock. A process in a Landlock domain may trace only inside that domain, which is what
//!   keeps one worker from reading another even though they share a user and a named ancestor, and
//!   why py-spy can have no domain of its own (`ToolConfinement`).
//!
//! So nothing a worker could do before is newly open to it. It can't read py-spy, whose directory
//! isn't in its Landlock paths, or run it. A hostile worker can refuse to be read, with
//! `PR_SET_DUMPABLE`, and it can write what it likes in its own memory, so the stacks are what it
//! allowed to be seen. py-spy shares a user with every worker, so if a hostile process took py-spy
//! over through what it reads, it could read other workers too, though not the supervisor, the
//! token or the network. A user per slot would close that.
//!
//! # What a dump shows
//!
//! Python's frames, whether the worker is in pure Python, or in a C call with the GIL or without
//! it, where the last frame is the Python function that made the call. `--native` isn't used: on
//! arm64 under py-spy 0.4.3 it adds an unsymbolized libc frame and a bad address, and nothing for a
//! C extension's own code. `--locals` isn't used, because a task's values have no place in the row.
//! py-spy refuses a stack deeper than about 4096 frames, and the row then says so.
//!
//! # Bounds
//!
//! py-spy gets half of `timeout` to pause the worker and read it. That fails if the worker is
//! already stopped or traced, and can't finish if it's stuck in the kernel, so py-spy then gets the
//! other half with `--nonblocking`, which only reads memory and may catch the stack mid-change. Its
//! first line says so. At the end of `timeout` py-spy is killed, and the task fails regardless.
//! The text is cut at `MAX_STACKS`, and control characters are replaced, so a file name holding a
//! NUL can't stop the row being written, or an escape sequence reach a terminal. Everything else in
//! it, new lines included, may be what the worker chose to write.

use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::containment::ToolConfinement;
use crate::supervisor::signal_name;

/// How long a hung task's dump may take: the most a task can outlive its deadline by. In practice
/// a dump takes milliseconds.
pub const DUMP_TIMEOUT: Duration = Duration::from_secs(10);
/// The most a row's stacks hold. A worker runs one thread, so this holds about a thousand frames,
/// and the frames that matter most, the innermost, come first.
pub const MAX_STACKS: usize = 64 * 1024;
/// The most a failed dump's reason holds.
const MAX_WHY: usize = 1000;
/// py-spy's limit. It maps little more than its own binary and what it reads.
const ADDRESS_SPACE: u64 = 1 << 30;

/// Runs py-spy on workers.
#[derive(Debug, Clone)]
pub(super) struct StackDumper {
    pub program: PathBuf,
    /// The workers' (uid, gid). See the module docs.
    pub user: Option<(u32, u32)>,
    pub timeout: Duration,
}

impl StackDumper {
    /// The worker's stacks, or why there are none.
    pub async fn dump(&self, pid: u32) -> Result<String, String> {
        let half = self.timeout / 2;
        let paused = match self.attempt(pid, &[], half).await {
            Ok(stacks) => return Ok(stacks),
            Err(why) => why,
        };
        tracing::warn!(pid, "py-spy couldn't pause a hung worker: {paused}");
        match self.attempt(pid, &["--nonblocking"], half).await {
            Ok(stacks) => {
                let note =
                    format!("(read while the process ran, because pausing it failed: {paused})\n");
                Ok(clip(note + &stacks))
            }
            Err(unpaused) => Err(format!("{paused}; and with --nonblocking, {unpaused}")),
        }
    }

    async fn attempt(&self, pid: u32, flags: &[&str], within: Duration) -> Result<String, String> {
        tokio::time::timeout(within, self.run(pid, flags))
            .await
            .unwrap_or_else(|_| Err(format!("py-spy didn't finish within {within:?}")))
    }

    async fn run(&self, pid: u32, flags: &[&str]) -> Result<String, String> {
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args(["dump", "--full-filenames"])
            .args(flags)
            .args(["--pid", &pid.to_string()])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some((uid, gid)) = self.user {
            command.uid(uid).gid(gid);
        }
        let confinement = ToolConfinement::new(ADDRESS_SPACE);
        // SAFETY: `apply` only makes system calls, on memory made before the fork
        unsafe {
            command.pre_exec(move || confinement.apply());
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("running {} failed: {e}", self.program.display()))?;
        let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            return Err("py-spy has no pipes".to_owned());
        };
        let reading = async {
            let read = read_capped(stdout, MAX_STACKS).await;
            // it may be blocked writing the rest
            if read.1
                && let Err(e) = child.start_kill()
            {
                tracing::warn!("killing py-spy: {e}");
            }
            read
        };
        let ((stdout, cut), (stderr, _)) = tokio::join!(reading, read_capped(stderr, MAX_WHY));
        if cut {
            return Ok(clip(clean(&stdout) + CUT));
        }
        let status = child
            .wait()
            .await
            .map_err(|e| format!("waiting for py-spy: {e}"))?;
        let stacks = clean(&stdout);
        if status.success() && !stacks.trim().is_empty() {
            return Ok(clip(stacks));
        }
        Err(format!(
            "py-spy {}: {}",
            how_it_ended(status),
            clean(&stderr).trim()
        ))
    }
}

const CUT: &str = "\n(cut here: the stacks are longer than the row keeps)\n";

/// Up to `cap` bytes, and whether there were more. A read that fails ends what's read.
async fn read_capped(reader: impl AsyncRead + Unpin, cap: usize) -> (Vec<u8>, bool) {
    let mut bytes = Vec::new();
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    if let Err(e) = reader.take(limit).read_to_end(&mut bytes).await {
        tracing::debug!("reading py-spy's output: {e}");
    }
    let more = bytes.len() > cap;
    bytes.truncate(cap);
    (bytes, more)
}

fn how_it_ended(status: ExitStatus) -> String {
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exited {code}"),
        (None, Some(signal)) => format!("was killed by {}", signal_name(signal)),
        (None, None) => "stopped".to_owned(),
    }
}

/// Text that's safe to store and to print: valid UTF-8, with every control character but a new
/// line and a tab replaced. Postgres refuses a NUL in text.
fn clean(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| match c {
            '\n' | '\t' => c,
            c if c.is_control() => char::REPLACEMENT_CHARACTER,
            c => c,
        })
        .collect()
}

/// At most `MAX_STACKS` bytes, whatever `clean` made of them, ending at a whole character.
fn clip(mut text: String) -> String {
    if text.len() > MAX_STACKS {
        let end = text.floor_char_boundary(MAX_STACKS - CUT.len());
        text.truncate(end);
        text.push_str(CUT);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_replaced_and_new_lines_and_tabs_kept() {
        assert_eq!(clean(b"a\n\tb"), "a\n\tb");
        assert_eq!(
            clean(b"a\0b\x1b[31mc\x7f"),
            "a\u{fffd}b\u{fffd}[31mc\u{fffd}"
        );
        // C1, which some terminals read as escapes, and bytes that aren't UTF-8
        assert_eq!(clean("\u{9b}x".as_bytes()), "\u{fffd}x");
        assert_eq!(clean(b"\xff\xfe"), "\u{fffd}\u{fffd}");
    }

    #[test]
    fn a_long_text_is_cut_at_a_character_and_says_so() {
        // characters of two bytes, so a cut in the middle of one would be easy to make
        let text = clip("\u{e9}".repeat(MAX_STACKS));
        assert!(text.len() <= MAX_STACKS, "{}", text.len());
        assert!(text.ends_with(CUT));
        assert_eq!(clip("short".to_owned()), "short");
    }
}
