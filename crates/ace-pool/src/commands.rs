//! GUI commands (PLAN.md 5.12, ace3's `docs/GUI_CLI.md`): a parser pool's supervisor leases the commands
//! analysts start from the GUI and runs each in a contained process, as it runs a parser's task.
//!
//! ace3 runs a GUI command as a child of the API worker that took the request, so the command is bounded
//! only while that worker lives and only when it stops the command (#973). Here the command is a row the
//! pool leases (`ace_core::commands`), and its deadline is fixed when the pool claims it: the claim's time
//! plus its timeout. The supervisor kills the process at that deadline, from its own clock, whatever
//! happens meanwhile to the session that started it, or to the API, which it needs only to report output
//! and to send the end. Two more bounds hold if the supervisor itself dies: the process sets its own
//! `alarm` a few seconds past the deadline before it contains itself, and its CPU-time limit is its
//! timeout.
//!
//! The process is the pool's own binary again, by exec (#982), in its `command` mode, as the task user
//! with an empty environment. It reads a `CommandRequest` on stdin, contains itself with a profile that
//! allows no paths and no ports (`contain`, PLAN.md 2.18: one thread, no fork or exec, rlimits, Landlock
//! and seccomp), and runs the binary's command line on the words after `ace`. So it holds no credential:
//! a command that needs the database or the bucket would go through the API as workers do, and none does
//! yet. One pipe takes its stdout and stderr, so the output keeps their order, as ace3's does. The
//! supervisor keeps the first `MAX_OUTPUT_BYTES` and reads and drops the rest, so the process never
//! blocks on a full pipe, and sends what it has every `REPORT_EVERY`, which also renews the lease and
//! tells it whether someone cancelled the command.
//!
//! How a command ends, and what its row says:
//! - It exits: `completed` with its exit code. `EXIT_SETUP` is the process failing before the command
//!   ran, such as containment refusing: `failed`, with the output saying why.
//! - Its deadline comes: the supervisor kills it, `timed_out`. Its own alarm firing (SIGALRM) is the same.
//! - Someone cancels it: the next report says so and the supervisor kills it, `cancelled`.
//! - A signal kills it, such as SIGSYS for a blocked call: `failed`, naming the signal.
//! - The pool stops: the supervisor kills it, `abandoned`. A command isn't given back to the queue,
//!   because it may have done part of its work.
//!
//! The end is sent until the API takes it, for up to `END_RETRY_FOR`, so a restart of the API between the
//! kill and the end only delays the row. A pool that loses the lease, because the reaper ended the
//! command as abandoned, kills the process and sends nothing.

use std::os::fd::OwnedFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{ExitCode, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ace_sdk::wire::{CommandEnd, CommandOutcome, CommandReport, LeasedCommand};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::client::{ClientError, LeaseClient};
use crate::containment::{SandboxProfile, contain};
use crate::supervisor::signal_name;

/// The most output a command keeps, as the core does (`ace_core::commands::MAX_OUTPUT_BYTES`).
pub const MAX_OUTPUT_BYTES: usize = 1 << 20;
/// How many commands a pool process runs at once by default, as ace3's `MAX_RUNNING_PER_NODE`.
pub const DEFAULT_CONCURRENCY: usize = 3;
/// The address space a command's process may map by default.
pub const ADDRESS_SPACE: u64 = 1 << 30;
/// How often the output so far goes to the API, as ace3's `OUTPUT_FLUSH_SECONDS`.
pub const REPORT_EVERY: Duration = Duration::from_secs(2);
/// How long past its deadline a command's process kills itself, should its supervisor not.
pub const ALARM_GRACE: Duration = Duration::from_secs(5);
/// How long the end is retried while the API can't be reached.
pub const END_RETRY_FOR: Duration = Duration::from_secs(300);
/// How long the end is retried at the pool's shutdown.
const SHUTDOWN_END_RETRY_FOR: Duration = Duration::from_secs(5);
/// The process couldn't set up, so the command never ran.
pub const EXIT_SETUP: u8 = 125;
/// How long the output's pipe may stay open after the process ended. It can't have children, so
/// its pipe closes as it dies; this only makes the bound explicit.
const PIPE_TIMEOUT: Duration = Duration::from_secs(5);
const READ_CHUNK: usize = 64 * 1024;

/// What the supervisor writes on a command's stdin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    /// The words after `ace`.
    pub argv: Vec<String>,
    pub profile: SandboxProfile,
    /// When the process kills itself, in seconds from when it reads this.
    pub alarm_seconds: u64,
}

/// How a pool starts command processes.
#[derive(Debug, Clone)]
pub struct CommandConfig {
    /// The binary, usually the pool's own.
    pub program: PathBuf,
    /// Its arguments, such as `command`.
    pub args: Vec<String>,
    /// The (uid, gid) the process runs as. None keeps the supervisor's, for tests only.
    pub user: Option<(u32, u32)>,
    /// How many run at once.
    pub concurrency: usize,
    pub address_space_bytes: u64,
}

impl CommandConfig {
    /// `program args...` as `user`, with the defaults for the rest.
    pub fn new(program: PathBuf, args: Vec<String>, user: Option<(u32, u32)>) -> Self {
        CommandConfig {
            program,
            args,
            user,
            concurrency: DEFAULT_CONCURRENCY,
            address_space_bytes: ADDRESS_SPACE,
        }
    }

    /// The profile of a command with `timeout_seconds`: no paths, no ports, and CPU time up to its
    /// timeout.
    pub fn profile(&self, timeout_seconds: u32) -> SandboxProfile {
        SandboxProfile {
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            tcp_ports: Vec::new(),
            address_space_bytes: self.address_space_bytes,
            cpu_seconds: u64::from(timeout_seconds.max(1)),
        }
    }
}

/// Leases commands and runs each in a contained process, up to the concurrency limit, until `stop`
/// fires; then kills the running ones, ends them as abandoned and returns how many it ran.
pub async fn run_commands(
    client: &LeaseClient,
    config: &CommandConfig,
    lease_wait: Duration,
    stop: CancellationToken,
) -> u64 {
    let slots = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let commands = CancellationToken::new();
    let mut running: JoinSet<()> = JoinSet::new();
    let mut ran = 0u64;
    loop {
        let slot = tokio::select! {
            biased;
            () = stop.cancelled() => break,
            slot = slots.clone().acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_) => break,
            },
        };
        while running.try_join_next().is_some() {}
        let leased = tokio::select! {
            biased;
            () = stop.cancelled() => break,
            leased = client.lease_command(lease_wait) => leased,
        };
        match leased {
            Ok(Some(command)) => {
                ran += 1;
                let (client, config, shutdown) =
                    (client.clone(), config.clone(), commands.child_token());
                running.spawn(async move {
                    let _slot = slot;
                    let id = command.id;
                    match run_command(&client, &config, command, &shutdown).await {
                        Ok(outcome) => tracing::info!(command = id, ?outcome, "the command ended"),
                        Err(e) => {
                            tracing::error!(command = id, "the command's end wasn't sent: {e}")
                        }
                    }
                });
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("leasing a command failed: {e}");
                tokio::select! {
                    () = stop.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(1)) => {}
                }
            }
        }
    }
    commands.cancel();
    // each kills its process at once and tries its end for a few seconds
    let bound = PIPE_TIMEOUT + SHUTDOWN_END_RETRY_FOR + crate::client::CALL_TIMEOUT;
    if tokio::time::timeout(bound, async {
        while running.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tracing::warn!(
            commands = running.len(),
            "commands were still ending at the shutdown deadline"
        );
        running.abort_all();
    }
    ran
}

/// Why the supervisor stopped watching a command.
enum Stopped {
    Exited(ExitStatus),
    Deadline,
    Cancelled,
    Shutdown,
    /// The reaper ended it, so the lease is gone.
    LeaseLost,
}

/// What a command has written, up to `MAX_OUTPUT_BYTES`.
#[derive(Default)]
struct Output {
    bytes: Vec<u8>,
    truncated: bool,
}

impl Output {
    fn append(&mut self, chunk: &[u8]) {
        let room = MAX_OUTPUT_BYTES.saturating_sub(self.bytes.len());
        if chunk.len() > room {
            self.truncated = true;
        }
        self.bytes
            .extend_from_slice(&chunk[..chunk.len().min(room)]);
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Runs one leased command to its end and sends the end. `shutdown` kills it as abandoned.
pub async fn run_command(
    client: &LeaseClient,
    config: &CommandConfig,
    command: LeasedCommand,
    shutdown: &CancellationToken,
) -> Result<CommandOutcome, ClientError> {
    let id = command.id;
    let deadline_in = Duration::try_from_secs_f64(command.deadline_seconds).unwrap_or_default();
    let deadline = Instant::now() + deadline_in;
    let mut output = Output::default();
    let stopped = match start(config, &command, deadline_in) {
        Ok((child, receiver)) => {
            watch(client, id, child, receiver, deadline, shutdown, &mut output).await
        }
        Err(e) => {
            let outcome = CommandOutcome::Failed {
                error: format!("the command's process didn't start: {e}"),
            };
            send_end(client, id, &outcome, &output, END_RETRY_FOR).await?;
            return Ok(outcome);
        }
    };
    let outcome = match stopped {
        Stopped::Exited(status) => outcome_of(status, &output),
        Stopped::Deadline => {
            tracing::warn!(command = id, "killed the command at its deadline");
            CommandOutcome::TimedOut
        }
        Stopped::Cancelled => CommandOutcome::Cancelled,
        Stopped::Shutdown => CommandOutcome::Abandoned {
            error: "its pool stopped while it ran, and killed it".to_owned(),
        },
        Stopped::LeaseLost => {
            tracing::warn!(command = id, "lost the command's lease; killed it");
            return Ok(CommandOutcome::Abandoned {
                error: "lost its lease".to_owned(),
            });
        }
    };
    let retry_for = if shutdown.is_cancelled() {
        SHUTDOWN_END_RETRY_FOR
    } else {
        END_RETRY_FOR
    };
    send_end(client, id, &outcome, &output, retry_for).await?;
    Ok(outcome)
}

type Started = (tokio::process::Child, tokio::net::unix::pipe::Receiver);

/// Starts the process with the request on its stdin and one pipe for its stdout and stderr.
fn start(
    config: &CommandConfig,
    command: &LeasedCommand,
    deadline_in: Duration,
) -> std::io::Result<Started> {
    let (reader, writer) = std::io::pipe()?;
    let error_writer = writer.try_clone()?;
    let mut process = tokio::process::Command::new(&config.program);
    process
        .args(&config.args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(writer)
        .stderr(error_writer)
        .kill_on_drop(true);
    if let Some((uid, gid)) = config.user {
        process.uid(uid).gid(gid);
    }
    let mut child = process.spawn()?;
    // the parent's copies of the pipe's write end go with the builder, so the pipe ends with the child
    drop(process);
    let receiver = tokio::net::unix::pipe::Receiver::from_owned_fd(OwnedFd::from(reader))?;
    let request = CommandRequest {
        argv: command.argv.clone(),
        profile: config.profile(command.timeout_seconds),
        alarm_seconds: deadline_in.as_secs_f64().ceil() as u64 + ALARM_GRACE.as_secs(),
    };
    let bytes = serde_json::to_vec(&request).map_err(std::io::Error::other)?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(std::io::Error::other("the command's process has no stdin"));
    };
    tokio::spawn(async move {
        if let Err(e) = async {
            stdin.write_all(&bytes).await?;
            stdin.shutdown().await
        }
        .await
        {
            tracing::debug!("writing the command's request: {e}");
        }
    });
    Ok((child, receiver))
}

/// Reads the process's output until it ends, killing it at the deadline, at a cancel, at the pool's
/// shutdown or when the lease is lost, and reporting the output every `REPORT_EVERY`.
async fn watch(
    client: &LeaseClient,
    id: i64,
    mut child: tokio::process::Child,
    mut receiver: tokio::net::unix::pipe::Receiver,
    deadline: Instant,
    shutdown: &CancellationToken,
    output: &mut Output,
) -> Stopped {
    let cancel = CancellationToken::new();
    let lost = CancellationToken::new();
    let mut report: Option<JoinHandle<()>> = None;
    let mut every = tokio::time::interval_at(Instant::now() + REPORT_EVERY, REPORT_EVERY);
    let mut buffer = vec![0u8; READ_CHUNK];
    let mut open = true;
    let stopped = loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => break Stopped::Deadline,
            () = cancel.cancelled() => break Stopped::Cancelled,
            () = lost.cancelled() => break Stopped::LeaseLost,
            () = shutdown.cancelled() => break Stopped::Shutdown,
            status = child.wait() => match status {
                Ok(status) => break Stopped::Exited(status),
                Err(e) => {
                    tracing::error!(command = id, "waiting for the command's process: {e}");
                    break Stopped::Shutdown;
                }
            },
            read = receiver.read(&mut buffer), if open => match read {
                Ok(0) => open = false,
                Ok(n) => output.append(&buffer[..n]),
                Err(e) => {
                    tracing::warn!(command = id, "reading the command's output: {e}");
                    open = false;
                }
            },
            // each report renews the lease too, so it goes whether or not there's new output; one at a
            // time, and the tick stays polled while one is out, so the next one goes when it's back
            _ = every.tick() => {
                if report.as_ref().is_some_and(|r| !r.is_finished()) {
                    continue;
                }
                let (client, cancel, lost) = (client.clone(), cancel.clone(), lost.clone());
                let sent = CommandReport { output: output.text(), output_truncated: output.truncated };
                report = Some(tokio::spawn(async move {
                    match client.report_command(id, &sent).await {
                        Ok(reply) if reply.cancel_requested => cancel.cancel(),
                        Ok(_) => {}
                        Err(ClientError::LeaseLost(_)) => lost.cancel(),
                        // the next report, or the end, may get through
                        Err(e) => tracing::warn!(command = id, "reporting the output failed: {e}"),
                    }
                }));
            }
        }
    };
    if let Some(report) = report {
        report.abort();
    }
    if !matches!(stopped, Stopped::Exited(_)) {
        // SIGKILL: one thread with no children, so this ends all of it (#981)
        if let Err(e) = child.kill().await {
            tracing::error!(command = id, "killing the command's process: {e}");
        }
    }
    // what it wrote before it ended
    let drained = tokio::time::timeout(PIPE_TIMEOUT, async {
        while open {
            match receiver.read(&mut buffer).await {
                Ok(0) | Err(_) => open = false,
                Ok(n) => output.append(&buffer[..n]),
            }
        }
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            command = id,
            "the command's output stayed open after it ended"
        );
    }
    stopped
}

/// How a process that exited by itself ended.
fn outcome_of(status: ExitStatus, output: &Output) -> CommandOutcome {
    match (status.code(), status.signal()) {
        (Some(code), _) if code == i32::from(EXIT_SETUP) => CommandOutcome::Failed {
            error: format!(
                "the command's process couldn't set up: {}",
                last_line(&output.text())
            ),
        },
        (Some(exit_code), _) => CommandOutcome::Completed { exit_code },
        (None, Some(libc::SIGALRM)) => CommandOutcome::TimedOut,
        (None, signal) => CommandOutcome::Failed {
            error: format!(
                "the command was killed by {}",
                signal_name(signal.unwrap_or_default())
            ),
        },
    }
}

fn last_line(text: &str) -> String {
    text.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .chars()
        .take(500)
        .collect()
}

/// Sends the end until the API takes it, for up to `retry_for` while the API can't be reached.
async fn send_end(
    client: &LeaseClient,
    id: i64,
    outcome: &CommandOutcome,
    output: &Output,
    retry_for: Duration,
) -> Result<(), ClientError> {
    let end = CommandEnd {
        outcome: outcome.clone(),
        output: output.text(),
        output_truncated: output.truncated,
    };
    let until = Instant::now() + retry_for;
    loop {
        match client.end_command(id, &end).await {
            Ok(()) => return Ok(()),
            Err(e) if e.is_unavailable() && Instant::now() < until => {
                tracing::warn!(
                    command = id,
                    "sending the command's end failed, trying again: {e}"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// The command process's side: what a pool's binary runs in its `command` mode. It reads a
/// `CommandRequest` from stdin, sets its alarm, contains itself, runs `run` on the words after `ace`
/// with its stdout and stderr as the output, and exits with what `run` returns, or `EXIT_SETUP`.
pub fn process_main(run: &dyn Fn(&[String]) -> u8) -> ExitCode {
    use std::io::{Read, Write};
    let mut bytes = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut bytes) {
        eprintln!("setup failed: reading the request: {e}");
        return ExitCode::from(EXIT_SETUP);
    }
    let request: CommandRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(e) => {
            eprintln!("setup failed: the request doesn't read: {e}");
            return ExitCode::from(EXIT_SETUP);
        }
    };
    let alarm = libc::c_uint::try_from(request.alarm_seconds).unwrap_or(libc::c_uint::MAX);
    // SAFETY: alarm takes an integer and only schedules a signal for this process.
    unsafe {
        libc::alarm(alarm.max(1));
    }
    if let Err(e) = contain(&request.profile) {
        eprintln!("setup failed: containment: {e}");
        return ExitCode::from(EXIT_SETUP);
    }
    let code = run(&request.argv);
    // the output is the pipe's, and a pipe that's gone has no one to tell
    if std::io::stdout().flush().is_err() || std::io::stderr().flush().is_err() {
        return ExitCode::from(EXIT_SETUP);
    }
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_keeps_its_first_mebibyte() {
        let mut output = Output::default();
        output.append(&vec![b'a'; MAX_OUTPUT_BYTES - 1]);
        assert!(!output.truncated);
        output.append(b"bc");
        assert!(output.truncated);
        assert_eq!(output.bytes.len(), MAX_OUTPUT_BYTES);
        assert_eq!(output.bytes.last(), Some(&b'b'));
    }

    #[test]
    fn a_command_profile_allows_nothing_but_its_time() {
        let config = CommandConfig::new("/bin/true".into(), vec![], None);
        let profile = config.profile(30);
        assert!(profile.read_paths.is_empty() && profile.write_paths.is_empty());
        assert!(profile.tcp_ports.is_empty());
        assert_eq!(
            (profile.cpu_seconds, profile.address_space_bytes),
            (30, ADDRESS_SPACE)
        );
    }
}
