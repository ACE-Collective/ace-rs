//! The scanner images a module sends a file or a URL through (PLAN.md 7.7), such as ace3's
//! js-deobfuscator, node running attacker JavaScript with no network, and phishkit, Chrome under
//! SeleniumBase loading an attacker's page.
//!
//! In ace3 each is a Celery manager that runs `docker run` of its scanner image per file through the
//! host's Docker socket. Here a module asks for a scan by delaying with a `ScanRequest`
//! (`Delay::with_scan`): the core queues the scan in `queue.scans` and wakes the task when it ends,
//! and the task waits as a delayed task, holding no slot meanwhile. The scanner pool
//! (`ace_pool::scanners`), which holds the Docker socket, leases the scan, starts the scanner's
//! image with its spec's limits, copies the inputs in and the output out, and removes the
//! container at the scan's deadline, at a cancellation, or after a crash of the pool. Whoever holds
//! the socket has root on the host, so that process parses nothing the scanner wrote: it hands the
//! core one archive (`OUTPUT_ARCHIVE`, `STDOUT`, `STDERR` inside it) whose bytes it never reads, and
//! the module's next run, a contained parser, reads it (`TaskContext::scan`).
//!
//! A module names the scanners it asks for in `Module::SCANNERS`, and the core refuses a request
//! for any other. It can't name an image or a program: the spec (`ScannerSpec`, `SCANNERS`) fixes
//! the image, the command the request's arguments follow, where inputs go and what comes back.

use std::path::PathBuf;
use std::time::Duration;

use ace_results::Sha256;
use serde::{Deserialize, Serialize};

use crate::wire::Presigned;

/// The network a scanner's container is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerNetwork {
    /// `--network none`: only its loopback.
    None,
    /// Docker's default network, `bridge`, as `docker run` gives one with no `--network`, or the
    /// network `variable` names.
    Default { variable: &'static str },
}

/// A scanner image the scanner pool runs, under the name modules ask for it by.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScannerSpec {
    pub name: &'static str,
    /// The image, unless `image_variable` names another.
    pub image: &'static str,
    pub image_variable: &'static str,
    /// What runs, before the request's arguments.
    pub command: &'static [&'static str],
    /// The directory a request's inputs are copied into, each at its own relative path.
    pub input_dir: &'static str,
    /// The directory that comes back: the pool creates it empty before the scanner starts.
    pub output_dir: &'static str,
    pub network: ScannerNetwork,
    /// `--memory` and `--memory-swap`: none for a scanner ace3 gives none.
    pub memory_bytes: Option<u64>,
    /// `--cpus`, in billionths of a CPU.
    pub nano_cpus: Option<i64>,
    /// `--init`: tini as its first process, which passes on the stop signal.
    pub init: bool,
    /// How long a stop at the deadline waits after SIGTERM before SIGKILL (`docker stop --time`):
    /// time a scanner that flushes what it has on SIGTERM gets to write it.
    pub stop_grace: Duration,
    /// The longest a request may ask for.
    pub max_timeout: Duration,
    /// The most a scan's output archive may hold; past it the scan fails.
    pub max_output_bytes: u64,
}

/// ace3's js-deobfuscator (`js_deobfuscator/js_deobfuscator.py`): node 26 with webcrack, running
/// `harness.js <input> <output>` with no network. ace3 gives it no memory or CPU limit, and neither
/// does this.
pub const JS_DEOBFUSCATOR: ScannerSpec = ScannerSpec {
    name: "js-deobfuscator",
    image: "ace4-js-deobfuscator:latest",
    image_variable: "ACE4_JS_DEOBFUSCATOR_IMAGE",
    command: &["node", "/opt/app/harness.js"],
    input_dir: "/js-deobfuscator/input",
    output_dir: "/js-deobfuscator/output",
    network: ScannerNetwork::None,
    memory_bytes: None,
    nano_cpus: None,
    init: false,
    stop_grace: Duration::from_secs(10),
    max_timeout: Duration::from_secs(600),
    max_output_bytes: 256 << 20,
};

/// ace3's phishkit scanner (`phishkit/phishkit.py`'s `_run_scanner`): Chrome under SeleniumBase,
/// which needs the network, with `--init`, `--stop-timeout 5` and the memory and CPU limits of
/// `etc/phishkit_config.yaml`'s `resource_limits` (2 GiB, swap included, and 2 CPUs).
pub const PHISHKIT: ScannerSpec = ScannerSpec {
    name: "phishkit",
    image: "ace4-phishkit:latest",
    image_variable: "ACE4_PHISHKIT_IMAGE",
    command: &["/opt/venv/bin/python", "/opt/app/scanner.py"],
    input_dir: "/phishkit/input",
    output_dir: "/phishkit/output",
    network: ScannerNetwork::Default {
        variable: "ACE4_PHISHKIT_NETWORK",
    },
    memory_bytes: Some(2 << 30),
    nano_cpus: Some(2_000_000_000),
    init: true,
    stop_grace: Duration::from_secs(5),
    max_timeout: Duration::from_secs(1800),
    max_output_bytes: 256 << 20,
};

/// The scanners ace4 builds images for (`docker/scanners/build`).
pub const SCANNERS: &[ScannerSpec] = &[JS_DEOBFUSCATOR, PHISHKIT];

/// The spec named `name` among `specs`.
pub fn find<'a>(specs: &'a [ScannerSpec], name: &str) -> Option<&'a ScannerSpec> {
    specs.iter().find(|s| s.name == name)
}

/// The most inputs, arguments and argument bytes a request may have.
pub const MAX_INPUTS: usize = 16;
pub const MAX_ARGS: usize = 64;
pub const MAX_ARG_BYTES: usize = 64 * 1024;
/// The longest a scan may wait for a scanner pool before the core gives up on it, past its timeout.
pub const QUEUED_GRACE: Duration = Duration::from_secs(600);

/// What `ACE4_POOLS` lists for a pool that runs scanner `name`: `@scan/<name>`, which no module
/// can be called.
pub fn pool_entry(name: &str) -> String {
    format!("@scan/{name}")
}

/// A file a scan copies into its scanner's input directory: bytes in the bucket by sha256, the
/// task's own file or one the module wrote (`TaskContext::write_scan_input`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanInput {
    /// Its path under the input directory: one or two plain names, such as `<job>/page.html`.
    pub name: String,
    pub sha256: Sha256,
    pub size: u64,
}

/// What a module asks a scanner to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    pub scanner: String,
    /// What follows the spec's command.
    pub args: Vec<String>,
    pub inputs: Vec<ScanInput>,
    /// How long the scanner may run before it's stopped, at most its spec's `max_timeout`.
    pub timeout_seconds: u32,
}

impl ScanRequest {
    pub fn new(scanner: &str, timeout: Duration) -> Self {
        ScanRequest {
            scanner: scanner.to_owned(),
            args: Vec::new(),
            inputs: Vec::new(),
            timeout_seconds: u32::try_from(timeout.as_secs()).unwrap_or(u32::MAX).max(1),
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn input(mut self, input: ScanInput) -> Self {
        self.inputs.push(input);
        self
    }

    /// Why the request can't be queued, whatever its scanner's spec says.
    pub fn refusal(&self) -> Option<String> {
        if self.inputs.len() > MAX_INPUTS {
            return Some(format!("more than {MAX_INPUTS} inputs"));
        }
        if self.args.len() > MAX_ARGS {
            return Some(format!("more than {MAX_ARGS} arguments"));
        }
        if let Some(arg) = self
            .args
            .iter()
            .find(|a| a.len() > MAX_ARG_BYTES || a.contains('\0'))
        {
            return Some(format!("an argument of {} bytes, or with a NUL", arg.len()));
        }
        if let Some(input) = self.inputs.iter().find(|i| !is_input_name(&i.name)) {
            return Some(format!("the input name {:?}", input.name));
        }
        for (i, input) in self.inputs.iter().enumerate() {
            if self.inputs[..i]
                .iter()
                .any(|other| other.name == input.name)
            {
                return Some(format!("two inputs named {:?}", input.name));
            }
        }
        if self.timeout_seconds == 0 {
            return Some("a timeout of 0".to_owned());
        }
        None
    }
}

/// Whether `name` is one or two plain names joined by `/`, each at most 255 bytes, with no NUL and
/// no `.` or `..`.
pub fn is_input_name(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    (1..=2).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 255
                && *part != "."
                && *part != ".."
                && !part.contains('\0')
        })
}

/// Where a scan is, as the module's next run sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    /// Queued or running: the task came due before the scan ended.
    Pending,
    /// The scanner exited by itself.
    Completed,
    /// The pool stopped it at its deadline. What it wrote by then came back.
    TimedOut,
    /// The task's root was cancelled, and the pool killed it.
    Cancelled,
    /// It didn't run, or its output couldn't come back.
    Failed,
    /// Nothing will finish it: no pool took it, or its pool stopped reporting on it.
    Abandoned,
}

impl ScanState {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanState::Pending => "pending",
            ScanState::Completed => "completed",
            ScanState::TimedOut => "timed_out",
            ScanState::Cancelled => "cancelled",
            ScanState::Failed => "failed",
            ScanState::Abandoned => "abandoned",
        }
    }
}

/// The task's latest scan, as its lease carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireScan {
    pub id: i64,
    pub scanner: String,
    pub state: ScanState,
    /// The scanner's exit code, from Docker, for one that exited or was stopped.
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub error: Option<String>,
    /// The output archive, for a scan that brought one back.
    #[serde(default)]
    pub output: Option<WireScanOutput>,
}

/// A scan's output archive in the bucket, and where to download it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireScanOutput {
    pub sha256: Sha256,
    pub size: u64,
    pub download: Presigned,
}

/// The task's latest scan, as its module reads it (`TaskContext::scan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub id: i64,
    pub scanner: String,
    pub state: ScanState,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    /// The output archive on this machine: a tar holding `OUTPUT_ARCHIVE`, `STDOUT` and `STDERR`.
    pub output: Option<PathBuf>,
}

/// In a scan's output archive: Docker's tar of the scanner's output directory, as the daemon made
/// it.
pub const OUTPUT_ARCHIVE: &str = "output.tar";
/// In a scan's output archive: the scanner's stdout and stderr, each as Docker's logs endpoint
/// gives one stream, in its frames: an 8-byte header (the stream, three zeros, a big-endian
/// length) before each piece.
pub const STDOUT: &str = "stdout";
pub const STDERR: &str = "stderr";

/// A scan a scanner pool holds the lease on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasedScan {
    pub id: i64,
    pub scanner: String,
    pub args: Vec<String>,
    pub inputs: Vec<LeasedScanInput>,
    pub timeout_seconds: u32,
    /// How long from now until its deadline, by the core's clock.
    pub deadline_seconds: f64,
    /// How long each renewal extends the lease.
    pub lease_seconds: f64,
}

/// An input of a leased scan, and where to download it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeasedScanInput {
    pub name: String,
    pub sha256: Sha256,
    pub size: u64,
    pub download: Presigned,
}

/// A scanner pool asking for a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanLeaseRequest {
    pub worker: String,
    #[serde(default)]
    pub wait_seconds: u64,
}

/// The core's answer to a renewal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanRenewal {
    /// The task's root was cancelled: kill the scanner and end the scan as cancelled.
    pub cancel_requested: bool,
}

/// How a scan ended, as its pool saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ScanOutcome {
    Completed {
        exit_code: i32,
    },
    TimedOut {
        #[serde(default)]
        exit_code: Option<i32>,
    },
    Cancelled,
    Failed {
        error: String,
    },
}

/// An output archive the pool uploaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanOutputRecord {
    pub sha256: Sha256,
    pub size: u64,
}

/// A scan's end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanEnd {
    pub outcome: ScanOutcome,
    #[serde(default)]
    pub output: Option<ScanOutputRecord>,
    /// The id of the image its container ran, from Docker, for a scan that got as far as a
    /// container: what the analysis cache keys a scanning module's result on, as ace3 keys
    /// phishkit's on its running scanner image's id (`crate::cache::Cache::scanners`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
}

/// A scanner pool asking where to upload a scan's output archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanUploadRequest {
    pub sha256: Sha256,
    pub size: u64,
}

/// The lease API's paths for scans.
pub mod paths {
    pub const LEASE: &str = "/api/worker/v1/scans/lease";

    /// `/api/worker/v1/scans/<id>/<action>`, where action is `renew`, `upload` or `end`.
    pub fn scan(id: i64, action: &str) -> String {
        format!("/api/worker/v1/scans/{id}/{action}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_names_are_one_or_two_plain_names() {
        for (name, ok) in [
            ("page.html", true),
            ("0f2e/page.html", true),
            ("a/b/c", false),
            ("../x", false),
            ("./x", false),
            ("/x", false),
            ("x/", false),
            ("", false),
            ("a\0b", false),
        ] {
            assert_eq!(is_input_name(name), ok, "{name:?}");
        }
        assert!(!is_input_name(&"x".repeat(256)));
    }

    #[test]
    fn a_request_is_refused_for_what_no_spec_allows() {
        let sha256 = Sha256([0; 32]);
        let input = |name: &str| ScanInput {
            name: name.to_owned(),
            sha256,
            size: 1,
        };
        let ok = ScanRequest::new("js-deobfuscator", Duration::from_secs(30))
            .arg("/x")
            .input(input("a/b.js"));
        assert_eq!(ok.refusal(), None);
        assert!(ok.clone().input(input("a/b.js")).refusal().is_some());
        assert!(ok.clone().input(input("../b.js")).refusal().is_some());
        assert!(ok.clone().arg("a\0b").refusal().is_some());
        let mut zero = ok;
        zero.timeout_seconds = 0;
        assert!(zero.refusal().is_some());
    }

    #[test]
    fn an_outcome_reads_as_written() {
        let end = ScanEnd {
            outcome: ScanOutcome::TimedOut {
                exit_code: Some(143),
            },
            output: None,
            image_id: None,
        };
        let json = serde_json::to_value(&end).expect("serializes");
        assert_eq!(
            json,
            serde_json::json!({"outcome": {"state": "timed_out", "exit_code": 143}, "output": null})
        );
        assert_eq!(serde_json::from_value::<ScanEnd>(json).expect("reads"), end);
    }
}
