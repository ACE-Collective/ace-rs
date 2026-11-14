//! SVS test runs (PLAN.md 7.10 batch 5): what ace3's `saq/svs/runs.py` decides without the database. The
//! writes are `ace_service`'s `svs_runs`.
//!
//! A launcher outside ACE registers a run for one catalog test against one or more test hosts, gets its
//! marker, starts it, may report how the test executed, and may cancel it. The timers move runs on by time:
//! a run never started goes to error and is closed, a started run ends when its observation window passes,
//! and a canceled or failed run is closed when its attribution window passes. An ended run waits for a
//! person.
//!
//! A run holds its test hosts from registration until its claim on them ends, and so does a maintenance
//! window ([`HostHolder`]), so an alert's context never has two runs to choose from.
//!
//! Times a window starts or ends at are whole seconds ([`whole_second`]), as in ace3: an event's time often
//! is (a hunt's), and a window stored from the exact time of the call would start after an event of that
//! same second. ace3 does it because MySQL rounds; the reason that holds here is the event's.

use std::collections::BTreeSet;

use ace_sdk::SvsRunsSection;
use chrono::{DateTime, SubsecRound, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::windows::WindowConfig;

/// The component the timers' transitions, and a refusal's alert, are written as: ace3's `TIMER_ACTOR`.
pub const SVS_COMPONENT: &str = "svs";

/// How many runs one timer pass moves per kind of transition, and how many maintenance windows it expires.
pub const TIMER_BATCH: i64 = 500;

pub const CLOSE_REASON_START_TIMEOUT: &str = "start timeout";
pub const CLOSE_REASON_CANCELED_BEFORE_START: &str = "canceled before start";
pub const CLOSE_REASON_ATTRIBUTION_ENDED: &str = "attribution window ended";

/// The launcher's calls, as they're recorded in a run's event log.
pub const CALL_START: &str = "start";
pub const CALL_EXECUTED: &str = "executed";
pub const CALL_CLEANUP: &str = "cleanup";
pub const CALL_CANCEL: &str = "cancel";

/// The outcome of a start refused because another run holds a target's host.
pub const OUTCOME_HOST_BUSY: &str = "host busy";

/// The state of a maintenance window that holds a host.
pub const HOLDER_MAINTENANCE: &str = "maintenance";

/// The test's output kept with the run; longer output keeps its start and its end, where errors are.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub const OUTPUT_TAIL_BYTES: usize = 16 * 1024;
/// Room for the marker between them.
const OUTPUT_MARKER_BYTES: usize = 100;

/// The overlay's `svs.runs`, checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunsConfig {
    pub start_timeout: TimeDelta,
    pub start_timeout_minutes: u32,
    pub max_extra_bytes: usize,
    pub max_targets: usize,
    pub max_maintenance_minutes: u32,
    pub windows: WindowConfig,
}

impl RunsConfig {
    pub fn from_section(section: &SvsRunsSection) -> Result<RunsConfig, String> {
        Ok(RunsConfig {
            windows: WindowConfig::from_section(section)?,
            start_timeout: TimeDelta::minutes(i64::from(section.start_timeout_minutes)),
            start_timeout_minutes: section.start_timeout_minutes,
            max_extra_bytes: section.max_extra_bytes as usize,
            max_targets: section.max_targets as usize,
            max_maintenance_minutes: section.max_maintenance_minutes,
        })
    }
}

impl Default for RunsConfig {
    fn default() -> Self {
        RunsConfig::from_section(&SvsRunsSection::default()).expect("the defaults are valid")
    }
}

/// Where a run's observation window came from: ace3's `ObservationSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    /// The test's settings.
    Override,
    /// The latency of the test's expected signatures.
    Expected,
    /// The test has no expectations yet: the slowest enabled hunt.
    AllHunts,
}

impl ObservationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ObservationSource::Override => "override",
            ObservationSource::Expected => "expected",
            ObservationSource::AllHunts => "all_hunts",
        }
    }
}

/// A host and user a launcher wants to run a test on, as it sent them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSpec {
    pub hostname: String,
    pub username: Option<String>,
}

impl TargetSpec {
    pub fn new(hostname: &str, username: Option<&str>) -> Self {
        TargetSpec {
            hostname: hostname.to_owned(),
            username: username.map(str::to_owned),
        }
    }
}

/// What a launcher sends to register a run: ace3's `Registration`.
#[derive(Debug, Clone, PartialEq)]
pub struct Registration {
    pub test_guid: String,
    pub targets: Vec<TargetSpec>,
    pub launcher: String,
    pub batch_id: Option<String>,
    /// Anything else the launcher wants kept with the run: a JSON object.
    pub extra: Value,
}

impl Registration {
    /// The registration as a run's first event and a refusal's alert keep it.
    pub fn payload(&self) -> Value {
        json!({
            "test_guid": self.test_guid,
            "targets": self.targets.iter().map(|target| json!({
                "hostname": target.hostname,
                "username": target.username,
            })).collect::<Vec<_>>(),
            "launcher": self.launcher,
            "batch_id": self.batch_id,
            "extra": self.extra,
        })
    }
}

/// What holds a test host: a run registered and not started, or started and inside its claim on the host,
/// or an open maintenance window. ace3's `HostHolder`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostHolder {
    /// The test host, by its short name.
    pub host: String,
    /// The run; None for a maintenance window.
    pub run: Option<Uuid>,
    /// The run's state, or [`HOLDER_MAINTENANCE`].
    pub state: String,
    /// When its claim ends; None while a run hasn't started.
    pub until: Option<DateTime<Utc>>,
    pub maintenance: Option<Uuid>,
}

fn time(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Why a registration, a start or a maintenance window can't have a host now: ace3's `HostBusy` message.
pub fn host_busy_message(holders: &[HostHolder]) -> String {
    holders
        .iter()
        .map(|holder| match (holder.maintenance, holder.run) {
            (Some(window), _) => format!(
                "test host {} is in maintenance window {window} until {}",
                holder.host,
                holder.until.map(time).unwrap_or_default()
            ),
            (None, run) => format!(
                "test host {} is held by run {} ({}{})",
                holder.host,
                run.map(|run| run.to_string()).unwrap_or_default(),
                holder.state,
                match holder.until {
                    Some(until) => format!(", until {}", time(until)),
                    None => ", not started".to_owned(),
                }
            ),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// A target's test host, as the run's platform reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPlatform<'a> {
    pub hostname: &'a str,
    pub platform: Option<&'a str>,
}

fn joined(platforms: &[String]) -> String {
    if platforms.is_empty() {
        "no platform".to_owned()
    } else {
        platforms.join(", ")
    }
}

/// The one platform a run is on: the platform of its targets' test hosts, which have to agree (a host
/// without one is taken to be on it too), else the test's only supported platform, as ATT&CK's slug. An
/// error says why neither tells, or which host's platform the test doesn't support. ace3's
/// `_run_platform`. `supported` is the test's `supported_platforms`.
pub fn run_platform(
    test_guid: Uuid,
    supported: &[String],
    hosts: &[HostPlatform<'_>],
) -> Result<String, String> {
    for host in hosts {
        if let Some(platform) = host.platform
            && !supported.iter().any(|supported| supported == platform)
        {
            return Err(format!(
                "test {test_guid} supports {}; test host {} is {platform}",
                joined(supported),
                host.hostname
            ));
        }
    }
    let of_hosts: BTreeSet<&str> = hosts.iter().filter_map(|host| host.platform).collect();
    if of_hosts.len() > 1 {
        return Err(format!(
            "the targets' test hosts are on different platforms ({}); a run is on one platform",
            of_hosts.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(platform) = of_hosts.into_iter().next() {
        return Ok(platform.to_owned());
    }
    let slugs = super::catalog::platform_slugs(supported);
    if let [only] = slugs.as_slice() {
        return Ok(only.clone());
    }
    Err(format!(
        "can't tell which platform the run is on: test {test_guid} supports {} and no target's test host \
         has a platform; set the test hosts' platform",
        joined(&slugs)
    ))
}

/// The time to the whole second it's in (the module's docs).
pub fn whole_second(at: DateTime<Utc>) -> DateTime<Utc> {
    at.trunc_subsecs(0)
}

/// The largest index at or below `index` that doesn't split a character.
fn floor_boundary(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

/// The smallest index at or above `index` that doesn't split a character.
fn ceil_boundary(text: &str, mut index: usize) -> usize {
    while !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// The output as kept with a run: whole when it fits [`MAX_OUTPUT_BYTES`], else its start and its last
/// [`OUTPUT_TAIL_BYTES`] around a marker saying how much was left out, a character a cut would split
/// dropped. It gives the output kept, the size the launcher sent in bytes, and whether it was truncated.
/// ace3's `truncate_output`; its replacing of a lone surrogate has no counterpart, since a Rust string
/// can't hold one and the API's JSON parser refuses it.
pub fn truncate_output(output: &str) -> (String, usize, bool) {
    let size = output.len();
    if size <= MAX_OUTPUT_BYTES {
        return (output.to_owned(), size, false);
    }
    let head_bytes = MAX_OUTPUT_BYTES - OUTPUT_TAIL_BYTES - OUTPUT_MARKER_BYTES;
    let head = &output[..floor_boundary(output, head_bytes)];
    let tail = &output[ceil_boundary(output, size - OUTPUT_TAIL_BYTES)..];
    // ace3 counts what its byte cuts left out, before it drops a split character
    let left_out = size - head_bytes - OUTPUT_TAIL_BYTES;
    (
        format!("{head}\n[... svs: {left_out} bytes of output left out ...]\n{tail}"),
        size,
        true,
    )
}

/// Whether what the launcher reported is a failure, which moves the run to error: a non-zero exit code or
/// an error.
pub fn failed(exit_code: i32, error: Option<&str>) -> bool {
    exit_code != 0 || error.is_some_and(|error| !error.is_empty())
}

/// The error reason of a run whose launcher reported a failure.
pub fn failure_reason(exit_code: i32, error: Option<&str>) -> String {
    match error.filter(|error| !error.is_empty()) {
        Some(error) => {
            format!("the launcher reported a failure (exit code {exit_code}: {error})")
        }
        None => format!("the launcher reported a failure (exit code {exit_code})"),
    }
}

/// The error reason of a run whose launcher never called start.
pub fn start_timeout_reason(minutes: u32) -> String {
    format!("start was not called within {minutes} minutes")
}

/// ace3's tests/saq/svs/test_runs.py's cases that need no database; the rest are `ace-service`'s.
#[cfg(test)]
mod tests {
    use super::*;

    /// ace3's `test_long_output_keeps_its_start_and_its_end`.
    #[test]
    fn long_output_keeps_its_start_and_its_end() {
        let output = format!("{}é{}the error", "a".repeat(100_000), "z".repeat(20_000));
        let (kept, size, truncated) = truncate_output(&output);
        assert!(truncated);
        assert_eq!(size, output.len());
        assert!(kept.len() <= MAX_OUTPUT_BYTES);
        assert!(kept.starts_with(&"a".repeat(1000)));
        assert!(kept.ends_with(&format!("{}the error", "z".repeat(1000))));
        let marker = kept
            .split_once("\n[... svs: ")
            .and_then(|(_, rest)| rest.split_once(" bytes of output left out ...]\n"))
            .expect("the marker");
        assert!(marker.0.bytes().all(|b| b.is_ascii_digit()));

        // a cut inside a multibyte character drops that character: both cuts split a 3-byte "€"
        let (kept, size, truncated) = truncate_output(&"€".repeat(30_000));
        assert!(truncated);
        assert_eq!(size, 90_000);
        assert!(kept.len() <= MAX_OUTPUT_BYTES);
        assert!(kept.starts_with('€') && kept.ends_with('€'));
        let (head, _) = kept.split_once('\n').expect("the marker's line");
        assert_eq!(head.len() % 3, 0, "no part of a character is kept");

        // whole when it fits
        assert_eq!(truncate_output("ok\n"), ("ok\n".to_owned(), 3, false));
        let fits = "x".repeat(MAX_OUTPUT_BYTES);
        assert_eq!(
            truncate_output(&fits),
            (fits.clone(), MAX_OUTPUT_BYTES, false)
        );
    }

    /// The platform half of ace3's `test_a_run_has_one_platform` and `test_register_rejects`.
    #[test]
    fn a_run_is_on_one_platform() {
        let guid = Uuid::from_u128(7);
        let host = |hostname, platform| HostPlatform { hostname, platform };
        let of = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        // the test hosts' platform; a host without one is taken to be on the others'
        assert_eq!(
            run_platform(
                guid,
                &of(&["linux", "macos"]),
                &[host("anyuser-01", None), host("mac-01", Some("macos"))]
            ),
            Ok("macos".to_owned())
        );
        // no host says: the test's only platform, as ATT&CK names it
        assert_eq!(
            run_platform(guid, &of(&["windows"]), &[host("anyuser-01", None)]),
            Ok("windows".to_owned())
        );
        assert_eq!(
            run_platform(
                guid,
                &of(&["iaas:aws", "iaas:azure"]),
                &[host("anyuser-01", None)]
            ),
            Ok("iaas".to_owned())
        );
        let error = run_platform(
            guid,
            &of(&["linux", "macos"]),
            &[host("win10-01", Some("windows"))],
        )
        .expect_err("unsupported");
        assert!(
            error.ends_with("supports linux, macos; test host win10-01 is windows"),
            "{error}"
        );
        let error = run_platform(
            guid,
            &of(&["linux", "macos"]),
            &[
                host("ubuntu-01", Some("linux")),
                host("mac-01", Some("macos")),
            ],
        )
        .expect_err("two platforms");
        assert!(
            error.contains("different platforms (linux, macos)"),
            "{error}"
        );
        let error = run_platform(guid, &of(&["linux", "macos"]), &[host("anyuser-01", None)])
            .expect_err("nothing says");
        assert!(
            error.starts_with("can't tell which platform the run is on: test ")
                && error
                    .contains(" supports linux, macos and no target's test host has a platform"),
            "{error}"
        );
        let error = run_platform(guid, &[], &[host("anyuser-01", None)]).expect_err("none");
        assert!(error.contains("supports no platform"), "{error}");
    }

    #[test]
    fn a_busy_host_says_what_holds_it() {
        let run = Uuid::from_u128(1);
        let window = Uuid::from_u128(2);
        let until = "2026-10-14T13:00:00Z".parse().expect("a time");
        let holder = |run, state: &str, until, maintenance| HostHolder {
            host: "win10-01".to_owned(),
            run,
            state: state.to_owned(),
            until,
            maintenance,
        };
        assert_eq!(
            host_busy_message(&[
                holder(Some(run), "created", None, None),
                holder(Some(run), "error", Some(until), None),
                holder(None, HOLDER_MAINTENANCE, Some(until), Some(window)),
            ]),
            format!(
                "test host win10-01 is held by run {run} (created, not started); \
                 test host win10-01 is held by run {run} (error, until 2026-10-14T13:00:00Z); \
                 test host win10-01 is in maintenance window {window} until 2026-10-14T13:00:00Z"
            )
        );
    }

    #[test]
    fn a_failure_is_an_exit_code_or_an_error() {
        assert!(!failed(0, None));
        assert!(!failed(0, Some("")));
        assert!(failed(1, None));
        assert!(failed(0, Some("Invoke-AtomicTest failed")));
        assert_eq!(
            failure_reason(1, None),
            "the launcher reported a failure (exit code 1)"
        );
        assert_eq!(
            failure_reason(0, Some("Invoke-AtomicTest failed")),
            "the launcher reported a failure (exit code 0: Invoke-AtomicTest failed)"
        );
        assert_eq!(
            start_timeout_reason(30),
            "start was not called within 30 minutes"
        );
        let at: DateTime<Utc> = "2026-10-14T12:05:00.600Z".parse().expect("a time");
        assert_eq!(whole_second(at).to_rfc3339(), "2026-10-14T12:05:00+00:00");
    }

    #[test]
    fn the_overlay_s_runs_section() {
        let config = RunsConfig::default();
        assert_eq!(
            (
                config.start_timeout_minutes,
                config.max_extra_bytes,
                config.max_targets,
                config.max_maintenance_minutes
            ),
            (30, 16384, 16, 240)
        );
        for key in [
            "start_timeout_minutes",
            "max_targets",
            "max_maintenance_minutes",
        ] {
            let section: SvsRunsSection =
                serde_json::from_value(json!({ key: 0 })).expect("parses");
            assert_eq!(
                RunsConfig::from_section(&section),
                Err(format!("{key} must be at least 1"))
            );
        }
    }
}
