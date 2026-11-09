//! `test_sandbox.py`: 25 cases, of ace3's Landlock sandbox runner for `type: executable`
//! (`sandbox.py`, `saq/sandbox/`). Under PLAN.md decision 16 ace4 runs no hunt script: each script
//! is a built-in script command type, and there is no runner, process, environment or file system
//! of a script's own to contain. Five cases still hold and run here: an executable that isn't a
//! script type never runs (`test_no_landlock_means_no_execution`), and the staging of a script's
//! `files:` from the hunt repositories (four `TestStaging` cases). The other 20 don't apply:
//!
//! | ace3 case | doesn't apply under decision 16 because |
//! |---|---|
//! | TestReadAllowlist.test_allowlist_never_names_a_secret_location | it checks the runner's read allowlist |
//! | TestReadAllowlist.test_secret_locations_are_unreadable | it runs a script that reads secret paths |
//! | TestWrites.test_cannot_delete_or_write_outside_workdir | it runs a script that writes outside its directory |
//! | TestWrites.test_workdir_is_writable_and_is_home_and_tmpdir | it runs a script in its working directory |
//! | TestWrites.test_user_env_can_override_home | it runs a script with `env: HOME` |
//! | TestLimits.test_memory_limit | it runs a script past the runner's memory rlimit |
//! | TestLimits.test_file_size_limit | it runs a script past the runner's file size rlimit |
//! | TestLimits.test_output_limit | it runs a script past the runner's output bound; a type's output is bounded by the engine's 16 MiB a command |
//! | TestLimits.test_stdin_is_empty_without_input | it runs a script reading stdin; a type gets no input then, which `test_executable_with_stdin_event`'s neighbours cover |
//! | TestLimits.test_tcp_connections_limited_to_allowed_ports | it runs a script against Landlock's TCP rules; a type reaches only the DNS, HTTPS and TLS calls of its `Net` |
//! | TestLimits.test_process_limit | it runs a script past the runner's process bound |
//! | TestProcessCleanup.test_background_process_killed_after_timeout | it runs a script whose child outlives its timeout |
//! | TestProcessCleanup.test_process_that_left_the_session_is_killed | it runs a script whose child leaves its session |
//! | TestProcessCleanup.test_command_cannot_signal_ace | it runs a script against Landlock's signal scoping |
//! | TestStaging.test_validation_api_script_runs_but_reads_nothing_of_ace | it runs a validation package's script; `ace serve` has no script types |
//! | TestStaging.test_bare_command_name_resolves_on_path | it runs a command found on PATH; no program on PATH is a script type |
//! | TestHuntSourceRoots.test_git_dir_preferred_over_rule_dir | it checks how the runner finds the repositories; the hunter's are its `signatures` checkout |
//! | TestHuntSourceRoots.test_rule_dir_used_without_git_dir | as above |
//! | TestHuntSourceRoots.test_root_containing_saq_home_is_ignored | as above |
//! | TestFailClosed.test_landlock_is_available_here | it checks the host can run the sandbox |

use std::path::{Path, PathBuf};

use serde_json::json;

use super::{Fixture, evs, logic};
use crate::correlate::script::no_script_type;

/// The error of the only step of a run of `command` over one event.
fn step_error(f: &Fixture, command: serde_json::Value) -> Option<String> {
    let config = logic(
        json!([{"transform": {"method": "property", "property_name": "p", "command": command}}]),
    );
    let result = f.simple(&config, evs(json!([{"id": 1}])));
    result.trace.event_traces[0].steps[0]
        .step
        .transform()
        .expect("a transform")
        .error
        .clone()
}

#[test]
fn test_no_landlock_means_no_execution() {
    // an executable that isn't a script type fails its step, its event alerts with the reason on
    // its trace, and nothing runs
    let marker = std::env::temp_dir().join(format!("ace4-never-ran-{}", std::process::id()));
    let config = logic(
        json!([{"transform": {"method": "property", "property_name": "p",
        "command": {"type": "executable", "path": "/usr/bin/touch", "args": [marker.to_string_lossy()]}}}]),
    );
    let result = Fixture::default().simple(&config, evs(json!([{"id": 1}])));
    assert_eq!(result.events.len(), 1);
    let et = &result.trace.event_traces[0];
    assert_eq!(et.outcome, "error");
    assert_eq!(
        et.steps[0]
            .step
            .transform()
            .expect("a transform")
            .error
            .as_deref(),
        Some(no_script_type("/usr/bin/touch").as_str())
    );
    assert!(!marker.exists());
}

/// A hunt repository holding `hunts/scripts/echo.py` and its data, and the fixture whose script
/// types must stage from it.
fn repository() -> (tempfile::TempDir, PathBuf, Fixture) {
    let dir = tempfile::tempdir().expect("a directory");
    let scripts = dir.path().join("repo/hunts/scripts");
    std::fs::create_dir_all(&scripts).expect("made");
    std::fs::write(scripts.join("echo.py"), "").expect("written");
    std::fs::write(scripts.join("data.txt"), "repository data\n").expect("written");
    let mut f = Fixture::default();
    f.types
        .scripts_mut()
        .set_roots(vec![dir.path().join("repo")]);
    let script = scripts.join("echo.py");
    (dir, script, f)
}

fn text(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn test_script_runs_with_its_files() {
    let (_dir, script, f) = repository();
    let data = script.with_file_name("data.txt");
    let config = logic(
        json!([{"transform": {"method": "property", "property_name": "p",
        "command": {"type": "executable", "path": text(&script), "args": ["read", "data.txt"], "files": [text(&data)]}}}]),
    );
    let result = f.simple(&config, evs(json!([{"id": 1}])));
    // a `str` property is the output stripped
    assert_eq!(super::js(&result.events[0])["p"], json!("repository data"));
    // a file the command doesn't stage isn't there for the script, as in ace3's working directory
    assert!(
        step_error(
            &f,
            json!({"type": "executable", "path": text(&script), "args": ["read", "data.txt"]})
        )
        .is_some_and(|e| e.contains("exited with code 1"))
    );
}

#[test]
fn test_file_outside_the_hunt_repositories_is_rejected() {
    let (dir, script, f) = repository();
    let outside = dir.path().join("outside.txt");
    std::fs::write(&outside, "secret").expect("written");
    let error = step_error(
        &f,
        json!({"type": "executable", "path": text(&script), "args": ["print", "x"], "files": [text(&outside)]}),
    );
    assert!(error.is_some_and(|e| e.contains("outside the hunt repositories")));
}

#[test]
fn test_symlink_out_of_the_repository_is_rejected() {
    let (dir, script, f) = repository();
    let outside = dir.path().join("outside.txt");
    std::fs::write(&outside, "secret").expect("written");
    let link = script.with_file_name("link.txt");
    std::os::unix::fs::symlink(&outside, &link).expect("linked");
    let error = step_error(
        &f,
        json!({"type": "executable", "path": text(&script), "args": ["read", "link.txt"], "files": [text(&link)]}),
    );
    assert!(error.is_some_and(|e| e.contains("outside the hunt repositories")));
}

#[test]
fn test_script_outside_the_hunt_repositories_is_rejected() {
    let (dir, _script, f) = repository();
    // a script type's path, but not in a hunt repository
    let elsewhere = dir.path().join("elsewhere/hunts/scripts");
    std::fs::create_dir_all(&elsewhere).expect("made");
    std::fs::write(elsewhere.join("echo.py"), "").expect("written");
    let error = step_error(
        &f,
        json!({"type": "executable", "path": text(&elsewhere.join("echo.py")), "args": ["print", "x"]}),
    );
    assert!(error.is_some_and(|e| e.contains("outside the hunt repositories")));
}
