//! `test_sandbox.py`: 25 cases, of ace3's Landlock sandbox runner for `type: executable`
//! (`sandbox.py`, `saq/sandbox/`). ace4 has no such runner: whether it gets one, with an
//! interpreter for hunt scripts, or the scripts become built-in command types, is the owner's
//! decision (PLAN.md 6.6). One case's intent holds now and runs here; the other 24 wait for that
//! decision, each for the reason given, and port with the runner if the owner picks one:
//!
//! | ace3 case | waits because |
//! |---|---|
//! | TestReadAllowlist.test_allowlist_never_names_a_secret_location | it checks the runner's read allowlist |
//! | TestReadAllowlist.test_secret_locations_are_unreadable | it runs a script that reads secret paths |
//! | TestWrites.test_cannot_delete_or_write_outside_workdir | it runs a script that writes outside its directory |
//! | TestWrites.test_workdir_is_writable_and_is_home_and_tmpdir | it runs a script in its working directory |
//! | TestWrites.test_user_env_can_override_home | it runs a script with `env: HOME` |
//! | TestLimits.test_memory_limit | it runs a script past the runner's memory rlimit |
//! | TestLimits.test_file_size_limit | it runs a script past the runner's file size rlimit |
//! | TestLimits.test_output_limit | it runs a script past the runner's output bound |
//! | TestLimits.test_stdin_is_empty_without_input | it runs a script reading stdin |
//! | TestLimits.test_tcp_connections_limited_to_allowed_ports | it runs a script against Landlock's TCP rules (skipped in ace3 below Landlock ABI 4) |
//! | TestLimits.test_process_limit | it runs a script past the runner's process bound |
//! | TestProcessCleanup.test_background_process_killed_after_timeout | it runs a script whose child outlives its timeout |
//! | TestProcessCleanup.test_process_that_left_the_session_is_killed | it runs a script whose child leaves its session |
//! | TestProcessCleanup.test_command_cannot_signal_ace | it runs a script against Landlock's signal scoping (skipped in ace3 below Landlock ABI 6) |
//! | TestStaging.test_script_runs_with_its_files | it stages a script and its `files:` from a hunt repository |
//! | TestStaging.test_file_outside_the_hunt_repositories_is_rejected | it stages a `files:` entry from outside the repositories |
//! | TestStaging.test_symlink_out_of_the_repository_is_rejected | it stages a symlink out of a repository |
//! | TestStaging.test_script_outside_the_hunt_repositories_is_rejected | it stages a script from outside the repositories |
//! | TestStaging.test_validation_api_script_runs_but_reads_nothing_of_ace | it runs a validation package's script |
//! | TestStaging.test_bare_command_name_resolves_on_path | it runs a command found on PATH |
//! | TestHuntSourceRoots.test_git_dir_preferred_over_rule_dir | it checks where the runner stages scripts from |
//! | TestHuntSourceRoots.test_rule_dir_used_without_git_dir | it checks where the runner stages scripts from |
//! | TestHuntSourceRoots.test_root_containing_saq_home_is_ignored | it checks where the runner stages scripts from |
//! | TestFailClosed.test_landlock_is_available_here | it checks the host can run the sandbox |
//!
//! `TestFailClosed.test_no_landlock_means_no_execution`, that without its sandbox a command is
//! never run unsandboxed, is ace4's state for every executable, below.

use serde_json::json;

use super::{Fixture, evs, logic};
use crate::correlate::command::EXECUTABLE_WAITS;

#[test]
fn test_no_landlock_means_no_execution() {
    // an executable step fails, its event alerts with the reason on its trace, and nothing runs
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
        Some(EXECUTABLE_WAITS)
    );
    assert!(!marker.exists());
}
