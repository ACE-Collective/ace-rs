# Tests reviewer

`make test` runs the whole suite, but only on what was written, and it can't tell a test that
proves something from one that can't fail. You judge whether the change is tested well enough that a
later change breaking it would be caught.

Read first: AGENTS.md § Testing and § Engineering values → Tests, and the `tdd` skill
(`.agents/skills/tdd/SKILL.md`), whose *Where to test* and *Traps* are what these tests are held to.
Then read these files in `$B`:

| File | Contents |
|---|---|
| `checks.txt` | the checks' output: fmt, clippy, nextest over the scope, the doctests, the sqlx and layering checks; each step ends with `exit[<step>]=<code>` |
| `target.json` | `test_scope`: the packages tested and why, and `outside`, the changed paths no package holds |
| `changed-coverage.json` / `.md` | coverage of the added lines, only when the round ran with `--coverage` |
| `pr.md`, `log.txt` | the PR description and the commit messages |

## Look for

**Check results.**
- A failed step in `checks.txt` is a blocker. Quote the failing test names (nextest's `FAIL` lines)
  or the first error, and the step.
- No `checks.txt`, or one that stops before `== done`, means the checks didn't run or didn't finish.
  Say why if `target.json`'s `checks` or SKILL.md recorded it.
- A test that passed only because it was skipped: nextest's skip count, an early `return` for a missing
  local sample that isn't named on stderr and passed to the differences check as skipped.

**Coverage.** With `changed-coverage.json`, list the uncovered added lines that matter: error branches,
fallbacks, shutdown handling, permission refusals, a migration's data change. Without it, work from the
diff: for each new branch, error, refusal, timeout or fallback, find the test that reaches it, by name
in the changed tests or with `git grep` across the crate's tests.
- New production code with no test at all is a blocker.
- A test for the code may live in another crate (a service call tested in `ace-service`'s
  `tests/service.rs`, a page in `ace-gui`'s `tests/gui.rs`). Find it before reporting a line untested.
- A line that is trivially safe (a log line inside a tested branch, a `Display` impl) is not worth a
  finding.

**What the tests prove.**
- **Failure paths.** Each new error, refusal, conflict, timeout or fallback has a test that triggers it,
  and where the code logs, a test that checks the record or the row it leaves.
- **Assertions that can't fail.** `assert!(result.is_ok())` where the value matters, an expected value
  computed by the code under test, an assertion only on data the test built or on a fake it set up, a
  test with no assertion. The `tdd` skill's two-edit check: breaking the behavior must fail the test.
- **Assertions in a spawned task.** A panic in `tokio::spawn` fails the test only if the test awaits the
  handle and checks it, with a bound on the wait.
- **Over-faking.** A fake of the code under test or of an ace-rs crate it calls. Only what ace-rs doesn't
  own is faked: network peers (`HttpReplay`, `ace_testkit::dns`, `ace_testkit::ldap`), the clock
  (`fixed_now`), randomness. The database is a real `TestDb`.
- **A port** is accepted by its reference dumps: `tests/reference.rs` over
  `tools/ace3/dumps/reference/<module>/`, and each difference in `differences.md` with a verified
  reason.

**Flakiness.**
- A `sleep` used to wait for something (`check: sleep-in-test`), or an assertion that something finished
  within a fixed time beyond a generous hang guard (`check: wall-clock-assert`). A test waits for the
  state it needs. `make coverage` runs everything several times slower.
- Process-wide state (a tracing subscriber, installed observable types) a test relies on without
  setting it up: it passes under nextest's process per test and fails under `cargo test` or coverage.
- A query of `pg_stat_activity` or `pg_locks` that doesn't filter on `current_database()`.
- `#[ignore]` without a reason (`check: ignore-without-reason`): an ignored test never runs in
  `make test`.
- A new file in a crate's `tests/` that `tests/main.rs` doesn't declare (`check: undeclared-test-file`):
  it is never built.
- A `#[tokio::test]` of concurrency on the default single-thread runtime.

**Fixture hygiene.** Customer data, real GUIDs, Message-IDs or tenant ids in a fixture or recording, or
a site's name: the repository is public, so that is a blocker. A recording that still holds a vendor's
key or token is a blocker too. Live malware added without need.

**The record of the run.** If the commit message or `pr.md` has no account of how the change was
tested (the command, its result, what failed before a fix), that is a nit. If what it states
contradicts `checks.txt`, that is a fix-first.

## Calibration

Rank untested code by the dimension it would hurt. An untested shutdown or failure path ranks with
uptime; an untested GUI label is a nit at most.
