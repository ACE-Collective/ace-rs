---
name: tdd
description: "Write ace-rs tests that can fail: red before green, one behavior at a time, through the interface the behavior is used by. Use when writing, changing or judging a test, adding a regression test for a bug, building a feature or a port test-first, answering a tests finding from /ace-review, or when asked for TDD, red-green or a failing test. Covers proving a test can fail by breaking the code it guards, the two-edit check for a test worth keeping, where to test each kind of ace-rs code (Harness, reference dumps, TestDb, the API and GUI tests), what to fake, and the Rust traps (spawned tasks, shared process state, timing). To find a bug's cause before fixing it use bug-fix."
---

# Tests that can fail

A test is a claim about what the code does for the code, user or service that calls it. Nobody has
evidence for that claim until they have seen the test fail. Most test findings are of two kinds: tests
that still pass with the code they cover removed, and failure branches that no test runs. This loop
prevents both. Write the test, watch it fail for the reason you expect, make it pass, and say in the
commit message what failed before.

AGENTS.md, *Testing*, says how to run tests (in the dev container, through nextest) and what each kind
of test has to hand. *Engineering values*, *Tests*, says what must be covered.

Adapted from Matt Pocock's `tdd` skill and the `tdd` and `principle-test-behavior-not-implementation`
skills of Lauren Tan's pstack (MIT, see `LICENSE`), by way of ace3's skill of the same name.

## The loop

1. **List the behaviors and where they are seen.** Write one line for each behavior the change adds or
   fixes, and name the interface a caller sees it through (see *Where to test*). Failure paths are
   behaviors too: each new error, refusal, timeout and fallback gets a line. Ask the user only when
   the code doesn't make the interface clear.
2. **Red.** Write the test for one behavior and run only that test:
   ```sh
   docker compose exec -T -e CI=true dev cargo nextest run --locked -p <crate> <test name>
   ```
   It must fail on an assertion about that behavior. A compile error, a missing fixture or a panic in
   setup doesn't count. A test that passes before the code exists is testing something else.
3. **Green.** Write only the code that test needs. Run it again and see it pass.
4. **Next behavior.** Don't write all the tests first. Tests written before you know the code test the
   shape you imagined, not the behavior.
5. **The whole set**, at the end: the changed crates' tests, then `make test`.

For a bug fix, the red run is against the unfixed code: the test fails on the bug, then the fix makes
it pass. For a port, the red run is the reference test before the port exists, or with a difference
from ace3 not yet listed.

## Prove that a test can fail

This applies when the code already exists: a test added after it, a test written to answer a review
finding, or a test you inherited.

1. Break what the test guards. Revert the fix, delete the line the test is about, invert the
   condition, or return a wrong value.
2. Run only that test, and see it fail with an assertion about the behavior.
3. Restore the code, see the test pass, and check with `git diff` that the break is gone.

If the test still passes with the behavior broken, fix the test. The usual causes:

- the assertion is looser than the contract (`is_ok()`, `!is_empty()`, `contains` where equality was
  meant);
- the expected value comes from the code under test;
- the test asserts on data it built itself, or on a fake it set up;
- the assertion runs in a spawned task whose panic nothing awaits (*Traps*).

Say in the commit message what you broke, the command, and that it failed and then passed after the
restore. The review looks for it.

## A test worth keeping

Check every test against two imagined edits:

- **Break the behavior:** a wrong value, a skipped effect, or the effect done twice. The test must fail.
- **Change the internals** and keep every result a caller can see. The test must still pass. One that
  fails here is tied to the implementation: it breaks on every refactor and catches no bug.

Take expected values from the requirement, or from ace3 for a port, and write them as literals. Don't
compute them by calling the code, or by repeating its arithmetic. Assert what the contract promises.
Don't pin more than that, such as an error's exact wording that no caller reads. Don't check less,
such as only that nothing failed.

## Where to test

| What the change touches | Test it through | Assert on |
|---|---|---|
| an analysis module | `ace_testkit::Harness`: its settings, a sample or file, dependency results, then `run_parser` or `run_lookup` | the result's details, the observables and files it adds, their tags and directives, its detections |
| a port of an ace3 module | `tests/reference.rs` over `tools/ace3/dumps/reference/<module>/`, with `tests/differences.md` | every difference listed with a verified reason; nothing else differs |
| a module's view | `ace_testkit::check_view_fixture` on the module's own result | the fixture, whose diff you read after `ACE_RS_WRITE_FIXTURES=1` |
| the queue, eligibility, submissions | `ace-core`'s `tests/`, a `TestDb`, the `common` workers | the task rows, what a worker claims, what a later read sees |
| the service layer | `ace-service`'s `tests/service.rs`, with an actor and its grants | what the call returns, the rows it wrote, the audit record, and the refusal without the grant |
| a JSON endpoint | `ace-api`'s `tests/api.rs` | the status, the body, what a later read returns; every documented status of the endpoint |
| a GUI page | `ace-gui`'s `tests/gui.rs`: a view is a function returning HTML | the HTML a user sees, escaped, and the refusal without the permission |
| a pool, containment, leases | `ace-pool`'s `tests/`, which start a core and a pool process | what the task's row says and what the process did |
| a failure path | make the dependency fail: a recording that answers 503, a stopped lease API, a module that errors | the error the caller gets, the record logged, the fallback taken |

Fake only what ace-rs doesn't own: network peers (`ace_testkit::replay::HttpReplay` for HTTP,
`ace_testkit::dns` for DNS, `ace_testkit::ldap`), the clock (`ace_testkit::fixed_now`), and randomness.
Use a real `TestDb` and the stack's bucket. Never fake the code under test or an ace-rs crate it
calls, because then the test only proves the fake.

## Traps

- **An undeclared test file.** In a crate whose `tests/main.rs` declares its files, a new file isn't
  built until it's declared; `every_test_file_is_declared` fails until then.
- **A panic in a spawned task.** `tokio::spawn`'s task panicking doesn't fail the test unless the test
  awaits its `JoinHandle` and checks it. Return the task's result to the test, and bound the await.
- **State the process shares.** nextest runs each test alone, but `cargo test`, the doctests and
  `make coverage` run a program's tests as threads of one process. A test that needs a global (a
  tracing subscriber, installed observable types) sets it up itself, or it passes only when another
  test ran first.
- **Time.** No `sleep` to wait for something, and no assertion that something finished within a fixed
  time except a generous hang guard. Poll the state you need (a count, a row, `pg_stat_activity` for a
  lock) with a deadline. Under `make coverage` everything runs several times slower.
- **A runtime with one thread.** `#[tokio::test]` defaults to a current-thread runtime, where a blocking
  call stalls every task. A test of concurrency uses `flavor = "multi_thread"`.
- **Catalog views across tests.** Every test's database is on the same Postgres, so a query of
  `pg_stat_activity` or `pg_locks` filters on `current_database()`.
- **Local samples.** A test on a file under `samples/local/` skips it when it's missing, names it, and
  passes it to the differences check as skipped. Another clone has none of them.
- **`#[ignore]`.** An ignored test never runs in `make test`. Use it only for a measurement run by
  hand, or a test another test runs, and give the reason in the attribute.
- **A fallback that hides the bug.** A test that a stored value is used must trip every fallback that
  could compute it again, not only the most expensive one.
- **An input the code never changes.** Give a test's input a value the code must replace, not one a
  default or a helper already supplies.
- **Deleting a "duplicate".** Two tests that run the same code can make different claims. Before
  deleting one, compare what each asserts.

## Before asking for a review

```sh
python3 .agents/skills/ace-review/scripts/prepare.py --check
```

It lists the lines the change adds that the review flags (a sleep in a test, a wall-clock assertion,
an `#[ignore]` with no reason, an undeclared test file, an unbounded wait), each with the fix it
expects. Fix them or add the comment it asks for, run it again until it prints nothing, then run
`make test`.
