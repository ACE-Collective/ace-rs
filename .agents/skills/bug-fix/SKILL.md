---
name: bug-fix
description: "Fix an ace-rs bug at its cause: make it fail on demand, prove the mechanism by running code, then fix it with a test that fails without the fix. Use when asked to fix, debug, diagnose or investigate a bug, a crash, a hang, a wrong result, a regression, a flaky test, a difference from ace3, or a CI failure in ace-rs, or when /ace-review says a fix works around a symptom. Covers building a check that goes red, ranking falsifiable hypotheses, the evidence ace-rs keeps (logs, failed tasks, task replay), finding the commit a regression started in, and what the commit must show. For writing the test itself use tdd."
---

# Fixing a bug at its cause

The fix is usually the easy part. The hard parts come first: a check that fails on this bug, and a
mechanism proven by running code. Skip them and the fix rests on a guess. Every line that ships
traces back to evidence. A backstop added because it "might help" is a hypothesis, and it doesn't
ship.

Adapted from Matt Pocock's `diagnosing-bugs` skill and the bug-fix playbook and root-cause principles
of Lauren Tan's pstack (MIT, see `LICENSE`), by way of ace3's skill of the same name.

## Ask in this order

1. **Can you make it fail on demand?** Build the check first. Nothing else starts until it fails, or
   until you have told the user why you can't build it.
2. **What is the mechanism, and what proves it?** A run that flips the check, not a reading of the code.
3. **Where is the first wrong decision?** That is where the fix goes.
4. **Does the correct fix belong in this change?** If it needs ace-rs's design to change, say so.
5. **Does the regression test fail without the fix?**

## 1. A check that goes red

Build one command that drives the real code path and asserts the symptom that was reported. Run it
once and keep the output. It has to fail on this bug, give the same result every run, and finish in
seconds. Some ways to build one, roughly best first:

- a test that reaches the bug (the `tdd` skill's *Where to test*), run alone:
  `docker compose exec -T -e CI=true dev cargo nextest run --locked -p <crate> <name>`;
- a module's `Harness` on the file or observable that broke it;
- for a difference from ace3, the module's `tests/reference.rs` on the dump that differs, or
  `ace compare` through `tests/e2e/run` for a whole tree;
- for a failed task on the dev stack, `ace task replay <id>`, which runs its module again on the
  inputs the bucket kept, outside containment, so a debugger can attach;
- a real `ace` command, or an HTTP request against the dev stack;
- for a bug that happens only sometimes: loop the trigger, add load, and shorten timeouts until it
  fails often enough to work with. `make coverage` is a ready source of load: it runs every test
  several times slower.

Never copy customer data into a fixture (AGENTS.md, *Conventions*): build the smallest input with the
same structure.

Then shrink the check. Cut inputs, settings and steps one at a time and rerun after each cut, until
every part left is needed for the failure. The shrunk check becomes the regression test.

If you can't build a check, stop and say what you tried. Ask for access to where it reproduces, for
the logs, or for permission to add instrumentation. Don't start theorizing without a check.

## 2. Evidence from where it happened

- **Logs.** Records carry their identifiers as tracing fields: the root, the observable, the module,
  the task. `ACE_RS_LOG` (tracing's filter syntax) turns a module's records up without touching others.
- **Failed tasks.** A task that failed, hung or was killed keeps its row in `queue.tasks` with its
  error and the hashes of its inputs. `GET /api/crashes/v1/crashes` lists them, and `ace task replay`
  runs one again.
- **The tree.** `ace root normal-form <uuid>` prints a root's tree in the form the comparisons use, so
  two runs or a run and ace3's tree can be diffed.
- **When it started.** A regression has a first commit. Run `git bisect run` with the check. In a site's
  workspace, the ace-rs tag it pins narrows the window first.
- **Another machine only.** An x86-64 machine differs from this arm64 Mac, and another clone has no
  `samples/local/`. Reproduce those conditions before guessing: move `samples/local/` aside and run
  with `CI=true`, or look for something chosen by architecture.

## 3. Hypotheses

Write 3 to 5 ranked hypotheses before testing any of them. Each one makes a prediction: "if X is the
cause, changing Y makes the failure go away" (or "changing Z makes it worse"). A hypothesis without a
prediction is a guess: sharpen it or drop it. Show the list to the user if they're around, since they
often know which one it is. Don't wait for them if they aren't.

Change one thing at a time. Instrument where the hypotheses disagree: temporary log lines with one
unique tag (`[DBG-7f3a]`) so a single grep removes them all, or a debugger on `ace task replay`.

The mechanism is proven when changing what the hypothesis names flips the check. Code that "would" do
it doesn't count until it has.

## 4. Fix the first wrong decision

Ask "why" at each step until the answer is a decision in the code, not a consequence of an earlier one.
Then ask whether the state that broke the code is legitimate:

- If ace-rs can be in that state, the code that broke on it is the cause, and handling the state there
  is the fix.
- If the state should never exist, a check where it broke only hides the bug. Find what produced the
  state.

A symptom fix is usually a guard, a retry, an ignored error, a clamped value or a longer timeout. Find
every place with the same fault and fix them all.

**A difference from ace3** is a bug in the port until shown otherwise. If ace-rs is right and ace3
isn't, the fix is a `differences.md` row with the reason, verified, not a change that copies ace3's
bug. Ask the user which it is when the reason isn't certain.

**No correct place in this change.** Sometimes the correct fix is a change to how ace-rs works: an
extension point that doesn't exist, state recorded in the wrong place, or no way for a test to reach
the bug. Tell the user, and let them choose between fixing the design first in its own change and a
contained workaround now.

**Two fixes on one premise failed.** Stop. Write down in one sentence the premise both fixes assumed,
and test it directly before you write a third.

## 5. The regression test and the commit

Turn the shrunk check into a test with the `tdd` loop. Watch it fail on the unfixed code for the reason
that was reported, apply the fix, and watch it pass. Then rerun the original check, before it was
shrunk. If the only test you can write is too shallow to reach the real pattern (one caller, when the
bug needs two), say so: that gap is a finding of its own.

Before asking for a review:

- remove the tagged log lines and throwaway scripts (grep the tag);
- run `python3 .agents/skills/ace-review/scripts/prepare.py --check` until it prints nothing, then
  `make test`;
- write the commit message so it states the mechanism and how it was proven, and lists anything left
  unfixed.

## Traps

- **Cached analysis.** A fix to a module that keeps results in the analysis cache doesn't reach
  observables whose result is already kept: the key holds the module's name, version and settings,
  not its code. Bump the module's version (`docs/decisions/0004-analysis-cache.md`, *The key*).
- **Persisted state.** A failure that shows only after a restart or rebuild usually comes from
  persisted state: the dev stack's volumes, sccache, the `target/` volume, a migration whose checksum
  changed. Check those first.
- **A timing bound.** A test that fails only under load usually asserts that something finished in
  time. The fix is to wait for state, not to raise the bound (AGENTS.md, *Testing*, *Time*).
- **The wrong bug.** A check that fails, but not with the reported symptom, is a different bug nearby,
  and fixing it leaves the reported one in place.
- **A fix that moves the failure.** Turning a hang into a restart loop, or an error into a silent
  default, changes the symptom but leaves the bug. Run the original check again, and read what the
  fixed code now does on the failing input.
