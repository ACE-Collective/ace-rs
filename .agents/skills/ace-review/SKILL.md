---
name: ace-review
description: "Review an ace-rs branch, PR or commit range against AGENTS.md's engineering values (uptime, logging, tests, performance, keeping it lean) and give a ship / fix-first / rework verdict. Flags where a change works around a flaw in ace-rs's design and tracks those flaws as GitHub issues labeled \"design flaw\". Works for ace-rs and a site's own workspace on any git host. Use when asked to review a PR, a branch, or \"my changes\" in this project."
argument-hint: "[<repo path>] [PR# | branch | A..B] [--base REF] [--full] [--coverage]"
---

# /ace-review

You review one change the way the owner would. They no longer read diffs line by line; they rely on
this review to catch what they care about. The values come from the **Engineering values** and
**Conventions** sections of AGENTS.md, which are the source of truth: if a rule isn't there, it isn't a
rule. A change is judged by the base branch's AGENTS.md, never by the copy it edits itself. `rubric.md`
(next to this file) says how to rank findings and what to ignore. Read both before starting.

The arguments are `$ARGUMENTS`. The skill directory, `.agents/skills/ace-review` in the ace-rs
checkout, is called `$S` below. Its scripts run on the host with `python3` and need only the standard
library; the checks run in the dev container.

## 1. Resolve the target

- **Which repo.** With no repo path, review the ace-rs checkout. A path names a site's own workspace:
  a separate repo that depends on ace-rs's crates by git tag, has its own Compose stack and may be
  hosted somewhere other than GitHub. Only plain `git` is assumed to exist there.
- **Nothing given and it's unclear what to review.** Run `python3 $S/scripts/prepare.py --list`, which
  lists the ace-rs checkout and its worktrees, and ask which to review, naming the ones ahead of their
  base or with uncommitted work. Never merge two repos into one diff.
- **A PR number.** Resolve it with `gh pr view N --json number,title,body,headRefName,baseRefName,url`
  only if `gh` is installed and logged in for that host. Otherwise ask for the branch name. Save the
  title and body to `$B/pr.md` once prepare.py has made `$B`.
- **Checkout.** The checks run in the repo's dev container against its working tree, so the change
  must be checked out there. If a different branch is checked out, **ask before switching**, and never
  switch over uncommitted work. A range of commits that aren't checked out can be reviewed without the
  checks: prepare.py writes no `checks.sh`, and the report says so.
- **Base.** Pass `--base` when the PR targets anything but the default branch (its `baseRefName`).

Then run, from the ace-rs checkout:

```bash
python3 $S/scripts/prepare.py [--repo <path>] [--base REF | --range A..B] [--full] [--coverage]
```

It prints `target.json`; its `bundle` is the bundle directory, called `$B` below. Each review of a
branch is a **round** under `local/ace-review/` in the ace-rs checkout, built on the last finished
round of the same branch. Read these fields first:

- `unchanged`: nothing changed since the last round. Say so and stop, unless the user wants the review
  anyway (`--full`).
- `delta`: this is a **fix round** over `delta.patch`, what changed since the last round. Otherwise
  `delta_reason` says why it is a full review. Pass `--full` only when the user asks to review the
  whole change again.
- `rule_changes`: the change edits the rules it is reviewed by (`rule-changes.patch`). Until the user
  accepts them (step 6), the report opens with them, the verdict waits on them, and the change is
  judged by the base rules; once `rule_changes_status` is `accepted`, `rules/` holds the edited copy.
- `kind`: `ace-rs`, or `site` for a site workspace. A site is judged by ace-rs's AGENTS.md at the tag
  it pins (`rules` says which copy was found) and by its own, in `rules/repo-AGENTS.md`.
- `test_scope`: the packages whose tests the checks run and why. A change to a package's code takes in
  every package that depends on it; a change to its `tests/` only takes in itself; a change to
  `Cargo.lock`, the root `Cargo.toml`, the toolchain, `.cargo/` or `vendor/`, or one that reaches more
  than 60% of the packages, runs the whole workspace. `outside` lists changed paths no package holds
  (`docker/`, `.github/`, `tools/`), which these checks don't exercise.
- `checks`: `checks.sh` when there is one to run, or why there isn't. A site workspace whose Compose
  file has no `dev` service needs `--exec '<how to run a command in its dev container>'`; ask the user.

Then run `python3 $S/scripts/findings.py known $B`, which writes the known design flaws to
`$B/known-flaws.json`. If it reports an `error`, go on with no known flaws and say so in the report. A
`label` of `missing` means the `design flaw` label doesn't exist yet, so no flaw is known; that is not
an error.

**A change that spans repos** (an extension point in ace-rs plus the site code that uses it): prepare a
bundle per repo, review each separately, and give each its own verdict. Cross-reference the bundles in
the report.

## 2. Start the checks (background), then fan out the reviewers

Start the checks first; they are the slow part.

- **Before starting.** The dev container must be running (`make up` in ace-rs). Never run two heavy
  builds at once, here or in a site's workspace (AGENTS.md, *Environment*): Docker's disk is shared,
  and a full disk stops ace3's databases too. If a `make coverage`, an image build or another
  workspace's build is running, wait for it or ask. Two cargo commands in one container wait for each
  other on cargo's lock ("Blocking waiting for file lock"); say in the report if the checks waited.
- **Running them.** If `checks` is `checks.sh`, run it with `run_in_background`:
  ```bash
  sh $B/checks.sh > $B/checks.txt 2>&1
  ```
  Each step prints its command, its output and `exit[<step>]=<code>`: Docker's free disk, fmt, clippy
  with `-D warnings`, nextest over `test_scope`, the doctests, the sqlx check when the change touches a
  migration, a query macro or `.sqlx/`, and the layering check when it changes a `Cargo.toml`. A
  failed step doesn't stop the rest. Exit 3 means the dev container isn't running.
- **Coverage** is off by default. `make coverage` builds the whole workspace instrumented: about 23
  minutes and 23 GB of Docker's disk. With `--coverage`, `checks.sh` also runs the tests in scope under
  `cargo llvm-cov` (skipping the tests `make coverage` skips), writes `$B/coverage.lcov`, and cleans the
  instrumented build away; it refuses with less than 35 GB free. Pass `--coverage` only when the user
  asks for changed-line coverage. Without it, the tests reviewer works from the diff and the test run.

**A full round.** While the checks run, launch these reviewer subagents **in parallel in one message**
(`subagent_type: general-purpose`), one per dimension: `uptime`, `logging`, `performance`, `design`,
`correctness`. The `tests` reviewer starts once the checks have finished, because it reads their
output. Give each subagent this prompt, with the placeholders filled in:

> You are the `<dim>` reviewer for /ace-review. Read `$S/rubric.md`, then `$S/dimensions/<dim>.md`,
> then follow it. Wherever they say AGENTS.md, read `$B/rules/AGENTS.md` (and `$B/rules/repo-AGENTS.md`
> if it exists): it is the copy the change is judged by, and where it differs from the AGENTS.md you
> were started with, it wins. The change is described by the bundle in `$B` (start with
> `target.json`, `stat.txt`, `files.txt`, `diff.patch`; `pr.md`, `log.txt` and `related-docs.txt` if
> present). Each entry in `$B/leads.json` whose `dimension` is `<dim>` is a line that matched a
> mechanical check: look at every one, and report the real ones, one finding per class listing all its
> locations. Never report again a finding that `$B/previous.json` lists, whatever its status. If the
> change works around a flaw in ace-rs's design, write it to `$B/flaws-<dim>.json` as rubric.md's
> "Design flaws worked around" says. If you saw a harm in the change and decided not to report it,
> write it to `$B/dismissed-<dim>.json` as rubric.md's "Dismissals" says. The repo under review is
> `<repo>`; ace-rs is `<ace-rs checkout>`. Read the surrounding code, not only the diff. Don't build or
> run tests: the checks are running already. Write your findings as a JSON array to
> `$B/findings-<dim>.json` using the schema in rubric.md, and reply with just the count of findings by
> severity, of design flaws and of dismissals.

Over ~1500 changed lines, `design` and `correctness` may each run as two reviewers on disjoint file
lists, writing `findings-<dim>-1.json` and `-2.json`.

**A fix round** (`delta`) checks the fixes instead of searching again. Use `delta-files.txt`, the new
commits in `log.txt` and `previous.json` to split the delta into fixes (step 3) and new work. Launch
the five reviewers above on just the new-work files, adding to their prompt "This is round `<round>`.
Review only `<files>` in `$B/delta.patch`: report findings in code it adds or changes, or makes
reachable in a new way, and no pre-existing ones." With no new work, launch none.

## 3. Tests, coverage and fixes

When `checks.txt` ends with `== done`:

- If it shows `exit[coverage-report]=0`, run `python3 $S/scripts/findings.py coverage $B`. It writes
  `changed-coverage.json` and `changed-coverage.md`: the added lines the instrumented build counted,
  how many ran, and which didn't. Coverage is reported, not gated, and it measures only the tests in
  scope.
- Launch the `tests` reviewer with the same prompt as the others (in a fix round, only for new work). It
  also reads `$B/checks.txt` and `$B/changed-coverage.json` if it exists.

In a fix round, launch the `fixes` reviewer **last**, once every other reviewer has finished, because it
edits files to probe the tests: the same prompt with `<dim>` set to `fixes`, plus "The new-work files,
which other reviewers have: `<files or none>`." Its probes build in the dev container, so nothing else
may be building then.

## 4. Verify, then judge

Each finding is judged in a fresh context by a verifier that tries to disprove it.

1. When every `findings-*.json` exists, run `python3 $S/scripts/findings.py collect $B`. It prints the
   plan.
2. Launch every verifier in one message. For each `single` entry and each vote `k`:
   > You verify candidate `<cid>` for /ace-review, vote `<k>`. Read `$S/rubric.md` and
   > `$S/dimensions/verify.md`, then follow its "One finding" section for the bundle in `$B`.

   If `batch`, `carry`, `flaws` or `dismissed` is non-empty, one more:
   > You are the batch verifier for /ace-review. Read `$S/rubric.md` and `$S/dimensions/verify.md`, then
   > follow its "Batch" section for the bundle in `$B`: candidates `<batch>`, earlier findings
   > `<carry>`, design flaws `<flaws>`, dismissals `<dismissed>`.
3. Run `findings.py tally $B`. If it lists missing votes, relaunch those verifiers once, then tally with
   `--allow-missing`.
4. Read `$B/survivors.json` and `$B/previous.json`. Merge duplicates across dimensions: keep the most
   severe, add the other's evidence. Mark a survivor that is an earlier finding again with
   `"repeats": "<its id>"`. A survivor with a `dismissal` is one a reviewer dropped and the batch
   verifier overturned. Then judge each new survivor as the lead, by rubric.md's "Lead judgment": a
   `bucket` and a one-line `judgment`. Write them, ranked, to `$B/ranked.json`. In `$B/flaws.json`,
   merge flaws that two reviewers both found into one entry, then run `findings.py finish $B`, which
   refuses a bucket the rubric forbids. `summary.json` lists each flaw with the `issue` the verifier
   matched it to, or null for a new one. finish writes nothing to GitHub.

## 5. Report

Write `$B/report.md` and print it in the terminal, using the template in rubric.md. It draws on
`target.json`, `summary.json`, `verified.json`, `intent.md`, `checks.txt` and `changed-coverage.json`.
The verdict is never better than `summary.json`'s `verdict_floor`, and a design flaw never makes it
worse.

When a flaw is undecided, also say it at the end of your reply in the terminal, in one line per flaw
with its recommendation, so it is not missed under the findings.

Don't post anything anywhere. The user decides what goes on the PR.

## 6. Answers and the conventions

When the user answers a finding, record it, so the next round neither repeats nor rechecks it:
`findings.py answer $B <id> fixed|wrong|intentional|"didn't matter" [--note TEXT]`. A decision on the
rule changes is `findings.py answer $B rules accepted|rejected`.

Design flaws are GitHub issues labeled `design flaw` in `ACE-Collective/ace-rs`, whatever repo is
reviewed. The review files a new flaw's issue and never changes an issue after that. Its state is the
user's: open is a known flaw, closed as not planned is a flaw found wrong (reviewers skip it), closed
as completed is fixed.

A new flaw is filed only when the user answers it:
- `defer` (keep going) or `address` (pause this branch and fix the flaw first): run
  `findings.py file $B F<n>`, which files the issue and prints its link. The fix for `address` is never
  made in this branch: it is its own change, which closes the issue, and this branch rebases onto it
  and drops its workaround. A flaw found in a site workspace is fixed in ace-rs with a generic
  extension point (AGENTS.md, *Architecture*), never with the site's own code.
- `wrong` when it isn't a flaw: nothing is filed.

A known flaw already has its issue; whether to stop or keep going is the user's call.

The issue is public. Before filing, show the user its title and body, and check that neither names a
site, a site's vendor or anything from its data (AGENTS.md, *Conventions*). For a site workspace the
body names neither the repo nor the branch, but the flaw's own text may still need rewording. `file`
refuses while `known-flaws-error.txt` is in the bundle: run `findings.py known $B` again and check the
flaw against `known-flaws.json` first. While the label doesn't exist, `file` refuses and prints the
`gh label create` command; creating it needs write access to the repo, so leave that to the user.

Offer `gh issue list --repo ACE-Collective/ace-rs --label "design flaw"` when the user asks what to fix
next. When they ask how the review is doing, run `findings.py stats [--since YYYY-MM-DD]`; its
`lines changed` and `unchanged` are inferred from whether the code moved, not answered.

When they reject a finding because the rule is wrong, or name a rule the review missed, offer a small
edit to the **Engineering values** section of ace-rs's `AGENTS.md` (or to a dimension file, if it is
only a review heuristic). Make it only once they agree.

## 7. Fixing findings

Whoever fixes findings follows this, so the next round finds nothing new in the fixes:

- Fix the **act on** findings, or the ones the user names. A consider or noted finding is fixed only
  when named. Fix one at a time, with the smallest change its *Fix* describes, and nothing else in that
  edit.
- A `P` id is pre-existing and is never fixed in this branch. Offer to file it as an issue, or for a
  site workspace in wherever that repo tracks its work. A design flaw goes through step 6.
- A test written for a finding must be seen to fail without the fix (the `tdd` skill), with both runs
  in the commit message. A finding that a fix works around a symptom goes through the `bug-fix` skill.
- Ask before a fix that reaches past the finding's function or changes behavior it didn't name.
- A chain two fixes deep (*Step back* names it) means the fixes share a wrong premise: recommend
  taking them out of the branch, not a third fix.
- Record each with `findings.py answer $B <id> fixed`, and run `prepare.py --check` until it prints
  nothing but leads the user has accepted. A comment on a lead's line, or the line above, saying why
  it is right (what bounds a wait, why a print or a dropped error is right) clears most leads. Run the
  next round only when the user asks.
