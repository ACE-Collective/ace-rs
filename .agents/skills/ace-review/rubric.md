# /ace-review rubric

## Who this review is for

The owner has stopped reading diffs and wants to know whether a change can ship and what must change
first. Every finding costs their attention, so it is about something they care about, backed by the
code, and says what goes wrong. Their priorities: **uptime > logging > tests > performance**, then lean
code. A correctness bug ranks by what it does to one of those. A bug that hangs a worker is an uptime
blocker; a wrong value shown on one GUI page is a fix-first.

## Severity

- **blocker**: the change must not merge as is.
  - It can take ace-rs (the core, a pool or the `ace` service) down, hang it, or keep it from
    restarting.
  - It can lose or corrupt data, or deadlock or long-lock a live table.
  - It edits a migration that has been applied, or adds one that isn't safe on a live, populated table
    (a full-table rewrite, a long lock).
  - It hides a failure from operators on a path that matters.
  - It can drop an event that should alert on a path that runs in production: a filter, exclusion or
    suppression that matches too much, or a cached answer read after the data behind it changed.
  - A check fails: fmt, clippy, a test, a doctest, the sqlx check or the layering check.
  - New behavior has no tests at all.
  - It is a security hole: a missing permission check, injection, unescaped output, a secret in a log,
    a hostile file parsed outside containment, or containment widened.
  - It names a site or a site's vendor, or holds customer data (AGENTS.md, *Conventions*): the
    repository is public.
- **fix-first**: merge after fixing.
  - An error is logged without its chain, or dropped with no comment saying why.
  - A failure path is untested.
  - It's an N+1 query, OFFSET paging, or per-request heavy work on a user-facing path.
  - It re-implements a helper that already exists.
  - It contains unrelated scope.
  - It breaks an established pattern in AGENTS.md: logic or a permission check in `ace-api` or
    `ace-gui` instead of `ace-service`, `anyhow` in a library, a query outside sqlx's macros without a
    reason, site-specific code in ace-rs instead of a generic extension point in `ace-app`, a port that
    departs from ace3 with no `differences.md` row or doc comment saying why.
  - It doesn't do what its description says, or a bug fix has no test that fails without it.
  - It's a real bug with limited blast radius.
- **nit**: worth one line, never blocks. Examples: a comment or doc comment that only restates the code,
  a needless module, trait or error variant, a small duplication, a misleading name.

## Lead judgment

Severity says how bad a finding would be; whether it holds the PR is the lead's call. After
verification each new survivor goes in one bucket, with a one-line `judgment`:

- **act on**: it holds the PR. Every confirmed blocker. A fix-first whose impact names harm on a path
  the change makes run in production (a hang or crash, a lost or wrong record, a dropped alert, a
  failure nobody hears about), or a test gap that would let this change's own fix or new behavior
  break unseen.
- **consider**: real, and fixing it now is the user's call. Every PLAUSIBLE finding, since its trigger
  isn't shown. A fix-first on a path nothing reaches today, or whose fix costs more than the harm it
  prevents.
- **noted**: the nits. Keep about 5, the ones that best show a habit worth correcting.

Six reviewers each fill a list, so some findings are always left over. A round whose survivors are all
consider and noted is a ship: say so.

## Verdict

- **rework**: an act-on blocker, or the change is so far from the conventions that fixing it item by
  item is the wrong approach (a site's code built into ace-rs, a second service layer), or a bug fix
  works around a symptom whose cause can be found and fixed within the change.
- **fix-first**: an act-on finding, or one from an earlier round still open.
- **ship**: everything else, consider and noted findings included.

When the checks weren't run (the range isn't checked out, the dev container was down, no `dev`
service), the verdict may not be "ship". Say "fix-first: checks not run" unless the change has no code
(docs only). Likewise, while `rule_changes_status` is `pending` say "fix-first: rule changes need your
decision", and when it is `rejected` the rule changes are a fix-first finding of their own.

## Design flaws worked around

Sometimes a change is shaped by a flaw in ace-rs's design rather than by a mistake of its own. The owner
hears about every such flaw and decides whether to stop or keep going; either way it becomes a
`design flaw` issue in `ACE-Collective/ace-rs`. A flaw never holds the change up by itself.

A design flaw is in the code on the base branch, not in the change, and fixing it is a piece of work
of its own, beyond what this change should take on. Signs of one:
- The change special-cases a type, mode, module or caller because a shared abstraction doesn't fit it.
- It copies or re-derives state because the schema doesn't record it, or records it in the wrong place.
- It polls, sleeps or re-reads because there is no event (`LISTEN/NOTIFY`, a channel), hook or
  persisted value to use instead.
- It matches on an error that an API returns for an ordinary condition, or checks for a value that an
  API should never return.
- It adds a lock, retry or ordering rule because ownership of some state is unclear.
- It reaches into another crate's internals, or a site copies ace-rs code, because the extension point
  it needs (an `App::` method, a trait in `ace-sdk`) doesn't exist.
- It is the second or third copy of the same workaround in the tree. Search for the others.

Keep the categories apart:
- A bug or a convention broken by the change itself is a **finding**.
- A symptom whose cause the change could fix itself is a finding (and a rework, per the verdict above),
  not a flaw.
- A flaw is reported **as well as** any finding on the workaround. The workaround is judged as code like
  anything else: a clean workaround of a real flaw has no finding at all.

For each flaw, size the real fix:
- **small**: one crate, no migration, a day or so.
- **medium**: several crates or a migration, but bounded.
- **large**: cross-cutting, many callers, or migrating existing data.

Then recommend **stop** (pause this branch and fix the flaw first, in its own change, never here) or
**keep going**:
- Recommend stop when the fix is small, when the workaround would spread (other code will copy it, it
  is a pattern other authors will follow), or when it writes data in a shape that is costly to migrate
  later.
- Recommend keep going when the fix is medium or large and the workaround is contained and easy to
  remove once the flaw is fixed.

Read the known flaws before reporting one: `$B/known-flaws.json`, one entry per issue, with its `id`
(the issue number), `status` (`open` or `wrong`) and `body`. A flaw already there is reported again
with its id in `known`. Skip a flaw whose status is `wrong`.

Report only flaws that this change actually works around, with the code that does it. A flaw you
happen to notice in code nearby, which the change doesn't depend on, isn't one.

## Do not report

- GUI implementation style: template structure, Datastar or JavaScript idiom, CSS. GUI code is reviewed
  only for broken behavior, performance and security.
- Software-engineering purism: SOLID, "should be a trait", dependency injection, function length,
  naming taste. The layering the `ace-layering` check enforces is a rule, not taste.
- How a log message is worded or formatted. Whether its identifiers are fields is the logging
  dimension's concern.
- Anything rustfmt or clippy would catch: they run in the checks, and a failure there is reported as a
  failed check.
- Hypothetical problems with no path in this codebase ("if someone later calls this with an empty
  slice..."). Name the caller or input that triggers it, or drop it. The consumer the PR description
  names counts as a caller, and so does the usage the change's own docs or examples recommend. A
  problem that appears when someone follows them is not hypothetical.
- The dev stack's own settings (`docker/site/overlay.yaml`, the defaults in `compose.yaml` for a laptop),
  judged as if they were a production site's.
- That a port does what ace3 does. Matching ace3 is the default (AGENTS.md, *Conventions*); a harm the
  copied behavior causes is reported like any other.

## New vs pre-existing

A finding is **new** if the change introduced or modified the offending lines, or if the change made
pre-existing code reachable in a new way (it now calls an old function with a new input that breaks
it).

A finding is **pre-existing** if the offending code was already there and the change only touches the
same function or file. Pre-existing findings are limited to the functions the change edits (not the
whole file), get `P` ids, never affect the verdict, and are never fixed in the branch: they are filed
for the owner's backlog. A fix round reports none.

## Findings schema

Each reviewer writes a JSON array to `$B/findings-<dim>.json`:

```json
[
  {
    "dimension": "uptime | logging | tests | performance | design | correctness",
    "severity": "blocker | fix-first | nit",
    "origin": "new | pre-existing",
    "file": "path relative to the repo under review",
    "line": 123,
    "title": "one line, the claim (<= 80 chars)",
    "evidence": "what the code does, quoting or citing file:line, including the caller/input that triggers it",
    "impact": "what happens in production because of it",
    "fix": "the smallest change that resolves it; name the existing helper to use if there is one"
  }
]
```

In a fix round, `answers` names the earlier finding whose fix put the code there. Write `[]` if there's
nothing. Don't pad.

A reviewer that finds a design flaw also writes `$B/flaws-<dim>.json`, an array of:

```json
[
  {
    "dimension": "the reviewer's dimension",
    "title": "one line, the flaw in ace-rs, not the change (<= 80 chars)",
    "flaw": "what is wrong in ace-rs's design and where (crates, files), and how it forces the workaround",
    "area": "the part of ace-rs, e.g. queue, eligibility, lease API, ace-sdk, alert page",
    "workaround": "what the change does because of the flaw",
    "file": "path in the repo under review where the workaround is",
    "line": 123,
    "fix_size": "small | medium | large",
    "fix": "a sketch of the real fix",
    "recommendation": "stop | keep going",
    "why": "one line: why stop or keep going",
    "known": "the issue number when known-flaws.json already has it, else omit"
  }
]
```

Write no file when there are none. The flaw's text becomes a public issue: describe ace-rs's code, never
a site's.

## Dismissals

A reviewer that saw a harm in the change and decided not to report it writes it to
`$B/dismissed-<dim>.json`: a trade-off it took to be someone else's choice, a problem it judged to have
no caller yet, a cost it judged too small. List only those, not every check that came up clean; most
rounds have none. The batch verifier tries to show each dismissal wrong, the way it tries a finding,
and a dismissal it overturns comes back as a finding.

```json
[
  {
    "dimension": "the reviewer's dimension",
    "file": "path relative to the repo under review",
    "line": 123,
    "title": "one line, the problem seen (<= 80 chars)",
    "harm": "what would go wrong, for whom, and what triggers it",
    "why_not": "why it was not reported"
  }
]
```

Write no file when there are none.

## Report template

```markdown
# /ace-review: <ace-rs | site workspace> <branch or range> (<short sha>, base <base>), round <N>

## Rule changes: your decision
<only while rule_changes_status is pending: what each entry in rule_changes does, from rule-changes.patch, one line each. The change was judged by the base branch's rules.>

## Design flaws: your decision
<one entry per flaw in summary.json whose status is undecided:>
- **<id>: <title>** (<fix_size> fix, <"new" | the issue link>): <the flaw, one or two lines>. *Here:* <what the change does around it, `file:line`>. *Real fix:* <fix>. *Recommend:* **<stop | keep going>**, <why>.
<then one line per flaw that already has an issue: "Also works around #<issue>: <title>. *Recommend:* **<stop | keep going>**, <why>.">
<end with: "Answer each new one with defer (keep going, fix it later), address (pause this branch; the fix is its own change, which lands first) or wrong; defer and address file it as a public issue in ACE-Collective/ace-rs." When `known` reported an error, say that the reviewers had no known flaws to match against, so a flaw listed as new may already have an issue.>

**Verdict: <SHIP | FIX-FIRST | REWORK>**: <2-4 sentences: the one or two things that decide it>

**Step back:** <when a chain in summary.json is 2 or more deep: its ids, and that its fixes share a wrong premise, so take them out of this branch and give the first finding its own change rather than a third fix. Otherwise only from round 4 on, when the verdict isn't ship: the new findings per round from target.json's history, and the part of the change that keeps producing them.>

**Intent:** <intent.md in one or two lines (a fix round with no correctness reviewer reuses the last round's): the stated problem, whether the change solves it at its cause, and whether that cause is shown or argued>

## Checks
- fmt / clippy / doctests: <pass | FAIL: first error | n/a>
- Tests: <N run, N passed, N failed, N skipped, from nextest's Summary | "not run: <reason>">, over <test_scope: the packages, or the workspace, and its reason>
- Changed-line coverage: <X% of N added lines; uncovered: file:lines, top few | not measured (no --coverage)>
- sqlx check: <pass | FAIL | n/a>; layering check: <pass | FAIL | n/a>
- Migrations: <n/a | new: <files> | EDITED: <applied migration>>
- Not exercised by these checks: <test_scope.outside, and what would check each (make images, make e2e, CI on x86-64) | none>
- Testing in the commit message or PR description: <present | missing>
- Review: <full | fix round since round N-1, new work: <files | none> | full, because <delta_reason>>

## Still open from earlier rounds
- **<id>: <title>** (`file:line`, <severity>)

## Act on
1. **<id>: <title>** (`file:line`, <severity>, <dimension>; <"from the fix for <answers>" when set>; <"dismissed by the <dimension> reviewer, overturned" when it has a dismissal>): <evidence>. *Impact:* <impact>. *Fix:* <fix>. *Why it holds the PR:* <judgment>
## Consider
<the same, ending *Why it can wait:* <judgment>>
## Noted
...

## Pre-existing, for the backlog
- **<P id>** `file:line` (<dimension>): <title>, <one line>
<end with: "These are not for this branch. File them as issues?">

<sub>Dropped as unverified: N (and N design flaws). Dismissals: N upheld, N overturned. Not repeated from earlier rounds: N. Fixed since the last round: <ids>. Bundle: $B</sub>
```

Number each finding with its `id` from `verified.json`, so the user can answer it by id. Leave out an
empty section's heading rather than writing "none", except under Checks.
