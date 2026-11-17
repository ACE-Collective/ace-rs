# Where `tests/e2e/run`'s time goes, and the comparison several samples at once

`tests/e2e/run` took about an hour, most of it in `ace compare`, which ran the 472 samples one at a time. This asks where a sample's time goes, what running several at once and waking the modules that run last save, and whether either changes a tree.

Measured on 2026-11-16 and 17 on one machine: Docker (Rancher Desktop) with 10 CPUs and 31 GiB, ace3's stack idle on the same VM, release images, the e2e stack's one-rule ruleset. "HEAD" is `7c770927`, before this change. Every run is the whole sample set, 472 samples, 232,927 tasks. Times are from `report.json` (`seconds`, which `ace compare` measures) unless a row says otherwise.

## The instruments

- **Phases.** A `psql \watch` of `queue.tasks` every 50 ms, in the stack's Postgres container, counts each root's tasks by state. A tick is *running* when a task of the root is leased, *due* when none is and one could be claimed, *module wait* when all that's left is a module's own delay, *path hold* when the core holds a file's first task for its path, and *blind* when all that's left is tasks of modules that run last, asleep until they next ask. A root's time is from its creation to its last `queue.root_completions` row. The query took 0.6 ms. It misses anything shorter than a tick, and at HEAD it started 15 minutes into the run, so it covers 432 of the 472 roots there.
- **Reports.** Two `report.json` files are compared by a script that sets aside what differs between any two runs (*The same report*, below).
- **CPU.** At HEAD, `docker stats --no-stream`, a few snapshots, which are moments and not an average. For the later runs, each container's cgroup `cpu.stat` (`usage_usec`) read as `ace compare` starts and ends.

What these could be measuring instead: `cargo check` ran in the dev container for about three minutes of the HEAD run (02:00 to 02:03 UTC, three jobs), so its *running* time is slightly high; the sampler itself adds a query every 50 ms; and one machine's numbers say nothing about another's.

## One at a time, at HEAD

Three runs of `ace compare` at HEAD, one at a time: 2,855 s (the director's first, 469 samples timed), 2,800 s and 2,820 s. Per sample in the last two: median 4.3 s both times, range 0.5 to 62.8 s and 0.5 to 61.2 s. 11 samples over 30 s held 470 s.

Of the last run's 2,820 s, the roots took 2,745 s from creation to completion. The other 75 s is the comparison's own: the submission, its poll of the root every 250 ms, and reading the tree (median 0.18 s a sample, range -0.17 to 0.28; the negative ones are roots whose completion row was written after the poll saw them idle).

| Phase | Seconds | Share | Per root: median (range) |
|---|---:|---:|---|
| running | 1,493 | 63% | 2.31 (0.35 to 35.0) |
| blind | 726 | 30% | 1.20 (0 to 40.0) |
| module wait | 86 | 4% | 0 (0 to 2.0) |
| due | 55 | 2% | 0.05 (0 to 1.3) |
| path hold | 13 | 1% | 0 (0 to 0.7) |
| all | 2,381 | | 4.08 (0.49 to 56.4) |

Over 432 roots. So nearly a third of a root's time was a wait for nothing, and a small sample's floor is not its modules' work:

- **A root is mostly tasks that find nothing to do.** A root has 337 tasks at the median (54 to 4,808). A file observable gets 51.8 tasks, one for each module that might apply, and 85% of all tasks end without a result (34,290 results from 232,927 tasks). While any task of a root was leased, 4.5 were on average, and the parser pool had all 4 of its slots leased in 60% of those moments (a one-minute sample at 20 Hz: parsers 3.3 leased on average, sandbox 1.4, lookups 1.0). The machine was about a third used meanwhile: one busy snapshot had the parser pool at 1.9 cores, the sandbox 0.5, Postgres 0.3 and the core 0.2, and five of six snapshots caught the stack idle.
- **A task costs about 22 ms before its module runs.** The parser and sandbox pools run each task in a process of its own, and that process builds every module its pool has before it runs the one. 100 starts of `ace-parsers task` with the e2e overlay and ruleset and nothing on stdin, which ends right after the modules are built: 2.24, 2.26 and 2.32 s, so 22 to 23 ms each. The same with an argument it refuses before building anything: 0.22 to 0.25 s, so 2.3 ms for the process alone. `ace-sandbox task`: 1.55 to 1.59 s, 15.5 ms. Measured in a container of its own from the pool's image, on an idle machine. Not changed here; see *Found and left*.
- **The wait of the modules that run last.** Six modules run when the rest of their root is done (`Module::RUNS_LAST`), and every file has a task of two of them. The lease asks whether the rest is done each time such a task is claimed, and if not delays it by 0.25 s, doubled each time the answer is the same, up to 32 s (`OTHERS_PENDING_DELAY`). Nothing told a delayed task that the rest had finished, so it slept out its wait. 25,238 delays in the run, 24,615 of them on those modules.

The three slowest kinds, at HEAD:

| Sample | Seconds (two runs) | running | blind | Tasks | Delays |
|---|---|---:|---:|---:|---:|
| `ace4/email/encrypted_in_zip.email.rfc822` | 58.0, 56.5 | 25.6 | 29.5 | 2,490 | 430 |
| `ace4/email/encrypted_rc4_xls.email.rfc822` | 50.2, 50.4 | 7.7 | 40.0 | | 153 |
| `ace3/archive/test.jar` | 37.0, 27.5 | | | 3,603 | 436 |

The phases are the second run's; `test.jar` ran before the sampler started, and its task table has its first run-last task ending at 22.6 s and its root at 27.2 s. The task and delay counts of the first two are the director's, from an earlier run.

## The wait of the modules that run last

The change: when a task's end leaves a root with nothing but tasks the core holds back, the ones that wait for the other modules are made due at once (`queue::check_completion`). Whether each runs is still decided where it is leased, by the same check, so only the sleep goes. A task that waits for a run-last task below it keeps its own wait, which starts at 0.25 s.

One at a time, so that a root's time is its own:

| Run | Code | Parser and sandbox slots | `ace compare` | Per sample: median (range) | Blind: total, per root median (longest) |
|---|---|---:|---:|---|---|
| HEAD | `7c770927` | 4 | 2,820 s | 4.3 s (0.5 to 61.2) | 726 s over 432 roots, 1.20 s (40.0) |
| S2 | this change | 4 | 2,039 s | 3.04 s (0.52 to 35.5) | 239 s over 472 roots, 0.45 s (7.2) |
| S1 | this change | 8 | 1,759 s | 2.29 s (0.27 to 30.0) | 246 s over 472 roots, 0.50 s (7.2) |

S2 against HEAD is the wake alone, with the same pools: 781 s less, 28%. The median sample went from 4.3 s to 3.0 s and the longest from 61 s to 35 s, and the blind time a root from 1.68 s to 0.51 s on average. S1 has 4 more slots in each pool as well. One run each, so the 20 s between the two HEAD runs is the only measure of spread there is.

The three samples, one at a time, in seconds:

| Sample | HEAD | S2: woken, 4 slots | S1: woken, 8 slots | ace3 (floor, below) |
|---|---:|---:|---:|---:|
| `ace4/email/encrypted_in_zip.email.rfc822` | 58.0, 56.5 | 28.4 | 30.0 | 8.9 |
| `ace4/email/encrypted_rc4_xls.email.rfc822` | 50.2, 50.4 | 10.3 | 9.3 | 7.4 |
| `ace3/archive/test.jar` | 37.0, 27.5 | 24.7 | 19.9 | 19.0 |

What is left of the blind time is the wait for a run-last task below: a file's own run-last tasks wait for those of the files under it, asking again after 0.25 s, 0.5 s and so on. `encrypted_in_zip` still has 7.2 s of it in S1. Waking those too at each such task's end would cost an ask per waiting task per end, which grows with the square of a root's files, so it was left.

The number of delays hardly moves (25,238 at HEAD; 25,428 in S1), because most asks happen while the others still run. A delay counts an ask, not a wait.

## Several samples at once

`ace compare --jobs N` keeps N samples in the stack. With the pools as the stack ships them, 4 parser and 4 sandbox slots, that overlaps the waits and little else, because one root already fills the parser pool. So `tests/e2e/run` also gives those two pools Docker's CPUs less two, from 4 to 8: 8 here.

| Run | Code | At once | Parser and sandbox slots | `ace compare` | Per sample: median (range) | CPU seconds (cores) |
|---|---|---:|---:|---:|---|---|
| the director's | HEAD | 1 | 4 | 2,800 s | 4.3 s (0.5 to 62.8) | |
| HEAD | HEAD | 1 | 4 | 2,820 s | 4.3 s (0.5 to 61.2) | |
| S2 | this change | 1 | 4 | 2,039 s | 3.04 s (0.52 to 35.5) | 7,526 (3.7) |
| S1 | this change | 1 | 8 | 1,759 s | 2.29 s (0.27 to 30.0) | 7,790 (4.4) |
| P1 | this change, less one error path | 8 | 4 | 1,592 s | 20.1 s (2.8 to 127.0) | |
| P3 | this change | 8 | 8 | 1,207 s | 14.9 s (1.5 to 94.8) | 8,215 (6.8) |
| P4 | this change, in `tests/e2e/run` | 8 | 8 | 1,254 s | 14.9 s (1.8 to 99.9) | |

One run each. CPU seconds are each container's cgroup `usage_usec` across `ace compare`, summed: in S1 the parser pool 4,270, the sandbox 1,616, Postgres 1,049, the core 613 and the bucket 209.

- **At 8 at once a sample takes longer and the set less.** A sample's own time is mostly its wait for a slot: in P3, 75% of the roots' time was *due*, 24% *running* and 1% *blind*.
- **The pools are the limit, not the machine.** P1 has 8 samples in the stack and 4 slots, and takes 90% of S1's time, which has one sample and 8 slots.
- **A task's start is over half the CPU.** A run has 150,250 parser tasks and 55,662 sandbox tasks (the pools' logs, one line a task). At 22.5 ms and 15.5 ms a start that is 4,240 core-seconds of a run's 7,790 to 8,215.
- **P1's image** differs from the others' in one line: the lease then failed when it couldn't wake held tasks, and now logs a warning. That path didn't run.

A run with the same settings as P3 was thrown away: a command meant to time the task process started a second parser pool in the stack's container for about three minutes. It still compared 472 samples with none failed and the same report.

`tests/e2e/run` as a whole, P4, one run: 26 minutes 37 seconds. That is 24 s to bring the stack up, with every image layer still cached from S1's build of the same sources, 5 minutes 10 seconds of scenario checks, and 21 minutes for the comparison with its setup. With the release build to run, as after any change to the sources, it is about 30 minutes, 3 to 4 more (*The image build*). The director's run at HEAD took 58.

## The same report

Two runs of the same code never give the same `report.json`, one at a time or not. Comparing the two HEAD runs, both one at a time, showed what moves, and all of it is in rows `differences.md` already has:

1. `seconds` and `root`.
2. Ghostscript's rewrite of a PDF, `<name>.gs.pdf`, has new bytes each run. So do its hashes, which the tree holds as `md5:`, `sha1:` and `sha256:` observables that ace3 doesn't have. Their number per sample is the same each run.
3. pdftotext's text of a PDF and of its rewrite is one file observable, redirected to whichever of the two PDFs has the lower sha256 (`tree::upsert_observable`). The rewrite's sha256 is new each run, so it is a coin toss whether the redirection is ace3's, which is the rewrite. 38 and 41 of them differed from ace3 in the two HEAD runs, in 20 samples a different number. This is the whole of "the count of explained differences moves by a few".
4. Values of ace4's that hold a time or a task's temporary directory: exif's `File:FileAccessDate`, `File:FileInodeChangeDate` and `File:FileModifyDate` (368 each), `dmg_analyzer`'s stderr (9), `de4dot`'s stdout (3), and `file_hash_analyzer`'s hashes of a rewrite (2 of each).
5. One value that `report.json` cut at 2,000 characters: an observable only ace4 has, whose results came in the order they landed. `ace compare` now sorts a value's keys before it cuts it.

With those set aside the script compares everything else exactly: the samples and their order, the absent and failed ones, the threshold's result, stale rows, what each row matched, each sample's failed tasks and skipped results, and for every sample each difference's path, module, class and both values.

Compared that way, every pair below is the same, with nothing left over:

| A | B | Redirections that follow the rewrite's hash (A, B) |
|---|---|---|
| the director's, HEAD, 1 at once | HEAD, 1 at once | 38, 41 |
| HEAD, 1 at once | P1, 8 at once | 41, 36 |
| HEAD, 1 at once | S1, 1 at once | 41, 40 |
| S1, 1 at once | P3, 8 at once | 40, 37 |
| HEAD, 1 at once | P3, 8 at once | 41, 37 |
| S1, 1 at once | S2, 1 at once | 40, 41 |
| S2, 1 at once | P3, 8 at once | 41, 37 |
| S2, 1 at once | P1, 8 at once | 41, 36 |
| S1, 1 at once | P4, 8 at once | 40, 33 |
| S2, 1 at once | P4, 8 at once | 41, 33 |
| P3, 8 at once | P4, 8 at once | 37, 33 |

S1, P3 and S2 ran on one stack, one after another, P3 and S2 with `--threshold`, and P4 is `tests/e2e/run`'s own enforcing run on a new stack. Each met the threshold: 0 unexplained, 0 failed, no stale row. Every run had 378 harness differences and 0 unported; the explained ones were 7,884 to 7,892, moving only with the coin tosses.

## How near a limit a run of 8 came

Running together doesn't make a task slower than one large root does, since the pools take as many tasks at once either way. It makes a task wait longer for a slot, and four limits run on the clock across that wait.

| Limit | One at a time (S1) | 8 at once, 8 slots (P3) | 8 at once, 4 slots (P1) |
|---|---:|---:|---:|
| `--sample-timeout`, 300 s: the longest sample | 30.0 s | 94.8 s | 127.0 s |
| A file's first task held for its path, 60 s (`PATH_HOLD_LIMIT`): times the core passed it | 0 | 0 | 0 |
| The JavaScript module's wait for its scan, 60 s: the longest from its delay to its end | 1.6 s | 12.9 s | 21.2 s |
| A Splunk query, 300 s: the longest from its first delay to its end | 5.9 s | 8.1 s | 4.2 s |
| A queued scan, its 30 s and 600 s more: the longest queued | 0.03 s | 0.02 s | 0.01 s |
| Tasks failed, or leased more than once | 0, 0 | 0, 0 | 0, not counted |

The core logs a warning when it passes the path hold, and none was logged in any run. The times are from `queue.tasks` and `queue.scans` after each run. P4's longest sample took 99.9 s. The nearest is the longest sample at 4 slots, at 42% of its limit. A machine with fewer CPUs, or more samples at once, comes nearer. `tests/e2e/run` gives a machine with fewer CPUs fewer slots and as many samples at once, down to 4 of each at 6 CPUs, and that wasn't run.

## ace3 on the three samples

`tools/ace3/trees/make-trees SAMPLE`, the whole command, three runs each, on an idle machine:

| Sample | Seconds | Less the trivial sample |
|---|---|---:|
| `ace3/pcap/sslkeylog.txt` (trivial) | 6.64, 5.98, 6.06 | |
| `ace4/email/encrypted_in_zip.email.rfc822` | 14.99, 14.94, 14.77 | 8.9 |
| `ace3/archive/test.jar` | 25.05, 25.28, 24.92 | 19.0 |
| `ace4/email/encrypted_rc4_xls.email.rfc822` | 13.46, 13.63, 13.38 | 7.4 |

What this is: one Python process that runs every enabled module on the sample in turn, with no queue, no database, no containment and no second process, after copying fixtures in and starting its fake Splunk and DNS. The trivial sample's time is that setup plus Python's start and ace3's imports. It is not ace3's engine, whose workers, database and message queue would add to it, so it is a floor for ace3. ace4's times for the same three are in the tables above and below.

## The image build

`tests/e2e/run` builds the six release images first. With the layers of the base stages cached, the `cargo build --release` step compiled the whole workspace whenever the sources had changed: 3 minutes 44 seconds and about 4 minutes 15 seconds from the script's start to the comparison's setup being done (two runs of `--compare`, which also wait for the ruleset and load the detections), against 24 s to the stack being up when no layer needed building. It never has a warm target directory: the step's target is a BuildKit cache mount, and this machine's builder keeps at most 1.29 GiB of cache mounts (`docker buildx inspect`: `GC Policy rule#0 ... type==exec.cachemount ... Max Used Space: 1.287GiB`), while a release target is about 10 GB. Its other rules start pruning when the disk has under 18.6 GiB free, which it had throughout, so layers go too: the run at HEAD rebuilt every stage and took about 20 minutes to bring the stack up. This is the machine's setting, not the repository's, and it wasn't changed.

## Found and left

- **A task process builds every module of its pool.** `parser_task` (`crates/ace-app/src/pools.rs`) builds the pool's modules "as the supervisor did" and then runs one. That is 4,240 of a run's 7,790 to 8,215 core-seconds here (*Several samples at once*), and with a production ruleset each task also loads the rules, whichever module it is for (`memory.md`). Building only the module the request names would need the request read before the modules are built. It changes what every task process does before containment, so it wants its own step and its own measurement.
- **Most tasks decline.** 85% of tasks store nothing. A module's manifest could say which files it takes, so the core queued fewer, but that is a change to eligibility.
- **`email_thread_analyzer` waits 10 s at a time** for the email logger to record the root's email (`RECORDING_DELAY`), and the logger takes milliseconds. It only happens for an email with the `original_email` directive, which no sample in the comparison has.
- **The builder's cache**, above.
- **`make-trees` fails now and then at its last step** with git's `detected dubious ownership in repository at '/opt/ace'`, after writing its trees. It did so on two of twelve runs here. The script's comment says the cause wasn't known; this is the message.

Not measured: the scenario checks before the comparison (about 7 minutes, the director's figure), a machine with fewer CPUs, more than 8 at once, and a production ruleset.
