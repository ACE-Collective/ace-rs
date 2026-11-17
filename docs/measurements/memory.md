# Memory

PLAN.md step 3.5 measures each pool's private memory while 3.3's comparison runs. These numbers come from a small load: `ace compare` over the 54 local samples, 5.3 MB of files, in about 31 seconds. **They aren't comparable like for like with ace3's production figures,** and *Against ace3's figures* below says what they do and don't support.

These runs were made when `ace compare` ran one sample at a time and the parser pool 4 tasks. Since 2026-11-16 `tests/e2e/run`, whose stack and comparison `tools/memory/measure` uses, runs 8 samples at once with 8 slots in the parser and sandbox pools on a machine with 10 CPUs (`compare-speed.md`), so a new run measures a heavier load than these did, and its peaks aren't comparable with these.

## Summary

Medians of runs, with the range over runs, in MB. Private dirty is the column to read against ace3, because that's what ace3's figures are (*What "private" means*). Series *fixture* is `tests/e2e/run`'s stack with its one-rule ruleset, 5 runs. Series *signatures* is the same stack with the ruleset built from ace3's signatures checkout, 3 runs, because every task process loads the ruleset and one rule hides that cost.

| Process | Moment | Fixture: private dirty | Fixture: private | Signatures: private dirty | Signatures: private |
|---|---|---|---|---|---|
| Parser supervisor | idle, before | 3.0 | 17.9 | 17.2 (16.2 to 17.5) | 32.7 (31.6 to 32.9) |
| Parser supervisor | peak during compare | 10.3 (9.3 to 12.0) | 25.4 (24.4 to 27.1) | 27.0 (26.9 to 27.9) | 42.7 (42.6 to 43.6) |
| Parser task process, one | median task's peak | 2.3 | 2.6 | 17.7 | 17.7 |
| Parser task process, one | largest task's peak | 6.8 | 8.4 | 17.7 | 19.5 (19.5 to 19.6) |
| Parser pool: supervisor and up to 4 tasks | peak at one moment | 19.8 (18.1 to 23.2) | 37.1 (36.1 to 41.8) | 97.9 (97.8 to 98.8) | 113.5 (112.8 to 114.4) |
| Lookup pool, one process | idle, before | 2.5 | 12.1 | 2.5 | 12.1 (12.0 to 12.1) |
| Lookup pool, one process | peak during compare | 5.1 (4.9 to 5.3) | 15.6 (15.4 to 15.9) | 5.3 (4.8 to 5.4) | 15.8 (15.4 to 16.0) |
| `ace` core, not a pool | idle, before | 6.1 (6.0 to 6.1) | 34.6 (34.5 to 34.7) | 33.0 (32.9 to 33.3) | 62.9 (62.7 to 63.2) |
| `ace` core, not a pool | peak during compare | 32.0 (29.1 to 33.2) | 56.8 (46.1 to 60.9) | 55.9 (55.5 to 58.4) | 75.5 (73.0 to 84.4) |

The sections below give the load, how the figures were taken and what else they include.

## The load

Each run's comparison finished with exit 0 over all 54 samples, every task ended `done`, and the counts were the same in all 8 runs.

| | Count |
|---|---|
| Samples, each one root in `cli` mode | 54, 5.3 MB in all; the largest is 1.8 MB |
| Parser task attempts: `archive` 330, `yara_scanner_v3_4` 330, `email_analyzer` 286 | 946, no retries, no non-zero exits |
| Lookup task attempts: `rdap_analyzer` 17 and `clicker_detection_splunk` 7, against recordings | 24 |
| Core task attempts: `yara_qa` | 0 in fixture, 1 in signatures, where a QA rule matched |
| Results stored | 71 |
| Length of the comparison | fixture 31.0 s (31.0 to 31.2), signatures 45.5 s (45.5 to 45.8) |
| Parser concurrency | 4, and 4 tasks did run at once in every run |

That is small. A parser task process lives for 3.9 ms at the median with the fixture ruleset. The 946 task processes add up to 3.3 s of CPU in a fixture run and 75.8 s in a signatures run. The rest of the 31 seconds wasn't broken down; it includes `ace compare`'s 250 ms poll for each sample and the delayed Splunk tasks. Nothing here has run for hours, seen a large email or met many alerts at once.

## How it was measured

```sh
tools/memory/measure OUT_DIR --runs 5 --idle 30
tools/memory/measure OUT_DIR --runs 3 --idle 30 --signatures /path/to/signatures
python3 tools/memory/summarize.py OUT_DIR --series NAME --tsv FILE --tasks-tsv FILE
```

`measure` brings up `tests/e2e/run`'s stack as project `ace4-e2e` from empty volumes, with that test's overlay, images and recorded responder, and takes it down after each run. Once the parser pool has loaded its ruleset it starts `tools/memory/sample.py`, then waits through three phases: `idle-before` for 30 seconds, `compare` while `ace compare` runs, and `idle-after` for 30 seconds. The `compare` phase uses `compare_with_ace3` from `tests/e2e/run` itself, without `--threshold`.

The sampler runs in a helper container on `ace4-dev:latest`, privileged, with the VM's PID namespace, cgroup tree and network namespace, because reading another user's `smaps_rollup` needs it and taskstats only reaches sockets in the VM's network namespace. It reads only the cgroups of `ace4-e2e`'s containers. It writes nothing to them except a reset of its own `memory.peak` file descriptor, which doesn't change the container's count. Taskstats is VM-wide, and the sampler keeps only records with the task user's uid and the pool's process name.

Raw data, one row per figure per run: [memory-3.5.tsv](memory-3.5.tsv). One row per task process: [memory-3.5-tasks.tsv](memory-3.5-tasks.tsv).

Measured on 2026-11-06 at commit df3474e, on Rancher Desktop's VM (Linux 6.18.60, aarch64, 10 CPUs, 24 GB), with release images from `docker/ace4/Dockerfile`.

### What "private" means

Each figure comes from `/proc/PID/smaps_rollup`.

- **Private dirty** is `Private_Dirty`. It's what ace3's investigation calls private: `ace3/local/proc_mem.sh` and `ace_node_memory_report.sh` both print `Private_Dirty` as `priv`, and the investigation's "232 MB is private dirty" is the worker it calls 232 MB private. It equals `Anonymous` exactly on every task process here, and on `ace` and lookups to within about 1 MB. On the supervisor a sample can read up to 27.8 MB lower than `Anonymous`. The likely cause is a fork in flight, when its pages count as shared until the child execs; Rust's standard library forks rather than uses `posix_spawn` when a uid is set. That wasn't confirmed, and it affects medians little: the signatures series' supervisor has a median of 26.8 and a peak of 27.0. Postgres differs by more, because its backends share pages with their parent.
- **Private** is `Private_Clean` + `Private_Dirty`. Its clean part is mostly the process's own binary, file-backed and droppable, which counts as private only while no other process maps those pages. That's why the idle supervisor shows 17.9 MB private and 3.0 MB private dirty: nothing else maps `ace-parsers` (52 MB on disk) at that moment. Once task processes map it, those pages move to shared. So private is the less stable figure of the two.
- **PSS** and **RSS** are in the TSV as well. A task's RSS is about 18 MB, nearly all of it the shared binary, and its PSS at the median is 8.4 MB in the fixture series.

### Catching the peak of a short-lived process

A task process can start and exit between samples, so three sources were cross-checked.

| Source | What it gives | What it can miss |
|---|---|---|
| Kernel taskstats exit records | One record per exit: peak RSS, lifetime, CPU, exit code | Nothing here: 946 records in each run, equal to the database's 946 parser attempts, and none dropped. But it knows peak RSS only, not private memory |
| `smaps_rollup` in a tight loop | Private, private dirty and PSS | A process between samples, or the last moments of one |
| cgroup `memory.peak` and `memory.stat` | Container-wide peak and anon | Includes page cache and kernel memory, and doesn't split by process |

The loop reached 24 samples at the median per task in the fixture series and 212 in the signatures series.

- **Tasks not sampled at all:** 29 of 4,730 in the fixture series, 0.6%, and 0 of 2,838 in the signatures series. The largest peak RSS among the 29 is 19.8 MB, well under the largest task's 24.0 MB.
- **Tasks sampled short of their peak:** by comparing the sampler's highest RSS with the kernel's, 134 of 4,730 fixture tasks ended more than 1 MB short, by up to 19.1 MB, and 16 of 2,838 in signatures, by at most 2.2 MB. A shortfall near 19 MB is a task sampled only just after exec, before it touched its binary. The 3 fixture tasks with the highest kernel peak had 65 to 176 samples each.

So the largest task's private figure is a sampled one, not an exact one, and could be low by the part of a peak a sampler missed. The kernel's RSS is its hard upper bound: 24.0 MB in fixture and 35.6 MB in signatures. Those two RSS figures, and the count of processes, can't be missed.

The sampler's RSS sits slightly above the kernel's peak on some tasks, by about 0.1 MB, because the two count differently at the edges. The shortfall figures above are approximate to that extent.

## What the ruleset costs

Since 2026-11-17 a task process builds only the module its task names ([`task-start.md`](task-start.md)), so only a YARA task loads the ruleset and what follows is true of YARA tasks alone. It wasn't measured again with a signatures ruleset.

When these runs were made, every parser task process built all the pool's modules before it read its task (`crates/ace-app/src/pools.rs`, `parser_task`), so an email or archive task loaded the YARA ruleset as well. The signatures series shows the cost: its ruleset file is 1.75 MB, at signatures commit `99a110b`, against the fixture's 69 KB.

| Per task process | Fixture | Signatures |
|---|---|---|
| Private dirty, median | 2.3 MB | 17.7 MB |
| Lifetime, median | 3.9 ms | 80.8 ms |
| CPU, median | 3 ms | 80 ms |
| Peak RSS from the kernel, largest | 24.0 MB | 35.6 MB |

Private dirty is 17.7 MB at the median, the 95th percentile and the peak, so all task kinds pay it and the load adds little beyond it. Those 946 tasks at about 77 ms more each are 72 more seconds of CPU across up to 4 slots, and the comparison took 14.5 seconds longer. The same ruleset takes the supervisor from 3.0 to 17.2 MB idle, and the core from 6.1 to 33.0 MB, because the core built it. The production ruleset's size wasn't measured here.

## Containers and limits

The largest `memory.peak` of each container over its life, against its `mem_limit`. `memory.events` showed zero `max`, `oom` and `oom_kill` for every container in every run, so no limit was reached.

| Container | `mem_limit` | Fixture peak | Signatures peak |
|---|---|---|---|
| `parsers` | 4 GB | 26.9 (25.1 to 29.4) | 112.0 (108.6 to 115.6) |
| `lookups` | 1 GB | 16.2 (14.5 to 16.6) | 15.6 (14.9 to 16.0) |
| `ace` | 1 GB | 43.3 (41.1 to 45.6) | 71.1 (71.1 to 74.7) |
| `postgres` | 1 GB | 147.7 (147.2 to 150.7) | 147.5 (147.2 to 151.3) |
| `bucket` | 1 GB | 389.1 (339.4 to 408.6) | 369.9 (359.0 to 371.9) |

`memory.peak` isn't private memory. It holds page cache and kernel memory, and it can read lower than a process's private figure: a file page is charged to whichever cgroup touched it first, so `ace`'s peak of 43 MB sits below its 56.8 MB private. These numbers show nothing wrong with any limit, and they can't show that a limit is right for a real load.

SeaweedFS is the largest process in the stack and it isn't a pool. It holds 368.6 MB private dirty at its peak (315.4 to 384.4) after storing a few hundred small files, up from about 115 MB idle. It's dev's bucket; production's would be S3 (PLAN.md's *Deferred*).

## Against ace3's figures

ace3's figures come from production: engine workers after 18 hours, a busy email scanner at load 34.7, and idle API workers. ace3 wasn't measured here. ace3 has 90 `analysis_module_*` sections (PLAN.md 7.1) and ace4 has 5 modules.

| ace3, private dirty per process | Nearest ace4 figure, private dirty | Why they differ in kind |
|---|---|---|
| About 230 MB, a fresh worker | Supervisor 3.0, or 17.2 with the signatures ruleset. Lookups 2.5 | The closest pair: both are idle processes that loaded their modules. But ace3's worker loads its whole module set, and ace4's links 5 |
| 365 to 491 MB, correlation workers after 18 hours | Lookups 5.1 at peak, after 24 tasks in 31 seconds | ace4 ran seconds, on recordings. How it grows over hours isn't measured |
| 597 to 1,028 MB, busy email scanner | A task process 17.7 with the signatures ruleset; the supervisor 27.0; the pool at once 97.9 | ace3's worker keeps what each email leaves behind, and a task process exits. But these samples are small test fixtures, not production email |
| 2.57 GB, `http-api-v2`'s 12 workers | `ace` core 6.1 idle, 32.0 at peak | The core serves only the lease and submit endpoints here. The API and GUI are phase 5 |

What this supports:

- A Rust process with these 5 modules starts one to two orders of magnitude below a fresh ace3 worker. That's the measure DESIGN.md called unmeasured, for this module set only.
- A parser task's memory ends when it exits, by construction. The supervisor does grow: from 3.0 MB idle to 9.8 (8.4 to 11.6) after the fixture runs, and it isn't known where that settles. 946 tasks is too few to call a trend either way.

What it doesn't support:

- That ace4 will use less than ace3 under production load. Phase 4 ended with no Python workers (PLAN.md 4.13): its libraries' ports run in the parser binary and aren't in these numbers. Phase 7 adds about 85 modules to these binaries. Production email is larger than these samples, these runs didn't test how scan memory grows with input size, and the production ruleset wasn't measured.
- A total for the system. ace3 runs dozens of services, and ace4 has only a few of them so far.
- Anything about ace4 under concurrency higher than 4, or lookups beyond 24 tasks.

## What else these numbers include

- **ace3's stack and others on the same VM.** ace3's 27 containers and `budge`'s 3 were running. Private memory of a process doesn't depend on them, except that a page counted as shared must be mapped twice, and ace3 doesn't map ace4's binaries. No container reached its limit; pressure on the VM as a whole wasn't recorded.
- **The sampler.** Its loop spins on one of the 10 CPUs with no sleep, and each read takes the process's memory-map lock briefly, which could slow the tasks a little. The comparison's length with no sampler wasn't timed in this step, so that cost isn't known. The helper isn't in the figures.
- **`idle-before` isn't a cold start.** The sampler starts after the ruleset has loaded, so idle figures include it. The core's build of the ruleset falls before sampling too: its private figures don't show that peak, and its `container-life` `memory.peak` does.
- **`ace compare` itself isn't measured.** It runs in a one-off container and it's the test's client, not part of the system. Nor is the responder, which restarts during the comparison.
- **Short-lived children.** The `ace` row sums the core with any child running at a sample, such as `git`, which the ruleset builder runs (`crates/ace-yara/src/ruleset.rs`); this setup polls for rulesets every 2 seconds against the default 60. During `compare` no sample caught one. `docker-init` is counted apart and holds 24 kB private.
- **Medians and peaks.** The tables' medians are over runs. A "peak" is the highest sample in that run, and a sample of long-lived processes happens every 250 ms, so a burst shorter than that can be missed on them. The peak at one moment for the parser pool uses the supervisor's latest such sample with the tasks' current one.
- **No errors hidden.** Every comparison exited 0, and the task counts above show every sample's work ran. In the signatures series the comparison reports differences from ace3 that mean nothing, because ace3's trees used the one-rule fixture. Only its load counts.
- **Page cache sharing.** Each run started from empty volumes but images and their page cache were warm, which affects the time more than private memory.
