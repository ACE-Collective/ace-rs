# What a lease costs, and a pool that leases several tasks a request

`task-start.md` found that a pool's slots no longer bound a run: a pool leased one task a request, and with thousands of tasks due the parser pool had 2 of its 8 slots busy. This is that step: where a lease's time went, the change, both measurements, and what bounds a run now.

Measured on 2026-11-17 on one machine: Docker (Rancher Desktop) with 10 CPUs and 31 GiB, ace3's stack idle on the same VM, release images, the e2e stack's one-rule ruleset and overlay (`tests/e2e/site`), 8 slots in the parser pool and in the sandbox pool, 16 in the lookup pool, a 15-second lease. "HEAD" is `3a888365`, before this change, with the timing events below added and nothing else. A run of the comparison is the whole sample set: 472 samples and 232,927 tasks in every run here. "This change" in a table is the final code but for one thing added after those runs, the renewal of a slow answer's leases (*What it does now*), which acts only on an answer that takes over a quarter of a lease after its claim, 3.75 s here, where the longest decision in these runs took 1.1 s; `tests/e2e/run`'s own run is on the code as it is.

## The instruments

- **`tools/lease/measure`** runs `ace compare` on a stack `tests/e2e/run --compare --keep` left up, over 14 of the larger samples (43,074 tasks) with 8 at once, or over the whole set with `--all`. While it runs, a `psql \watch` in the stack's Postgres counts every 100 ms the tasks each pool has leased, the tasks that are due, and the roots in each phase: one with a task leased, one with a task due and none leased, and the rest by what they wait for. It reads each container's CPU time from its cgroup before and after.
- **The timing events.** The core logs one event for each task it claims, with the microseconds of the claim and of each part of the lease's decision, and a pool logs one for each lease request, with its round trip, the slots it had free and the tasks that came back. Both are at debug under the target `ace_lease`, off unless `ACE_RS_LOG=info,ace_lease=debug`; `tools/lease/measure --timing` turns them on and reads them. They stay in the code.
- **Postgres's own statement times**, from pg_stat_statements, which `tools/lease/measure --statements` loads into the stack's Postgres and reads.
- **`tools/lease/cpu`**, for a whole comparison: one helper container reads every container's cgroup `usage_usec` every 5 seconds from the Docker VM's cgroup tree, so nothing runs inside the containers it reads. `task-start.md` read the same counters with a `docker exec` a container a tick, and its runs were 16% to 29% longer for it.

What these could be measuring instead. The queue sampler sees a moment every 100 ms and a task lasts a few milliseconds, so a pool's count is an average over moments. It counts a task from its claim, before the pool has heard of it, so it overcounts busy slots a little, more so the longer a request's answer takes. Its own query took 3 ms in Postgres by the end, 3% of one core. The timing events are written by the processes they time, one line a task. Runs on a kept stack read tables that hold every earlier run's rows, so a later run has more to read; runs are compared in the same order on each stack. The 14 samples are chosen for having many tasks and few waits of their own, so their tasks a second is the stack's rate under load, not a comparison's average.

## Where a lease's time went, at HEAD

Two runs of the 14 samples with the timing events on, 465 s together: the core claimed 205,084 tasks to lease 86,296.

| The core's time on one claimed task, milliseconds | Leased: 86,296 | Not leased: 118,788 |
|---|---|---|
| The claim: one transaction, one statement | 2.48 (0.43 to 444), mean 2.65 | 1.32 (0.36 to 443), mean 1.52 |
| The path hold's decision, and the hold | 0.17 (0 to 36), mean 0.28 | 1.32 (0 to 497), mean 1.60 |
| The file: its path settled, its record, its download URL | 0.99 (0 to 115), mean 1.32 | 0, mean 0.07 |
| Whether a task that runs last is held back, and its delay | 0 (0 to 20), mean 0.04 | 0 (0 to 54), mean 0.10 |
| What the task reads of its tree | 0.48 (0.11 to 486), mean 1.07 | 0 |
| All of it | 4.42 (0.69 to 488), mean 5.37 | 2.71 (1.08 to 500), mean 3.29 |

Median and range, with the mean because the pool waits for the sum. Three things follow.

**A pool made one lease request at a time, and was in one all the time.** The parser pool's 54,938 requests took 8.59 ms each on average as the pool saw them (median 5.59), 472 s of the two runs' 465 s. So the parser pool started a task every 8.6 ms, 116 a second, whatever its slots: `task-start.md`'s "9 ms a task". The sandbox pool's 19,980 answered requests took 4.34 ms at the median, and the lookup pool's 11,378 took 4.28 ms. The request's round trip is not the cost: a request that leased the first task it claimed took the core 4.4 ms at the median and the pool saw 5.6 ms for all requests, held tasks included.

**More than half of the claims were thrown away.** For every task leased the core claimed 1.4 more that it then held for their file's path (decision 15): 55,436 holds in a run of 43,074 tasks, by Postgres's count of the hold's statement. A file's tasks are all queued at once, about 50 of them, and each is claimed, held for 100 ms to 2 s and claimed again while a task nearer the root is pending. Each such claim cost the pool's one lease loop 3.3 ms. Tasks that run last and were held back were 4,562 more.

**The claim is the largest single cost, in the core and in Postgres.** One run of the 14 samples with pg_stat_statements, 285 s (slower than the others, with the statistics and the timing events both on): the claim's `UPDATE` ran 124,278 times, 21,188 of them claiming nothing, at 1.03 ms each in Postgres, 127 s in a run in which Postgres's container used 362 CPU-seconds. It reads every due task of the pool's modules to find the oldest (`module = ANY($3) ... ORDER BY run_after, id`), and 3,600 to 5,400 were due at the median. Next came waits for a root's row lock, which every hold, delay and end takes: `SELECT id FROM analysis.roots ... FOR UPDATE` 103,373 times at 0.54 ms (56 s, mostly waiting), and the orchestrator's lock of the same row when a result lands, 6,590 times at 3.97 ms (26 s). Everything else the lease runs is under 0.1 ms a call in Postgres. The core sees more than Postgres does: the claim's transaction is four round trips to Postgres (begin, the isolation level, the statement, commit) and took the core 2.5 ms, of which the statement was 1.0 ms in Postgres.

So what bounded a pool was the lease rate: one request in flight, each the sum of a claim that grows with the queue and a dozen statements one after another, twice over for the tasks it held instead.

## What it does now

**The pool** (`lease_loop` in `crates/ace-pool/src/pool.rs`). When a slot is free the loop takes every slot that is free at that moment, asks the core for that many tasks in one request, and starts each task that comes back in one of those slots. The slots it got no task for are free again for the next request. One request is in flight at a time, as before.

**The core** (`Api::lease_for` and `Api::leased_each` in `crates/ace-core/src/api.rs`). The request names how many tasks the pool can start (`max`). The core claims up to that many in one statement (`Worker::claim_up_to`): the oldest that are due, the same tasks and the same order that many single claims would take. Then it decides each task's lease with the function that decided a single one (`Api::leased`), one task after another, and answers with the tasks that were leased, oldest first. It answers as soon as one task is leased and never waits to fill the list. If every claimed task was held back it claims again, as before.

What the change had to keep, and how.

**A lease is a promise the pool can keep.** The pool holds a slot for every task it asks for, before it asks, so every task in the answer starts when the answer arrives. It never asks ahead of its free slots, so no task waits in a busy pool while another replica could run it, and each task runs in its own slot, so a slow one delays none that came with it. The core answers with no more than the request asked for, and no more than 64 whatever it asked (`MAX_LEASED_AT_ONCE`); a pool that is still handed a task it has no slot for gives it back at once and logs an error. A request asks for the slots that are free when it is sent. A request that waits while running tasks finish therefore brings no more than it asked for, and the next asks for the rest, one round trip later.

The leases of a batch all begin at its claim, and the answer waits for the last decision. A decision that waits long, as on a row lock, would hand the pool tasks whose leases were partly spent or gone. So an answer that took more than a quarter of a lease renews each task it holds first, and leaves out any the worker no longer owns; if none is left it claims again. What a pool is handed is its to run, with a whole lease ahead.

**What a killed or frozen pool costs.** A pool holds at most as many leases as it has slots, counting running tasks and an answer on its way together, before and after. So a pool that is killed takes at most its slot count with it, 8 for each of the e2e stack's parser and sandbox pools, as it did when it was killed with every slot busy. What changed is a pool that is frozen or killed while idle: it used to be given one task, and it is now given up to its slot count, the tasks its last request asked for. They come back the same way: their leases run out, the reaper queues them again with the attempt counted, and a task fails after `max_attempts` such claims. `tests/e2e/run` still freezes and kills the parser pool and expects the root to complete.

One window is kept as narrow as it was, which a batch would have widened. A request can end before its answer: the pool is stopped or killed while the core is deciding the leases it claimed for it. Before, the one claimed task then waited for its lease to run out. Now the core gives back the tasks such a request had claimed, at once and with the claim uncounted (`InHand`, on the drop of the request), so they don't wait out a lease no pool will renew. All but one: the task whose lease was being decided at that moment keeps its lease until it runs out, with its attempt counted, as the one task did before. A request also ends when a decision panics, and a task whose decision panics every time has to use up its attempts and fail; given back uncounted, it would be claimed again for ever ahead of the tasks behind it. What none of this covers is an answer the core finished writing to a pool that never read it, which is the frozen pool above.

**Every decision at the lease is made for each task alone.** `Api::leased` is unchanged but for its timing, and `leased_each` calls it once for each claimed task. Each of these is per task as before: the path hold and its length, the file's path being settled, a file that isn't in the bucket failing its task, a task that runs last being held back with its doubling wait and its mark for `queue::check_completion`'s wake, the wake of the others when one is held back by a task below, the carrying email and whether emails are pending, the dependency results and their errors, the lists, the tree, the scan, and a cancelled task ending cancelled. Delayed tasks are claimed only once `run_after` has passed, and a cancelled root's queued tasks not at all, by the claim's own condition, which is the single claim's. Each claim counts one attempt on its task, and a hold takes it back, as before. Secrets never were in a lease: a pool resolves them itself.

A batch is not all or nothing. A task that is held, delayed, failed or cancelled at its lease is left out of the answer and the others are leased. A task whose decision fails with an error, such as a statement Postgres refused, is left out too and logged, and its lease runs out, which is what a failed request did with its one task; only when no task was leased is the error the request's answer.

The decisions look at which tasks of a root are queued, delayed or running, and never tell a queued task from a running one. So claiming several tasks of a root together, which makes them all running before any is decided, gives each the answer it would have had one at a time: a task that runs last still sees the others pending, and a file's first task still sees the task nearer the root.

**Order and fairness.** The claim takes the oldest due tasks of the pool's modules by `run_after` and then id, across all roots, with `FOR UPDATE SKIP LOCKED`, as the single claim did. A batch of n is what n single claims in a row would have taken, so the order tasks are leased in is the same and a root with many tasks due gets no more of a turn than it had: the queue was first in, first out across roots before, and is now. What differs is between replicas of one pool. Two idle replicas used to take a burst's tasks about alternately, one each a request. Now the replica whose request is answered first takes as many as it has free slots, and the other takes what is left. Every task still starts at once in a slot of its own, so none is parked, but the work can sit on one replica while the other is idle, up to the first one's slot count.

**The wire.** `LeaseRequest` gains `max`, which is 1 when left out, and the answer to a lease is a list of `LeasedTask` where it was one. The core and its pools come from one tag and the wire types refuse unknown fields, so they change together, as with any change to these types. A site's code doesn't change: `ParserPool`, `LookupPool`, `App::pool_main` and `LeaseClient::lease` are as they were, and a site's workspace calls none of the lease loop directly. It gets the change when its `Cargo.toml` moves to the tag.

The tests:

| What | Test |
|---|---|
| A claim of several takes the oldest due, in the order single claims would, across a large root and a small one, and leaves what isn't due and other modules' tasks | `ace-core` `tests/queue.rs`: `a_claim_of_several_takes_the_oldest_due_in_the_order_single_claims_would` |
| Two workers claiming seven at a time run each of 1,000 tasks once, and no claim takes more than it asked for | `ace-core` `tests/queue.rs`: `two_workers_draining_1000_tasks_seven_at_a_time_run_each_once` |
| Seven tasks claimed together: a task that runs last is held back and marked, a file's first task is held for its path, a file not in the bucket fails, and the other four are leased, each with its own observable, file, delay state and attempt; a task not due and a cancelled root's are not claimed; the held tasks are leased in their turn | `ace-pool` `tests/lease_api.rs`: `a_request_for_several_tasks_decides_each_lease_alone` |
| The answer holds no more than was asked for, one without `max`, no more than the core's limit, and what is due now without waiting for more | `ace-pool` `tests/lease_api.rs`: `a_lease_request_is_answered_with_no_more_than_it_asks_for` |
| A request that ends before its answer gives back the task whose lease was decided and the one not reached, claims uncounted, and the one being decided keeps its lease | `ace-pool` `tests/lease_api.rs`: `a_lease_request_dropped_before_its_answer_gives_its_tasks_back` |
| A request whose decision outlasts the lease, its tasks reaped meanwhile, answers with none of them as they were: it claims again and answers with each on its second claim, with a whole lease | `ace-pool` `tests/lease_api.rs`: `a_request_that_outlasts_its_leases_answers_only_with_tasks_it_holds` |
| A signal during the tool runner's handshake doesn't fail the tool (below) | `ace-pool` `src/tools.rs`: `a_signal_during_the_runners_handshake_doesnt_fail_it` |
| A pool with 4 slots never holds a fifth lease, by the queue's own count, and its first request brings four tasks | `ace-pool` `tests/async_pool.rs`: `a_pool_with_a_limit_of_4_never_runs_a_fifth_task` |
| A frozen pool with 3 slots is given 3 of 7 due tasks and no more; killed, its 3 come back when their leases run out and all 7 end done | `ace-pool` `tests/async_pool.rs`: `a_killed_pool_takes_as_many_tasks_with_it_as_it_has_slots_and_they_come_back` |
| A task that runs last is leased when the last other task ends | `ace-pool` `tests/lease_api.rs`: `a_task_that_runs_last_is_leased_when_the_last_other_task_ends`, unchanged |
| Shutdown gives back the leases of tasks still running | `ace-pool` `tests/shutdown.rs`, unchanged |
| The parser pool frozen and killed while it holds leases, and the root completes | `tests/e2e/run` |

**A fault the change exposed, fixed here.** The first whole comparison on this change had one failed task, where every run at HEAD had none: `qrcode`'s tool couldn't start, "the tool runner didn't contain itself: Interrupted system call". The supervisor waits for a tool runner's listener in a blocking `recvmsg` on a socket with a receive timeout (`receive_listener` in `crates/ace-pool/src/tools.rs`), and didn't wait again when a signal ended the call. The supervisor handles SIGCHLD for every process it starts, the kernel doesn't restart a receive that has a timeout whatever the handler's flags, and the sandbox pool now runs up to 8 tasks at once where it ran about one. The wait now goes on for what is left of its timeout, and the answer to the tool's exec (`SECCOMP_IOCTL_NOTIF_SEND`) is sent again if a signal ends that call. No run on the fix has a failed task (*Before and after*).

**A test whose premise was the old rate.** `a_switch_during_a_stream_of_scans_drops_none` (`ace-pool` `tests/yara_pool.rs`) queued 15 scans and expected some to be unfinished when the second ruleset had been built, so that the pool switched rulesets with scans queued. A pool with 2 slots that leases 2 at a time finishes 15 small scans first, and the test failed on that expectation with nothing dropped. It now stops the pool while 14 scans are queued and the ruleset is built, checks that all 14 are waiting, and lets the pool go, so the switch happens under queued scans whatever the pool's rate. What it asserts about the switch is unchanged: no scan dropped, each scanned by one generation whole, the first by the first ruleset and the last by the second. Five runs: each time two scans ran on the first ruleset after the pool was let go and the rest on the second.

## Before and after

**The 14 samples**, `tools/lease/measure`, 43,074 tasks a run, 8 samples at once, each stack made by `tests/e2e/run --compare --keep` and used after its one whole comparison. Every run: 14 samples, none failed, no task failed or leased twice.

| | HEAD | This change |
|---|---|---|
| Seconds in `ace compare`, runs with the timing events on | 249.4, 215.3 | 176.1, 260.2, 173.4 |
| The same, with pg_stat_statements on (and at HEAD the timing events too) | 285.2 | 164.8 |
| The same, with neither | 230.4 | not run |
| Tasks a second, all runs | 151 to 200, median 180 | 166 to 261, median 247 |
| Parser tasks leased while over 50 tasks were due: mean, by run | 1.61 to 1.76 | 4.96 to 5.13 |
| Sandbox tasks leased then | 0.87 to 0.97 | 2.91 to 3.12 |
| Lookup tasks leased then | 0.45 to 0.74 | 2.06 to 2.43 |
| Tasks due then, median by run | 3,594 to 5,448 | 3,522 to 4,499 |
| CPU seconds a run, all containers | 789 to 886 | 672 to 803 |
| Postgres | 320 to 362 | 216 to 282 |
| the core | 142 to 171 | 123 to 155 |
| parsers | 173 to 196 | 193 to 217 |
| sandbox | 106 to 112 | 112 to 117 |

Four runs at HEAD and four on this change. By the median of each four a run is 27% shorter, 240 s to 175 s, and the stack ends 37% more tasks a second, 180 to 247. One run on this change took 260 s, longer than three of HEAD's four. Nothing in the stack's logs marks it, no other container on the VM used more CPU than in the runs beside it, and the stack itself used more (803 CPU-seconds against 706 and 714), so its cause isn't known; it is in the ranges above. Two more runs of 159.1 s and 160.5 s, on an earlier build of this change that decided leases in turn through a setting since removed, are left out of the table.

**A lease on this change**, the three runs with the timing events: 297,011 tasks claimed in batches of 5 at the median (1 to 16, mean 5.1), 129,444 of them leased.

| The core's time, milliseconds | Leased: 129,444 | Not leased: 167,567 |
|---|---|---|
| The claim, once for the tasks claimed together | 3.55 (0.63 to 489), mean 4.06 | 1.98 (0.42 to 175), mean 2.66 |
| The path hold's decision, and the hold | 0.20 (0 to 80), mean 0.40 | 1.75 (0 to 1,140), mean 2.86 |
| The file | 1.14 (0 to 333), mean 1.79 | 0, mean 0.13 |
| A task that runs last | 0 (0 to 27), mean 0.06 | 0 (0 to 136), mean 0.19 |
| What the task reads of its tree | 0.56 (0.10 to 527), mean 1.39 | 0 |
| The decision, without the claim | 2.04 (0.10 to 527), mean 3.64 | 1.87 (0.69 to 1,140), mean 3.18 |

At HEAD a decision without its claim took 2.72 ms on average for a leased task and 1.77 ms for one not leased (the means of the first table, less the claim's). So a decision costs more than it did, a hold most of all: the pools run more tasks at once, and more of what the lease does waits behind a root's row lock. What the batch saves is the claim, once for five tasks where it was once for each.

| A pool's lease requests | HEAD | This change |
|---|---|---|
| Parser pool: tasks in an answer, median (range), mean | 1 | 3 (1 to 8), 3.28 |
| Parser pool: an answered request's round trip, ms, median and mean | 5.59, 8.59 | 15.91, 24.52 |
| Parser pool: slots free when it asked, mean | 5.99 | 3.76 |
| Sandbox pool: tasks in an answer | 1 | 2 (1 to 8), 2.60 |
| Lookup pool: tasks in an answer | 1 | 4 (1 to 15), 4.21 |
| Claims in Postgres, a run of 43,074 tasks | 124,278 | 41,988 |
| The claim's time in Postgres, a run | 127 s | 42 s |
| Holds for a file's path, a run | 55,436 | 45,488 |
| Waits for a root's row lock (`lock_root`), a run: calls, mean, sum | 103,373, 0.54 ms, 56 s | 93,392, 0.77 ms, 72 s |
| The orchestrator's lock of the same row: calls, mean, sum | 6,590, 3.97 ms, 26 s | 6,590, 5.83 ms, 38 s |

The claims, holds and locks are from the one run of each with pg_stat_statements. The mean round trips include requests that waited for a task to come due.

**How many leases to decide at once.** The first build of this change decided four of a batch's leases at once. On the stack that build left, with the number as a setting since removed, one or two runs of the 14 samples each:

| Leases decided at once | The core's connections | Seconds | A leased task's decision, mean ms |
|---:|---:|---|---:|
| 1 | 10 | 159.1, 160.5 | 2.71 |
| 4 | 10 | 168.7, 194.1 | 8.06 |
| 8 | 10 | 191.8 | 9.54 |
| 8 | 30 | 175.2 | 5.02 |
| 16 | 30 | 177.3 | 5.15 |

Deciding them in turn was the fastest and used the least CPU (653 and 667 CPU-seconds against 725 to 855). The tasks claimed together are mostly one root's, the oldest due being neighbours in the queue, and their holds each take that root's row lock, so deciding them at once only made them queue there: with four at once the waits for that lock were 161 s in a run, against 72 s in turn. More connections for the core changed nothing that one run can show. So the core decides a batch's leases one after another and keeps its 10 connections.

**The whole comparison**, 472 samples and 232,927 tasks, 8 samples at once, none failed in any run. Three kinds of run, each compared with its like: `tests/e2e/run` whole, which makes a new stack and runs its scenario checks first; `tests/e2e/run --compare --keep` on a new stack; and a second pass over the whole set on the stack that left, with `tools/lease/measure --all`. CPU is every container of the stack, by `tools/lease/cpu`.

| Run | HEAD | This change |
|---|---|---|
| `tests/e2e/run` whole: `ace compare`, seconds | 1,049.7 (the director's) | 940.8 |
| a sample: median (range), seconds | 12.35 (1.28 to 82.48) | 12.73 (1.53 to 72.21) |
| CPU seconds | not read | 3,731 |
| `--compare --keep`, a new stack: `ace compare`, seconds | 1,006.7 | 900.1 |
| a sample: median (range), seconds | 13.85 (1.53 to 82.48) | 10.85 (1.28 to 71.22) |
| CPU seconds | not read | 3,724 |
| A second pass on that stack: `ace compare`, seconds | 1,001.4 | 770.2 |
| a sample: median (range), seconds | 12.84 (1.28 to 82.23) | 9.83 (1.27 to 62.37) |
| tasks a second | 233 | 302 |
| parser tasks leased while over 50 were due: median, mean | 2, 2.02 | 5, 5.20 |
| sandbox tasks leased then | 1, 1.21 | 2, 3.01 |
| tasks due then, median | 433 | 443 |
| CPU seconds | 3,934 | 3,479 |
| Postgres | 1,232 | 942 |
| the core | 755 | 626 |
| parsers | 1,046 | 1,093 |
| sandbox | 630 | 635 |
| bucket | 224 | 146 |

- **A whole comparison is 10% to 23% shorter**: 10% in `tests/e2e/run`, 11% on a new stack with `--compare`, 23% on the second pass. One run of each kind on each side, so the three pairs are the spread there is. The first build of this change, which decided four leases at once and had the runner's fault, took 938.0 s on a new stack with `--compare` (a sample 10.73 s, 1.28 to 75.61), with one task failed.
- **Why the pairs differ so much isn't known.** At HEAD the second pass took what the first did. On this change it took 130 s less than the first. A cargo check and a `cargo sqlx prepare` ran in the dev container for about a minute of HEAD's `--compare` run, which can only have made it longer.
- **The stack does the work on 11% less CPU** on the second pass, 3,934 to 3,479 CPU-seconds, nearly all of it Postgres's and the core's: the claim was Postgres's most expensive statement, and a run of the 14 samples makes 82,000 fewer of them. The pools use what they did, since they run the same task processes.
- **A sample's own time** fell by about a fifth at the median in two of the pairs and not in `tests/e2e/run`'s, 12.35 s to 12.73 s. The longest sample went from 82 s to 62 to 72 s in all three.

**The same report.** `tools/lease/same-report` compares two reports by `compare-speed.md`'s method: it sets aside seconds, roots, the hashes only one report has, ace-rs's values that hold a time or a temporary directory, and counts apart the redirection of pdftotext's text, the coin toss that doc describes. Checked on a report with one value changed, one difference dropped and one class changed, it names all three. Compared pair by pair: the three reports at HEAD (the director's, the `--compare` run's and the second pass's) and the three on the final code (the `--compare` run's, the second pass's and `tests/e2e/run`'s). Every pair has the same samples in the same order, none absent or failed, the threshold met, the same rows of `differences.md` matched and none stale, and for every sample the same differences by module, class and path with the same values. The redirections differ in 17 to 25 samples in any pair, between two runs at HEAD (21 to 25) as between a run at HEAD and one on this change (17 to 24). Every report has 0 unexplained, 378 harness and 0 unported differences, and 7,885 to 7,891 explained. That is all 15 pairs of the six. The first build's report differs from all of these in one thing, the failed `qrcode` task above and the result it didn't store.

```sh
tests/e2e/run --compare --keep                       # a new stack and one whole comparison
tools/lease/measure --runs 3 --timing                # the 14 samples, with the timing events
tools/lease/measure --statements                     # with Postgres's statement times
tools/lease/cpu start                                # before a whole comparison
tools/lease/measure --all                            # the whole set again, on the kept stack
tools/lease/cpu report SINCE UNTIL                   # the times `measure` prints for its run
tools/lease/same-report A/report.json B/report.json
```

## What bounds a run now

Still how fast a pool leases, by a smaller margin and for another reason. On the second pass the roots' time was 28% with a task leased, 70% with a task due and none leased, and 2% waiting on the tasks that run last; `compare-speed.md` found 24% and 75% with these pool sizes before either this change or `task-start.md`'s. The pools aren't full: 5.2 of the parser pool's 8 slots and 3.0 of the sandbox pool's are leased, by a count that includes each task's wait for its request's answer.

A pool still makes one lease request at a time and is still in one all the time under load. What a request's time is made of has changed. In a run of the 14 samples the three pools' loops had about 2.7 requests in flight between them, on average, and the core spent that time in three nearly equal parts:

| What the core's lease time went to, a run of 43,074 tasks | About |
|---|---:|
| Claims: 41,988, some 3 ms each | 29% |
| The decisions of the 43,074 tasks leased, 3.6 ms each | 35% |
| The decisions of the 50,000 not leased, 3.2 ms each: 45,488 holds for a file's path, the rest tasks that run last | 36% |

The counts are Postgres's, from the run with pg_stat_statements, and the times are the means of the three runs with the timing events, so the shares are near, not exact.

- **The holds.** A file's tasks are held while a task nearer the root is pending, each on its own, each asked again every 100 ms to 2 s, and each hold takes its root's row lock: 45,488 holds for 43,074 tasks. That lock is also what every end takes, so holds and ends of one root queue behind each other, and behind the transaction that lands a result, which holds it longest (5.8 ms at the mean, 38 s a run). Nothing wakes a held task when the task it waits for ends, as `queue::check_completion` wakes the tasks that run last.
- **The claim** still reads every due task of the pool's modules to find the oldest, a millisecond in Postgres with 4,000 due, now once for five tasks.
- **One request at a time.** A slot that frees while a request is in flight waits for it and for the next: the parser pool had 3.8 slots free when it asked. More requests at once weren't tried. They would start a task sooner on a free slot, at the price of a claim each, and their decisions would wait on the same roots' locks.

## The path hold decided for the file, measured and dropped; the isolation level and the claim, kept

The owner's go-ahead of 2026-11-18 asked for one change of four parts, measured two runs each against HEAD. Measured on 2026-11-18 on the same machine as above, with the same instruments and stack settings. HEAD is `dc1994b1`, built from a temporary worktree; "the change" is the code with all four parts. **By the owner's decision of 2026-11-18, parts 1 and 2 (the wake of held files and the hold decided once for a file) were dropped, because they saved no time or CPU, and parts 3 and 4 (the isolation level in `BEGIN` and the claim by module) were kept.** The code is HEAD's hold, decided for each task, as decision 15 describes it; the measurements below are of all four parts together. The isolation level and the claim weren't measured alone, and the table's rows for them (the claim's time in Postgres and in the core, the `SET TRANSACTION` statements) are what they change.

**What the hold was.** A file's first task is held while a task nearer the root than the file is queued, delayed or running (PLAN.md decision 15), so the rule that picks its analysis path sees every path. Each held task was asked again after `waited / 2`, 0.1 s to 2 s, for 60 s at most, and each asking was a claim, the test and a transaction on the root's lock. Nothing woke a held task when the task it waited for ended.

**What the four parts were.** Parts 1 and 2, as measured and dropped:

1. **The hold was the file's** (`queue::Worker::hold_for_path`, migration 0074's `queue.path_holds`). The first task of the file claimed decides it: with the root locked and the file's observable row locked, it tests `tree::pending_above` again, and if something is pending above it waits `waited / 2` as before and records the hold, with the file's depth, the modules that run last, and when it is next decided. In the same transaction the file's other queued and delayed tasks wait until the file has waited 60 s. A task of the file claimed before the hold is next decided joins it, with no test of its own, and waits as long. When the deciding task comes back, the first task claimed decides again, by the same test.
2. **A task added later** (a mode change, a fact that arrives later) is queued as any task is. If the file's hold is current when it is claimed, it joins the hold. If the deciding task decides again first, the new task is held with the others in that decision's transaction, without being claimed.
3. **The wake.** Every end runs `check_completion`, with the root locked. It now also deletes the hold of each file with nothing left above it, by `pending_above`'s test (the depth and module list come from the hold's row), and makes that file's held tasks due at once, as `wake_held_back` does for the tasks that run last. Settling a file's path (`tree::choose_analysis_file`) wakes its held tasks too, as at the limit. A delay ends nothing that holds a file, since a delayed task is still pending. A held task the wake misses comes back when its wait ends: the deciding task within 2 s, and it then decides again or settles the path, which wakes the rest.
4. **Why the path chosen can't change.** The wake and the per-file record change only when a file's tasks ask. A path is settled only where it was before: a task's lease when the path is already chosen, when nothing is pending above the file by the unchanged `pending_above`, or after 60 s with the warning; and the orchestrator's settle when a kept type or a kept result needs it, which is unchanged. A woken task asks `held_for_path` again before anything is settled. The test is still on observables shallower than the file, so a task as deep or deeper never holds it and two held files can't wait on each other, and the modules that run last are still left out. A hold is begun only with the root and the file's row locked and the path re-read, so it can't start just after the end or the settle that would have woken it.

None of parts 1 and 2 is in the code now: `hold_for_path`, migration 0074 and its `queue.path_holds`, and the wake in `check_completion` and `tree::choose_analysis_file` are gone, and a file's held task is asked again after `waited / 2` as at HEAD.

**Kept: the isolation level** is in the transaction's `BEGIN` (`BEGIN ISOLATION LEVEL READ COMMITTED`, `Db::transaction`), where it was a statement of its own. READ COMMITTED is still named rather than left to the server's default, so a server or role with another `default_transaction_isolation` doesn't change it; `tests/transactions.rs` checks each level, and READ COMMITTED on a database whose default is SERIALIZABLE. REPEATABLE READ and SERIALIZABLE are kept as their callers ask.
**Kept: the claim** (`Worker::claim_up_to`) reads each of the pool's modules' oldest `max` due tasks from that module's range of `tasks_claimable`, which is in `(module, run_after, id)` order, keeps the oldest `2 × max` of them, and locks the oldest `max` of those it can, skipping what another claim holds. Only when another claim holds every one of them does it read all the pool's due tasks, as the claim always did; Postgres tests that condition once and otherwise reads nothing there. So it takes the same tasks in the same order as before, reads at most `max` index entries a module, and a pool with nothing due reads one empty range a module. No migration was needed for it.

**An index in the claim's own order** was what *Found and left* proposed. On a table of 4,000 due parser tasks among 4,800 due (`EXPLAIN ANALYZE` in the dev Postgres), an index on `(run_after, id)` took the parser pool's claim of five from 2.7 ms to 0.08 ms. But the claim is a prepared statement, and under the generic plan Postgres uses for a prepared statement after five runs, it chose that index for every pool: a lookup pool with nothing due read all 4,300 due tasks to find none, 2.4 ms against 0.07 ms on `tasks_claimable`. The per-module read took 0.57 ms for the parser pool's claim and 0.20 ms for the idle lookup pool's, under the generic plan. One run of the 14 samples at HEAD with the ordered index added beside `tasks_claimable`: 66.6 s, the claim 6,846 times at 0.342 ms in Postgres, against HEAD's 0.534 and 0.570 ms and this change's 0.213 and 0.208 ms. So no index in the claim's order won both ways, and the change keeps `tasks_claimable` and reads it by module.

### Before and after

`tools/lease/measure --runs 1 --timing --statements`, twice on each side, so each run's statement counts are its own; each stack made by `tests/e2e/run --compare --keep` and used after its one whole comparison. Every run: 14 samples, none failed, no task failed or leased twice, 6,309 results, none from the cache. pg_stat_statements was loaded only in the e2e stack's Postgres, by `measure --statements` (`ALTER SYSTEM SET shared_preload_libraries`, which restarts that container), and was reset at each run's start.

| | HEAD | The change |
|---|---|---|
| Seconds in `ace compare` | 63.5, 65.0 | 64.2, 65.2 |
| Tasks | 15,102, 15,107 | 15,107, 15,077 |
| Tasks a second | 238, 232 | 235, 231 |
| A sample, seconds: median (range) | 28.50 (19.19 to 52.86), 30.37 (22.43 to 58.86) | 30.63 (22.44 to 56.15), 29.08 (22.93 to 57.87) |
| Parser tasks leased while over 50 were due, mean | 5.41, 5.47 | 5.46, 5.62 |
| Sandbox tasks leased then | 1.77, 1.77 | 1.73, 1.74 |
| Lookup tasks leased then | 3.42, 3.36 | 3.71, 3.76 |
| Tasks due then, median | 1,248, 1,144 | 1,321, 998 |
| Roots' time: a task leased, a task due and none leased, held for a path, tasks that run last held back | 24%, 75%, 0%, 1%; 23%, 76%, 0%, 1% | 24%, 75%, 0%, 1%; 22%, 77%, 0%, 1% |
| CPU seconds, all containers | 221.4, 225.3 | 225.0, 224.0 |
| the core | 47.8, 48.2 | 47.7, 46.9 |
| Postgres | 57.0, 58.0 | 59.4, 58.0 |
| parsers | 62.2, 64.6 | 62.3, 64.4 |
| sandbox | 43.7, 43.4 | 44.5, 43.8 |
| lookups, bucket | 2.5, 2.5; 8.2, 8.5 | 2.6, 2.5; 8.5, 8.4 |
| Holds for a file's path | 2,289 (second run; the first's wasn't read) | 136, 94: 133 and 94 decided, 3 and 0 joined |
| Held tasks woken by an end; by a settle | none | 53 and 91; none in either run, of 716 settles each |
| Claims in Postgres: calls, mean | 6,652 at 0.534 ms; 7,063 at 0.571 ms | 6,712 at 0.213 ms; 7,076 at 0.208 ms |
| The claim, as the core sees it, a leased task: median | 1.49, 1.56 ms | 1.05, 1.04 ms |
| `SET TRANSACTION ISOLATION LEVEL READ COMMITTED` | 37,949 (second run) | 0 |
| Waits for a root's row lock (`lock_root`): calls, mean | 17,380 at 2.78 ms; 17,665 at 2.86 ms | 17,493 at 2.93 ms; 17,376 at 3.25 ms |
| The orchestrator's lock of the same row: calls, mean | 6,328 at 8.90 ms; 6,333 at 9.13 ms | 6,333 at 9.26 ms; 6,303 at 9.59 ms |
| The wake, a statement in every end: calls, mean | none | 15,093 at 0.038 ms; 15,063 at 0.036 ms |

- **Holds fell from about 2,300 a run to about 115**, and the claim's time in Postgres by 62%. Each transaction makes one round trip fewer, 37,949 fewer statements a run.
- **The run's time and CPU didn't change** beyond the spread of two runs: 63.5 and 65.0 s against 64.2 and 65.2 s, 221 and 225 CPU-seconds against 225 and 224. What the change removed was small by the time it was built. The hold was 0% of the roots' time at HEAD, and the claim 4 s of Postgres's 58 CPU-seconds. The wake adds a statement to every end, 0.6 s of Postgres time a run.
- **The premise of this step was a run of 43,074 tasks.** The same 14 samples now make 15,100. Decision 23 queues no task a module declines, and decision 25 types a file before anything else is queued on it, so a file's first task is mostly its type step, alone, and there was rarely a file with 30 tasks to hold. Of what `lease.md` measured, 45,488 holds in a run became about 2,300 before this step and about 115 after it.
- **What else the numbers could be measuring.** The two sides ran on different stacks, each after its own whole comparison, so their tables held the same rows. The timing events and pg_stat_statements were on in all four runs. HEAD's statement counts for its first run come from the top 30 `measure` prints, so its holds and its `SET TRANSACTION`s are from its second run only. The 14 samples are chosen to keep the pools busy, so a whole comparison's share of holds may differ.

**The whole comparison**, `tests/e2e/run --compare --keep` on a new stack, once on each side:

| | HEAD | The change |
|---|---|---|
| `ace compare`, seconds | 366.7 | 386.7 |
| A sample: median (range), seconds | 4.30 (0.27 to 34.24) | 4.80 (0.52 to 36.22) |
| Differences: unexplained, harness, unported, explained | 0, 324, 0, 7,800 | 0, 324, 0, 7,802 |

One run of each, 20 s apart. `task-start.md` found two runs of the same code 39 s apart, so this is within the noise of one run. During HEAD's comparison the dev container compiled `ace-core` for `cargo sqlx prepare` for a few minutes, which can only have slowed HEAD. CPU wasn't read for either whole run.

**The same report.** `tools/lease/same-report` on the two reports: the same 472 samples, none absent or failed, and 8,073 differences compared, the same by module, class, path and value. Only the redirections of pdftotext's text differ, in 14 samples (51 against 53), the coin toss `compare-speed.md` describes. That accounts for the two more explained differences.

**The tests of what was kept.**

| What | Test |
|---|---|
| The claim takes the oldest across modules, a module named twice once, past rows another transaction holds by its spares and, when every spare is held, by reading all of them; a pool with nothing due claims nothing | `ace-core` `tests/queue.rs`: `a_claim_takes_the_oldest_across_modules_and_past_what_another_holds` |
| A transaction runs at the level it asks for, READ COMMITTED on a database whose default is SERIALIZABLE | `ace-core` `tests/transactions.rs`: `a_transaction_runs_at_the_level_it_asks_for` |
| The earlier claim, hold and lease tests | unchanged, and passing |

The tests of parts 1 and 2 (two in `ace-core` `tests/queue.rs`, one in `ace-pool` `tests/lease_api.rs`) went with them.

### What bounds a run after the path hold step

The root's row lock, which the owner wants kept in view for a later step. In each run on the change, `lock_root`'s `SELECT ... FOR UPDATE` waited 51 s and 56 s in all, and the orchestrator's lock of the same row, when a result lands, 59 s and 60 s, in runs of 64 and 65 s with 8 roots at once. Everything else Postgres ran took 21 s and 22 s. Every end, delay and hold takes that lock, and so does the transaction that lands a result, which holds it longest. So a root's tasks end one at a time, and its next tasks wait behind those ends: roots spent 75% to 77% of their time with a task due and none leased. The pools aren't full: the parser pool had 5.5 of 8 slots leased, the sandbox pool 1.7 of 8 and the lookup pool 3.7 of 16. Making a root's ends not wait on each other means not taking the root's row for each; this step doesn't try it. Parts 1 and 2 left this as it was, and dropping them leaves it so: the hold was already 0% of the roots' time.

## Found and left

- **A hold for a file's path** cost a claim, a decision and the root's lock, 45,000 times a run of 43,000 tasks when this was written. By 2026-11-18 decisions 23 and 25 had cut a run of the 14 samples to 15,100 tasks and its holds to about 2,300, 0% of the roots' time. The wake and the hold decided once for a file cut them to about 115 and saved no time or CPU, and the owner dropped them (*The path hold decided for the file, measured and dropped*). The hold is decided for each task, as before.
- **The claim's index.** Done, and kept (*The path hold decided for the file, measured and dropped*): the claim reads each module's own range of `tasks_claimable`, and no new index was needed.
- **Every transaction set its isolation level in a statement of its own.** Done, and kept: the level is in the `BEGIN`.
- **Two replicas of one pool share a burst less evenly** than they did (*Order and fairness*). Not measured: the stack has one of each pool.
- **A request asks for the slots free when it is sent.** A pool that is idle but for one long task asks for one slot fewer than it will have, and takes one more round trip to fill it.
- **The root's row lock** is now what bounds a run and what a lease waits for most (*What bounds a run after the path hold step*): about 107 s of waits in Postgres in a run of 65 s, behind the transaction that lands a result. The owner wants it kept in view for a later step.

## For the next step

Built since: `task-start.md`'s *Option 2, built* has the runs that compare with these. The `takes` function of `task-start.md`'s option 2 changes how many tasks exist, so its measurements compare with these by task and by run:

- A whole comparison is 232,927 tasks: 150,098 parser, 55,662 sandbox and 26,695 lookup tasks and 472 of the core's hooks (`task-start.md`). The 14 samples of `tools/lease/measure` are 43,074.
- On this change a run of the whole set took 770 to 941 s on 3,479 to 3,731 CPU-seconds, which is 3.3 to 4.0 ms of wall time and 14.9 to 16.0 ms of CPU a task. The 14 samples took 165 to 260 s, 3.8 to 6.0 ms a task, on 672 to 803 CPU-seconds.
- The lease's own counts a run of the 14 samples: 41,988 claims, 45,488 holds, 93,392 waits for a root's row lock. A task that is never queued saves its share of each.
- `tools/lease/measure`, `tools/lease/cpu` and `tools/lease/same-report` are the instruments, and the timing events stay in the core and the pools.

## What is the owner's to decide

1. Whether a pool that is frozen or killed while idle taking up to its slot count of tasks with it, where it took one, is acceptable. They come back when their leases run out, 60 s by default. The other choice is a limit on a request's size below the slot count.
2. Whether to lower the cost of the path hold next, and which way. Decided on 2026-11-18: the wake and the decision once for a file were built, measured and dropped, since they saved no time or CPU; the isolation level in `BEGIN` and the claim by module are kept (*The path hold decided for the file, measured and dropped*). The third way, taking the root's lock for a hold only when its root was cancelled, wasn't tried.
3. Whether replicas of one pool sharing a burst less evenly matters for a deployment with more than one.

## Not measured

- A whole comparison's time on each side more than once of each kind: the three pairs differ by more than twice over, and why isn't known.
- More than one request in flight from a pool, and a batch limit below the slot count.
- A pool with more than 16 slots, a machine with fewer CPUs, two replicas of a pool, and a production ruleset.
- The roots' time by phase at HEAD: the sampler counted phases only from this change's runs on, so the comparison is with `compare-speed.md`'s figures.
- The 260 s run of the 14 samples on this change, whose cause wasn't found.
