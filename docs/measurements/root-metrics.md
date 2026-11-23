# What the per-root metrics event adds to a pass's end

A root's pass logs one metrics event when it completes (`ace_core::metrics`, ace3's per-root event). The transaction that ends the pass reads it with one statement: the root's row, its observables counted by type, and its tasks counted. Nothing runs for a task's end that leaves the pass open. This asks what that statement adds to the pass's last transaction on a root with many tasks.

Measured on 2026-11-17 on one machine: Docker (Rancher Desktop) with 10 CPUs and 31 GiB, ace3's stack idle on the same VM, Postgres 18 in the dev stack and in the e2e stack.

## The answer

About 0.3 to 0.45 ms, once per pass, on a root with 3,600 tasks: 0.30 ms in the core's own test, 0.43 ms for the statement on the comparison's real `test.jar` root. The root's tasks have all ended by then, so none of them waits for it; the root's row stays locked that much longer. Counting the tasks (`task_count`, `failed_task_count`, which ace3's event doesn't have) is nine tenths of it in the plan below.

## In the core, with the event and without it

`the_metrics_events_cost_at_a_pass_s_end` in `crates/ace-core/tests/completion.rs`, an ignored test, builds a root with as many tasks as the comparison's `ace3/archive/test.jar`: 71 observables and 3,621 tasks, one of 51 modules on each observable, plus the one task that ends the pass. It ends a pass 200 times. Each time it queues that task again, leases it and times the call that ends it (`Worker::complete`), which is the pass's whole last transaction: the task's end, the completion check, the event's statement, the routing and search inserts and the commit. The event is taken on every other pass and not taken on the rest, which is what `ACE_RS_LOG` without `ace_metrics` does: the statement doesn't run. Then it times the statement alone, 200 times in one open transaction.

```
docker compose exec -T -e CI=true dev cargo test --release -p ace-core --test completion -- \
    --ignored --nocapture the_metrics_events_cost
```

Three runs of the test, a release build, against the dev stack's Postgres. Each cell is one run's median, with the range across the three runs below it.

| | Run 1 | Run 2 | Run 3 | Range of all runs |
|---|---:|---:|---:|---|
| The last transaction with the event, 100 passes a run | 0.959 ms | 0.981 ms | 0.966 ms | 0.881 to 12.211 ms |
| The last transaction without it, 100 passes a run | 0.663 ms | 0.684 ms | 0.676 ms | 0.593 to 1.259 ms |
| Difference of the medians | 0.296 ms | 0.297 ms | 0.290 ms | |
| The statement alone, 200 executions a run | 0.286 ms | 0.287 ms | 0.279 ms | 0.239 to 1.187 ms |

The median of the three differences is 0.296 ms (range 0.290 to 0.297). The statement alone accounts for it. A debug build, one run: 1.952 ms with, 1.470 ms without, 0.483 ms between them, and 0.359 ms for the statement alone.

The largest time with the event, 11 to 12 ms, is the first pass of each run: the statement is prepared and planned on its connection once. One connection pays that once.

## On the real root

After a whole `tests/e2e/run`, kept up with `--keep`, the e2e stack's Postgres held 479 roots, 234,866 tasks and 9,653 observables. The core had logged 481 events and `queue.root_completions` had 481 rows: one event for each completed pass (477 roots with one pass, 2 with two).

The statement was then run against that database for two of the comparison's roots, with `pgbench` in the Postgres container, one connection, 500 executions a run, three runs each way: `-M prepared`, which plans once on the connection as sqlx does, and `-M simple`, which plans every time. The statement is `ace_core::metrics::read`'s with the root's id written in, and `now()` for the completion's time.

```
pgbench -n -M prepared -c 1 -t 500 -f metrics-root.sql -l --log-prefix=/tmp/m
```

| Root | Tasks | Observables | Heap pages of its tasks | Prepared: medians of three runs | Range | Planned each time: medians | Range |
|---|---:|---:|---:|---|---|---|---|
| `ace3/archive/test.jar` | 3,603 | 184 | 283 | 0.470, 0.430, 0.430 ms | 0.366 to 4.470 ms | 0.605, 0.533, 0.601 ms | 0.477 to 4.073 ms |
| `ace-rs/rtf/objects.rtf`, the root with the most tasks | 4,808 | 182 | 810 | 0.645, 0.722, 0.645 ms | 0.555 to 5.020 ms | 0.782, 0.861, 0.737 ms | 0.666 to 4.768 ms |

So on the real root it is 0.43 ms (median of the three runs), against 0.29 ms on the test's root with the same number of tasks. The difference is where the rows are: the comparison ran eight samples at once, so a root's tasks are spread over more pages than a root built alone. `objects.rtf`'s 4,808 tasks sit on 810 pages and take 0.65 ms.

`EXPLAIN (ANALYZE, BUFFERS)` of the statement for `objects.rtf`: 1.4 ms executed and 1.2 ms planned, 856 buffers, all in memory. It reads the root by its key, the observables through `observables_in_root` (23 buffers) and the tasks through `tasks_by_root` (830 buffers, of which 810 are the tasks' own pages). The tasks are nine tenths of the cost. An index alone can't answer the count, because it leaves out the core's hooks task by its module, and rows that new aren't marked all-visible anyway.

Those passes took 71.3 s and 43.9 s (`total_time_seconds` in their events then, `pass_open_seconds` now), eight samples at once.

Four of the 6,000 logged executions have a latency of 0 in `pgbench`'s log, all in the first prepared run on `test.jar`. They were left out, so that run counts 496.

## What else these could be measuring

- **A pass that didn't end.** A call that ended a task without ending the pass would be faster and would make the event look cheap. The test checks that each of the 200 calls recorded a completion and that the 100 with the event emitted 100 events, with the task and observable counts it built.
- **The planner on an empty database.** The test's database holds one root, where a sequential scan is as good as an index. The real root above is in a database with every sample's rows, and its plan reads both tables through their indexes by root.
- **Warm pages.** Every row was written moments before in both measurements, so it is in memory. That is also the case in production: a pass ends in the transaction that ends its last task, just after the root's tasks were written. A root whose last pass ended long ago and which gets one more task would read its task rows from disk.
- **The log write.** The event is formatted and logged after the commit, inside the timed call. In the test the subscriber parses the JSON and keeps it; a process writes the line to standard error, which wasn't timed here. It is one line of about 400 bytes a pass.
- **`pass_started_at`.** Migration 0066's column is set by the statement that already begins a pass, and the completion's time comes back from the insert that already records it, so neither adds a statement. Both are in the "without" column.
- **One machine, one Postgres, nothing else running on the root.** A root's tasks ending on many connections wait for the root's row lock in turn. The statement lengthens only the last holder's turn.

# What the tasks' run times add (decision 24)

Since migration 0068 a task keeps its run time (`ace_core::metrics`, *A task's run*): the claim sets `claimed_at`, and the statement that ends a task or delays it adds the run to `run_seconds` and `runs` for the pass it ended in (`run_pass`). The pass's event then reads the root's tasks grouped by module, for ace3's `total_analysis_time_seconds` and one module event for each module that ran. No statement was added: the claim sets one column more, the end and the delay three more, and the root's lock they already took (`SELECT ... FOR UPDATE` on the root) returns the pass instead of the id. So the question is what those columns cost on the lease and a task's end, the hottest statements in the core (`lease.md`), and what the grouped read costs at a pass's end.

Measured on 2026-11-17 on the same machine as above: Docker (Rancher Desktop) with 10 CPUs and 31 GiB, ace3's stack idle on the same VM, Postgres 18.

## In the core

The same ignored test, `the_metrics_events_cost_at_a_pass_s_end` in `crates/ace-core/tests/completion.rs`, on the same root of 71 observables and 3,622 tasks, now with every task's run in the root's first pass, as on a root of the comparison. After the 200 passes and the statement alone, it times three pairs, each pair in turn 200 times (400 executions), the statement as it was before migration 0068 against as it is now: the event's statement, in one open transaction; the claim's statement in a transaction of its own, with and without `claimed_at = now()`, on one task made due again each turn; and the end's statement in a transaction of its own, with and without the three run columns (the "without" carries the pass as a parameter it multiplies by 0, so both bind the same parameters). The claim and the end are timed with their commit, as the core runs them, which is the lease's and the end's own cost and leaves out their other statements.

```
docker compose exec -T -e CI=true dev cargo test --release -p ace-core --test completion -- \
    --ignored --nocapture the_metrics_events_cost
```

Three runs, a release build, against the dev stack's Postgres. Each cell is one run's median.

| | Run 1 | Run 2 | Run 3 | Range of all runs |
|---|---:|---:|---:|---|
| The event's statement before the run times | 0.311 ms | 0.286 ms | 0.325 ms | 0.244 to 1.779 ms |
| The event's statement now | 0.711 ms | 0.643 ms | 0.749 ms | 0.599 to 4.870 ms |
| Difference of the medians | 0.401 ms | 0.357 ms | 0.424 ms | |
| The claim's transaction without `claimed_at` | 0.240 ms | 0.276 ms | 0.276 ms | 0.187 to 10.490 ms |
| The claim's transaction with it | 0.248 ms | 0.285 ms | 0.287 ms | 0.193 to 4.905 ms |
| Difference of the medians | 0.009 ms | 0.008 ms | 0.010 ms | |
| The end's statement and commit without the run | 0.194 ms | 0.233 ms | 0.230 ms | 0.153 to 0.946 ms |
| The end's statement and commit with it | 0.201 ms | 0.234 ms | 0.231 ms | 0.155 to 0.521 ms |
| Difference of the medians | 0.007 ms | 0.001 ms | 0.001 ms | |
| The pass's last transaction with the events, 100 passes a run | 1.558 ms | 1.308 ms | 1.280 ms | 1.188 to 13.631 ms |
| The pass's last transaction without them, 100 passes a run | 0.817 ms | 0.672 ms | 0.671 ms | 0.612 to 17.742 ms |
| Difference of the medians | 0.741 ms | 0.637 ms | 0.609 ms | |

So:

- **The lease and a task's end** gain 0.008 ms and 0.001 ms at the median of the three runs (ranges 0.008 to 0.010 and 0.001 to 0.007), against a claim of 0.28 ms and an end of 0.23 ms here and a lease of 4.4 ms and its claim of 2.5 ms as the core saw them in `lease.md`. That is within what separates one run's median from the next for the same statement (0.24 to 0.28 ms for the claim without the column). Neither runs a statement more.
- **The event's statement** costs 0.40 ms more (median of the three differences; range 0.36 to 0.42): 0.70 ms where it was 0.31. Reading the tasks grouped by module, with their run times summed for the pass, takes about twice what counting them did. It runs once a pass, after the root's last task, and no task waits for it but the root's next lock holder.
- **The pass's last transaction** with the events is 0.64 ms longer than without (range 0.61 to 0.74), where it was 0.30 ms longer before: the 0.40 ms of the statement and the 52 log records the root now emits instead of one, each formatted as JSON and, in this test, parsed back by the capturing subscriber, which a process doesn't do.

## On the real root

After a whole `tests/e2e/run` on this change, kept up with `--keep`, the e2e stack's Postgres held 479 roots, 165,446 tasks and 480 completions. Since decision 23 the root with the most tasks is `ace-rs/rtf/objects.rtf`, with 3,403 tasks (on 631 heap pages) and 182 observables; `ace3/archive/test.jar` has 2,473. The statement as it was and as it is were each run for both roots with `pgbench` in the Postgres container, as above: one connection, `-M prepared`, 500 executions a run, the two statements in turn, three runs each. The root's id and its pass (1) are written in, and `now()` stands for the completion's time.

| Root | Tasks | Before: medians of three runs | Now: medians of three runs | Difference, each run | Range, before and now |
|---|---:|---|---|---|---|
| `ace-rs/rtf/objects.rtf` | 3,403 | 0.506, 0.582, 0.601 ms | 0.790, 0.783, 0.776 ms | 0.284, 0.201, 0.175 ms | 0.460 to 4.807, 0.662 to 5.792 ms |
| `ace3/archive/test.jar` | 2,473 | 0.370, 0.327, 0.324 ms | 0.549, 0.621, 0.532 ms | 0.179, 0.294, 0.208 ms | 0.262 to 4.213, 0.462 to 4.868 ms |

On the root with the most tasks the statement takes 0.78 ms where it took 0.58, 0.20 ms more (median of the three differences, range 0.18 to 0.28). `EXPLAIN (ANALYZE, BUFFERS)` of it reads 664 buffers, all in memory, the same pages as before: the root, the observables through `observables_in_root` and the tasks through `tasks_by_root`. What is new is the work on rows already read, grouping them by module and summing two columns. Two of the 6,000 logged executions had a latency of 0 in `pgbench`'s log and were left out.

The run times themselves, in that database: `objects.rtf`'s pass was open 22.4 s and its 3,875 runs (some of its tasks were delayed and ran again) add up to 95.0 s, since tasks run side by side in 8 slots; `test.jar`'s was open 57.6 s for 141.1 s of runs. Over the whole comparison, 180,838 runs add up to 4,790 s, a median run of 20.9 ms, and 6,034 tasks ran more than once. That is why `pass_open_seconds` and `total_analysis_time_seconds` must not be read as one another.

## What else these could be measuring

- **Less work than a real pass does.** Every executed statement was checked to have done its work: each claim claimed the task and each end ended it (the test asserts both), the event's statement returned all 51 modules each time, and the 200 passes recorded 200 completions and 100 events.
- **A "before" that isn't the old code.** The "before" statements are the old statements' text, run against today's schema, with the columns 0068 added present but unread. The old claim and end ran on a table without those columns; four columns more on a row of `queue.tasks` makes its tuples a little wider, which neither side here shows.
- **The clock.** The claim's and the end's differences, 0.001 to 0.010 ms, are smaller than what separates two runs' medians of the same statement (up to 0.04 ms). What they show is that the columns cost nothing measurable, not a number to the microsecond.
- **Warm pages, one machine, nothing else on the root.** As in the first measurement: every row was in memory, and the comparison's eight samples at once are the only concurrency. The read lengthens the last holder's turn on the root's row lock, once a pass.
- **The log records.** A pass now logs one record for each module that ran, 54 on the e2e's email roots and 51 in the test, as well as the root's. The test's last-transaction times include formatting and, in the test only, parsing them; a process writes them to standard error, about 250 bytes each.
