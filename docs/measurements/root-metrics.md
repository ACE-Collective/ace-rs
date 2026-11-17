# What the per-root metrics event adds to a pass's end

A root's pass logs one metrics event when it completes (`ace_core::metrics`, ace3's per-root event). The transaction that ends the pass reads it with one statement: the root's row, its observables counted by type, and its tasks counted. Nothing runs for a task's end that leaves the pass open. This asks what that statement adds to the pass's last transaction on a root with many tasks.

Measured on 2026-11-17 on one machine: Docker (Rancher Desktop) with 10 CPUs and 31 GiB, ace3's stack idle on the same VM, Postgres 18 in the dev stack and in the e2e stack.

## The answer

About 0.3 to 0.45 ms, once per pass, on a root with 3,600 tasks: 0.30 ms in the core's own test, 0.43 ms for the statement on the comparison's real `test.jar` root. The root's tasks have all ended by then, so none of them waits for it; the root's row stays locked that much longer. Counting the tasks (`task_count`, `failed_task_count`, which ace3's event doesn't have) is nine tenths of it in the plan below.

## In the core, with the event and without it

`the_metrics_events_cost_at_a_pass_s_end` in `crates/ace-core/tests/completion.rs`, an ignored test, builds a root with as many tasks as the comparison's `ace3/archive/test.jar`: 71 observables and 3,621 tasks, one of 51 modules on each observable, plus the one task that ends the pass. It ends a pass 200 times. Each time it queues that task again, leases it and times the call that ends it (`Worker::complete`), which is the pass's whole last transaction: the task's end, the completion check, the event's statement, the routing and search inserts and the commit. The event is taken on every other pass and not taken on the rest, which is what `ACE4_LOG` without `ace_metrics` does: the statement doesn't run. Then it times the statement alone, 200 times in one open transaction.

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
| `ace4/rtf/objects.rtf`, the root with the most tasks | 4,808 | 182 | 810 | 0.645, 0.722, 0.645 ms | 0.555 to 5.020 ms | 0.782, 0.861, 0.737 ms | 0.666 to 4.768 ms |

So on the real root it is 0.43 ms (median of the three runs), against 0.29 ms on the test's root with the same number of tasks. The difference is where the rows are: the comparison ran eight samples at once, so a root's tasks are spread over more pages than a root built alone. `objects.rtf`'s 4,808 tasks sit on 810 pages and take 0.65 ms.

`EXPLAIN (ANALYZE, BUFFERS)` of the statement for `objects.rtf`: 1.4 ms executed and 1.2 ms planned, 856 buffers, all in memory. It reads the root by its key, the observables through `observables_in_root` (23 buffers) and the tasks through `tasks_by_root` (830 buffers, of which 810 are the tasks' own pages). The tasks are nine tenths of the cost. An index alone can't answer the count, because it leaves out the core's hooks task by its module, and rows that new aren't marked all-visible anyway.

Those passes took 71.3 s and 43.9 s (`total_time_seconds` in their events), eight samples at once.

Four of the 6,000 logged executions have a latency of 0 in `pgbench`'s log, all in the first prepared run on `test.jar`. They were left out, so that run counts 496.

## What else these could be measuring

- **A pass that didn't end.** A call that ended a task without ending the pass would be faster and would make the event look cheap. The test checks that each of the 200 calls recorded a completion and that the 100 with the event emitted 100 events, with the task and observable counts it built.
- **The planner on an empty database.** The test's database holds one root, where a sequential scan is as good as an index. The real root above is in a database with every sample's rows, and its plan reads both tables through their indexes by root.
- **Warm pages.** Every row was written moments before in both measurements, so it is in memory. That is also the case in production: a pass ends in the transaction that ends its last task, just after the root's tasks were written. A root whose last pass ended long ago and which gets one more task would read its task rows from disk.
- **The log write.** The event is formatted and logged after the commit, inside the timed call. In the test the subscriber parses the JSON and keeps it; a process writes the line to standard error, which wasn't timed here. It is one line of about 400 bytes a pass.
- **`pass_started_at`.** Migration 0066's column is set by the statement that already begins a pass, and the completion's time comes back from the insert that already records it, so neither adds a statement. Both are in the "without" column.
- **One machine, one Postgres, nothing else running on the root.** A root's tasks ending on many connections wait for the root's row lock in turn. The statement lengthens only the last holder's turn.
