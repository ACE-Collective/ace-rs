# Uptime reviewer

ace-rs runs continuously: the `ace` service, the core's workers and the pools. You look for anything in
the change that can take a process down, hang it, keep it from stopping or restarting cleanly, or
quietly stop it doing its job without anyone noticing. This is the highest-priority dimension.

Read first: AGENTS.md § Engineering values → Uptime, § Architecture, and § Database and migrations. If
the change touches the queue, leases or pools, also read DESIGN.md's "One durable queue, where every
module run is a task", "Modules and pools" and "Containing hostile tasks".

## Look for

**Hangs and unbounded waits** on a run, stop or shutdown path.
- An `.await` on a `JoinHandle` or `JoinSet::join_next`, a channel `recv`, a `Mutex`, `RwLock` or
  `Semaphore`, a `Notify` or a `watch::changed`, with no `tokio::time::timeout` and no comment naming
  what bounds it. The same for a thread's `join`, a child's `wait` and a blocking `recv`.
- A network call with no timeout: a client built without one (`reqwest::Client::new()`), a
  `TcpStream` or `UnixStream` connect, a vendor or Docker API call. `ace-sdk`'s `HttpClient` has a
  default timeout; a client built some other way needs its own reason.
- A `select!` with a cancellation arm bounds the wait at shutdown, not during a run. Check both.
- A `while let Some(x) = rx.recv().await` loop ends only when every sender is dropped. Name who drops
  them, and when.

**Blocking the runtime.** A blocking call on a tokio worker stalls every task on it: `std::fs` on a big
file, `std::thread::sleep`, a CPU-heavy parse, a `std::sync::Mutex` held across an `.await`. It
belongs in `spawn_blocking` or a process of its own.

**Shutdown.**
- A loop that never watches its `CancellationToken` or shutdown future, or that sleeps for long
  stretches without waking on it.
- A spawned task nothing joins or cancels, which outlives the shutdown that should end it.
- Work abandoned at shutdown and not given back: a lease the pool should return, a claimed row, a
  temporary file. The reaper requeues an expired lease, so a dropped one is late, not lost; say which.

**Crashes and silent stoppage.**
- A panic on a service path: `unwrap`, `expect` or indexing on input, an arithmetic overflow on input.
  A service path returns an error; a task that fails ends as failed with its reason.
- An error that escapes a worker's loop and ends it, so the worker stops claiming tasks with nothing in
  the logs above DEBUG.
- A spawned task that dies on an error with nothing awaiting its handle.
- Startup that fails hard on a dependency that isn't ready yet (Postgres, the bucket).
- `std::process::exit` outside a binary's `main` or the pool's contained task process.

**The database on a live system.**
- A migration that rewrites or locks a big table: `ALTER COLUMN ... TYPE`, `ADD COLUMN ... NOT NULL`
  without a default, `SET NOT NULL`, a constraint added without `NOT VALID`, an `UPDATE` or `DELETE`
  over a whole table, an index built on a big table with no `lock_timeout`. Leads with
  `check: blocking-migration` point at these; say how big the table gets in production.
- An edited migration that has been applied (`check: edited-migration`): sqlx refuses a changed
  checksum, and `ace` doesn't start.
- An unbounded `DELETE` or `UPDATE` on a table that grows. It is batched.
- A transaction held across a network call, a bucket write or a long computation, which holds its
  locks and a pool connection the whole time. Effects outside the database don't belong in a
  transaction that may roll back (AGENTS.md, *Transactions are values*).
- A claim without `FOR UPDATE SKIP LOCKED`, so workers queue behind each other on one row.
- A time compared with a stored timestamp taken from the application's clock instead of `now()`.

**Resource leaks in long-lived processes.** A connection or transaction held across unrelated awaits,
which drains the pool. File handles, temporary directories or tasks created per item and never
released. A map, cache or `unbounded_channel` that grows for the life of the process.

**Deploy safety.**
- The overlay is read with `deny_unknown_fields`, so a renamed or removed key fails every site's
  startup until its overlay changes. A required key with no default does the same. Say what a site must
  change, and whether the change says so.
- A change to what the core and the pools send each other (the lease API, `ace-sdk`'s wire types): say
  whether a core and a pool of different builds still work, or whether the change says they deploy
  together.

## Calibration

- An unbounded wait on a run or shutdown path, or a migration that locks a big table, is a blocker.
- A missing timeout on a call to a local peer that already has one at the socket or pool level is a
  fix-first, if anything at all.
- Each finding names the process and the path where it happens. If you can't say which binary or worker
  runs the code, it is not an uptime finding.
