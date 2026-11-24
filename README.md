# ace-rs

ace-rs is a rebuild of the Analysis Correlation Engine in Rust. It keeps
[ace3](https://github.com/ACE-Collective/ace3)'s functionality and changes the language and
the design underneath it. ace3 continues [the ACE project from 2014](https://github.com/ace-ecosystem/ACE).

For now ace-rs is a proof of concept:

- It runs on one machine beside ace3, and ace3 sends it nothing.
- It's checked by running the same sample files through both systems and comparing the analysis
  trees.
- Moving data out of ace3, comparing against production traffic, production deployment and
  cutover wait until there's a decision to take it further.
- Until then, expect breaking changes and no migrations between versions.

- [DESIGN.md](DESIGN.md) is the design: what to build and why.
- [PLAN.md](PLAN.md) breaks it into steps, each with the check that shows it's done, and records
  the decisions made along the way.
- [docs/decisions/](docs/decisions/) holds the larger decisions, and
  [docs/measurements/](docs/measurements/) the numbers behind them.

## Quick setup

```bash
docker compose up -d --build
```

The first build compiles the whole workspace and takes a while. ace-rs makes no default account,
so make the first user yourself. It prints a generated password once:

```bash
docker compose exec ace ace user create-first analyst
```

Then open [http://127.0.0.1:7443](http://127.0.0.1:7443) and log in as **analyst**.

Use `ace user create-key NAME --grant alert:create` to make an API key. The JSON API's OpenAPI
document is [crates/ace-api/openapi.json](crates/ace-api/openapi.json).

The site's config is a small YAML overlay, [docker/site/overlay.yaml](docker/site/overlay.yaml).
Set `ACE_RS_SITE` to use another directory. Set `ACE_RS_SIGNATURES` to a signatures checkout to
build YARA rulesets from it.

### Running beside ace3

ace-rs's stack can run on the same machine as ace3's:

- **Compose project:** `ace-rs`.
- **Images:** all named `ace-rs-*`.
- **Variables:** every one starts with `ACE_RS_`, so a shell that exports ace3's `ACE_*`
  variables doesn't change ace-rs.
- **Host ports:** ace-rs fixes one, `ACE_RS_PORT_HTTPS` (default 7443). Everything else publishes
  on ephemeral ports bound to `127.0.0.1`.

`bin/check-coexistence` checks the Compose file against these rules. PLAN.md's *Running beside
ace3* has the full list.

## Testing

The checks and tests run in the Compose stack's dev container, with its Postgres and bucket, as CI
runs them.

```bash
make test       # formatting, clippy, the sqlx and layering checks, then every crate's tests
make e2e        # the end-to-end test: the sample set through the stack, compared with ace3's trees
make coverage   # every crate's tests with coverage, reported in coverage/html/index.html
make help       # the other targets
```

`make e2e` needs an ace3 checkout at `../ace3`. `make coverage` builds a separate instrumented
copy of every test program, which peaks at about 23 GB on Docker's disk, and refuses to start with
less than 35 GB free there.

## Why Rust, Postgres and the rest

This is a short version of [DESIGN.md](DESIGN.md).

### The design matters more than the language

Of the 43 ace3 issues labeled `design flaw`, nine come from how Python starts processes and
imports modules: forking processes that already run threads, imports that do registration work,
core and web code importing each other, and no stop signal a module can pass to a blocking call.
The other 34 would follow ACE into any language. Most of the gain comes from the design changes
below, and most of those could be made in Python too.

### Why Rust

Models write the code and people review it. So how long a person takes to learn a language counts
for little, and what the compiler checks on every change counts for more. Rust's compiler enforces
several of ACE's engineering rules:

- **An ignored error fails the build.** `Result` is `#[must_use]`, and the workspace denies
  dropping one.
- **New cases can't be missed.** A new task state or observable kind fails the build at every
  `match` that doesn't handle it.
- **No null.** A missing value is an `Option`, which the code must handle before using it.
- **A panic stays in its task.** It ends that tokio task, and the process keeps serving.
- **Transactions are values.** `commit` consumes the transaction and dropping it rolls back, so
  a stuck session after a failed commit can't be written. Data races are compile errors.
- **Layering is checked.** Cargo rejects cycles between crates, and `ace-layering` keeps the
  API, GUI and search crates off analyzer crates.

What Rust costs:

- **Build time.** A build from scratch takes minutes.
- **Async mistakes.** Async Rust is where models and reviewers make the most mistakes,
  cancellation especially. So async stays at the edges, and parsers stay synchronous in their own
  processes.
- **No vendor SDKs.** Few vendors publish Rust SDKs, so those clients are written from the APIs'
  docs.
- **Reading during an incident.** Rust is harder to read under pressure. Tracing spans that carry
  the alert, observable and module on every log line make up for part of that.

### Why Postgres and a bucket, and nothing else that holds state

ace3 keeps state in four MySQL databases, a read replica, Redis, RabbitMQ, Qdrant and node-local
storage directories. ace-rs keeps it in Postgres and an S3-compatible bucket.

Postgres over MySQL, for four things ace3 works around:

- **Transactional DDL.** A failed migration rolls back instead of leaving half a schema.
- **`LISTEN/NOTIFY`.** Workers wake when there's work, so nothing polls.
- **JSONB with GIN indexes.** Queries can reach into analysis details.
- **Template databases.** Each test copies a migrated, seeded database instead of running
  migrations.

Migrations are plain SQL files, and sqlx checks every query against the migrated schema at build
time. There are no ORM models, so nothing can drift from the schema.

File bytes go into a content-addressed bucket: SeaweedFS in the dev stack, S3 on AWS. Any node
can serve any alert's files, so node-to-node transfers go away.

Whether search moves from Qdrant to pgvector and Postgres full-text search hasn't been decided.
[docs/decisions/0002-search-index.md](docs/decisions/0002-search-index.md) has the comparison
so far.

### The rest of the design

- **One durable queue.** The analysis tree is rows in Postgres, and every module run is a task.
  Workers claim tasks with `FOR UPDATE SKIP LOCKED` and hold a lease. If a worker crashes, its
  lease expires and the task runs again. Modules for one alert run in parallel on different
  workers, so the per-alert lock goes away.
- **A versioned result schema.** Each analysis type's details are a Rust type in `ace-results`,
  checked when written, with bytes kept as bytes. The API, GUI and search read results without
  loading any analyzer code.
- **Pools.** A pool is a container that hosts a set of modules. Network lookups run as many async
  tasks in one process. Parsers of hostile files run one process per task, held by rlimits,
  Landlock and a seccomp filter that blocks fork and exec.
- **YARA on yara-x.** ACE's two scanner layers, `yara_scanner_v2` and ACE's meta directives, are
  ported to Rust in `ace-yara`, over VirusTotal's yara-x.
- **A GUI of server-rendered HTML.** askama templates, checked at build time, with Datastar for
  live updates as results arrive. There's no npm dependency tree.
- **Site integrations as crates.** A site's integrations live in their own repository and are
  linked into its binaries at build time by `ace-app`, instead of being loaded as Python packages
  at run time.
- **Docker Compose,** one stack per node, as today.

### Alternatives considered

- **Go:** fast builds, easier to read in an incident, a proven Postgres queue. Its compiler checks
  less: errors can be dropped, there are no sum types, nil exists, and an unrecovered panic in any
  goroutine kills the process.
- **Python, rebuilt with this design:** gets most of the design's value, but keeps the fork,
  import-cost and cancellation problems, and no compiler checks a model's changes.
- **Elixir/OTP:** supervisors and timeouts fit ACE's uptime rules, at the cost of reaching
  Python and native parsers through ports.
- **Temporal:** one more stateful cluster, a history cap a large email alert could hit, and a tree
  that isn't in tables you can query.
- **A React GUI:** a second language, an npm dependency tree, and client state to merge live
  updates into.
- **Kubernetes:** per-task cgroups and autoscaling on queue depth, which at ACE's volume aren't
  worth running a cluster for.

## Malware

[samples/](samples/) holds ace3's live malware samples, which the comparison with ace3 runs
through both systems. Keep this in mind on a machine with antivirus.

## License

ace-rs is licensed under the Apache License 2.0 ([LICENSE](LICENSE)). [vendor/](vendor/) holds source from other
projects that ace-rs builds and ships under their own licenses, which aren't necessarily
ace-rs's. See [vendor/README.md](vendor/README.md).
