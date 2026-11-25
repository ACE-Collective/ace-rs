# AGENTS.md

Guidance for coding agents (Claude Code and Codex) working in this repository.

## What this is

ace-rs is a rebuild of the Analysis Correlation Engine in Rust. It keeps
[ace3](https://github.com/ACE-Collective/ace3)'s functionality and changes the design. For now it
is a proof of concept: it runs on one machine beside ace3, ace3 sends it nothing, and it is checked
by running the same sample files through both and comparing the analysis trees.

Read these before changing what they cover:

- `DESIGN.md`: what ace-rs is built on and why.
- `PLAN.md`: the steps, each with its *Done when*, and the **Decisions** the owner has made. A
  decision there is settled; don't reopen it without being asked.
- `docs/decisions/`: the larger decisions. `0002-search-index.md` (Qdrant or pgvector) is still open.
- `docs/acceptance.md`: when a port of an ace3 module counts as matching ace3.
- `docs/modules.md`: every ace3 module and where its port stands.
- `docs/measurements/`: the numbers behind decisions, each with how it was measured.

**Agent configuration.** This file is the instructions for both agents. Claude Code reads it through
`CLAUDE.md`, a one-line `@AGENTS.md` import: keep that import, since Claude Code skips `AGENTS.md`
wherever a `CLAUDE.md` exists. Skills live in `.agents/skills/`, which Codex reads, and
`.claude/skills` is a tracked link to it, so a skill is added or edited only under `.agents/skills/`.
Your own untracked instructions go in `CLAUDE.local.md` or `AGENTS.local.md`, which git ignores.

## Repo layout

- `crates/`: the Cargo workspace. PLAN.md's *Crates* table says what each crate holds and which step
  added it. The ones most changes touch:
  - `ace-core`: the schema and its migrations, the task queue, eligibility, the lease API, submissions.
  - `ace-results`: observable kinds and every analysis type's result, the contract between the core
    and the modules.
  - `ace-sdk`: what a module is written against (the module traits, the task context, the overlay,
    secrets, the HTTP client).
  - `ace-mod-*`: one crate per analysis module or module family.
  - `ace-pool`: the pool runtime, its lease loop and the containment of hostile tasks.
  - `ace-service`, `ace-api`, `ace-gui`: the service layer and its JSON and HTML adapters.
  - `ace-app`: builds the `ace` binary and the pool binaries from a list of crates, here and in a
    site's own repository.
  - `ace-testkit`: the module test harness, reference dumps, HTTP replay.
  - Ports of Python libraries ace3 used: `ace-pycompat`, `ace-urlfinder`, `ace-lxml`, `ace-xlrd`,
    `ace-xlsb`, `ace-lnkparse`, `ace-dhash`, `ace-x509`.
- `docker/`: the dev image (`docker/dev`), the stack's images (`docker/ace-rs`), Postgres, the
  scanner images built from ace3's sources, and the dev stack's site overlay (`docker/site`).
- `tests/e2e/run`: the end-to-end test. `tests/coexistence/`: the coexistence check's tests.
- `tools/`: `ace3/` (scripts that run in ace3's dev container to make the reference dumps and trees),
  `library-diff/`, `samples/`, `search/`, `sqlx-check`, `help-screenshots/`, measurement scripts.
- `samples/`: the sample set. `ace3/` and `ace-rs/` are tracked; `local/` is git-ignored and made by
  `tools/samples/gather`.
- `vendor/`: vendored C and C++ dependencies, and why each is vendored (`vendor/README.md`).
- `.sqlx/`: sqlx's offline query data, which builds check queries against.

A site's integrations live in a repository of its own, which depends on these crates by git tag and
builds its own binaries through `ace-app`. Nothing here names a site (see *Conventions*).

**Changing a site's workspace too.** A change that spans this repository and a site's is made in both
checkouts at once: the site's `make live` builds it against this checkout's working tree, with no
commit or tag here, and its `make pinned` goes back to its tag. Build and test the site's side from
its checkout. Where the site workspaces are is in `.site-workspaces` at this checkout's root, one
path per line, which git ignores. When a change needs a site's workspace and that file is missing or
doesn't name it, ask the user where it is and write the path there. Nothing of the site's (its code,
its names, its path) goes into a file this repository tracks.

## Environment

Everything builds and runs in the Compose stack's `dev` container. `make up` starts it with Postgres,
the bucket and the telemetry collector; run a command there with `docker compose exec -T dev <command>`.
`target/` is a named volume of that container, so the host doesn't see it.

- **The host is macOS with zsh.** Quote a glob (zsh fails a command whose glob matches nothing), and
  don't rely on an unquoted `$VAR` splitting into words: zsh doesn't split it. There is no `timeout`.
- **Docker's disk is not the host's.** It is a VM disk of its own; `df` on the host says nothing about
  it. Check it with `docker run --rm alpine:3.24.2 df -h /` before a heavy build. `target/debug` is
  about 17 to 23 GB, `make coverage` peaks at about 23 GB, and an e2e image build uses about 10 GB
  while it runs. Never run two heavy builds at once, here or in a site's workspace: a full disk stops
  ace3's databases too. `docker builder prune -f --keep-storage 15GB` frees BuildKit's cache when
  nothing is building.
- **ace3 runs beside it.** ace-rs's Compose project is `ace-rs`, its variables start with `ACE_RS_`,
  it fixes one host port (`ACE_RS_PORT_HTTPS`, 7443; the end-to-end test uses 7444), and its images are
  named `ace-rs-*`. `bin/check-coexistence` enforces this (PLAN.md, *Running beside ace3*). Never stop,
  change or remove ace3's containers, volumes or images. ace-rs reads ace3's data only through ace3's
  API, ace3's own commands run in its dev container (`tools/ace3/`), or read-only bind mounts.
- **The whole stack:** `docker compose up -d --build`, then `docker compose exec ace ace user
  create-first <name>`, which prints a password once. The GUI is http://127.0.0.1:7443.
- **Git hooks:** `make hooks` once per clone. The pre-push hook keeps T3 Code's `refs/t3/` refs local.

## Testing

```sh
make test       # fmt, clippy -D warnings, the sqlx check, the layering check, nextest, doctests
make e2e        # tests/e2e/run: the stack's images, the sample set compared with ace3's trees
make coverage   # every crate's tests instrumented; the report in coverage/html/index.html
```

One test or one crate, in the dev container:

```sh
docker compose exec -T -e CI=true dev cargo nextest run --locked -p ace-mod-rdap
docker compose exec -T -e CI=true dev cargo nextest run --locked -p ace-core --test integration wakeups::
```

- **One test program per crate.** In the crates whose `tests/` has several files, `tests/main.rs`
  declares them as modules and `Cargo.toml` sets `autotests = false`, so the target is
  `--test integration` and a test's name starts with its file's module. A new file there is built
  only once `main.rs` declares it, and `every_test_file_is_declared` fails until it does.
- **A process per test, or not.** nextest runs each test in a process of its own; `cargo test`, the
  doctests and `make coverage` run a program's tests as threads of one process. A test that needs
  process-wide state (a tracing subscriber, installed observable types) sets it up itself, or it
  passes only when another test happened to run first.
- **The database.** `ace_core::testing::TestDb` (the `testing` feature) gives each test a database
  copied from a template migrated once, so tests share no rows. A query of a catalog view
  (`pg_stat_activity`, `pg_locks`) filters on `current_database()` to see only its own test.
- **A module's tests** go through `ace_testkit::Harness`: settings, a sample or a file, dependency
  results, `run_parser` or `run_lookup`, and the result checked against its type.
- **Matching ace3.** `tools/ace3/dumps/reference/<module>/` holds what ace3's module made of each
  sample. A port's `tests/reference.rs` compares the normal forms, and `tests/differences.md` lists
  each difference with a reason someone verified. An unlisted difference fails, and so does a row
  that matches nothing (`docs/acceptance.md`, *Listing a difference*).
- **Outside services.** Tests reach nothing outside the machine. A vendor's answers are recordings
  under the crate's `tests/recordings/`, replayed by `ace_testkit::replay::HttpReplay`. Where none
  could be recorded, they are written by hand in the shape of the vendor's documentation, and say so.
- **View fixtures and snapshots.** `ace_testkit::check_view_fixture` checks a result against its
  analysis view's fixture; `ACE_RS_WRITE_FIXTURES=1` rewrites them. A few tests use insta snapshots.
- **Local samples.** `samples/local/` is git-ignored, so another clone has none of it. A test that
  reads one skips a dump whose local sample is missing, names it on stderr, and passes it to the
  differences check as skipped (the email, archive, encrypted and scripts reference tests do this).
- **Time.** A test never asserts that something finished within a fixed time, except as a generous
  guard against a hang. It waits for the state it needs (a count, a row, a lock in
  `pg_stat_activity`) instead. `make coverage` runs the tests several times slower, and a test that
  assumes speed fails there.
- **No CI for now.** The GitHub workflows were removed until ace-rs is more stable: `make test` and
  the coexistence check (`bin/check-coexistence`) are the checks, run here before a push. This Mac
  is arm64, so nothing checks an x86-64 build (OpenCV's hardware libraries, say) until CI is back.
  The end-to-end test and `tools/library-diff/run` run by hand: the first needs an ace3 checkout at
  `../ace3`, the second compares a Python library with its Rust port when a port changes.

## Database and migrations

One Postgres, with a schema per area (`analysis`, `queue`, `cache`, `search`, `service`, `lists` and
more), and an S3-compatible bucket for file bytes. Nothing else holds state.

- **Migrations** are plain SQL files, `crates/ace-core/migrations/NNNN_<what>.sql`, numbered in
  order. Never edit one that has been applied anywhere: sqlx records each migration's checksum and
  refuses a changed one. A change is a new migration.
- **Queries** go through sqlx's macros, which are checked at build time against `.sqlx/`. After
  changing a query or a migration, run `cargo sqlx migrate run && cargo sqlx prepare --workspace` in
  the dev container and commit `.sqlx/`. `make check` (through `tools/sqlx-check`) fails on stale data.
- **A migration must be safe on a live, populated table**: no full-table rewrite or long lock. An
  index on a big table holds the table's writes while it builds, so before ace-rs runs against a
  production-sized database such builds move to `CREATE INDEX CONCURRENTLY`.
- **Transactions are values.** `commit` consumes one and dropping it rolls back. Keep effects outside
  the database (the bucket, a vendor call) out of a transaction that may roll back, or make them safe
  to repeat.

## Configuration

Each process reads the site overlay, a YAML file (`ACE_RS_OVERLAY`; the dev stack's is
`docker/site/overlay.yaml`), deserialized with `deny_unknown_fields`, so an unknown key fails at
startup with its path.

- A module's block holds its settings, its `connections:` and, for a module that runs as several
  instances, `instances:`. `settings_file:` names a YAML file whose keys go over `settings:`, read again
  when it changes (PLAN.md decision 65).
- `connections:` are shared credentials by type, named once and bound to a component's slots.
- `secrets:` are `env:<VARIABLE>` or `file:<path>`. A process resolves only the secrets of the
  connections its own components bind.
- `ACE_RS_OBSERVABLE_TYPES` names a site's types file, in ace3's `observable_types.yaml` format, which
  every process reads and a long-running one reads again (PLAN.md decision 66).
- The stack's variables all start with `ACE_RS_`; `compose.yaml` says what each is for.

## Architecture

DESIGN.md has the design. In short:

- **The tree is rows.** A root, its observables and each module's result are rows in `analysis`. A
  result is a typed struct from `ace-results`, checked against its JSON Schema when it is written,
  with bytes kept as bytes.
- **Every module run is a task** in `queue`. Eligibility queues the (observable, module) pairs a new
  result makes eligible, by the module's inputs, its dependencies, the directives, the analysis mode
  and what the module says it takes. Workers claim with `FOR UPDATE SKIP LOCKED`, wake on
  `LISTEN/NOTIFY` and hold a lease; the reaper requeues a task whose lease ran out. A delay is a
  task with a `run_after`.
- **Pools** lease tasks through the core's lease API and never hold database credentials. Network
  lookups run as async tasks in one process. A parser of a hostile file runs one process per task,
  held by rlimits, Landlock and a seccomp filter that blocks fork and exec.
- **The service layer** (`ace-service`) holds the logic and the permission checks, with one actor
  type for users, API keys and internal callers. `ace-api` (JSON, OpenAPI from utoipa) and `ace-gui`
  (askama templates, Datastar for live updates) are thin adapters over it.
- **Layering.** `ace-results`, `ace-service`, `ace-api`, `ace-gui` and `ace-search` never depend on an
  `ace-mod-*` crate; `ace-layering` fails the build when one does.
- **Sites extend through `ace-app`**: `App::` methods add modules, observable types, collectors,
  command types, hunt types, views, alert actions and more. A site needing something `App` lacks gets
  a generic extension point here, never its own code.

## Engineering values

What a change is judged on, in this order: **uptime, logging, tests, performance**, then keeping it
lean. A bug ranks by what it does to one of those. A change does what its description says, and a
bug fix removes the cause, not the symptom. The `ace-review` skill reviews a change against this
section as it is on the base branch.

### Uptime

- Every wait on a run, stop or shutdown path is bounded: a network call, a lock, a join, a channel
  receive. Wrap it in `tokio::time::timeout`, or say in a comment what bounds it.
- A service path returns an error rather than panicking, and a task that fails ends as failed with its
  reason; it doesn't take its process down.
- Deletes and updates over a table that grows are batched, never unbounded. Times compared with stored
  timestamps come from the database's `now()`.
- A failure an operator needs to hear about is logged at ERROR, not at DEBUG.
- A change that can drop an event that should alert, through a filter, an exclusion or a stale cached
  answer, is a failure nobody hears about.

### Logging

The goal is that a production failure can be diagnosed from the logs alone.

- `tracing`, with the identifiers in span or event fields: the root or alert uuid, the observable,
  the module, the task, the path. A field is searchable where text isn't.
- An error is logged with its whole chain (`{e:#}` for anyhow, or the source chain).
- A dropped `Result` fails the build (`unused_must_use` and clippy's `let_underscore_must_use` are
  denied). An error deliberately ignored says why in a comment.
- A state change worth knowing later (work claimed, a fallback taken, an item retired) gets an INFO
  record. Per-item detail in a hot loop goes at DEBUG.

### Tests

- New and changed code comes with tests, the failure paths included: the error returned, the record
  logged, the fallback taken.
- A bug fix comes with a test that fails on the code before the fix.
- A port of an ace3 module is accepted by its reference dumps: each difference from ace3 is listed with
  a verified reason, or it is a bug.
- No `sleep` to wait for something, and no wall-clock bound beyond a hang guard (*Testing*, *Time*).

### Performance

- No N+1 queries: batch per-row lookups into one query.
- Lists page by keyset, never by OFFSET, with a bounded page size.
- Nothing expensive per request or per render. Persist a derived value instead.

### Keep it lean

- Before writing a helper, search for one, and extend it if it's close.
- One concern per change. A refactor the change doesn't need goes in its own.
- Comments say why, not what the code says.
- No new crate, trait or config key without a second caller or a concrete need.
- Remove what a change replaces. A change that renames or removes a path, function or key also
  updates the lines of this file, `docs/` and the skills that name it.

## Conventions

- **This repository is public.** It names no site, and no site's vendors beyond those ace3's public
  repository names for the parts ace-rs ports (its hunt types, its samples, its pivot links). It holds
  no customer data: a fixture reproduces a real case's structure with made-up values, never a copied
  alert, and identifiers (GUIDs, Message-IDs, tenant ids) are made up.
- **The samples include live malware.** Keep that in mind on a machine with antivirus.
- **Matching ace3 is the default.** A port does what ace3 does. A departure is a choice someone made:
  the crate's doc comments or `differences.md` say what differs and why, and an owner's decision goes
  in PLAN.md's *Decisions*.
- **A PLAN.md step is one change**, with its tests, done when its *Done when* holds. A measurement
  records the command, the number of runs, the median and the range, and what else the number could
  include.
- **Commits** go to `main`. The subject says what is true after the change, as a plain sentence
  without a type prefix; the body says why and what was checked. Push only when asked.
- **Rust:** edition 2024, the toolchain `rust-toolchain.toml` pins, `cargo fmt`, clippy with
  `-D warnings`. Libraries return typed errors (`thiserror`); `anyhow` is for `ace-app`'s commands.
