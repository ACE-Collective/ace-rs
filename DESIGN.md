# Rebuilding ACE from scratch

2026-10-29. The question: if ACE were rebuilt today, keeping its functionality but free to pick any language, framework or design, what should it be built on?

The team no longer writes code by hand. Models write it and people review it. So the time a person needs to write a language counts for little, and what its compiler checks on every change counts for more.

For now the rebuild, ace4, is a proof of concept that runs on one laptop beside ace3, and ace3 sends it nothing. Comparing against production traffic, moving data out of ace3 and cutover wait until there's a decision to take it further. [PLAN.md](PLAN.md) lists what waits.

## Recommendation

- Rust for the core (orchestrator, API, GUI, ingest, scheduler and CLI) and for most analysis modules.
- A Python module pool only for libraries that have no complete Rust equivalent yet. Each one moves to Rust once a port matches it on ACE's sample corpus.
- ACE's YARA scanner layers, the team's `yara_scanner_v2` library and ACE's own meta directives, ported to Rust on yara-x and checked against today's scanner on the same corpus.
- Postgres and an S3-compatible bucket as the only systems that hold state.
- A versioned result schema, in a crate of its own, as the contract between the core and the modules.
- Server-rendered HTML with Datastar for the GUI, over the same service layer as the JSON API.
- Docker Compose, one stack per node, as today.
- Site integrations such as site_ace as crates in their own repositories, linked into the site's images at build time.

Most of what has hurt ACE comes from design decisions that would carry over into any language, and most of the design changes below could be made in Python. Rust is the pick because a model writes every change and the compiler checks each one before a person reads it.

## Basis

- The 43 GitHub issues labeled `design flaw` on 2026-10-29, open and closed. The grouping in the appendix is my reading of their titles and of three issue bodies ([#982](https://github.com/ACE-Collective/ace3/issues/982), [#1029](https://github.com/ACE-Collective/ace3/issues/1029), [#999](https://github.com/ACE-Collective/ace3/issues/999)).
- The current layout: [`ace3/saq/engine/`](../ace3/saq/engine/), [`ace3/saq/analysis/`](../ace3/saq/analysis/), [`ace3/saq/cas/`](../ace3/saq/cas/), [`ace3/aceapi_v2/engine/`](../ace3/aceapi_v2/engine/), [`ace3/docker-compose.yml`](../ace3/docker-compose.yml) (31 services) and [`ace3/app/`](../ace3/app/) (124 Jinja templates, with Datastar 1.0.4 vendored and used by 4 of them).
- Memory figures from [`ace3/local/20261021-engine-worker-memory-investigation.md`](../ace3/local/20261021-engine-worker-memory-investigation.md).
- `yara_scanner_v2` v3.0.0 and yara-python 4.5.4 as installed in the dev container, and the YARA rules in the signatures checkout under ace3 as they are on disk today.
- The decisions recorded in [PLAN.md](PLAN.md) the same day, after checking this document against ace3 at commit `141a60a2`.

File paths are in the ace3 checkout at `../ace3`, and each link is relative to this file.

Nothing here was prototyped or measured for this document. Rust's build times and how the signatures repo fares on yara-x under the ported scanner layer are the first things to measure, because either could change the pick.

## Language and design

Nine of the 43 design flaws come from how Python starts processes and imports modules:

- ACE forks processes that already run threads ([#982](https://github.com/ACE-Collective/ace3/issues/982)).
- Importing a module does registration work and pulls in heavy libraries ([#1029](https://github.com/ACE-Collective/ace3/issues/1029), [#1030](https://github.com/ACE-Collective/ace3/issues/1030), [#1031](https://github.com/ACE-Collective/ace3/issues/1031), [#1032](https://github.com/ACE-Collective/ace3/issues/1032), [#1066](https://github.com/ACE-Collective/ace3/issues/1066)).
- Core and the web layer import each other ([#843](https://github.com/ACE-Collective/ace3/issues/843), [#953](https://github.com/ACE-Collective/ace3/issues/953)).
- A module has no stop signal it can pass to a blocking call ([#984](https://github.com/ACE-Collective/ace3/issues/984)).

The other 34 would follow ACE into any language. They include lossy bytes in analysis details ([#999](https://github.com/ACE-Collective/ace3/issues/999)), every process resolving every `env:` reference ([#1009](https://github.com/ACE-Collective/ace3/issues/1009)), process groups that don't nest ([#981](https://github.com/ACE-Collective/ace3/issues/981)) and no actor type for internal callers ([#1089](https://github.com/ACE-Collective/ace3/issues/1089)). So the design carries most of the value.

The language still matters more than nine issues suggest, because of who writes the code. Rust's compiler enforces several of ACE's engineering values on every change:

- **Ignored errors fail the build.** `Result` is `#[must_use]`. With `unused_must_use` and clippy's `let_underscore_must_use` set to deny, a dropped error can't merge. That is ACE's "every except logs, re-raises or says why" rule, checked by the compiler.
- **New cases can't be missed.** Adding a task state or an observable kind fails the build at every `match` that doesn't handle it.
- **No null.** A missing value is an `Option`, and the code has to handle it before using it.
- **A panic stays in its task.** A panic in a tokio task ends that task, its `JoinHandle` returns the error, and the process keeps serving.
- **Transactions are values.** `commit` consumes the transaction and dropping it rolls back, so the stuck session after a failed commit ([#852](https://github.com/ACE-Collective/ace3/issues/852)) and the second connection ([#1040](https://github.com/ACE-Collective/ace3/issues/1040)) can't be written. Data races are compile errors.
- **Identifiers reach every log line.** `tracing` spans attach the alert uuid, observable and module to every record inside them, which is the logging rule's "identifiers in `extra={}`" by default.
- **Layering is checked.** Cargo rejects cyclic dependencies between crates, so a core crate that depends on the web crate fails the build.

## What to build

### A result schema in its own crate

Each analysis type declares its details as a versioned Rust type in a results crate. The core checks every result against its type when it is written, keeps bytes as bytes, and stores the result under the analysis type's name rather than a code path. `schemars` exports each type as JSON Schema, which is what the core checks the Python pool's results against.

The API, the GUI and the search indexer depend on the results crate and on no analyzer crate, so reading an alert never loads analyzer code, and a dependency from the API on an analyzer fails the build. That removes the cause of #1029, #999, [#827](https://github.com/ACE-Collective/ace3/issues/827) and #1032.

### One durable queue, where every module run is a task

The analysis tree lives in Postgres as rows. Each result is a row keyed by (root, observable, module). New observables are upserted on (root, type, value).

When a result lands, the orchestrator finds the (observable, module) pairs that just became eligible and queues them. Eligibility covers the module's input types, its dependencies, the observable's directives (such as `no_scan`) and the root's analysis mode. A mode names the module groups that run, as ace3's `analysis_mode_*` config does. When a root's mode changes, as when a detection turns it into an alert in correlation mode, eligibility reruns over every observable the root already has. Delayed analysis is a task with a `run_after` time. A worker holds a lease on its task and renews it, so if the worker crashes, the lease expires and the task runs again. A root is complete when it has no queued or running tasks.

Modules for one alert run in parallel on different workers. They don't conflict because each writes its own rows, so the per-root lock goes away. A large email alert that today runs module by module under one worker's lock spreads across every free worker.

Workers claim tasks with `FOR UPDATE SKIP LOCKED` and wake on `LISTEN/NOTIFY`. The queue is written on sqlx inside the core rather than taken from a library, because the Rust Postgres queue crates are younger than Go's River and the queue has to fit the eligibility model exactly. Every worker, Rust or Python, leases tasks through the core's API rather than the database, so a parser never holds database credentials.

### Modules and pools

A pool is a container image that hosts a set of modules and declares its resource limits, sandbox profile, concurrency and the secrets it needs. A Rust pool is one binary that links its module crates, so it contains only its own modules. The import rules in [`ace3/docs/IMPORTS.md`](../ace3/docs/IMPORTS.md) and the lazy package `__init__.py` files have no counterpart.

- Network lookups (DNS, RDAP, a mail API, Splunk, LogScale) run as async tasks inside one pool process, many at a time.
- Parsers of hostile files run one process per task, contained as described in *Containing hostile tasks*.
- The Python pool runs oletools, msoffcrypto, pcodedmp and XLMMacroDeobfuscator until their ports match. It imports only those libraries, pins each one (ace3 installs XLMMacroDeobfuscator from GitHub master), and recycles a worker after a task count or a memory limit.
- PDFs go through libqpdf, the C++ library under pikepdf, by way of the qpdf crate, in-process inside a contained task. ace3 uses pikepdf to pull annotation URIs, form fields and JavaScript, and runs pdf-parser.py beside it. The Rust module replaces both.
- phishkit (SeleniumBase's anti-detection) and js_deobfuscator (node:vm) stay as they are, since they are already separate services with narrow interfaces. tshark stays in the sandbox runner.

Crates that cover most of the rest: yara-x (VirusTotal's Rust YARA) under ACE's ported scanner layer, described in *The YARA scanner*, mail-parser for MIME, goblin and object for PE/ELF/Mach-O, cfb for OLE containers, zip, sevenz-rust, flate2 and unrar (which binds RARLAB's C++ library) for archives, hickory-dns, ICANN's own RDAP client, and minijinja, by Jinja's author, so hunt templates keep their syntax.

The libraries without a Rust equivalent carry years of handling real malformed files, which a port loses until it is tested against them. ACE already holds the test set. Every file a YARA rule matched on a dispositioned alert is kept as an SVS sample. A port runs alongside the Python library over that corpus, the outputs are diffed, and the port replaces the library when they match. The SVS corpus lives in production, so the proof of concept runs the same check over sample files on the laptop.

In production today, Python engine workers hold 365 to 491 MB private on correlation and 597 to 1,028 MB on a busy email scanner, against about 230 MB for a fresh worker. A Rust process carries no interpreter and no imported modules. How much its work adds is unmeasured.

URL extraction is CPU-bound Python today and times out at its 15-second cap on multi-line blobs. In the rebuild it is compiled code.

### The YARA scanner

libyara itself is stock: yara-python 4.5.4 from PyPI, built with the standard modules. ACE adds two layers above it, and both have to be ported.

The first is the team's own library, [`yara_scanner_v2`](https://github.com/unixfreak0037/yara_scanner_v2) v3.0.0, 1,531 lines of Python:

- Each subdirectory of the signature directory is its own namespace.
- A namespace in a git repository reloads only on a new commit, and every match reports that commit.
- Each rule file is compiled alone first. A file that fails is logged and left out, and the rest are compiled together.
- It sets default external variables (`filename`, `filepath`, `extension`) and keeps a blacklist of rule names.
- It filters matches after the scan, driven by meta directives in each rule.
- It has a per-rule timing harness.

The second is ACE's own. About 15 modules tag the files they produce with `yara_meta` values such as `type=email.attachment` or `type=document.html.phishkit` ([`ace3/saq/observables/file.py`](../ace3/saq/observables/file.py)), and the scanner passes a file's tags to the filter as its `meta_tags`. [`ace3/saq/signatures/yara_meta.py`](../ace3/saq/signatures/yara_meta.py) reads `modifiers` (`qa`, and `no_alert`, which SVS treats the same way), `enabled` and the rule uuid, and [`ace3/saq/yara_scanning/`](../ace3/saq/yara_scanning/) is the pre-fork scanning service.

The rules depend on the filter. In the signatures checkout, 164 meta lines across 289 rules in 87 files use it:

| Directive | Lines | Compared against |
|---|---|---|
| `meta_tags` | 137 | the tags the caller passes for the file |
| `file_name` | 14 | the file's name |
| `mime_type` | 10 | the output of `file -b --mime-type` |
| `full_path` | 2 | the file's path |
| `file_ext` | 1 | the file's extension |

A directive's value is a comma-separated list, and the rule is kept if any item matches. Comparisons ignore case. `!` negates the list, `re:` makes each item a regex search, and `sub:` makes it a substring test. A rule with a non-negated `meta_tags` is dropped when the caller passes no tags. Of the 164 lines, 64 are lists and 16 use `re:`; none use `!` or `sub:`. 25 rules carry `modifiers`.

yara-x's public API covers everything these layers need from libyara: namespaces, global variables set per scan, rule metadata and pattern offsets on each match, compiled rules serialized to bytes, a scan timeout, and slowest-rule reports when built with the `rules-profiling` feature. So the port is a rewrite of the two layers on yara-x, not a fork of YARA.

Both layers go into one `ace-yara` crate. The YARA pool, SVS validation and the `ace yara scan` command all use it, so production and SVS filter matches the same way.

- **A ruleset per commit.** A build task compiles the signatures repo at a commit, file by file as today. A file that fails is logged at ERROR with its path and the commit, and is left out. The task also compiles every `re:` directive with Rust's regex crate, so a pattern the crate can't handle fails its file at build time instead of at scan time. The serialized ruleset goes into the bucket under its hash. A Postgres row records the commit, the yara-x version, the files and rules included and the files left out, which fixes [#1051](https://github.com/ACE-Collective/ace3/issues/1051). A rule directory outside git is keyed by the hash of its sources.
- **Generations.** A pool worker loads a ruleset by hash and switches to a new one only after the new one has loaded, as the yara service's generations do today. Every match records the ruleset and commit it came from.
- **The filter.** It is ported with the same semantics and still runs after the match. The mime type comes from libmagic, the library `file` itself uses. It is computed once when the file enters the bucket and stored with it, instead of a `file` subprocess per scan. The image pins the magic database, so answers don't change under a rule.
- **Names and paths.** The bucket stores bytes by hash, but `file_name` and `full_path` compare against the name and path a file has in the alert. Several of those 16 lines match names that ACE's own modules produce (`.ocr`, `.pdfparser`, `.lnkparser.json`, `.rfc822.headers`, `.pptx.extracted/`). So each file observable keeps its name and its path inside the alert, the YARA task passes both along with the `meta_tags`, and a ported module keeps its output names. The rules keyed on those suffixes could move to `type=` tags, which don't depend on names. Today `full_path` is the absolute path on the node. Inside the alert it is relative, and both `full_path` lines start with `re:.*`, so they still match. This is also why an SVS sample unit is a (sha256, file path, meta tags) triple rather than the bytes alone ([`ace3/saq/svs/yara/corpus.py`](../ace3/saq/svs/yara/corpus.py)).
- **QA and timing.** QA rules still never alert. A QA match queues a task that records it, and the file is already in the bucket, so the spool directory and its hardlinks ([`ace3/saq/yara_scanning/qa.py`](../ace3/saq/yara_scanning/qa.py)) go away. The timing harness becomes yara-x's slowest-rule report, built into SVS validation only, because profiling adds overhead to every scan.
- **Integrations.** Integration code that calls yara-python directly, such as the journal email collector's blacklist check, moves to the same crate.

The acceptance test runs before any production traffic depends on the port. Build the signatures repo with both scanners, scan every SVS unit with both, and compare the matched namespace, rule and pattern offsets for each unit. Each difference is either a yara-x incompatibility, fixed in the signatures repo, or a bug in the port. On the laptop, the build half covers the whole signatures repo and the scan half covers local sample files only. Incompatibilities are recorded rather than fixed, and the full SVS run waits.

### Containing hostile tasks

Docker mounts `/sys/fs/cgroup` read-only in an unprivileged container, so a pool can't create a cgroup per task. Within what Compose allows, each hostile task is one single-threaded process with:

- rlimits on address space and CPU time
- Landlock rules for files and TCP ports
- a seccomp filter that blocks fork, clone and exec once the process has started

Landlock doesn't cover UDP, so a DNS query sent straight to a resolver's address gets out, and it doesn't stop `stat` on any path. Task processes run as a non-root user with no capabilities, so raw sockets aren't open to them either.

A process that can't have children dies completely when its PID is killed, which avoids #981's problem without cgroups. The pool container's `mem_limit` bounds the pool as a whole. External tools that start children keep ACE's existing sandbox runner. Workers start by exec, so the at-fork repair hooks behind #982 aren't needed.

A failed or hung task leaves a row with its error and the hashes of its inputs, which are already in the bucket, so the task can be replayed under a debugger. Before killing a hung Python task, the pool supervisor captures its stacks with `py-spy dump` into the row's `stacks` column. py-spy runs as the worker's own user, which the worker has named to Yama as allowed, so the pool's container needs no added capability, and Landlock still stops one worker reading another.

### Postgres and an object store, and nothing else that holds state

File bytes go into a content-addressed bucket, which is [`ace3/saq/cas/`](../ace3/saq/cas/) grown into the only file store, with a local cache on each node. Any node can serve any alert, crash report, YARA QA file or SVS sample, and the notes saying a multi-node site must give a pool a shared backend no longer apply.

Postgres over MySQL, for four things ACE works around today:

- DDL runs inside transactions, so a failed migration rolls back instead of leaving half a schema.
- `LISTEN/NOTIFY` wakes workers, so nothing polls.
- JSONB with GIN indexes lets queries reach into analysis details.
- Template databases let each test worker copy a migrated, seeded database instead of running four Alembic chains.

Migrations are SQL files, and sqlx checks every query against the migrated schema at build time, from metadata committed with the code so builds don't need a database. With no ORM models there is nothing for the schema to drift from.

Production holds about 26K alerts and adds about 80 a day. At that size, pgvector plus Postgres full-text search could replace Qdrant. [`ace3/tests/saq/search/test_retrieval.py`](../ace3/tests/saq/search/test_retrieval.py) would show whether retrieval quality holds up before Qdrant is dropped.

### The core

tokio, axum, sqlx, `tracing` with OpenTelemetry, and rustls. ACE's uptime rule that every wait is bounded becomes `tokio::time::timeout` around every network call, lock and join on a run or shutdown path. Child processes start without running at-fork hooks or interpreter code in the child.

`http-api-v2` runs 12 uvicorn workers at about 211 MB private each, 2.57 GB in all, because each worker is a spawned interpreter that imports everything itself. The Rust API is one process with no per-worker interpreter. Its memory is unmeasured.

### What Rust costs

- **Build time.** A workspace with tokio, axum, sqlx and the AWS SDK takes minutes to build from scratch, and an agent fixing compile errors waits for a rebuild on every attempt. The unrar and qpdf crates bring C++ into the build. Small crates, the mold linker, sccache, and `target/` on a named volume instead of the macOS bind mount all help.
- **Async Rust.** It is where models and reviewers make the most mistakes, cancellation especially. A dropped future stops at its last await without running any cleanup. Inside a database transaction that is a rollback, which is safe. Code outside a transaction has to be written for it. Async stays at the edges (HTTP, database, queue), and parsers stay synchronous in their own processes.
- **No official SDKs.** Microsoft and EndpointVendor don't publish Rust SDKs, so those integrations are REST clients written from the API docs.
- **YARA compatibility.** yara-x is stricter than libyara about some rules, and ACE's scanner layers have to be rewritten on top of it. The comparison over the SVS corpus finds both kinds of difference.
- **Reading under pressure.** Rust is harder to read during an incident. Spans that carry identifiers mean the logs answer more of those questions without reading code.
- **A slower dev loop.** A `.py` edit today needs only a container restart. A Rust edit needs an incremental build first, which `cargo watch` or bacon in the `dev` container runs on every save.

### Config that belongs to its component

Each module ships a manifest with its input types, output schema, resources, sandbox, settings and the secrets it needs. Site config is a small YAML overlay deserialized with `deny_unknown_fields`, so unknown keys fail.

- A module can run as several named instances declared in the overlay, each with its own inputs and settings, as ace3's `analysis_module_*` sections run many Splunk queries on one class.
- A process resolves only the secrets its pool declares (#1009).
- A removed module named in an overlay logs a warning instead of stopping startup ([#901](https://github.com/ACE-Collective/ace3/issues/901), [#916](https://github.com/ACE-Collective/ace3/issues/916)).
- Lists analysts edit at runtime, such as whitelists and suppressions, live in the database behind the API with an audit record ([#1063](https://github.com/ACE-Collective/ace3/issues/1063)).
- Detection content (hunts, YARA, modifier rules) stays in git with CI.

### The API and the GUI

One service layer holds the logic and the permission checks, with one actor type for users, API keys and internal callers from the start (#1089, [#830](https://github.com/ACE-Collective/ace3/issues/830)). Two thin adapters sit over it: a JSON API with an OpenAPI spec generated by utoipa, and server-rendered HTML views. Nothing is repeated in a client.

The JSON API is new. It keeps no `/api/v2` paths or payloads.

The GUI keeps ACE's current model, server-rendered HTML with Datastar:

- **Live updates.** Results arrive over seconds or minutes as modules finish in parallel. Datastar streams HTML fragments to the page over server-sent events, so the server pushes each new result into the open alert page when Postgres notifies it.
- **Tests without a browser.** A view is a function that returns HTML, so the Rust test suite tests it directly.
- **Compile-checked templates.** askama compiles Jinja-like templates into Rust, escapes output by default, and fails the build when a template uses a field that doesn't exist.
- **No npm dependency tree.** In September 2025 an attacker phished a maintainer's account and published malicious releases of chalk and debug, and the Shai-Hulud worm then spread through npm on stolen publish tokens. Datastar is one vendored file.

A page that needs real client-side interaction, such as an observable relationship graph, loads one vendored component and feeds it JSON from the API.

### Site integrations

ace3 loads integrations at run time as Python packages cloned into [`ace3/integrations/`](../ace3/integrations/), and each one runs registration hooks when it is imported ([#1031](https://github.com/ACE-Collective/ace3/issues/1031)). site_ace is one of them. It is its own repository, ignored by ace3's git, and holds the journal email collector and the a mail API, EndpointVendor (with LogScale), Rapid7, VirusTotal, ExampleSandbox, ExampleCloud and intel feed integrations.

In the rebuild an integration is a set of crates in its own repository. An `ace-app` crate builds the `ace` binary and each pool binary from a list of crates. The open-source binaries call it with the open-source crates, and a site repository calls it with those crates, pinned by tag, plus its own. The list takes analysis modules, collectors, hunt query sources and command types, alert routers, API routes, alert toolbar buttons, observable actions, alert page cards and templates, which is what an ace3 integration can add today ([`ace3/docs/INTEGRATIONS.md`](../ace3/docs/INTEGRATIONS.md)). It also takes observable types. ace3 accepts any type name it doesn't know through a generic `DefaultObservable` class, but the rebuild's types are a fixed list, so a site's types join that list when its binary is built. The site's CI also builds against the open-source main branch, so a breaking change shows up before a tag.

## Deployment with Docker Compose

Today's [`ace3/docker-compose.yml`](../ace3/docker-compose.yml) has 31 services. The rebuild has:

- `postgres`
- `bucket`, SeaweedFS's S3 server, for dev and single-node installs; production in AWS uses S3. MinIO stopped publishing community images in October 2025.
- `ace`, one binary for the API, GUI, orchestrator and scheduler, or an engine container and an API container if they should restart separately
- one container per module pool, scaled with `replicas`: Rust parsers, network lookups, and the Python pool
- `phishkit` and `js-deobfuscator`, unchanged
- `fluent-bit`, if logs still ship to Splunk
- a TLS proxy, or rustls inside the `ace` binary

Multi-node is one Compose stack per node, as today. Every node points at the same Postgres and bucket and runs only the pools it should host. Node-to-node calls go away. Draining a node means stopping its pools, which release their leases.

On a developer's machine, the ace4 stack runs beside ace3's. ace4 uses its own Compose project name (`ace4`) and `ACE4_`-prefixed variables. It fixes one host port, which ace3 doesn't use, and names its images `ace4-*`. Its dev stack doesn't use Docker's fluentd log driver, because that driver needs a fixed host port and ace3 already holds 24224. [PLAN.md](PLAN.md) has the full list under *Running beside ace3*.

Kubernetes would add per-task cgroups and autoscaling on queue depth. At ACE's volume neither is worth running a cluster for.
## What it replaces

| Today | In the rebuild |
|---|---|
| `workload` table, polled | the task queue, woken by `LISTEN/NOTIFY` |
| `delayed_analysis` table | a task with `run_after` |
| `locks` table with a keepalive per root | leases on tasks; no root lock |
| node manager, `nodes` table, drain state machine | workers lease from one queue; draining a node means it stops leasing |
| `/api/v2/engine/download` and `upload` tarball transfer | files in the shared bucket |
| Celery, RabbitMQ and Redis for phishkit and js_deobfuscator | two pools on the same queue |
| yara service's unix socket and shared-path rule | a YARA pool that loads a serialized ruleset from the bucket and switches generations once the new one loads |
| `yara_scanner_v2` over yara-python | the `ace-yara` crate over yara-x |
| a `file -b --mime-type` subprocess per scan | libmagic, once per file |
| the YARA QA spool directory and its hardlinks | a QA task; the file is already in the bucket |
| `network-semaphore` service | per-pool concurrency limits |
| Qdrant | pgvector and Postgres full-text search, if the retrieval tests pass |
| four MySQL databases and a read replica | one Postgres with a schema per area |
| four Alembic chains and [`ace3/bin/check_model_drift.py`](../ace3/bin/check_model_drift.py) | SQL migrations, with sqlx checking every query at build time |
| node-local storage dirs, crash report replication, `ace crash sync` | the bucket, plus a failed-task row with its input hashes |
| at-fork hooks in [`ace3/saq/database/pool.py`](../ace3/saq/database/pool.py), [`ace3/saq/storage/factory.py`](../ace3/saq/storage/factory.py), [`ace3/saq/cas/registry.py`](../ace3/saq/cas/registry.py), [`ace3/saq/cas/metrics.py`](../ace3/saq/cas/metrics.py) | nothing; workers start by exec |
| [`ace3/docs/IMPORTS.md`](../ace3/docs/IMPORTS.md) rules, lazy package inits, [`ace3/tests/saq/test_imports.py`](../ace3/tests/saq/test_imports.py) | crate boundaries; a pool binary links only its modules |
| Flask GUI and FastAPI | one Rust service with a JSON API and server-rendered views |
| the merged [`ace3/etc/saq.default.yaml`](../ace3/etc/saq.default.yaml) | per-module manifests and a small site overlay |
| `unzip`, `7z` and `unrar` subprocesses | the zip, sevenz-rust, flate2 and unrar crates |
| pikepdf and `pdf-parser.py` | a Rust module on libqpdf |
| integrations loaded as Python packages at run time | crates in each integration's own repository, linked at build time |
| alert trees in storage directories | rows in Postgres |

## Alternatives considered

- **Go for the core.** It builds in seconds, is easier to read during an incident, has River as a proven Postgres queue, and has official a mail API and EndpointVendor SDKs. Its compiler checks less. A caller can drop an error unless a linter catches it, there are no sum types, nil exists, and an unrecovered panic in any goroutine kills the process. It is the better pick if the build loop or incident reading matters more than what the compiler catches.
- **All Python, rebuilt with the design above.** It gets most of the design value. Free-threaded Python 3.14 removes the GIL but not the fork, import-cost or cancellation problems, and no compiler checks a model's changes.
- **Elixir/OTP.** Supervisors, timeouts and distribution match ACE's uptime rules well. The costs are calling Python and native parsers through ports, and a smaller pool of people and of training data.
- **Temporal.** It provides durable timers, retries, heartbeats and cancellation. It is also one more stateful cluster to keep running. It caps a workflow's history at about 50K events, which a large email alert could hit. And it keeps the tree in workflow history rather than in tables you can query, so results would go to Postgres anyway.
- **A React single-page GUI.** It gives a typed client generated from the OpenAPI spec and richer client-side interaction. It costs a second language, an npm dependency tree, client state to merge live updates into, and tests that need a JavaScript runner or a browser.
- **Kubernetes.** It gives per-task cgroups and autoscaling on queue depth, at the cost of a cluster to keep up.

## Sequence

1. Build the results crate, the module SDK and the module test harness. Port five modules that cover the main shapes: email parsing with mail-parser, an RDAP lookup, a delayed module, archive extraction (which writes files), and YARA with the ported scanner layer on yara-x. Measure the build loop and run the YARA comparison here, since either result could change the language pick. On the laptop the comparison compiles the whole signatures repo with both scanners and compares matches on local sample files.
2. Build the core with the queue and the bucket, and run those five end to end from a submission. Build `ace-app` and start the site_ace workspace on it here, so the boundary between the two repositories is tested from the start.
3. Compare with ace3 on the laptop's sample files: run each one through both systems and compare the trees. That comparison is the acceptance test for every module ported after this point. Shadow mode, with production traffic sent to both systems, waits until ace4 goes past a proof of concept.
4. Port the libraries without a Rust equivalent against the local sample files, running the Python pool until each port matches.
5. Build the API and the alert view, then a site's journal email collector and the hunter, then port the remaining modules one pool at a time. Alert routing, detection verdicts and AI query port as they are.

Most of the work is the roughly 90 analysis modules and the GUI. The core is the small part.

## Without a rewrite

Most of the design fits into the current codebase. The three changes to make first:

- per-analysis-type schemas with a registry keyed by type name (#1029, #999)
- engine workers started by spawn that import only their pool's modules (#982 and the memory work)
- the CAS as the only file store, which removes the node-to-node transfer

## Appendix: the 43 design flaws, grouped

Python's process and import model (9): #982, #984, #1029, #1030, #1031, #1032, #1066, #843, #953.

The other 34:

| Group | Issues |
|---|---|
| Serialization and data model | #999, #827, #850, #848, #1101 |
| Configuration | #1009, #1044, #916, #901, #858, #1063, #1064 |
| Database sessions and transactions | #1040, #852, #1084, #1023 |
| Process containment and cancellation | #981, #973, #986, #846, #845, #847 |
| Identity and audit | #1089, #830, #831 |
| Missing shared mechanisms | #894, #842, #840, #829, #1051 |
| Integrations and clients | #1100, #1018, #1096 |
| Environment | #920 |
